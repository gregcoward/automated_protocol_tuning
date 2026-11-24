"""MetricsQL Historical Traffic Analyzer & Comprehensive 135-Setting F5 Profile Optimizer."""

from __future__ import annotations

import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.bigip_client import SYSTEM_DEFAULT_PROFILES, BigIpClient, split_full_path
from backend.models import (
    AttachedProfileRef,
    ConfidenceScore,
    DiffCategory,
    ParameterDiff,
    ProtocolType,
    TuningRecommendation,
    VirtualServerItem,
)
from backend.optimizer.knowledge_base import KNOWLEDGE_BASE
from backend.optimizer.settings_catalog import SETTINGS_BY_PROTOCOL, SETTINGS_BY_REST_KEY
from backend.otel_exporter import OtelMetricsExporter
from backend.vm_client import VictoriaMetricsClient, window_to_seconds

logger = logging.getLogger(__name__)

STATEFUL_UDP_PORTS: set[int] = {443, 500, 1194, 4500, 4789, 5061, 6081, 51820}
REALTIME_MEDIA_UDP_PORTS: set[int] = {5060, 3478, 5349}


def _sanitize_name(raw: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", raw).strip("_")[:42]


def _next_power_buffer(target_bytes: float, minimum: int = 131072, maximum: int = 1048576) -> int:
    val = minimum
    while val < target_bytes and val < maximum:
        val *= 2
    return min(val, maximum)


def _extract_vs_port(destination: str) -> int:
    """Parse destination like '/Common/10.20.10.40:443' or '/Common/2001:db8::1.443' -> port int."""
    if not destination:
        return 0
    tail = destination.rsplit("/", 1)[-1]
    for sep in (":", "."):
        if sep in tail:
            maybe_port = tail.rsplit(sep, 1)[-1]
            if maybe_port.isdigit():
                return int(maybe_port)
    return 0


def _parse_timeout_num(raw: Any, default: float = 300.0) -> tuple[float, bool, bool]:
    """Return (numeric_seconds_or_ms, is_indefinite, is_immediate)."""
    s = str(raw).strip().lower() if raw is not None else ""
    if s in ("indefinite", "unlimited", "4294967295"):
        return float("inf"), True, False
    if s == "immediate":
        return 0.0, False, True
    try:
        v = float(raw)
        if v >= 4294967295:
            return float("inf"), True, False
        return v, False, v == 0.0
    except (TypeError, ValueError):
        return default, False, False


def _make_diff(
    protocol: ProtocolType,
    parameter: str,
    current_value: Any,
    recommended_value: Any,
    rationale: str,
    *,
    unit: str | None = None,
    category: DiffCategory = "telemetry",
    safe_auto_apply: bool | None = None,
    lookup_key: str | None = None,
) -> ParameterDiff:
    spec = SETTINGS_BY_REST_KEY.get((protocol, lookup_key or parameter))
    resolved_safe = spec.safe_auto_apply if (safe_auto_apply is None and spec is not None) else (
        True if safe_auto_apply is None else safe_auto_apply
    )
    return ParameterDiff(
        parameter=parameter,
        gui_name=spec.gui_name if spec else parameter,
        section=spec.section if spec else None,
        current_value=current_value,
        recommended_value=recommended_value,
        unit=unit,
        rationale=rationale,
        category=category,
        safe_auto_apply=resolved_safe,
    )


class ProtocolAnalyzer:
    """Evaluates VictoriaMetrics telemetry + all 135 BIG-IP profile settings against F5 best practices."""

    def __init__(self, vm_client: VictoriaMetricsClient, otel_exporter: OtelMetricsExporter) -> None:
        self.vm = vm_client
        self.otel = otel_exporter

    def analyze_device(
        self,
        client: BigIpClient,
        enrolled_paths: list[str] | None,
        target_vs_filter: set[str] | None,
        protocols: set[ProtocolType],
        window: str,
    ) -> tuple[list[TuningRecommendation], int, str]:
        """Run analysis across enrolled Virtual Servers on a BIG-IP device."""
        vs_list = client.discover_virtual_servers(enrolled_paths)
        selected_vs = [
            vs
            for vs in vs_list
            if vs.enrolled and (not target_vs_filter or vs.full_path in target_vs_filter)
        ]
        if not selected_vs:
            return [], 0, "none"

        vm_healthy = self.vm.is_healthy()
        telemetry_source = "victoriametrics" if vm_healthy else "live_poll_buffer"

        first_buf = self.otel.get_local_buffer_samples(client.host, selected_vs[0].full_path, 3600)
        if len(first_buf) < 2:
            try:
                s1 = client.poll_protocol_telemetry(enrolled_paths)
                self.otel.export_samples(s1)
                time.sleep(0.06)
                s2 = client.poll_protocol_telemetry(enrolled_paths)
                self.otel.export_samples(s2)
            except Exception as exc:
                logger.debug("On-demand pre-analysis poll warning on %s: %s", client.host, exc)

        recommendations: list[TuningRecommendation] = []
        for vs in selected_vs:
            vs_metrics, src = self._collect_vs_window_metrics(client.host, vs, window, vm_healthy)
            if src == "live_poll_buffer" and telemetry_source == "victoriametrics":
                telemetry_source = "hybrid_vm_and_live"

            # Pre-load all attached profile configs on this VS so cross-profile rules (e.g. proxyMss) work
            loaded_cfgs: dict[tuple[ProtocolType, str], dict[str, Any]] = {}
            for pref in vs.profiles:
                try:
                    loaded_cfgs[(pref.protocol, pref.full_path)] = client.get_profile_config(
                        pref.protocol, pref.full_path
                    )
                except Exception as exc:
                    logger.warning("Could not fetch %s profile %s: %s", pref.protocol, pref.full_path, exc)

            peer_tcp_by_ctx: dict[str, dict[str, Any]] = {}
            for pref in vs.profiles:
                if pref.protocol == "tcp" and (pref.protocol, pref.full_path) in loaded_cfgs:
                    cfg_obj = loaded_cfgs[(pref.protocol, pref.full_path)]
                    if pref.context in ("clientside", "all"):
                        peer_tcp_by_ctx["clientside"] = cfg_obj
                    if pref.context in ("serverside", "all"):
                        peer_tcp_by_ctx["serverside"] = cfg_obj

            for pref in vs.profiles:
                if pref.protocol not in protocols:
                    continue
                live_cfg = loaded_cfgs.get((pref.protocol, pref.full_path))
                if not live_cfg:
                    continue

                contexts: list[str] = (
                    ["clientside", "serverside"]
                    if (pref.protocol == "tcp" and pref.context == "all")
                    else (["serverside"] if pref.context == "serverside" else ["clientside"])
                )
                for ctx in contexts:
                    if pref.protocol == "tcp":
                        rec = self._evaluate_tcp_profile(
                            client, vs, pref, ctx, live_cfg, vs_metrics, peer_tcp_by_ctx
                        )
                        if rec:
                            recommendations.append(rec)
                    elif pref.protocol == "udp" and ctx == "clientside":
                        rec = self._evaluate_udp_profile(client, vs, pref, live_cfg, vs_metrics)
                        if rec:
                            recommendations.append(rec)
                    elif pref.protocol == "http" and ctx == "clientside":
                        rec = self._evaluate_http_profile(client, vs, pref, live_cfg, vs_metrics)
                        if rec:
                            recommendations.append(rec)

        return recommendations, len(selected_vs), telemetry_source

    def _collect_vs_window_metrics(
        self,
        bigip_host: str,
        vs: VirtualServerItem,
        window: str,
        vm_healthy: bool,
    ) -> tuple[dict[str, float], str]:
        """Query MetricsQL aggregates over `window`, falling back cleanly to recent OTLP buffer."""
        lbl = f'bigip_host="{bigip_host}",virtual_server="{vs.full_path}"'
        metrics: dict[str, float] = {}

        if vm_healthy:
            bps_out = self.vm.query_scalar(f"avg(rate(bigip_vs_bits_out_total{{{lbl}}}[{window}]))")
            if bps_out is not None:
                metrics["bps_out"] = bps_out
                metrics["bps_in"] = (
                    self.vm.query_scalar(f"avg(rate(bigip_vs_bits_in_total{{{lbl}}}[{window}]))", 0.0) or 0.0
                )
                metrics["pps_out"] = (
                    self.vm.query_scalar(f"avg(rate(bigip_vs_pkts_out_total{{{lbl}}}[{window}]))", 1.0) or 1.0
                )
                metrics["pps_in"] = (
                    self.vm.query_scalar(f"avg(rate(bigip_vs_pkts_in_total{{{lbl}}}[{window}]))", 1.0) or 1.0
                )
                metrics["cur_conns_avg"] = (
                    self.vm.query_scalar(f"avg(avg_over_time(bigip_vs_cur_conns{{{lbl}}}[{window}]))", 0.0)
                    or 0.0
                )
                metrics["ephemeral_conns_max"] = (
                    self.vm.query_scalar(
                        f"max(max_over_time(bigip_vs_ephemeral_cur_conns{{{lbl}}}[{window}]))", 0.0
                    )
                    or 0.0
                )
                metrics["syn_cookies_inc"] = (
                    self.vm.query_scalar(f"sum(increase(bigip_vs_syn_cookies_total{{{lbl}}}[{window}]))", 0.0)
                    or 0.0
                )

                for ctx in ("clientside", "serverside"):
                    clbl = f'{lbl},context="{ctx}"'
                    # Prefer true window ratio of retransmits/segments if available, else gauge average
                    rxm_rate = self.vm.query_scalar(
                        f"100 * sum(increase(bigip_tcp_retransmits_total{{{clbl}}}[{window}])) / "
                        f"clamp_min(sum(increase(bigip_tcp_segments_out_total{{{clbl}}}[{window}])), 1)"
                    )
                    if rxm_rate is None or rxm_rate <= 0:
                        rxm_rate = (
                            self.vm.query_scalar(
                                f"avg(avg_over_time(bigip_tcp_retransmit_rate_pct{{{clbl}}}[{window}]))", 0.0
                            )
                            or 0.0
                        )
                    metrics[f"tcp_{ctx}_retrans_pct"] = rxm_rate
                    metrics[f"tcp_{ctx}_rtt_ms"] = (
                        self.vm.query_scalar(f"avg(avg_over_time(bigip_tcp_rtt_ms{{{clbl}}}[{window}]))", 0.0)
                        or 0.0
                    )
                    metrics[f"tcp_{ctx}_rtt_var_ms"] = (
                        self.vm.query_scalar(
                            f"avg(avg_over_time(bigip_tcp_rtt_variance_ms{{{clbl}}}[{window}]))", 0.0
                        )
                        or 0.0
                    )
                    metrics[f"tcp_{ctx}_buf_waits"] = (
                        self.vm.query_scalar(
                            f"sum(increase(bigip_tcp_buffer_exhaustion_total{{{clbl}}}[{window}]))", 0.0
                        )
                        or 0.0
                    )
                    metrics[f"tcp_{ctx}_zero_wnd"] = (
                        self.vm.query_scalar(
                            f"sum(increase(bigip_tcp_zero_window_events_total{{{clbl}}}[{window}]))", 0.0
                        )
                        or 0.0
                    )
                    metrics[f"tcp_{ctx}_resets"] = (
                        self.vm.query_scalar(f"sum(increase(bigip_tcp_resets_total{{{clbl}}}[{window}]))", 0.0)
                        or 0.0
                    )
                    metrics[f"tcp_{ctx}_embryonic"] = (
                        self.vm.query_scalar(
                            f"max(max_over_time(bigip_tcp_embryonic_conns{{{clbl}}}[{window}]))", 0.0
                        )
                        or 0.0
                    )

                metrics["udp_drop_pct"] = (
                    self.vm.query_scalar(f"avg(avg_over_time(bigip_udp_drop_rate_pct{{{lbl}}}[{window}]))", 0.0)
                    or 0.0
                )
                metrics["udp_dgrams_per_conn"] = (
                    self.vm.query_scalar(
                        f"avg(avg_over_time(bigip_udp_datagrams_per_conn{{{lbl}}}[{window}]))", 0.0
                    )
                    or 0.0
                )
                metrics["udp_buf_overflows"] = (
                    self.vm.query_scalar(
                        f"sum(increase(bigip_udp_buffer_overflows_total{{{lbl}}}[{window}]))", 0.0
                    )
                    or 0.0
                )

                metrics["http_keepalive_reuse"] = (
                    self.vm.query_scalar(
                        f"avg(avg_over_time(bigip_http_keepalive_reqs_per_conn{{{lbl}}}[{window}]))", 0.0
                    )
                    or 0.0
                )
                metrics["http_header_drops"] = (
                    self.vm.query_scalar(
                        f"sum(increase(bigip_http_header_size_drops_total{{{lbl}}}[{window}]))", 0.0
                    )
                    or 0.0
                )
                metrics["http_header_count_drops"] = (
                    self.vm.query_scalar(
                        f"sum(increase(bigip_http_header_count_drops_total{{{lbl}}}[{window}]))", 0.0
                    )
                    or 0.0
                )
                metrics["http_pipelined_reqs"] = (
                    self.vm.query_scalar(
                        f"sum(increase(bigip_http_pipelined_requests_total{{{lbl}}}[{window}]))", 0.0
                    )
                    or 0.0
                )
                metrics["http_svr_closes"] = (
                    self.vm.query_scalar(
                        f"sum(increase(bigip_http_server_closes_total{{{lbl}}}[{window}]))", 0.0
                    )
                    or 0.0
                )
                metrics["http_reqs_inc"] = (
                    self.vm.query_scalar(f"sum(increase(bigip_http_requests_total{{{lbl}}}[{window}]))", 0.0)
                    or 0.0
                )
                metrics["http_compression_ratio"] = (
                    self.vm.query_scalar(
                        f"avg(avg_over_time(bigip_http_compression_ratio{{{lbl}}}[{window}]))", 1.0
                    )
                    or 1.0
                )
                return metrics, "victoriametrics"

        # Fallback to local OTLP sample ring buffer
        buf = self.otel.get_local_buffer_samples(bigip_host, vs.full_path, window_to_seconds(window))
        vs_pts = [b for b in buf if b.get("category") == "virtual"]
        if len(vs_pts) >= 2:
            dt = max(0.02, vs_pts[-1]["ts"] - vs_pts[0]["ts"])
            m0, m1 = vs_pts[0]["metrics"], vs_pts[-1]["metrics"]
            metrics["bps_out"] = max(
                0.0, (m1.get("bigip_vs_bits_out_total", 0) - m0.get("bigip_vs_bits_out_total", 0)) / dt
            )
            metrics["bps_in"] = max(
                0.0, (m1.get("bigip_vs_bits_in_total", 0) - m0.get("bigip_vs_bits_in_total", 0)) / dt
            )
            metrics["pps_out"] = max(
                1.0, (m1.get("bigip_vs_pkts_out_total", 0) - m0.get("bigip_vs_pkts_out_total", 0)) / dt
            )
            metrics["pps_in"] = max(
                1.0, (m1.get("bigip_vs_pkts_in_total", 0) - m0.get("bigip_vs_pkts_in_total", 0)) / dt
            )
            metrics["cur_conns_avg"] = float(m1.get("bigip_vs_cur_conns", 0))
            metrics["ephemeral_conns_max"] = float(m1.get("bigip_vs_ephemeral_cur_conns", 0))
            metrics["syn_cookies_inc"] = max(
                0.0, m1.get("bigip_vs_syn_cookies_total", 0) - m0.get("bigip_vs_syn_cookies_total", 0)
            )
        elif len(vs_pts) == 1:
            m1 = vs_pts[0]["metrics"]
            metrics["bps_out"] = float(m1.get("bigip_vs_bits_out_total", 0)) / 30.0
            metrics["bps_in"] = float(m1.get("bigip_vs_bits_in_total", 0)) / 30.0
            metrics["pps_out"] = max(1.0, float(m1.get("bigip_vs_pkts_out_total", 1)) / 30.0)
            metrics["pps_in"] = max(1.0, float(m1.get("bigip_vs_pkts_in_total", 1)) / 30.0)
            metrics["cur_conns_avg"] = float(m1.get("bigip_vs_cur_conns", 0))
            metrics["ephemeral_conns_max"] = float(m1.get("bigip_vs_ephemeral_cur_conns", 0))

        for ctx in ("clientside", "serverside"):
            t_pts = [b for b in buf if b.get("category") == "tcp" and b.get("context") == ctx]
            if t_pts:
                latest = t_pts[-1]["metrics"]
                first = t_pts[0]["metrics"]
                metrics[f"tcp_{ctx}_retrans_pct"] = float(latest.get("bigip_tcp_retransmit_rate_pct", 0.0))
                metrics[f"tcp_{ctx}_rtt_ms"] = float(latest.get("bigip_tcp_rtt_ms", 0.0))
                metrics[f"tcp_{ctx}_rtt_var_ms"] = float(latest.get("bigip_tcp_rtt_variance_ms", 0.0))
                buf_delta = latest.get("bigip_tcp_buffer_exhaustion_total", 0) - first.get(
                    "bigip_tcp_buffer_exhaustion_total", 0
                )
                metrics[f"tcp_{ctx}_buf_waits"] = max(0.0, buf_delta)
                zw_delta = latest.get("bigip_tcp_zero_window_events_total", 0) - first.get(
                    "bigip_tcp_zero_window_events_total", 0
                )
                metrics[f"tcp_{ctx}_zero_wnd"] = max(0.0, zw_delta)
                metrics[f"tcp_{ctx}_resets"] = max(
                    0.0, latest.get("bigip_tcp_resets_total", 0) - first.get("bigip_tcp_resets_total", 0)
                )
                metrics[f"tcp_{ctx}_embryonic"] = float(latest.get("bigip_tcp_embryonic_conns", 0.0))

        u_pts = [b for b in buf if b.get("category") == "udp"]
        if u_pts:
            ul = u_pts[-1]["metrics"]
            uf = u_pts[0]["metrics"]
            metrics["udp_drop_pct"] = float(ul.get("bigip_udp_drop_rate_pct", 0.0))
            metrics["udp_dgrams_per_conn"] = float(ul.get("bigip_udp_datagrams_per_conn", 0.0))
            ubuf_delta = ul.get("bigip_udp_buffer_overflows_total", 0.0) - uf.get(
                "bigip_udp_buffer_overflows_total", 0.0
            )
            metrics["udp_buf_overflows"] = max(
                float(ul.get("bigip_udp_buffer_overflows_total", 0.0)) if len(u_pts) == 1 else 0.0,
                ubuf_delta,
            )

        h_pts = [b for b in buf if b.get("category") == "http"]
        if h_pts:
            hl = h_pts[-1]["metrics"]
            hf = h_pts[0]["metrics"]
            metrics["http_keepalive_reuse"] = float(hl.get("bigip_http_keepalive_reqs_per_conn", 0.0))
            metrics["http_header_drops"] = max(
                0.0,
                hl.get("bigip_http_header_size_drops_total", 0.0)
                - hf.get("bigip_http_header_size_drops_total", 0.0),
            )
            metrics["http_header_count_drops"] = max(
                0.0,
                hl.get("bigip_http_header_count_drops_total", 0.0)
                - hf.get("bigip_http_header_count_drops_total", 0.0),
            )
            metrics["http_pipelined_reqs"] = max(
                0.0,
                hl.get("bigip_http_pipelined_requests_total", 0.0)
                - hf.get("bigip_http_pipelined_requests_total", 0.0),
            )
            metrics["http_svr_closes"] = max(
                0.0,
                hl.get("bigip_http_server_closes_total", 0.0) - hf.get("bigip_http_server_closes_total", 0.0),
            )
            metrics["http_reqs_inc"] = max(
                0.0, hl.get("bigip_http_requests_total", 0.0) - hf.get("bigip_http_requests_total", 0.0)
            )
            metrics["http_compression_ratio"] = float(hl.get("bigip_http_compression_ratio", 1.0))

        return metrics, "live_poll_buffer"

    # =========================================================================
    # TCP Profile Evaluator — All 76 Settings across 8 Sections
    # =========================================================================
    def _evaluate_tcp_profile(
        self,
        client: BigIpClient,
        vs: VirtualServerItem,
        pref: AttachedProfileRef,
        ctx: str,
        cfg: dict[str, Any],
        m: dict[str, float],
        peer_tcp_by_ctx: dict[str, dict[str, Any]],
    ) -> TuningRecommendation | None:
        diffs: list[ParameterDiff] = []
        advisories: list[str] = []
        evidence_parts: list[str] = []
        primary_kb = "K75593415"
        confidence: ConfidenceScore = "Medium"
        impact: ConfidenceScore = "Medium"

        retrans_pct = m.get(f"tcp_{ctx}_retrans_pct", 0.0)
        rtt_ms = m.get(f"tcp_{ctx}_rtt_ms", 0.0)
        rtt_var_ms = m.get(f"tcp_{ctx}_rtt_var_ms", 0.0)
        buf_waits = m.get(f"tcp_{ctx}_buf_waits", 0.0)
        zero_wnd = m.get(f"tcp_{ctx}_zero_wnd", 0.0)
        resets = m.get(f"tcp_{ctx}_resets", 0.0)
        embryonic = m.get(f"tcp_{ctx}_embryonic", 0.0)
        bps_out = m.get("bps_out", 0.0)
        bps_in = m.get("bps_in", 0.0)
        pps_out = max(1.0, m.get("pps_out", 1.0))
        cur_conns = m.get("cur_conns_avg", 0.0)
        ephem_conns = m.get("ephemeral_conns_max", 0.0)
        syn_cookies = m.get("syn_cookies_inc", 0.0)
        avg_pkt_bytes = (bps_out / 8.0) / pps_out if bps_out > 0 else 800.0
        vs_port = _extract_vs_port(vs.destination)
        has_http = any(p.protocol == "http" for p in vs.profiles)

        recommended_parent: str | None = None
        if pref.full_path == "/Common/tcp":
            if ctx == "clientside":
                recommended_parent = (
                    "/Common/f5-tcp-progressive"
                    if (rtt_var_ms >= 12.0 and cur_conns >= 500)
                    else ("/Common/f5-tcp-wan" if rtt_ms >= 20.0 else "/Common/f5-tcp-progressive")
                )
            else:
                recommended_parent = "/Common/f5-tcp-lan"
            evidence_parts.append(
                f"Legacy /Common/tcp attached on {ctx}; recommend split-TCP inheritance from {recommended_parent}"
            )

        # --- Section 5: Congestion Control (13 settings) ---
        cur_cc = str(cfg.get("congestionControl", "high-speed"))
        cur_abc = str(cfg.get("abc", "enabled"))
        cur_slow_start = str(cfg.get("slowStart", "enabled"))
        cur_cmetrics = str(cfg.get("cmetricsCache", "enabled"))
        cur_cmetrics_to = int(cfg.get("cmetricsCacheTimeout", 0) or 0)
        cur_dwc = str(cfg.get("delayWindowControl", "disabled"))
        cur_ecn = str(cfg.get("ecn", "enabled"))
        cur_init_cwnd = int(cfg.get("initCwnd", 10) or 0)
        cur_loss_burst = int(cfg.get("pktLossIgnoreBurst", 0) or 0)
        cur_loss_rate = int(cfg.get("pktLossIgnoreRate", 0) or 0)
        cur_rate_pace = str(cfg.get("ratePace", "enabled"))
        cur_rate_pace_max = int(cfg.get("ratePaceMaxRate", 0) or 0)
        cur_timestamps = str(cfg.get("timestamps", "enabled"))

        target_cc = cur_cc
        if cur_cc in ("none", "reno", "new-reno"):
            target_cc = "bbr" if (ctx == "clientside" and rtt_ms >= 25.0) else (
                "woodside" if ctx == "serverside" else "cubic"
            )
            diffs.append(
                _make_diff(
                    "tcp", "congestionControl", cur_cc, target_cc,
                    f"Replace legacy/unsafe congestionControl '{cur_cc}' with modern '{target_cc}'.",
                    category="hygiene",
                )
            )
            primary_kb = "K02412420"
            confidence, impact = "High", "High"
        elif ctx == "clientside" and retrans_pct >= 1.5 and (rtt_ms >= 25.0 or rtt_var_ms >= 10.0):
            if cur_cc != "bbr":
                target_cc = "bbr"
                diffs.append(
                    _make_diff(
                        "tcp", "congestionControl", cur_cc, "bbr",
                        f"BBR paces by bottleneck bandwidth & min-RTT instead of collapsing cwnd on {retrans_pct:.2f}% WAN loss.",
                    )
                )
                evidence_parts.append(
                    f"Retransmission rate {retrans_pct:.2f}% with RTT {rtt_ms:.1f} ms (variance {rtt_var_ms:.1f} ms)"
                )
                primary_kb = "K02412420"
                confidence, impact = "High", "High"
        elif ctx == "clientside" and rtt_ms >= 20.0 and cur_cc == "high-speed":
            target_cc = "cubic"
            diffs.append(
                _make_diff(
                    "tcp", "congestionControl", cur_cc, "cubic",
                    f"Switch WAN profile ({rtt_ms:.1f} ms RTT) from legacy High-Speed TCP to CUBIC.",
                )
            )
        elif ctx == "serverside" and rtt_ms <= 8.0 and bps_out > 5_000_000 and cur_cc == "high-speed":
            target_cc = "woodside"
            diffs.append(
                _make_diff(
                    "tcp", "congestionControl", cur_cc, "woodside",
                    "Use Woodside congestion recovery on low-latency LAN server-side connections.",
                )
            )

        if cur_abc == "disabled":
            diffs.append(
                _make_diff(
                    "tcp", "abc", cur_abc, "enabled",
                    "F5 recommends Appropriate Byte Counting (RFC 3465) enabled so delayed/lost ACKs do not stall cwnd.",
                    category="hygiene",
                )
            )

        if cur_slow_start == "disabled" and (ctx == "clientside" or rtt_ms >= 5.0 or retrans_pct >= 0.5):
            diffs.append(
                _make_diff(
                    "tcp", "slowStart", cur_slow_start, "enabled",
                    "Disabling Slow Start bursts immediately at max window scale and disables Congestion Metrics Cache.",
                    category="hygiene",
                )
            )
            cur_slow_start = "enabled"

        if cur_slow_start == "enabled" and cur_cmetrics == "disabled" and ctx == "serverside":
            diffs.append(
                _make_diff(
                    "tcp", "cmetricsCache", cur_cmetrics, "enabled",
                    "Enable Congestion Metrics Cache on server-side pool connections to reuse learned RTT/ssthresh.",
                    category="hygiene",
                )
            )
        elif cur_slow_start == "disabled" and cur_cmetrics == "enabled":
            advisories.append(
                "Congestion Metrics Cache (cmetricsCache) is currently ignored because Slow Start is disabled."
            )

        if cur_cmetrics == "enabled" and ctx == "clientside" and rtt_var_ms >= 18.0 and cur_cmetrics_to > 3600:
            diffs.append(
                _make_diff(
                    "tcp", "cmetricsCacheTimeout", cur_cmetrics_to, 1800,
                    "Bound cached peer congestion metrics to 1800s on high-jitter WAN/mobile paths.",
                    unit="seconds",
                )
            )

        if target_cc in ("bbr", "cdg", "chd", "vegas") and cur_dwc == "enabled":
            diffs.append(
                _make_diff(
                    "tcp", "delayWindowControl", cur_dwc, "disabled",
                    f"Disable Delay Window Control when delay-aware congestionControl '{target_cc}' is active.",
                    category="dependency",
                )
            )

        if target_cc == "bbr" and (cur_loss_rate > 0 or cur_loss_burst > 0):
            if cur_loss_rate > 0:
                diffs.append(
                    _make_diff(
                        "tcp", "pktLossIgnoreRate", cur_loss_rate, 0,
                        "Reset Packet Loss Ignore Rate to 0 when BBR handles random loss natively.",
                        category="dependency",
                    )
                )
            if cur_loss_burst > 0:
                diffs.append(
                    _make_diff(
                        "tcp", "pktLossIgnoreBurst", cur_loss_burst, 0,
                        "Reset Packet Loss Ignore Burst to 0 when BBR is active.",
                        category="dependency",
                    )
                )
        elif cur_loss_rate > 25000:
            diffs.append(
                _make_diff(
                    "tcp", "pktLossIgnoreRate", cur_loss_rate, 5000,
                    f"Packet Loss Ignore Rate ({cur_loss_rate}/M) ignores >{cur_loss_rate / 10000:.1f}% loss, risking congestive collapse.",
                    category="hygiene",
                )
            )

        if cur_rate_pace == "disabled" and ctx == "clientside" and (rtt_ms >= 15.0 or retrans_pct >= 1.0):
            diffs.append(
                _make_diff(
                    "tcp", "ratePace", cur_rate_pace, "enabled",
                    "Enable Rate Pace to smooth egress bursts and avoid router queue tail-drops on WAN/mobile links.",
                )
            )
            cur_rate_pace = "enabled"

        if cur_rate_pace_max > 0 and cur_rate_pace == "disabled":
            advisories.append(
                f"Rate Pace Maximum Rate ({cur_rate_pace_max:,} B/s) has no effect while Rate Pace is disabled."
            )

        if cur_timestamps == "disabled" and (target_cc == "bbr" or bps_out > 50_000_000 or rtt_ms >= 20.0):
            diffs.append(
                _make_diff(
                    "tcp", "timestamps", cur_timestamps, "enabled",
                    "Enable RFC 1323 Timestamps for accurate RTT measurement and high-speed PAWS protection.",
                    category="dependency",
                )
            )

        if cur_init_cwnd < 10:
            new_cwnd = 16 if (ctx == "clientside" and rtt_ms >= 20.0 and cur_rate_pace == "enabled") else 10
            diffs.append(
                _make_diff(
                    "tcp", "initCwnd", cur_init_cwnd, new_cwnd,
                    f"Raise Initial Congestion Window from {cur_init_cwnd} to {new_cwnd}x MSS (RFC 6928 / F5 WAN baseline).",
                    unit="x MSS",
                )
            )
        elif ctx == "clientside" and rtt_ms >= 20.0 and bps_out >= 10_000_000 and cur_init_cwnd < 16 and cur_rate_pace == "enabled":
            diffs.append(
                _make_diff(
                    "tcp", "initCwnd", cur_init_cwnd, 16,
                    f"Increase Initial Congestion Window to 16x MSS over {rtt_ms:.1f} ms WAN so TLS/HTTP fits first flight.",
                    unit="x MSS",
                )
            )

        if ctx == "serverside" and cur_ecn == "enabled":
            # Per TCP_Profile_Settings.docx: ECN is effective on client-side only by design
            pass
        elif ctx == "clientside" and cur_ecn == "enabled" and retrans_pct < 0.2 and buf_waits == 0 and rtt_ms > 50 and bps_out < 2_000_000:
            advisories.append(
                "ECN is enabled on client-side; verify intermediate WAN devices are not spoofing CWR flags if throughput appears capped."
            )

        # --- Section 2: Memory Management (7 settings) ---
        cur_snd = int(cfg.get("sendBufferSize", 131072) or 131072)
        cur_rcv = int(cfg.get("receiveWindowSize", 65535) or 65535)
        cur_pb_high = int(cfg.get("proxyBufferHigh", 131072) or 131072)
        cur_pb_low = int(cfg.get("proxyBufferLow", 98304) or 98304)
        cur_auto_pb = str(cfg.get("autoProxyBufferSize", "disabled"))
        cur_auto_rcv = str(cfg.get("autoReceiveWindowSize", "disabled"))
        cur_auto_snd = str(cfg.get("autoSendBufferSize", "disabled"))
        cur_mss = int(cfg.get("maxSegmentSize", 1460) or 1460)

        # Per-connection BDP estimate: VS bps_out/bps_in are aggregate across all active connections,
        # so bound single-socket BDP estimation rather than attributing entire VIP rate to 1 socket.
        per_flow_bps_out = min(bps_out, max(bps_out / max(1.0, cur_conns * 0.05), 100_000_000.0))
        per_flow_bps_in = min(bps_in, max(bps_in / max(1.0, cur_conns * 0.05), 50_000_000.0))
        eff_rtt_sec = max(rtt_ms, 1.0 if ctx == "serverside" else 5.0) / 1000.0
        bdp_bytes = (per_flow_bps_out / 8.0) * eff_rtt_sec
        bdp_in_bytes = (per_flow_bps_in / 8.0) * eff_rtt_sec
        min_cwnd_bytes = max(cur_init_cwnd, 16 if rtt_ms >= 20 else 10) * max(cur_mss, 1460)
        desired_snd = _next_power_buffer(
            max(bdp_bytes * 2.5, min_cwnd_bytes * 2, 262144 if (buf_waits > 0 and rtt_ms >= 25) else 131072),
            minimum=131072,
            maximum=1048576,
        )

        target_snd = cur_snd
        if (buf_waits > 0 or bdp_bytes > cur_snd * 0.8) and cur_snd < desired_snd:
            target_snd = desired_snd
            diffs.append(
                _make_diff(
                    "tcp", "sendBufferSize", cur_snd, desired_snd,
                    f"Scale Send Buffer above 2x BDP ({int(bdp_bytes):,} B) to eliminate {int(buf_waits)} buffer exhaustion waits.",
                    unit="bytes",
                )
            )
            evidence_parts.append(
                f"Buffer waits={int(buf_waits)} at {bps_out / 1e6:.1f} Mbps (BDP {int(bdp_bytes):,} B vs sendBufferSize {cur_snd:,} B)"
            )
            if primary_kb == "K75593415":
                primary_kb = "K3422"
            confidence, impact = "High", "High"

        new_pb_high = max(cur_pb_high, target_snd)
        if new_pb_high != cur_pb_high:
            diffs.append(
                _make_diff(
                    "tcp", "proxyBufferHigh", cur_pb_high, new_pb_high,
                    "Maintain Proxy Buffer High >= Send Buffer Size to prevent premature content-spooling backpressure.",
                    unit="bytes",
                    category="dependency" if target_snd == cur_snd else "telemetry",
                )
            )
        desired_pb_low = int(new_pb_high * 0.75)
        if new_pb_high != cur_pb_high or cur_pb_low >= new_pb_high or cur_pb_low > int(new_pb_high * 0.9):
            if cur_pb_low != desired_pb_low:
                diffs.append(
                    _make_diff(
                        "tcp", "proxyBufferLow", cur_pb_low, desired_pb_low,
                        "Set Proxy Buffer Low to 75% of Proxy Buffer High to prevent receive-window open/close oscillation.",
                        unit="bytes",
                        category="dependency",
                    )
                )

        if (zero_wnd > 0 or bdp_in_bytes > cur_rcv * 0.8 or bps_in >= 25_000_000) and cur_rcv < 131072:
            desired_rcv = _next_power_buffer(max(131072.0, bdp_in_bytes * 2.5), 131072, 524288)
            diffs.append(
                _make_diff(
                    "tcp", "receiveWindowSize", cur_rcv, desired_rcv,
                    f"Widen Receive Window > 65535 B ({desired_rcv:,} B) to enable RFC 1323 Window Scaling (zero-window events={int(zero_wnd)}).",
                    unit="bytes",
                )
            )
            evidence_parts.append(f"Zero-window events={int(zero_wnd)} on {ctx} with receiveWindowSize={cur_rcv:,} B")
            if primary_kb == "K75593415":
                primary_kb = "K3422"

        if ctx == "clientside" and rtt_var_ms >= 10.0 and cur_conns >= 500:
            if cur_auto_snd == "disabled":
                diffs.append(
                    _make_diff(
                        "tcp", "autoSendBufferSize", cur_auto_snd, "enabled",
                        f"Enable Auto Send Buffer for mixed-RTT client traffic (RTT variance {rtt_var_ms:.1f} ms across {int(cur_conns)} conns).",
                    )
                )
            if cur_auto_pb == "disabled":
                diffs.append(
                    _make_diff(
                        "tcp", "autoProxyBufferSize", cur_auto_pb, "enabled",
                        "Enable Auto Proxy Buffer to dynamically tune content-spooling watermarks per flow.",
                    )
                )
            if cur_auto_rcv == "disabled" and (zero_wnd > 0 or bps_in >= 20_000_000):
                diffs.append(
                    _make_diff(
                        "tcp", "autoReceiveWindowSize", cur_auto_rcv, "enabled",
                        "Enable Auto Receive Window to dynamically scale client upload receive windows.",
                    )
                )

        # --- Section 4: Data Transfer (10 settings) ---
        raw_nagle = str(cfg.get("nagle", "disabled"))
        cur_nagle = "auto" if raw_nagle == "progressive" else raw_nagle
        cur_ack_push = str(cfg.get("ackOnPush", "enabled"))
        cur_delayed_acks = str(cfg.get("delayedAcks", "enabled"))
        cur_df = str(cfg.get("ipDfMode", "pmtu"))
        cur_init_rwnd = int(cfg.get("initRwnd", 10) or 0)
        cur_push = str(cfg.get("pushFlag", "default"))
        cur_ttl_mode = str(cfg.get("ipTtlMode", "proxy"))
        cur_ttl_v4 = int(cfg.get("ipTtlV4", 255) or 255)
        cur_ttl_v6 = int(cfg.get("ipTtlV6", 64) or 64)

        if cur_nagle == "enabled" and (avg_pkt_bytes < 680.0 or bps_out > 1_000_000):
            target_nagle = "disabled" if avg_pkt_bytes < 550.0 else "auto"
            diffs.append(
                _make_diff(
                    "tcp", "nagle", raw_nagle, target_nagle,
                    f"Small/interactive segments ({avg_pkt_bytes:.0f} B avg) with Nagle 'enabled' + Delayed ACKs inject 40-200 ms stalls.",
                )
            )
            evidence_parts.append(f"Small-packet workload ({avg_pkt_bytes:.0f} B/pkt) with Nagle '{raw_nagle}'")
            if primary_kb == "K75593415":
                primary_kb = "K15812"
            confidence, impact = "High", "High"

        if cur_ack_push == "disabled" and cur_delayed_acks == "enabled":
            diffs.append(
                _make_diff(
                    "tcp", "ackOnPush", cur_ack_push, "enabled",
                    "Enable Acknowledge on Push to prevent small-buffer stalls for Windows/macOS peers when Delayed ACKs are active.",
                    category="hygiene",
                )
            )

        if ctx == "serverside" and rtt_ms < 5.0 and avg_pkt_bytes < 450.0 and bps_out > 5_000_000 and cur_delayed_acks == "enabled":
            diffs.append(
                _make_diff(
                    "tcp", "delayedAcks", cur_delayed_acks, "disabled",
                    "Disable Delayed ACKs on ultra-low-latency (<5 ms), tiny-segment (<450 B) server-side RPC traffic.",
                    safe_auto_apply=False,
                )
            )

        if pps_out > 15_000 and avg_pkt_bytes >= 900.0 and cur_push == "default":
            diffs.append(
                _make_diff(
                    "tcp", "pushFlag", cur_push, "auto",
                    f"Set PUSH Flag to 'auto' at {pps_out:,.0f} pps egress to coalesce peer ACKs to once per RTT / response end.",
                )
            )

        if (bps_in >= 25_000_000 or zero_wnd > 0) and cur_init_rwnd < 16:
            diffs.append(
                _make_diff(
                    "tcp", "initRwnd", cur_init_rwnd, 16,
                    "Raise Initial Receive Window Size to 16x MSS to accelerate immediate client request uploads.",
                    unit="x MSS",
                )
            )

        if 0 < cur_mss < 1200:
            advisories.append(
                f"Max Segment Size ({cur_mss} B) is unusually small (<1200 B), increasing TCP/IP header overhead unless required by an overlay tunnel."
            )
        if cur_df == "set" and retrans_pct >= 2.0 and rtt_ms >= 20.0:
            diffs.append(
                _make_diff(
                    "tcp", "ipDfMode", cur_df, "pmtu",
                    "Use 'pmtu' rather than forced 'set' for Don't Fragment flag to respect Path MTU Discovery.",
                    category="hygiene",
                )
            )

        if cur_ttl_mode == "set":
            if cur_ttl_v4 < 32:
                diffs.append(
                    _make_diff(
                        "tcp", "ipTtlV4", cur_ttl_v4, 64,
                        f"IPv4 TTL ({cur_ttl_v4}) under TTL Mode 'set' risks premature hop expiration across WAN paths.",
                        category="dependency",
                    )
                )
            if cur_ttl_v6 < 32:
                diffs.append(
                    _make_diff(
                        "tcp", "ipTtlV6", cur_ttl_v6, 64,
                        f"IPv6 Hop Limit ({cur_ttl_v6}) under TTL Mode 'set' risks premature hop expiration.",
                        category="dependency",
                    )
                )

        # --- Section 3: Connection Setup (6 settings) ---
        cur_deferred = str(cfg.get("deferredAccept", "disabled"))
        cur_fast_open = str(cfg.get("fastOpen", "enabled"))
        cur_tfo_exp = int(cfg.get("fastOpenCookieExpiration", 21600) or 0)
        cur_proxy_mss = str(cfg.get("proxyMss", "enabled"))
        cur_proxy_opts = str(cfg.get("proxyOptions", "enabled"))
        cur_verified = str(cfg.get("verifiedAccept", "disabled"))
        cur_md5 = str(cfg.get("md5Signature", "disabled"))

        if cur_verified == "enabled" and (vs.has_apm or vs.irules or has_http):
            diffs.append(
                _make_diff(
                    "tcp", "verifiedAccept", cur_verified, "disabled",
                    "Verified Accept is incompatible with APM and reorders iRule/HTTP events (SERVER_CONNECTED fires before HTTP_REQUEST).",
                    category="dependency",
                    safe_auto_apply=False,
                )
            )
            evidence_parts.append("Verified Accept enabled alongside HTTP/iRules/APM on Virtual Server")
            confidence, impact = "High", "High"

        if ctx == "clientside" and cur_deferred == "disabled" and (vs.has_clientssl or has_http) and (syn_cookies > 0 or embryonic >= 40):
            diffs.append(
                _make_diff(
                    "tcp", "deferredAccept", cur_deferred, "enabled",
                    f"Enable Deferred Accept on client-speaks-first HTTP/TLS VIP to defer context allocation during handshake spikes (embryonic={int(embryonic)}).",
                    safe_auto_apply=False,
                )
            )

        if ctx == "clientside" and cur_fast_open == "disabled" and cur_md5 == "disabled" and cur_verified == "disabled":
            if avg_pkt_bytes < 680.0 or vs.has_clientssl or cur_conns > 250:
                diffs.append(
                    _make_diff(
                        "tcp", "fastOpen", cur_fast_open, "enabled",
                        "Enable client-side TCP Fast Open to save 1 RTT on repeat client SYN handshakes.",
                    )
                )
        if ctx == "clientside" and cur_fast_open == "enabled" and 0 < cur_tfo_exp < 300:
            diffs.append(
                _make_diff(
                    "tcp", "fastOpenCookieExpiration", cur_tfo_exp, 21600,
                    f"Fast Open Cookie Expiration ({cur_tfo_exp}s) is too short for repeat-client TFO reuse; restore 21600s (6h).",
                    unit="seconds",
                    category="hygiene",
                )
            )

        if ctx == "clientside" and cur_proxy_mss == "enabled":
            srv_tcp = peer_tcp_by_ctx.get("serverside")
            if srv_tcp and str(srv_tcp.get("proxyMss", "enabled")) == "disabled":
                advisories.append(
                    "Proxy Maximum Segment (proxyMss) is enabled on client-side TCP profile but disabled on the server-side TCP profile — both must be enabled for MSS proxying to function."
                )

        if ctx == "serverside" and cur_proxy_opts == "enabled" and m.get("tcp_clientside_retrans_pct", 0.0) >= 2.0:
            advisories.append(
                "Proxy Options is enabled on server-side; consider disabling if legacy WAN clients omit TCP Timestamps so server-side LAN always negotiates full RFC 1323 options."
            )

        # --- Section 6: Loss Detection and Recovery (11 settings) ---
        cur_sack = str(cfg.get("selectiveAcks", "enabled"))
        cur_snack = str(cfg.get("selectiveNack", "disabled"))
        cur_dsack = str(cfg.get("dsack", "disabled"))
        cur_er = str(cfg.get("earlyRetransmit", "enabled"))
        cur_elr = str(cfg.get("enhancedLossRecovery", "enabled"))
        cur_lt = str(cfg.get("limitedTransmit", "enabled"))
        cur_tlp = str(cfg.get("tailLossProbe", "enabled"))
        cur_syn_rto = int(cfg.get("synRtoBase", 3000) or 3000)
        cur_max_rxm = int(cfg.get("maxRetrans", 8) or 8)
        cur_syn_rxm = int(cfg.get("synMaxRetrans", 3) or 3)
        cur_rxm_thresh = int(cfg.get("rexmtThresh", 3) or 3)

        if cur_sack == "disabled" and cur_md5 == "disabled":
            diffs.append(
                _make_diff(
                    "tcp", "selectiveAcks", cur_sack, "enabled",
                    "Enable Selective ACKs (SACK) — required for Enhanced Loss Recovery, D-SACK, and multi-loss recovery.",
                    category="dependency",
                )
            )
            cur_sack = "enabled"

        if cur_snack == "enabled":
            diffs.append(
                _make_diff(
                    "tcp", "selectiveNack", cur_snack, "disabled",
                    "F5 recommends keeping Selective NACK disabled outside legacy WAN Optimization Module links.",
                    category="hygiene",
                )
            )

        if cur_er == "disabled":
            diffs.append(
                _make_diff(
                    "tcp", "earlyRetransmit", cur_er, "enabled",
                    "Enable Early Retransmit (RFC 5827) to speed recovery on short/window-limited flights.",
                    category="hygiene",
                )
            )

        if cur_lt == "disabled":
            diffs.append(
                _make_diff(
                    "tcp", "limitedTransmit", cur_lt, "enabled",
                    "Enable Limited Transmit Recovery (RFC 3042) to sustain ACK clocking during loss.",
                    category="hygiene",
                )
            )

        if cur_tlp == "disabled":
            diffs.append(
                _make_diff(
                    "tcp", "tailLossProbe", cur_tlp, "enabled",
                    "Enable Tail Loss Probe to convert end-of-burst tail drops into fast recovery instead of 1s+ RTOs.",
                    category="hygiene",
                )
            )

        if cur_elr == "disabled" and cur_sack == "enabled":
            diffs.append(
                _make_diff(
                    "tcp", "enhancedLossRecovery", cur_elr, "enabled",
                    "Enable Enhanced Loss Recovery (with Selective ACKs) to prevent timeout stalls under high loss.",
                    category="hygiene",
                )
            )

        if ctx == "clientside" and cur_dsack == "disabled" and cur_sack == "enabled" and retrans_pct >= 1.5 and rtt_var_ms >= 10.0:
            diffs.append(
                _make_diff(
                    "tcp", "dsack", cur_dsack, "enabled",
                    f"Enable D-SACK (RFC 2883) to detect spurious retransmissions under {rtt_var_ms:.1f} ms WAN jitter.",
                )
            )

        if cur_syn_rto >= 2000 and (bps_out > 1_000_000 or cur_conns > 50):
            target_syn_rto = 500 if (ctx == "serverside" and rtt_ms < 10.0) else 1000
            if rtt_ms < 250.0:
                diffs.append(
                    _make_diff(
                        "tcp", "synRtoBase", cur_syn_rto, target_syn_rto,
                        f"Lower SYN RTO Base from {cur_syn_rto} ms to {target_syn_rto} ms so dropped handshake SYNs do not stall for 3s.",
                        unit="ms",
                    )
                )

        if cur_syn_rxm > 3 and (cur_conns > 2000 or syn_cookies > 0 or ctx == "serverside"):
            diffs.append(
                _make_diff(
                    "tcp", "synMaxRetrans", cur_syn_rxm, 2 if ctx == "serverside" else 3,
                    "Bound Maximum SYN Retransmissions to prevent half-open backlog stalls and speed backend failover.",
                )
            )

        if cur_max_rxm < 4 or cur_max_rxm > 12:
            target_max_rxm = 6 if ctx == "serverside" else 8
            diffs.append(
                _make_diff(
                    "tcp", "maxRetrans", cur_max_rxm, target_max_rxm,
                    f"Right-size Maximum Segment Retransmissions from {cur_max_rxm} to {target_max_rxm}.",
                    category="hygiene",
                )
            )

        if cur_rxm_thresh > 4:
            diffs.append(
                _make_diff(
                    "tcp", "rexmtThresh", cur_rxm_thresh, 3,
                    f"Lower Retransmit Threshold from {cur_rxm_thresh} to standard 3 duplicate ACKs.",
                    category="hygiene",
                )
            )

        # --- Section 1: Timer Management (10 settings) ---
        cw_val, cw_indef, _ = _parse_timeout_num(cfg.get("closeWaitTimeout", 5), 5)
        fw1_val, fw1_indef, _ = _parse_timeout_num(cfg.get("finWaitTimeout", 5), 5)
        fw2_val, fw2_indef, _ = _parse_timeout_num(cfg.get("finWait_2Timeout", 300), 300)
        idle_val, idle_indef, _ = _parse_timeout_num(cfg.get("idleTimeout", 300), 300)
        ka_val, ka_indef, _ = _parse_timeout_num(cfg.get("keepAliveInterval", 1800), 1800)
        tw_val, tw_indef, _ = _parse_timeout_num(cfg.get("timeWaitTimeout", 2000), 2000)
        zw_val, zw_indef, _ = _parse_timeout_num(cfg.get("zeroWindowTimeout", 20000), 20000)
        cur_min_rto = int(cfg.get("minimumRto", 1000) or 1000)
        cur_rst_to = str(cfg.get("resetOnTimeout", "enabled"))
        cur_tw_recycle = str(cfg.get("timeWaitRecycle", "enabled"))
        cur_mptcp = str(cfg.get("mptcp", "disabled"))

        if cw_indef or cw_val > 30:
            diffs.append(
                _make_diff(
                    "tcp", "closeWaitTimeout", cfg.get("closeWaitTimeout"), 5,
                    "Bound Close Wait timeout to 5s to prevent leaked sockets in LAST-ACK/CLOSE-WAIT.",
                    unit="seconds",
                    category="hygiene",
                )
            )

        if fw1_indef or fw1_val > 30:
            diffs.append(
                _make_diff(
                    "tcp", "finWaitTimeout", cfg.get("finWaitTimeout"), 5,
                    "Bound Fin Wait 1 timeout to 5s to reclaim SNAT ports promptly on unacknowledged FINs.",
                    unit="seconds",
                )
            )

        if fw2_indef or (cur_conns > 2500 and fw2_val > 120 and ephem_conns > 1200):
            diffs.append(
                _make_diff(
                    "tcp", "finWait_2Timeout", cfg.get("finWait_2Timeout"), 60,
                    f"Reduce Fin Wait 2 from {cfg.get('finWait_2Timeout')}s to 60s under high concurrency ({int(cur_conns)} active conns).",
                    unit="seconds",
                    safe_auto_apply=False,
                )
            )

        if idle_indef and ka_indef:
            diffs.append(
                _make_diff(
                    "tcp", "keepAliveInterval", cfg.get("keepAliveInterval"), 300,
                    "Idle Timeout is 'indefinite' with Keep-Alive disabled — set Keep-Alive Interval to 300s to detect dead peers.",
                    unit="seconds",
                    category="dependency",
                )
            )
        elif not idle_indef and idle_val > 600 and cur_conns > 2000:
            diffs.append(
                _make_diff(
                    "tcp", "idleTimeout", int(idle_val), 300,
                    f"Reclaim idle connection slots under high concurrency ({int(cur_conns)} active conns).",
                    unit="seconds",
                    safe_auto_apply=False,
                )
            )
            evidence_parts.append(f"High idleTimeout ({int(idle_val)}s) with {int(cur_conns)} active connections")
            if len(diffs) <= 2:
                primary_kb = "K7606"
        elif not idle_indef and idle_val >= 900 and (ka_indef or ka_val >= idle_val):
            target_ka = min(300, int(idle_val // 2))
            diffs.append(
                _make_diff(
                    "tcp", "keepAliveInterval", cfg.get("keepAliveInterval"), target_ka,
                    f"Keep-Alive Interval ({cfg.get('keepAliveInterval')}s) >= Idle Timeout ({int(idle_val)}s) never fires; set to {target_ka}s.",
                    unit="seconds",
                    category="dependency",
                )
            )

        # Minimum RTO: note TMOS auto-drops to 203 ms when pktLossIgnore* > 0 and 200 ms when mptcp=enabled
        auto_low_rto = (cur_mptcp == "enabled") or (
            target_cc != "bbr" and (cur_loss_rate > 0 or cur_loss_burst > 0)
        )
        if not auto_low_rto and cur_min_rto >= 1000 and (bps_out > 1_000_000 or retrans_pct > 0.3):
            if ctx == "serverside" and rtt_ms < 10.0:
                diffs.append(
                    _make_diff(
                        "tcp", "minimumRto", cur_min_rto, 200,
                        f"Lower Minimum RTO floor from {cur_min_rto} ms to 200 ms on low-RTT ({rtt_ms:.1f} ms) LAN server-side links.",
                        unit="ms",
                    )
                )
            elif ctx == "clientside" and 5.0 <= rtt_ms <= 100.0 and retrans_pct >= 0.5:
                diffs.append(
                    _make_diff(
                        "tcp", "minimumRto", cur_min_rto, 300,
                        f"Lower Minimum RTO floor from {cur_min_rto} ms to 300 ms for faster WAN timeout recovery ({rtt_ms:.1f} ms RTT).",
                        unit="ms",
                    )
                )

        if ctx == "serverside" and cur_rst_to == "disabled":
            diffs.append(
                _make_diff(
                    "tcp", "resetOnTimeout", cur_rst_to, "enabled",
                    "Enable Reset on Timeout on server-side profile so backend pool members do not accumulate zombie sockets.",
                    category="hygiene",
                    safe_auto_apply=False,
                )
            )

        if tw_indef or tw_val > 10000:
            diffs.append(
                _make_diff(
                    "tcp", "timeWaitTimeout", cfg.get("timeWaitTimeout"), 2000,
                    "Bound Time Wait timeout to 2000 ms to prevent SNAT ephemeral port exhaustion.",
                    unit="ms",
                )
            )

        if cur_tw_recycle == "disabled" and (ctx == "serverside" or ephem_conns > 2000):
            diffs.append(
                _make_diff(
                    "tcp", "timeWaitRecycle", cur_tw_recycle, "enabled",
                    "Enable Time Wait Recycle to permit immediate reuse of wait-state SNAT/server tuples.",
                    category="hygiene",
                )
            )

        if ctx == "clientside" and zw_indef:
            diffs.append(
                _make_diff(
                    "tcp", "zeroWindowTimeout", cfg.get("zeroWindowTimeout"), 20000,
                    "Avoid 'indefinite' Zero Window Timeout on client-side VIPs to mitigate Slow-Read buffer exhaustion DoS.",
                    unit="ms",
                    category="security",
                    safe_auto_apply=False,
                )
            )
        elif ctx == "serverside" and zero_wnd > 5 and resets > 10 and not zw_indef and zw_val <= 20000:
            advisories.append(
                f"Observed {int(zero_wnd)} server-side zero-window stalls alongside {int(resets)} resets; if backend batch consumers pause >20s legitimately, consider raising zeroWindowTimeout to 45000 ms."
            )

        # --- Section 7: Security And Quality of Service (6 settings) ---
        cur_syn_cookie = str(cfg.get("synCookieEnable", "enabled"))
        cur_syn_wl = str(cfg.get("synCookieWhitelist", "disabled"))
        cur_md5_pw = str(cfg.get("md5SignaturePassphrase", "") or "")
        cur_tos = str(cfg.get("ipTosToClient", "0"))
        cur_qos = str(cfg.get("linkQosToClient", "0"))

        if ctx == "clientside" and cur_syn_cookie == "disabled" and (syn_cookies > 0 or embryonic >= 30):
            diffs.append(
                _make_diff(
                    "tcp", "synCookieEnable", cur_syn_cookie, "enabled",
                    "Re-enable SYN Challenge Handling on client-side profile experiencing embryonic SYN load.",
                    category="security",
                    safe_auto_apply=False,
                )
            )

        if cur_syn_wl == "enabled" and (has_http or vs.has_clientssl):
            diffs.append(
                _make_diff(
                    "tcp", "synCookieWhitelist", cur_syn_wl, "disabled",
                    "SYN Cookie White List is designed for asymmetric nPath (DSR) routing and sends disruptive RST challenges on standard L7 full-proxy VIPs.",
                    category="dependency",
                    safe_auto_apply=False,
                )
            )

        if cur_md5 == "enabled":
            if not cur_md5_pw:
                advisories.append("MD5 Signature (RFC 2385) is enabled without an MD5 Signature Passphrase configured.")
            if vs_port != 179 and (has_http or vs.has_clientssl):
                advisories.append(
                    "TCP MD5 Signature is enabled on a non-BGP L7 Virtual Server, consuming 18B of TCP option space and disabling Fast Open/ePVA."
                )

        if cur_tos not in ("0", "") or cur_qos not in ("0", ""):
            advisories.append(f"Preserving custom QoS policy markings (IP ToS={cur_tos}, Link QoS={cur_qos}).")

        # --- Section 8: Multipath TCP / MPTCP (14 settings) ---
        if cur_mptcp == "passthrough" and not vs.has_fastl4:
            diffs.append(
                _make_diff(
                    "tcp", "mptcp", cur_mptcp, "disabled",
                    "MPTCP 'passthrough' requires a matching fastL4 Virtual Server or incoming flows are blocked!",
                    category="dependency",
                    safe_auto_apply=False,
                )
            )
        elif cur_mptcp == "enabled" and ctx == "clientside":
            cur_mp_fb = str(cfg.get("mptcpFallback", "reset"))
            cur_mp_fj = str(cfg.get("mptcpFastjoin", "disabled"))
            cur_mp_csum = str(cfg.get("mptcpCsum", "disabled"))
            cur_mp_csum_v = str(cfg.get("mptcpCsumVerify", "disabled"))
            cur_mp_sub_max = int(cfg.get("mptcpSubflowmax", 6) or 0)
            cur_mp_join_max = int(cfg.get("mptcpJoinMax", 5) or 5)
            cur_mp_rxm_min = int(cfg.get("mptcpRxmitmin", 1000) or 1000)
            cur_mp_rto_max = int(cfg.get("mptcpRtomax", 5) or 5)
            cur_mp_idle = int(cfg.get("mptcpIdleTimeout", 300) or 300)
            cur_mp_to = int(cfg.get("mptcpTimeout", 3600) or 3600)
            cur_mp_mab = str(cfg.get("mptcpMakeafterbreak", "disabled"))
            cur_mp_join = str(cfg.get("mptcpJoin", "disabled"))
            cur_mp_nodss = str(cfg.get("mptcpNojoindssack", "disabled"))

            if cur_mp_fb == "reset":
                diffs.append(
                    _make_diff(
                        "tcp", "mptcpFallback", cur_mp_fb, "accept",
                        "Change MPTCP Fallback from 'reset' to 'accept' so middlebox option-stripping falls back gracefully to regular TCP.",
                        category="hygiene",
                    )
                )
            if cur_mp_fj == "disabled" and rtt_ms >= 20.0:
                diffs.append(
                    _make_diff(
                        "tcp", "mptcpFastjoin", cur_mp_fj, "enabled",
                        "Enable MPTCP Fast Join to carry data on MP_JOIN_SYN over WAN links.",
                    )
                )
            if cur_mp_csum != cur_mp_csum_v:
                diffs.append(
                    _make_diff(
                        "tcp", "mptcpCsumVerify", cur_mp_csum_v, cur_mp_csum,
                        "Align MPTCP Checksum Verify with MPTCP Checksum setting.",
                        category="dependency",
                    )
                )
            if cur_mp_sub_max == 0 or cur_mp_sub_max > 8:
                diffs.append(
                    _make_diff(
                        "tcp", "mptcpSubflowmax", cur_mp_sub_max, 6,
                        "Bound MPTCP Subflow Max to 6 (avoid unlimited 0) to cap per-client subflow memory.",
                        category="hygiene",
                    )
                )
                cur_mp_sub_max = 6
            if cur_mp_join_max < max(1, cur_mp_sub_max - 1):
                diffs.append(
                    _make_diff(
                        "tcp", "mptcpJoinMax", cur_mp_join_max, cur_mp_sub_max,
                        "Ensure MPTCP Join Max >= MPTCP Subflow Max - 1 so legitimate subflows can join.",
                        category="dependency",
                    )
                )
            if cur_mp_rxm_min >= 1000 and rtt_ms < 200.0:
                diffs.append(
                    _make_diff(
                        "tcp", "mptcpRxmitmin", cur_mp_rxm_min, 300,
                        "Lower MPTCP Retransmit Min from 1000 ms to 300 ms for faster cross-subflow retransmission.",
                        unit="ms",
                    )
                )
            if cur_mp_rto_max > 5 and rtt_var_ms >= 12.0:
                diffs.append(
                    _make_diff(
                        "tcp", "mptcpRtomax", cur_mp_rto_max, 4,
                        "Lower MPTCP RTO Max to 4 to detect dead Wi-Fi subflows faster during mobile handoffs.",
                    )
                )
            if not idle_indef and cur_mp_idle < idle_val:
                diffs.append(
                    _make_diff(
                        "tcp", "mptcpIdleTimeout", cur_mp_idle, int(idle_val),
                        "Align MPTCP Idle Timeout >= TCP Idle Timeout.",
                        unit="seconds",
                        category="dependency",
                    )
                )
            if cur_conns > 2000 and cur_mp_to > 1800:
                diffs.append(
                    _make_diff(
                        "tcp", "mptcpTimeout", cur_mp_to, 1800,
                        "Cap dormant MPTCP session timeout to 1800s under high concurrency.",
                        unit="seconds",
                    )
                )
            if cur_mp_mab == "enabled" and cur_mp_join == "disabled":
                diffs.append(
                    _make_diff(
                        "tcp", "mptcpJoin", cur_mp_join, "enabled",
                        "MPTCP Make After Break requires MPTCP Join enabled to accept subflows after initial flow break.",
                        category="dependency",
                        safe_auto_apply=False,
                    )
                )
            if cur_mp_nodss == "enabled":
                advisories.append("MPTCP No Join DSS ACK is enabled; verify peer requires suppressing DSS on JOIN ACK.")

        if not diffs and not advisories:
            return None
        if not diffs:
            # Pure advisory without profile parameter mutations — only emit if actionable diffs exist
            return None

        kb = KNOWLEDGE_BASE.get(primary_kb, KNOWLEDGE_BASE["K75593415"])
        is_default = pref.full_path in SYSTEM_DEFAULT_PROFILES
        _, vs_short = split_full_path(vs.full_path)
        suggested_name = f"tuner_{_sanitize_name(vs_short)}_{ctx}_tcp" if is_default else pref.name
        overall_safe = all(d.safe_auto_apply for d in diffs)

        return TuningRecommendation(
            id=f"rec-{uuid.uuid4().hex[:10]}",
            bigip_id=client.session_id,
            bigip_host=client.host,
            virtual_server=vs.full_path,
            partition=vs.partition,
            protocol="tcp",
            context=ctx,  # type: ignore[arg-type]
            profile_name=pref.name,
            profile_full_path=pref.full_path,
            is_system_default_profile=is_default,
            recommended_parent_profile=recommended_parent or (pref.full_path if is_default else pref.defaults_from),
            target_profile_action="create_and_attach_child_profile" if is_default else "update_custom_profile",
            suggested_profile_name=suggested_name,
            parameter_diffs=diffs,
            advisories=advisories,
            settings_evaluated=len(SETTINGS_BY_PROTOCOL["tcp"]),
            supporting_evidence="; ".join(evidence_parts) or f"Evaluated all {len(SETTINGS_BY_PROTOCOL['tcp'])} TCP profile settings",
            metrics_snapshot={
                "throughput_mbps": round(bps_out / 1e6, 2),
                "retransmit_rate_pct": round(retrans_pct, 3),
                "rtt_ms": round(rtt_ms, 2),
                "rtt_variance_ms": round(rtt_var_ms, 2),
                "buffer_waits": round(buf_waits, 1),
                "zero_window_events": round(zero_wnd, 1),
            },
            f5_kb_id=kb.kb_id,
            f5_kb_title=kb.title,
            f5_kb_url=kb.url,
            confidence=confidence,
            impact=impact,
            safe_auto_apply=overall_safe,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    # =========================================================================
    # UDP Profile Evaluator — All 9 Settings (+ IPv4/IPv6 TTL sub-settings)
    # =========================================================================
    def _evaluate_udp_profile(
        self,
        client: BigIpClient,
        vs: VirtualServerItem,
        pref: AttachedProfileRef,
        cfg: dict[str, Any],
        m: dict[str, float],
    ) -> TuningRecommendation | None:
        diffs: list[ParameterDiff] = []
        advisories: list[str] = []
        evidence_parts: list[str] = []
        primary_kb = "K3605"
        confidence: ConfidenceScore = "High"
        impact: ConfidenceScore = "High"

        drop_pct = m.get("udp_drop_pct", 0.0)
        dgrams_per_conn = m.get("udp_dgrams_per_conn", 0.0)
        buf_overflows = m.get("udp_buf_overflows", 0.0)
        ephem_conns = m.get("ephemeral_conns_max", 0.0)
        bps_in = m.get("bps_in", 0.0)
        pps_in = max(1.0, m.get("pps_in", 1.0))
        avg_dgram_bytes = (bps_in / 8.0) / pps_in if bps_in > 0 else 512.0
        vs_port = _extract_vs_port(vs.destination)
        is_stateful_port = vs_port in STATEFUL_UDP_PORTS
        is_media_port = vs_port in REALTIME_MEDIA_UDP_PORTS or (16384 <= vs_port <= 32768)

        cur_dlb = str(cfg.get("datagramLoadBalancing", "disabled"))
        idle_val, idle_indef, idle_imm = _parse_timeout_num(cfg.get("idleTimeout", 60), 60)
        cur_buf_bytes = int(cfg.get("bufferMaxBytes", 655350) or 655350)
        cur_buf_pkts = int(cfg.get("bufferMaxPackets", 0) or 0)
        cur_no_payload = str(cfg.get("allowNoPayload", "disabled"))
        cur_proxy_mss = str(cfg.get("proxyMss", "enabled"))
        cur_ttl_mode = str(cfg.get("ipTtlMode", "proxy"))
        cur_ttl_v4 = int(cfg.get("ipTtlV4", 255) or 255)
        cur_ttl_v6 = int(cfg.get("ipTtlV6", 64) or 64)
        cur_tos = str(cfg.get("ipTosToClient", "0"))
        cur_qos = str(cfg.get("linkQosToClient", "0"))

        # 1. Datagram Load Balancing (port-aware safety gating)
        if cur_dlb == "disabled" and (dgrams_per_conn >= 250.0 or drop_pct >= 0.5 or buf_overflows > 0):
            if is_stateful_port:
                advisories.append(
                    f"Destination port :{vs_port} commonly carries stateful UDP (QUIC/DTLS/VPN); skipping automatic Datagram LB to preserve per-session affinity — scaling Max Buffer Bytes instead."
                )
            else:
                safe_dlb = vs_port in (53, 514, 1514, 2055, 4739, 5514, 6343, 8125)
                diffs.append(
                    _make_diff(
                        "udp", "datagramLoadBalancing", cur_dlb, "enabled",
                        f"Distribute stateless datagrams packet-by-packet across TMMs and pool members ({dgrams_per_conn:.0f} datagrams/conn, {drop_pct:.2f}% drops).",
                        safe_auto_apply=safe_dlb,
                    )
                )
                evidence_parts.append(
                    f"UDP datagrams/conn={dgrams_per_conn:.0f} with drop rate {drop_pct:.2f}% and {int(buf_overflows)} buffer overflows"
                )

        # 2. Max Buffer Bytes & Max Buffer Packets
        if cur_buf_pkts > 0 and (buf_overflows > 0 or drop_pct > 0):
            diffs.append(
                _make_diff(
                    "udp", "bufferMaxPackets", cur_buf_pkts, 0,
                    f"Max Buffer Packets ({cur_buf_pkts}) caps queued packets prematurely before Max Buffer Bytes ({cur_buf_bytes:,} B) is used; set to 0.",
                    category="hygiene",
                )
            )
            primary_kb = "K7537"

        if buf_overflows > 0 and cur_buf_bytes < 2097152 and (is_stateful_port or buf_overflows >= 10):
            target_buf = 4194304 if buf_overflows >= 50 else 2097152
            diffs.append(
                _make_diff(
                    "udp", "bufferMaxBytes", cur_buf_bytes, target_buf,
                    f"Increase ingress UDP Max Buffer Bytes to {target_buf:,} B to absorb burst queues ({int(buf_overflows)} buffer overflows).",
                    unit="bytes",
                )
            )
            evidence_parts.append(f"UDP ingress buffer overflows={int(buf_overflows)} at {cur_buf_bytes:,} B limit")
            if len(diffs) == 1:
                primary_kb = "K7537"

        # 3. Idle Timeout
        if idle_indef and not is_media_port:
            diffs.append(
                _make_diff(
                    "udp", "idleTimeout", cfg.get("idleTimeout"), 30,
                    "Replace 'indefinite' UDP Idle Timeout with 30s to prevent unbounded TMM connection table growth.",
                    unit="seconds",
                    safe_auto_apply=False,
                )
            )
        elif not idle_imm and ephem_conns >= 8000 and idle_val > 30:
            target_idle = 5 if vs_port == 53 else 15
            diffs.append(
                _make_diff(
                    "udp", "idleTimeout", int(idle_val), target_idle,
                    f"Ephemeral UDP connections reached {int(ephem_conns):,}; lower Idle Timeout from {int(idle_val)}s to {target_idle}s.",
                    unit="seconds",
                )
            )
            evidence_parts.append(
                f"High UDP ephemeral connection table occupancy ({int(ephem_conns):,} conns) at {int(idle_val)}s idleTimeout"
            )
            if len(diffs) == 1:
                primary_kb = "K3667"
                impact = "Medium"

        # 4. Allow No Payload
        if cur_no_payload == "disabled" and drop_pct > 0.2 and buf_overflows == 0 and avg_dgram_bytes <= 36.0:
            diffs.append(
                _make_diff(
                    "udp", "allowNoPayload", cur_no_payload, "enabled",
                    f"Observed {drop_pct:.2f}% UDP drops with zero buffer overflows and tiny datagrams ({avg_dgram_bytes:.0f} B) — enable Allow No Payload for 0-byte probes/keepalives.",
                    safe_auto_apply=False,
                )
            )
            primary_kb = "K48620311"

        # 5. Proxy Maximum Segment, TTL Mode & QoS
        if cur_proxy_mss == "disabled" and drop_pct >= 1.0:
            diffs.append(
                _make_diff(
                    "udp", "proxyMss", cur_proxy_mss, "enabled",
                    "Enable Proxy Maximum Segment to propagate path MSS limits across proxied connections.",
                    category="hygiene",
                )
            )

        if cur_ttl_mode == "set":
            if cur_ttl_v4 < 32:
                diffs.append(
                    _make_diff(
                        "udp", "ipTtlV4", cur_ttl_v4, 64,
                        f"Raise IPv4 TTL ({cur_ttl_v4}) under TTL Mode 'set' to prevent WAN hop expiration.",
                        category="hygiene",
                        lookup_key="ipTtlMode",
                    )
                )
            if cur_ttl_v6 < 32:
                diffs.append(
                    _make_diff(
                        "udp", "ipTtlV6", cur_ttl_v6, 64,
                        f"Raise IPv6 Hop Limit ({cur_ttl_v6}) under TTL Mode 'set'.",
                        category="hygiene",
                        lookup_key="ipTtlMode",
                    )
                )

        if is_media_port and cur_tos in ("0", ""):
            advisories.append(
                f"Real-time media/SIP port (:{vs_port}) has IP ToS=0 (resets DSCP markings); consider IP ToS='mimic' or 'pass-through' (Link QoS={cur_qos})."
            )

        if not diffs:
            return None

        kb = KNOWLEDGE_BASE.get(primary_kb, KNOWLEDGE_BASE["K3605"])
        is_default = pref.full_path in SYSTEM_DEFAULT_PROFILES
        _, vs_short = split_full_path(vs.full_path)
        suggested_name = f"tuner_{_sanitize_name(vs_short)}_clientside_udp" if is_default else pref.name
        overall_safe = all(d.safe_auto_apply for d in diffs)

        return TuningRecommendation(
            id=f"rec-{uuid.uuid4().hex[:10]}",
            bigip_id=client.session_id,
            bigip_host=client.host,
            virtual_server=vs.full_path,
            partition=vs.partition,
            protocol="udp",
            context="clientside",
            profile_name=pref.name,
            profile_full_path=pref.full_path,
            is_system_default_profile=is_default,
            recommended_parent_profile=pref.full_path if is_default else pref.defaults_from,
            target_profile_action="create_and_attach_child_profile" if is_default else "update_custom_profile",
            suggested_profile_name=suggested_name,
            parameter_diffs=diffs,
            advisories=advisories,
            settings_evaluated=len(SETTINGS_BY_PROTOCOL["udp"]),
            supporting_evidence="; ".join(evidence_parts) or f"Evaluated all {len(SETTINGS_BY_PROTOCOL['udp'])} UDP profile settings",
            metrics_snapshot={
                "udp_drop_rate_pct": round(drop_pct, 3),
                "datagrams_per_conn": round(dgrams_per_conn, 1),
                "ephemeral_conns": round(ephem_conns, 0),
                "buffer_overflows": round(buf_overflows, 1),
            },
            f5_kb_id=kb.kb_id,
            f5_kb_title=kb.title,
            f5_kb_url=kb.url,
            confidence=confidence,
            impact=impact,
            safe_auto_apply=overall_safe,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    # =========================================================================
    # HTTP Profile Evaluator — All 50 Settings across 5 Sections
    # =========================================================================
    def _evaluate_http_profile(
        self,
        client: BigIpClient,
        vs: VirtualServerItem,
        pref: AttachedProfileRef,
        cfg: dict[str, Any],
        m: dict[str, float],
    ) -> TuningRecommendation | None:
        diffs: list[ParameterDiff] = []
        advisories: list[str] = []
        evidence_parts: list[str] = []
        primary_kb = "K7208"
        confidence: ConfidenceScore = "High"
        impact: ConfidenceScore = "Medium"

        reuse = m.get("http_keepalive_reuse", 0.0)
        hdr_size_drops = m.get("http_header_drops", 0.0)
        hdr_cnt_drops = m.get("http_header_count_drops", 0.0)
        pipelined_reqs = m.get("http_pipelined_reqs", 0.0)
        svr_closes = m.get("http_svr_closes", 0.0)
        reqs_inc = m.get("http_reqs_inc", 0.0)
        comp_ratio = m.get("http_compression_ratio", 1.0)
        bps_out = m.get("bps_out", 0.0)
        pps_in = m.get("pps_in", 0.0)

        enf = cfg.get("enforcement") or {}
        hsts = cfg.get("hsts") or {}
        sflow = cfg.get("sflow") or {}
        exp = cfg.get("explicitProxy") or {}

        proxy_type = str(cfg.get("proxyType", "reverse"))
        req_chunk = str(cfg.get("requestChunking", "sustain"))
        resp_chunk = str(cfg.get("responseChunking", "sustain"))
        cur_oneconnect = str(cfg.get("oneconnectTransformations", "enabled"))
        cur_oc_codes = str(cfg.get("oneconnectStatusCodes", "200 206")).strip()
        cur_redir = str(cfg.get("redirectRewrite", "none"))
        cur_xff = str(cfg.get("insertXforwardedFor", "disabled"))
        cur_accept_xff = str(cfg.get("acceptXff", "disabled"))
        cur_xff_alt = cfg.get("xffAlternativeNames")
        cur_hdr_erase = str(cfg.get("headerErase", "none") or "none")
        cur_hdr_insert = str(cfg.get("headerInsert", "none") or "none")
        cur_resp_perm = cfg.get("responseHeadersPermitted")
        cur_lws_width = int(cfg.get("lwsWidth", 80) or 80)
        cur_lws_sep = str(cfg.get("lwsSeparator", "none") or "none")
        cur_fb_host = str(cfg.get("fallbackHost", "none") or "none")
        cur_fb_codes = cfg.get("fallbackStatusCodes")
        cur_enc_cookies = cfg.get("encryptCookies")
        cur_enc_secret = str(cfg.get("encryptCookieSecret", "") or "")
        cur_via_req = str(cfg.get("viaRequest", "preserve"))
        cur_via_resp = str(cfg.get("viaResponse", "preserve"))
        cur_via_host = str(cfg.get("viaHostName", "none") or "none")
        cur_agent = str(cfg.get("serverAgentName", "BigIP"))

        # Schema-aware maxRequests & pipeline lookup (supports nested enforcement.* and legacy top-level)
        has_enf_max_req = "maxRequests" in enf
        cur_max_req = int(enf.get("maxRequests", cfg.get("maxRequests", 0)) or 0)
        max_req_key = "enforcement.maxRequests" if (has_enf_max_req or "enforcement" in cfg) else "maxRequests"

        if "pipeline" in enf or "enforcement" in cfg:
            cur_pipeline = str(enf.get("pipeline", "allow"))
            pipeline_key = "enforcement.pipeline"
            pipeline_target = "reject"
        else:
            cur_pipeline = str(cfg.get("pipelining", "enabled"))
            pipeline_key = "pipelining"
            pipeline_target = "disabled"

        # --- 1. Chunking & Keep-Alive Reuse (General) ---
        if resp_chunk == "unchunk":
            diffs.append(
                _make_diff(
                    "http", "responseChunking", resp_chunk, "sustain",
                    "Response Chunking 'unchunk' buffers entire payloads in TMM RAM and forces 'Connection: close', breaking HTTP Keep-Alive!",
                    category="hygiene",
                )
            )
            evidence_parts.append("responseChunking='unchunk' is forcing Connection: close on chunked responses")
            primary_kb = "K48382192"
            impact = "High"

        if req_chunk == "unchunk":
            diffs.append(
                _make_diff(
                    "http", "requestChunking", req_chunk, "sustain",
                    "Request Chunking 'unchunk' buffers full client upload bodies in TMM memory; use 'sustain' for streaming.",
                    category="hygiene",
                )
            )

        if 0 < cur_max_req < 250:
            diffs.append(
                _make_diff(
                    "http", max_req_key, cur_max_req, 0,
                    f"Maximum Requests={cur_max_req} forces premature TCP/TLS teardown (observed reuse {reuse:.1f} reqs/conn); set 0 (unlimited).",
                    unit="requests/conn (0=unlimited)",
                    lookup_key="enforcement.maxRequests",
                )
            )
            evidence_parts.append(f"Restrictive Maximum Requests={cur_max_req} capping keep-alive reuse ({reuse:.1f} reqs/conn)")
            impact = "High"

        if cur_oneconnect == "disabled" and (0 < cur_max_req < 250 or (0.0 < reuse < 15.0)):
            diffs.append(
                _make_diff(
                    "http", "oneconnectTransformations", cur_oneconnect, "enabled",
                    "Enable OneConnect Transformations so HTTP headers stay eligible for persistent backend connection pooling.",
                )
            )
            evidence_parts.append(f"Low HTTP keep-alive reuse ({reuse:.1f} reqs/conn) with oneconnectTransformations='disabled'")
            impact = "High"

        if (cur_oneconnect == "enabled" or any(d.parameter == "oneconnectTransformations" for d in diffs)) and not vs.has_oneconnect:
            advisories.append(
                "OneConnect Transformations applies only when a OneConnect profile (e.g. /Common/oneconnect) is attached to the Virtual Server — attach a OneConnect profile (verify backend does not use NTLM/Kerberos auth)."
            )

        if vs.has_oneconnect and cur_oc_codes == "200 206" and reqs_inc > 100 and svr_closes > reqs_inc * 0.15:
            diffs.append(
                _make_diff(
                    "http", "oneconnectStatusCodes", cur_oc_codes, "200 201 204 206 301 302 304",
                    "Expand OneConnect Status Reuse codes so REST API 201/204 and cache 304 responses return server sockets to the OneConnect pool.",
                )
            )

        # --- 2. Header Manipulation, LWS, Redirects, Fallback & Cookies (General) ---
        if cur_xff == "disabled" and vs.snat_type not in ("none", ""):
            diffs.append(
                _make_diff(
                    "http", "insertXforwardedFor", cur_xff, "enabled",
                    f"Virtual Server uses SNAT ({vs.snat_type}); enable Insert X-Forwarded-For to preserve client source IP for backend logs.",
                    category="hygiene",
                    safe_auto_apply=False,
                )
            )
            if cur_accept_xff == "disabled" and cur_hdr_erase in ("none", ""):
                advisories.append(
                    "When enabling Insert X-Forwarded-For on untrusted VIPs, consider setting Request Header Erase='X-Forwarded-For' (or configuring trusted Accept XFF) to prevent client XFF spoofing."
                )

        if cur_xff_alt and cur_xff_alt != "none" and cur_accept_xff == "disabled":
            advisories.append(
                f"XFF Alternative Names ({cur_xff_alt}) is configured while Accept XFF is disabled — alternative XFF headers will not be trusted until Accept XFF is enabled."
            )

        if cur_hdr_insert not in ("none", "") and len(cur_hdr_insert) > cur_lws_width and cur_lws_sep != "none":
            diffs.append(
                _make_diff(
                    "http", "lwsWidth", cur_lws_width, 1024,
                    f"Request Header Insert ({len(cur_hdr_insert)} chars) exceeds LWS Maximum Columns ({cur_lws_width}), causing RFC 7230 deprecated line-folding 400 errors on modern backends.",
                    category="dependency",
                )
            )
        if cur_lws_sep in ("cr", "lf"):
            diffs.append(
                _make_diff(
                    "http", "lwsSeparator", cur_lws_sep, "none",
                    f"Bare '{cur_lws_sep}' LWS Separator violates RFC 7230 framing; set to 'none'.",
                    category="security",
                )
            )

        if cur_redir == "all" and vs.has_clientssl:
            diffs.append(
                _make_diff(
                    "http", "redirectRewrite", cur_redir, "matching",
                    "Redirect Rewrite 'all' rewrites external 3rd-party/OAuth http:// redirects; 'matching' safely rewrites only matching host/URI redirects.",
                    category="dependency",
                    safe_auto_apply=False,
                )
            )

        if cur_fb_codes and cur_fb_codes != "none" and cur_fb_host in ("none", ""):
            advisories.append(
                f"Fallback on Error Codes ({cur_fb_codes}) has no effect because Fallback Host is not configured."
            )

        if cur_enc_cookies and cur_enc_cookies != "none" and not cur_enc_secret:
            advisories.append(
                "Encrypt Cookies lists cookie names, but Cookie Encryption Passphrase is empty!"
            )

        if (cur_via_req == "append" or cur_via_resp == "append") and cur_via_host in ("none", ""):
            advisories.append(
                "Send Proxy Via Header is set to 'append' without a Send Proxy Via Header Host Name configured."
            )

        if cur_resp_perm and cur_resp_perm != "none" and str(hsts.get("mode", "disabled")) == "enabled":
            perm_str = " ".join(cur_resp_perm) if isinstance(cur_resp_perm, list) else str(cur_resp_perm)
            if "strict-transport-security" not in perm_str.lower():
                advisories.append(
                    "Response Headers Allowed allowlist does not include Strict-Transport-Security and may strip HSTS headers."
                )

        if cur_agent == "BigIP":
            advisories.append(
                "Security hardening note: Server Agent Name is default 'BigIP' (set empty string if banner suppression is required by security policy)."
            )

        # --- 3. Enforcement (12 settings) ---
        cur_max_hdr_size = int(enf.get("maxHeaderSize", 32768) or 32768)
        cur_max_hdr_cnt = int(enf.get("maxHeaderCount", 64) or 64)
        cur_rfc = str(enf.get("rfcCompliance", "disabled"))
        cur_ws_hdr = str(enf.get("allowWsHeaderName", "disabled"))
        cur_trunc_redir = str(enf.get("truncatedRedirects", "disabled"))
        cur_over_cli = str(enf.get("oversizeClientHeaders", "reject"))
        cur_over_srv = str(enf.get("oversizeServerHeaders", "reject"))
        cur_exc_cli = str(enf.get("excessClientHeaders", "reject"))
        cur_exc_srv = str(enf.get("excessServerHeaders", "reject"))
        cur_unk_method = str(enf.get("unknownMethod", "allow"))
        cur_known_methods = enf.get("knownMethods") or []

        if hdr_size_drops > 0 and cur_max_hdr_size < 131072:
            target_hdr_size = 65536 if cur_max_hdr_size < 65536 else 131072
            diffs.append(
                _make_diff(
                    "http", "enforcement.maxHeaderSize", cur_max_hdr_size, target_hdr_size,
                    f"Observed {int(hdr_size_drops)} dropped requests exceeding {cur_max_hdr_size:,} B Maximum Header Size (e.g. OIDC/JWT headers).",
                    unit="bytes",
                )
            )
            evidence_parts.append(f"HTTP maxHeaderSize drops={int(hdr_size_drops)} at {cur_max_hdr_size:,} B")
            primary_kb = "K13525"
            impact = "High"

        if hdr_cnt_drops > 0 and cur_max_hdr_cnt < 256:
            target_hdr_cnt = 128 if cur_max_hdr_cnt < 128 else 256
            diffs.append(
                _make_diff(
                    "http", "enforcement.maxHeaderCount", cur_max_hdr_cnt, target_hdr_cnt,
                    f"Observed {int(hdr_cnt_drops)} dropped requests exceeding {cur_max_hdr_cnt} Maximum Header Count.",
                    unit="headers",
                )
            )
            evidence_parts.append(f"HTTP maxHeaderCount drops={int(hdr_cnt_drops)} at {cur_max_hdr_cnt} headers")
            primary_kb = "K13525"
            impact = "High"

        for key_suffix, label, cur_val in (
            ("oversizeClientHeaders", "Oversize Client Headers", cur_over_cli),
            ("oversizeServerHeaders", "Oversize Server Headers", cur_over_srv),
            ("excessClientHeaders", "Excess Client Headers", cur_exc_cli),
            ("excessServerHeaders", "Excess Server Headers", cur_exc_srv),
        ):
            if cur_val == "pass-through":
                diffs.append(
                    _make_diff(
                        "http", f"enforcement.{key_suffix}", cur_val, "reject",
                        f"{label} set to 'pass-through' disables L7 HTTP inspection/iRules/WAF when limits are exceeded; use 'reject' and right-size header limits.",
                        category="security",
                        safe_auto_apply=False,
                    )
                )
                primary_kb = "K13525"

        if cur_pipeline == "pass-through":
            diffs.append(
                _make_diff(
                    "http", pipeline_key, cur_pipeline, pipeline_target,
                    "Pipeline Action 'pass-through' disables the HTTP filter on pipelined data; set to 'reject'.",
                    category="security",
                    safe_auto_apply=False,
                    lookup_key="enforcement.pipeline",
                )
            )
        elif cur_pipeline in ("allow", "enabled") and pipelined_reqs == 0:
            diffs.append(
                _make_diff(
                    "http", pipeline_key, cur_pipeline, pipeline_target,
                    "Disable legacy HTTP/1.1 pipelining (0 pipelined requests observed) to prevent Head-of-Line blocking & desync; prefer HTTP/2 on WAN.",
                    category="hygiene",
                    safe_auto_apply=False,
                    lookup_key="enforcement.pipeline",
                )
            )
            evidence_parts.append(f"HTTP/1.1 pipelining enabled ({pipeline_key}='{cur_pipeline}') with 0 pipelined requests")

        if cur_ws_hdr == "enabled":
            diffs.append(
                _make_diff(
                    "http", "enforcement.allowWsHeaderName", cur_ws_hdr, "disabled",
                    "Disable Allow Space Header Name to prevent RFC 7230 HTTP Request Smuggling.",
                    category="security",
                    safe_auto_apply=False,
                )
            )

        if cur_trunc_redir == "enabled":
            diffs.append(
                _make_diff(
                    "http", "enforcement.truncatedRedirects", cur_trunc_redir, "disabled",
                    "Disable Allow Truncated Redirect so malformed 3xx responses do not trigger L7 pass-through.",
                    category="security",
                    safe_auto_apply=False,
                )
            )

        if cur_rfc == "disabled" and not vs.has_asm and vs.has_clientssl:
            diffs.append(
                _make_diff(
                    "http", "enforcement.rfcCompliance", cur_rfc, "enabled",
                    "Enable Enforce RFC Compliance on HTTPS VIP (without ASM/AWAF) to block CL.TE / malformed HTTP desync attacks.",
                    category="security",
                    safe_auto_apply=False,
                )
            )

        known_list = (
            cur_known_methods.split()
            if isinstance(cur_known_methods, str)
            else [str(x).upper() for x in cur_known_methods]
        )
        if cur_unk_method == "pass-through":
            diffs.append(
                _make_diff(
                    "http", "enforcement.unknownMethod", cur_unk_method, "allow",
                    "Unknown Method 'pass-through' bypasses L7 HTTP inspection on unrecognized verbs.",
                    category="security",
                    safe_auto_apply=False,
                )
            )
        elif cur_unk_method == "reject" and known_list and "PATCH" not in known_list:
            updated_methods = sorted(set(known_list + ["PATCH"]))
            diffs.append(
                _make_diff(
                    "http", "enforcement.knownMethods", known_list, updated_methods,
                    "Unknown Method is 'reject' while 'PATCH' is missing from default Known Methods — add PATCH so REST API calls are not rejected.",
                    category="dependency",
                    safe_auto_apply=False,
                )
            )

        # --- 4. Explicit Proxy (11 settings — active ONLY when proxyType == 'explicit') ---
        if proxy_type == "explicit":
            dns_res = str(exp.get("dnsResolver", "none") or "none")
            tun_name = str(exp.get("tunnelName", "none") or "none")
            tun_any = str(exp.get("tunnelOnAnyRequest", "disabled"))
            def_conn = str(exp.get("defaultConnectHandling", "deny"))
            if dns_res in ("none", ""):
                advisories.append(
                    "Explicit Proxy mode requires an Explicit Proxy DNS Resolver, which is currently unset!"
                )
            if (def_conn == "deny" or tun_any == "enabled") and tun_name in ("none", ""):
                advisories.append(
                    f"Explicit Proxy has defaultConnectHandling='{def_conn}' / tunnelOnAnyRequest='{tun_any}' without a Tunnel Name configured."
                )
            if def_conn == "allow":
                advisories.append(
                    "Explicit Proxy Default Connect Handling is 'allow' — verify outbound ACLs restrict open CONNECT tunneling."
                )

        # --- 5. sFlow (2 settings) ---
        sflow_rate_global = str(sflow.get("samplingRateGlobal", "yes"))
        sflow_rate = int(sflow.get("samplingRate", 1024) or 1024)
        sflow_poll_global = str(sflow.get("pollIntervalGlobal", "yes"))
        sflow_poll = int(sflow.get("pollInterval", 10) or 10)
        if sflow_rate_global == "no" and 0 < sflow_rate < 128 and pps_in > 5000:
            diffs.append(
                _make_diff(
                    "http", "sflow.samplingRate", sflow_rate, 1024,
                    f"Custom HTTP sFlow Sampling Rate (1:{sflow_rate}) at {pps_in:,.0f} pps causes excessive TMM sampling overhead; raise to 1024.",
                )
            )
        if sflow_poll_global == "no" and 0 < sflow_poll < 5:
            diffs.append(
                _make_diff(
                    "http", "sflow.pollInterval", sflow_poll, 10,
                    f"Raise HTTP sFlow Polling Interval from {sflow_poll}s to 10s to reduce control-plane polling churn.",
                    unit="seconds",
                    category="hygiene",
                )
            )

        # --- 6. HTTP Strict Transport Security / HSTS (4 settings) ---
        hsts_mode = str(hsts.get("mode", "disabled"))
        hsts_age = int(hsts.get("maximumAge", 16070400) or 0)
        hsts_sub = str(hsts.get("includeSubdomains", "enabled"))
        hsts_preload = str(hsts.get("preload", "disabled"))

        if hsts_mode == "enabled" and not vs.has_clientssl:
            diffs.append(
                _make_diff(
                    "http", "hsts.mode", hsts_mode, "disabled",
                    "HSTS Mode is enabled on a Virtual Server without ClientSSL (RFC 6797 ignores HSTS over plaintext HTTP).",
                    category="dependency",
                    safe_auto_apply=False,
                )
            )
        elif hsts_mode == "enabled":
            if hsts_preload == "enabled" and hsts_age < 31536000:
                diffs.append(
                    _make_diff(
                        "http", "hsts.maximumAge", hsts_age, 31536000,
                        f"HSTS Preload is enabled, which requires HSTS Maximum Age >= 31536000s (1 year); current is {hsts_age}s.",
                        unit="seconds",
                        category="dependency",
                    )
                )
                primary_kb = "K68657325"
            elif hsts_age == 0:
                advisories.append("HSTS Mode is enabled with Maximum Age=0, which instructs browsers to revoke HSTS!")
            if hsts_preload == "enabled" and hsts_sub == "disabled":
                diffs.append(
                    _make_diff(
                        "http", "hsts.includeSubdomains", hsts_sub, "enabled",
                        "HSTS Preload requires Include Subdomains='enabled'.",
                        category="dependency",
                        safe_auto_apply=False,
                    )
                )

        if bps_out > 50_000_000 and comp_ratio < 1.25:
            advisories.append(
                f"Outbound HTTP throughput is {bps_out / 1e6:.1f} Mbps with {comp_ratio:.2f}x compression (K15434) — consider pairing /Common/httpcompression & /Common/http2."
            )

        if not diffs:
            return None

        kb = KNOWLEDGE_BASE.get(primary_kb, KNOWLEDGE_BASE["K7208"])
        is_default = pref.full_path in SYSTEM_DEFAULT_PROFILES
        _, vs_short = split_full_path(vs.full_path)
        suggested_name = f"tuner_{_sanitize_name(vs_short)}_clientside_http" if is_default else pref.name
        overall_safe = all(d.safe_auto_apply for d in diffs)

        return TuningRecommendation(
            id=f"rec-{uuid.uuid4().hex[:10]}",
            bigip_id=client.session_id,
            bigip_host=client.host,
            virtual_server=vs.full_path,
            partition=vs.partition,
            protocol="http",
            context="clientside",
            profile_name=pref.name,
            profile_full_path=pref.full_path,
            is_system_default_profile=is_default,
            recommended_parent_profile=pref.full_path if is_default else pref.defaults_from,
            target_profile_action="create_and_attach_child_profile" if is_default else "update_custom_profile",
            suggested_profile_name=suggested_name,
            parameter_diffs=diffs,
            advisories=advisories,
            settings_evaluated=len(SETTINGS_BY_PROTOCOL["http"]),
            supporting_evidence="; ".join(evidence_parts) or f"Evaluated all {len(SETTINGS_BY_PROTOCOL['http'])} HTTP profile settings",
            metrics_snapshot={
                "keepalive_reqs_per_conn": round(reuse, 2),
                "header_size_drops": round(hdr_size_drops, 1),
                "header_count_drops": round(hdr_cnt_drops, 1),
                "compression_ratio": round(comp_ratio, 2),
                "throughput_mbps": round(bps_out / 1e6, 2),
            },
            f5_kb_id=kb.kb_id,
            f5_kb_title=kb.title,
            f5_kb_url=kb.url,
            confidence=confidence,
            impact=impact,
            safe_auto_apply=overall_safe,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
