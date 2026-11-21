"""MetricsQL Historical Traffic Analyzer & F5 Protocol Profile Recommendation Engine."""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.bigip_client import SYSTEM_DEFAULT_PROFILES, BigIpClient, split_full_path
from backend.models import (
    AttachedProfileRef,
    ConfidenceScore,
    ParameterDiff,
    ProtocolType,
    TuningRecommendation,
    VirtualServerItem,
)
from backend.optimizer.knowledge_base import KNOWLEDGE_BASE
from backend.otel_exporter import OtelMetricsExporter
from backend.vm_client import VictoriaMetricsClient, window_to_seconds

logger = logging.getLogger(__name__)


def _sanitize_name(raw: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", raw).strip("_")[:42]


def _next_power_buffer(target_bytes: float, minimum: int = 131072, maximum: int = 1048576) -> int:
    val = minimum
    while val < target_bytes and val < maximum:
        val *= 2
    return min(val, maximum)


class ProtocolAnalyzer:
    """Evaluates VictoriaMetrics telemetry + live BIG-IP profile configs against F5 best practices."""

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

        # Ensure at least two recent samples exist in local fallback buffer if VM doesn't have history yet
        first_buf = self.otel.get_local_buffer_samples(client.host, selected_vs[0].full_path, 3600)
        if len(first_buf) < 2:
            try:
                s1 = client.poll_protocol_telemetry(enrolled_paths)
                self.otel.export_samples(s1)
                s2 = client.poll_protocol_telemetry(enrolled_paths)
                self.otel.export_samples(s2)
            except Exception as exc:
                logger.debug("On-demand pre-analysis poll warning on %s: %s", client.host, exc)

        recommendations: list[TuningRecommendation] = []
        for vs in selected_vs:
            vs_metrics, src = self._collect_vs_window_metrics(client.host, vs, window, vm_healthy)
            if src == "live_poll_buffer" and telemetry_source == "victoriametrics":
                telemetry_source = "hybrid_vm_and_live"

            for pref in vs.profiles:
                if pref.protocol not in protocols:
                    continue
                try:
                    live_cfg = client.get_profile_config(pref.protocol, pref.full_path)
                except Exception as exc:
                    logger.warning("Could not fetch %s profile %s: %s", pref.protocol, pref.full_path, exc)
                    continue

                contexts: list[str] = (
                    ["clientside", "serverside"]
                    if (pref.protocol == "tcp" and pref.context == "all")
                    else (["serverside"] if pref.context == "serverside" else ["clientside"])
                )
                for ctx in contexts:
                    if pref.protocol == "tcp":
                        rec = self._evaluate_tcp_profile(client, vs, pref, ctx, live_cfg, vs_metrics)
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
                metrics["bps_in"] = self.vm.query_scalar(
                    f"avg(rate(bigip_vs_bits_in_total{{{lbl}}}[{window}]))", 0.0
                ) or 0.0
                metrics["pps_out"] = self.vm.query_scalar(
                    f"avg(rate(bigip_vs_pkts_out_total{{{lbl}}}[{window}]))", 1.0
                ) or 1.0
                metrics["pps_in"] = self.vm.query_scalar(
                    f"avg(rate(bigip_vs_pkts_in_total{{{lbl}}}[{window}]))", 1.0
                ) or 1.0
                metrics["cur_conns_avg"] = self.vm.query_scalar(
                    f"avg(avg_over_time(bigip_vs_cur_conns{{{lbl}}}[{window}]))", 0.0
                ) or 0.0
                metrics["ephemeral_conns_max"] = self.vm.query_scalar(
                    f"max(max_over_time(bigip_vs_ephemeral_cur_conns{{{lbl}}}[{window}]))", 0.0
                ) or 0.0
                metrics["syn_cookies_inc"] = self.vm.query_scalar(
                    f"sum(increase(bigip_vs_syn_cookies_total{{{lbl}}}[{window}]))", 0.0
                ) or 0.0

                for ctx in ("clientside", "serverside"):
                    clbl = f'{lbl},context="{ctx}"'
                    metrics[f"tcp_{ctx}_retrans_pct"] = self.vm.query_scalar(
                        f"avg(avg_over_time(bigip_tcp_retransmit_rate_pct{{{clbl}}}[{window}]))", 0.0
                    ) or 0.0
                    metrics[f"tcp_{ctx}_rtt_ms"] = self.vm.query_scalar(
                        f"avg(avg_over_time(bigip_tcp_rtt_ms{{{clbl}}}[{window}]))", 0.0
                    ) or 0.0
                    metrics[f"tcp_{ctx}_rtt_var_ms"] = self.vm.query_scalar(
                        f"avg(avg_over_time(bigip_tcp_rtt_variance_ms{{{clbl}}}[{window}]))", 0.0
                    ) or 0.0
                    metrics[f"tcp_{ctx}_buf_waits"] = self.vm.query_scalar(
                        f"sum(increase(bigip_tcp_buffer_exhaustion_total{{{clbl}}}[{window}]))", 0.0
                    ) or 0.0
                    metrics[f"tcp_{ctx}_zero_wnd"] = self.vm.query_scalar(
                        f"sum(increase(bigip_tcp_zero_window_events_total{{{clbl}}}[{window}]))", 0.0
                    ) or 0.0
                    metrics[f"tcp_{ctx}_resets"] = self.vm.query_scalar(
                        f"sum(increase(bigip_tcp_resets_total{{{clbl}}}[{window}]))", 0.0
                    ) or 0.0

                metrics["udp_drop_pct"] = self.vm.query_scalar(
                    f"avg(avg_over_time(bigip_udp_drop_rate_pct{{{lbl}}}[{window}]))", 0.0
                ) or 0.0
                metrics["udp_dgrams_per_conn"] = self.vm.query_scalar(
                    f"avg(avg_over_time(bigip_udp_datagrams_per_conn{{{lbl}}}[{window}]))", 0.0
                ) or 0.0
                metrics["udp_buf_overflows"] = self.vm.query_scalar(
                    f"sum(increase(bigip_udp_buffer_overflows_total{{{lbl}}}[{window}]))", 0.0
                ) or 0.0

                metrics["http_keepalive_reuse"] = self.vm.query_scalar(
                    f"avg(avg_over_time(bigip_http_keepalive_reqs_per_conn{{{lbl}}}[{window}]))", 0.0
                ) or 0.0
                metrics["http_header_drops"] = self.vm.query_scalar(
                    f"sum(increase(bigip_http_header_size_drops_total{{{lbl}}}[{window}]))", 0.0
                ) or 0.0
                metrics["http_compression_ratio"] = self.vm.query_scalar(
                    f"avg(avg_over_time(bigip_http_compression_ratio{{{lbl}}}[{window}]))", 1.0
                ) or 1.0
                return metrics, "victoriametrics"

        # Fallback to local OTLP sample ring buffer
        buf = self.otel.get_local_buffer_samples(bigip_host, vs.full_path, window_to_seconds(window))
        vs_pts = [b for b in buf if b.get("category") == "virtual"]
        if len(vs_pts) >= 2:
            dt = max(1.0, vs_pts[-1]["ts"] - vs_pts[0]["ts"])
            m0, m1 = vs_pts[0]["metrics"], vs_pts[-1]["metrics"]
            metrics["bps_out"] = max(0.0, (m1.get("bigip_vs_bits_out_total", 0) - m0.get("bigip_vs_bits_out_total", 0)) / dt)
            metrics["bps_in"] = max(0.0, (m1.get("bigip_vs_bits_in_total", 0) - m0.get("bigip_vs_bits_in_total", 0)) / dt)
            metrics["pps_out"] = max(1.0, (m1.get("bigip_vs_pkts_out_total", 0) - m0.get("bigip_vs_pkts_out_total", 0)) / dt)
            metrics["pps_in"] = max(1.0, (m1.get("bigip_vs_pkts_in_total", 0) - m0.get("bigip_vs_pkts_in_total", 0)) / dt)
            metrics["cur_conns_avg"] = float(m1.get("bigip_vs_cur_conns", 0))
            metrics["ephemeral_conns_max"] = float(m1.get("bigip_vs_ephemeral_cur_conns", 0))
            metrics["syn_cookies_inc"] = max(0.0, m1.get("bigip_vs_syn_cookies_total", 0) - m0.get("bigip_vs_syn_cookies_total", 0))
        elif len(vs_pts) == 1:
            m1 = vs_pts[0]["metrics"]
            metrics["bps_out"] = float(m1.get("bigip_vs_bits_out_total", 0)) / 30.0
            metrics["pps_out"] = max(1.0, float(m1.get("bigip_vs_pkts_out_total", 1)) / 30.0)
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
                metrics[f"tcp_{ctx}_buf_waits"] = max(
                    1.0 if latest.get("bigip_tcp_buffer_exhaustion_total", 0) > 0 else 0.0,
                    latest.get("bigip_tcp_buffer_exhaustion_total", 0) - first.get("bigip_tcp_buffer_exhaustion_total", 0),
                )
                metrics[f"tcp_{ctx}_zero_wnd"] = max(
                    1.0 if latest.get("bigip_tcp_zero_window_events_total", 0) > 0 else 0.0,
                    latest.get("bigip_tcp_zero_window_events_total", 0) - first.get("bigip_tcp_zero_window_events_total", 0),
                )
                metrics[f"tcp_{ctx}_resets"] = max(
                    0.0, latest.get("bigip_tcp_resets_total", 0) - first.get("bigip_tcp_resets_total", 0)
                )

        u_pts = [b for b in buf if b.get("category") == "udp"]
        if u_pts:
            ul = u_pts[-1]["metrics"]
            metrics["udp_drop_pct"] = float(ul.get("bigip_udp_drop_rate_pct", 0.0))
            metrics["udp_dgrams_per_conn"] = float(ul.get("bigip_udp_datagrams_per_conn", 0.0))
            metrics["udp_buf_overflows"] = float(ul.get("bigip_udp_buffer_overflows_total", 0.0))

        h_pts = [b for b in buf if b.get("category") == "http"]
        if h_pts:
            hl = h_pts[-1]["metrics"]
            metrics["http_keepalive_reuse"] = float(hl.get("bigip_http_keepalive_reqs_per_conn", 0.0))
            metrics["http_header_drops"] = float(hl.get("bigip_http_header_size_drops_total", 0.0))
            metrics["http_compression_ratio"] = float(hl.get("bigip_http_compression_ratio", 1.0))

        return metrics, "live_poll_buffer"

    def _evaluate_tcp_profile(
        self,
        client: BigIpClient,
        vs: VirtualServerItem,
        pref: AttachedProfileRef,
        ctx: str,
        cfg: dict[str, Any],
        m: dict[str, float],
    ) -> TuningRecommendation | None:
        diffs: list[ParameterDiff] = []
        evidence_parts: list[str] = []
        primary_kb = "K75593415"
        confidence: ConfidenceScore = "Medium"
        impact: ConfidenceScore = "Medium"

        retrans_pct = m.get(f"tcp_{ctx}_retrans_pct", 0.0)
        rtt_ms = m.get(f"tcp_{ctx}_rtt_ms", 0.0)
        rtt_var_ms = m.get(f"tcp_{ctx}_rtt_var_ms", 0.0)
        buf_waits = m.get(f"tcp_{ctx}_buf_waits", 0.0)
        zero_wnd = m.get(f"tcp_{ctx}_zero_wnd", 0.0)
        bps_out = m.get("bps_out", 0.0)
        pps_out = max(1.0, m.get("pps_out", 1.0))
        avg_pkt_bytes = (bps_out / 8.0) / pps_out if bps_out > 0 else 800.0

        cur_cc = str(cfg.get("congestionControl", "high-speed"))
        cur_snd = int(cfg.get("sendBufferSize", 65535))
        cur_rcv = int(cfg.get("receiveWindowSize", 65535))
        cur_pb_high = int(cfg.get("proxyBufferHigh", 131072))
        cur_pb_low = int(cfg.get("proxyBufferLow", 98304))
        cur_nagle = str(cfg.get("nagle", "enabled"))
        cur_idle = int(cfg.get("idleTimeout", 300))
        cur_syn_retrans = int(cfg.get("synMaxRetrans", 3))
        cur_fast_open = str(cfg.get("fastOpen", "disabled"))

        recommended_parent: str | None = None
        if pref.full_path == "/Common/tcp":
            recommended_parent = "/Common/f5-tcp-wan" if (ctx == "clientside" and rtt_ms >= 20.0) else (
                "/Common/f5-tcp-lan" if ctx == "serverside" else "/Common/f5-tcp-progressive"
            )
            evidence_parts.append(
                f"Attached profile is legacy system default /Common/tcp; F5 recommends split-TCP inheritance via {recommended_parent}"
            )

        # 1. Congestion Control (WAN loss / RTT variance)
        if ctx == "clientside" and retrans_pct >= 2.0 and (rtt_ms >= 30.0 or rtt_var_ms >= 10.0):
            if cur_cc != "bbr":
                diffs.append(
                    ParameterDiff(
                        parameter="congestionControl",
                        current_value=cur_cc,
                        recommended_value="bbr",
                        rationale=(
                            f"BBR paces segments by estimated bottleneck bandwidth and min-RTT instead of halving cwnd "
                            f"under {retrans_pct:.2f}% WAN loss."
                        ),
                    )
                )
                evidence_parts.append(
                    f"Retransmission rate {retrans_pct:.2f}% (> 2.0%) with mean RTT {rtt_ms:.1f} ms and RTT variance {rtt_var_ms:.1f} ms"
                )
                primary_kb = "K02412420"
                confidence = "High"
                impact = "High"

        # 2. Bandwidth-Delay Product (BDP) & Buffer Exhaustion / Zero-Window tuning
        bdp_bytes = (bps_out / 8.0) * (max(rtt_ms, 5.0) / 1000.0)
        desired_snd = _next_power_buffer(max(bdp_bytes * 2.5, 262144 if (buf_waits > 0 and rtt_ms >= 25) else 131072))
        if (buf_waits > 0 or bdp_bytes > cur_snd * 0.8) and cur_snd < desired_snd:
            diffs.append(
                ParameterDiff(
                    parameter="sendBufferSize",
                    current_value=cur_snd,
                    recommended_value=desired_snd,
                    unit="bytes",
                    rationale=f"Scale send buffer above 2x BDP ({int(bdp_bytes):,} B) and eliminate {int(buf_waits)} buffer exhaustion waits.",
                )
            )
            new_pb_high = max(cur_pb_high, desired_snd)
            new_pb_low = int(new_pb_high * 0.75)
            if new_pb_high != cur_pb_high:
                diffs.append(
                    ParameterDiff(
                        parameter="proxyBufferHigh",
                        current_value=cur_pb_high,
                        recommended_value=new_pb_high,
                        unit="bytes",
                        rationale="Keep proxyBufferHigh >= sendBufferSize to prevent TMM content-spooling backpressure.",
                    )
                )
                diffs.append(
                    ParameterDiff(
                        parameter="proxyBufferLow",
                        current_value=cur_pb_low,
                        recommended_value=new_pb_low,
                        unit="bytes",
                        rationale="Maintain 75% low-watermark hysteresis below proxyBufferHigh.",
                    )
                )
            evidence_parts.append(
                f"Buffer wait events={int(buf_waits)} with throughput {bps_out / 1e6:.1f} Mbps (BDP {int(bdp_bytes):,} B vs sendBufferSize {cur_snd:,} B)"
            )
            if primary_kb == "K75593415":
                primary_kb = "K3422"
            confidence = "High"
            impact = "High"

        if zero_wnd > 0 and cur_rcv < 131072:
            diffs.append(
                ParameterDiff(
                    parameter="receiveWindowSize",
                    current_value=cur_rcv,
                    recommended_value=131072,
                    unit="bytes",
                    rationale=f"Observed {int(zero_wnd)} TCP zero-window stalls; widen receive window to 128 KB.",
                )
            )
            evidence_parts.append(f"Zero-window events={int(zero_wnd)} on {ctx}")

        # 3. Interactive / Low-Latency Nagle + Delayed-ACK deadlock check
        if cur_nagle == "enabled" and avg_pkt_bytes < 680.0 and bps_out > 1_000_000:
            target_nagle = "disabled" if avg_pkt_bytes < 550.0 else "progressive"
            diffs.append(
                ParameterDiff(
                    parameter="nagle",
                    current_value=cur_nagle,
                    recommended_value=target_nagle,
                    rationale=(
                        f"Average payload segment is small ({avg_pkt_bytes:.0f} B); Nagle + Delayed-ACK interaction "
                        f"injects artificial 40-200 ms latency spikes."
                    ),
                )
            )
            if ctx == "clientside" and cur_fast_open == "disabled":
                diffs.append(
                    ParameterDiff(
                        parameter="fastOpen",
                        current_value=cur_fast_open,
                        recommended_value="enabled",
                        rationale="Save 1 RTT on repeat client TCP handshakes.",
                    )
                )
            evidence_parts.append(
                f"Interactive small-packet workload ({avg_pkt_bytes:.0f} B/pkt avg, RTT {rtt_ms:.1f} ms) with nagle='enabled'"
            )
            if primary_kb == "K75593415":
                primary_kb = "K15812"
            confidence = "High"
            impact = "High"

        # 4. Idle timeout & SYN retransmission hygiene
        if cur_idle > 600 and m.get("cur_conns_avg", 0.0) > 2000:
            diffs.append(
                ParameterDiff(
                    parameter="idleTimeout",
                    current_value=cur_idle,
                    recommended_value=300,
                    unit="seconds",
                    rationale="Reclaim idle connection table slots under high concurrency (>2,000 active conns).",
                )
            )
            if cur_syn_retrans > 3:
                diffs.append(
                    ParameterDiff(
                        parameter="synMaxRetrans",
                        current_value=cur_syn_retrans,
                        recommended_value=3,
                        rationale="Cap embryonic SYN retries to 3 to bound half-open queue occupancy.",
                    )
                )
            evidence_parts.append(f"High idleTimeout ({cur_idle}s) with {m.get('cur_conns_avg', 0):.0f} active connections")
            if len(diffs) <= 2:
                primary_kb = "K7606"

        if not diffs:
            return None

        kb = KNOWLEDGE_BASE[primary_kb]
        is_default = pref.full_path in SYSTEM_DEFAULT_PROFILES
        _, vs_short = split_full_path(vs.full_path)
        suggested_name = (
            f"tuner_{_sanitize_name(vs_short)}_{ctx}_tcp" if is_default else pref.name
        )

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
            supporting_evidence="; ".join(evidence_parts),
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
            safe_auto_apply=True,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def _evaluate_udp_profile(
        self,
        client: BigIpClient,
        vs: VirtualServerItem,
        pref: AttachedProfileRef,
        cfg: dict[str, Any],
        m: dict[str, float],
    ) -> TuningRecommendation | None:
        diffs: list[ParameterDiff] = []
        evidence_parts: list[str] = []
        primary_kb = "K3605"
        confidence: ConfidenceScore = "High"
        impact: ConfidenceScore = "High"

        drop_pct = m.get("udp_drop_pct", 0.0)
        dgrams_per_conn = m.get("udp_dgrams_per_conn", 0.0)
        buf_overflows = m.get("udp_buf_overflows", 0.0)
        ephem_conns = m.get("ephemeral_conns_max", 0.0)

        cur_dlb = str(cfg.get("datagramLoadBalancing", "disabled"))
        cur_idle = int(cfg.get("idleTimeout", 60))

        if cur_dlb == "disabled" and (dgrams_per_conn >= 250.0 or drop_pct >= 0.5 or buf_overflows > 0):
            diffs.append(
                ParameterDiff(
                    parameter="datagramLoadBalancing",
                    current_value=cur_dlb,
                    recommended_value="enabled",
                    rationale=(
                        f"Distribute stateless datagrams across all TMM threads and pool members "
                        f"(observed {dgrams_per_conn:.0f} datagrams/conn and {drop_pct:.2f}% packet drop rate)."
                    ),
                )
            )
            evidence_parts.append(
                f"UDP datagrams/conn={dgrams_per_conn:.0f} (>250) with drop rate {drop_pct:.2f}% and {int(buf_overflows)} buffer overflows"
            )

        if ephem_conns >= 8000 and cur_idle > 30:
            diffs.append(
                ParameterDiff(
                    parameter="idleTimeout",
                    current_value=cur_idle,
                    recommended_value=15,
                    unit="seconds",
                    rationale=(
                        f"Ephemeral connection count reached {int(ephem_conns):,}; lowering idleTimeout from "
                        f"{cur_idle}s to 15s prevents ephemeral port exhaustion and TMM memory bloat."
                    ),
                )
            )
            evidence_parts.append(f"High UDP ephemeral connection table occupancy ({int(ephem_conns):,} conns) at {cur_idle}s idleTimeout")
            if not diffs[:-1]:
                primary_kb = "K3667"
                impact = "Medium"

        if not diffs:
            return None

        kb = KNOWLEDGE_BASE[primary_kb]
        is_default = pref.full_path in SYSTEM_DEFAULT_PROFILES
        _, vs_short = split_full_path(vs.full_path)
        suggested_name = f"tuner_{_sanitize_name(vs_short)}_clientside_udp" if is_default else pref.name

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
            supporting_evidence="; ".join(evidence_parts),
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
            safe_auto_apply=True,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def _evaluate_http_profile(
        self,
        client: BigIpClient,
        vs: VirtualServerItem,
        pref: AttachedProfileRef,
        cfg: dict[str, Any],
        m: dict[str, float],
    ) -> TuningRecommendation | None:
        diffs: list[ParameterDiff] = []
        evidence_parts: list[str] = []
        primary_kb = "K7208"
        confidence: ConfidenceScore = "High"
        impact: ConfidenceScore = "Medium"

        reuse = m.get("http_keepalive_reuse", 0.0)
        hdr_drops = m.get("http_header_drops", 0.0)
        comp_ratio = m.get("http_compression_ratio", 1.0)
        bps_out = m.get("bps_out", 0.0)

        cur_max_req = int(cfg.get("maxRequests", 0))
        cur_oneconnect = str(cfg.get("oneconnectTransformations", "enabled"))
        cur_pipelining = str(cfg.get("pipelining", "enabled"))
        cur_xff = str(cfg.get("insertXforwardedFor", "disabled"))
        enf = cfg.get("enforcement") or {}
        cur_max_hdr_size = int(enf.get("maxHeaderSize", 32768))

        if (0 < cur_max_req < 250) or (0.0 < reuse < 10.0 and cur_oneconnect == "disabled"):
            if 0 < cur_max_req < 250:
                diffs.append(
                    ParameterDiff(
                        parameter="maxRequests",
                        current_value=cur_max_req,
                        recommended_value=0,
                        unit="requests/conn (0=unlimited)",
                        rationale=(
                            f"Current maxRequests={cur_max_req} forces premature TCP/TLS teardown "
                            f"(measured reuse only {reuse:.1f} reqs/conn)."
                        ),
                    )
                )
            if cur_oneconnect == "disabled":
                diffs.append(
                    ParameterDiff(
                        parameter="oneconnectTransformations",
                        current_value=cur_oneconnect,
                        recommended_value="enabled",
                        rationale="Enable HTTP header transformations required for L7 keep-alive connection pooling.",
                    )
                )
            evidence_parts.append(
                f"Low HTTP keep-alive reuse ({reuse:.1f} reqs/conn) with maxRequests={cur_max_req} and oneconnectTransformations='{cur_oneconnect}'"
            )
            impact = "High"

        if hdr_drops > 0 and cur_max_hdr_size < 65536:
            diffs.append(
                ParameterDiff(
                    parameter="enforcement.maxHeaderSize",
                    current_value=cur_max_hdr_size,
                    recommended_value=65536,
                    unit="bytes",
                    rationale=f"Observed {int(hdr_drops)} dropped requests exceeding {cur_max_hdr_size:,} B header cap (e.g. OIDC/JWT cookies).",
                )
            )
            evidence_parts.append(f"HTTP maxHeaderSize drops={int(hdr_drops)} (>0) at {cur_max_hdr_size:,} B limit")
            primary_kb = "K13525"
            impact = "High"

        if cur_pipelining == "enabled":
            diffs.append(
                ParameterDiff(
                    parameter="pipelining",
                    current_value=cur_pipelining,
                    recommended_value="disabled",
                    rationale="Disable legacy HTTP/1.1 pipelining to prevent Head-of-Line blocking; prefer HTTP/2 profile on WAN.",
                )
            )
            evidence_parts.append("HTTP/1.1 pipelining is currently enabled")

        if cur_xff == "disabled":
            diffs.append(
                ParameterDiff(
                    parameter="insertXforwardedFor",
                    current_value=cur_xff,
                    recommended_value="enabled",
                    rationale="Preserve original client source IP across SNAT/proxy hops for upstream telemetry.",
                )
            )

        if bps_out > 50_000_000 and comp_ratio < 1.25:
            evidence_parts.append(
                f"Advisory (K15434): Outbound HTTP rate {bps_out / 1e6:.1f} Mbps with {comp_ratio:.2f}x compression — consider pairing /Common/httpcompression & /Common/http2"
            )

        if not diffs:
            return None

        kb = KNOWLEDGE_BASE[primary_kb]
        is_default = pref.full_path in SYSTEM_DEFAULT_PROFILES
        _, vs_short = split_full_path(vs.full_path)
        suggested_name = f"tuner_{_sanitize_name(vs_short)}_clientside_http" if is_default else pref.name

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
            supporting_evidence="; ".join(evidence_parts),
            metrics_snapshot={
                "keepalive_reqs_per_conn": round(reuse, 2),
                "header_size_drops": round(hdr_drops, 1),
                "compression_ratio": round(comp_ratio, 2),
                "throughput_mbps": round(bps_out / 1e6, 2),
            },
            f5_kb_id=kb.kb_id,
            f5_kb_title=kb.title,
            f5_kb_url=kb.url,
            confidence=confidence,
            impact=impact,
            safe_auto_apply=True,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
