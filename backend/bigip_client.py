"""BIG-IP iControl REST client with in-memory token management and selective protocol polling."""

from __future__ import annotations

import copy
import logging
import math
import random
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from backend.models import AttachedProfileRef, ProtocolType, VirtualServerItem

logger = logging.getLogger(__name__)

# Built-in TMOS base profiles that must NEVER be directly mutated via PATCH
SYSTEM_DEFAULT_PROFILES: set[str] = {
    "/Common/tcp",
    "/Common/tcp-legacy",
    "/Common/tcp-lan-optimized",
    "/Common/tcp-wan-optimized",
    "/Common/tcp-mobile-optimized",
    "/Common/f5-tcp-wan",
    "/Common/f5-tcp-lan",
    "/Common/f5-tcp-mobile",
    "/Common/f5-tcp-progressive",
    "/Common/mptcp-mobile-optimized",
    "/Common/udp",
    "/Common/udp_gtm_dns",
    "/Common/udp_dns",
    "/Common/http",
    "/Common/http-explicit",
    "/Common/http-transparent",
}


def full_path_to_rest_id(full_path: str) -> str:
    """Convert '/Common/my_profile' to '~Common~my_profile' for iControl REST URLs."""
    cleaned = full_path.strip()
    if not cleaned.startswith("/"):
        cleaned = f"/Common/{cleaned}"
    return "~" + cleaned.lstrip("/").replace("/", "~")


def split_full_path(full_path: str) -> tuple[str, str]:
    """Split '/Common/vip_app' into ('Common', 'vip_app')."""
    cleaned = full_path.strip().lstrip("/")
    if "/" not in cleaned:
        return "Common", cleaned
    parts = cleaned.split("/")
    return parts[0], parts[-1]


def _extract_stat_val(entries: dict[str, Any], *keys: str, default: float = 0.0) -> float:
    """Safely extract numeric value from TMOS nestedStats.entries."""
    for key in keys:
        item = entries.get(key)
        if isinstance(item, dict):
            if "value" in item and item["value"] is not None:
                try:
                    return float(item["value"])
                except (TypeError, ValueError):
                    pass
            if "description" in item and item["description"] is not None:
                try:
                    return float(item["description"])
                except (TypeError, ValueError):
                    pass
    return default


def _extract_stat_str(entries: dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        item = entries.get(key)
        if isinstance(item, dict):
            desc = item.get("description")
            if desc is not None:
                return str(desc)
            val = item.get("value")
            if val is not None:
                return str(val)
    return default


class _DemoBigIpSimulator:
    """Stateful lab simulator modeling realistic BIG-IP Virtual Servers, profiles, and traffic physics."""

    def __init__(self, host: str) -> None:
        self.host = host
        self.started_at = time.time()
        self._rng = random.Random(hash(host) & 0xFFFFFFFF)
        self.profiles: dict[str, dict[str, dict[str, Any]]] = {
            "tcp": {
                "/Common/tcp": {
                    "name": "tcp",
                    "partition": "Common",
                    "fullPath": "/Common/tcp",
                    "defaultsFrom": None,
                    "proxyBufferLow": 98304,
                    "proxyBufferHigh": 131072,
                    "sendBufferSize": 65535,
                    "receiveWindowSize": 65535,
                    "congestionControl": "high-speed",
                    "idleTimeout": 300,
                    "keepAliveInterval": 1800,
                    "synMaxRetrans": 3,
                    "delayedAcks": "enabled",
                    "nagle": "enabled",
                    "pktLossIgnoreRate": 0,
                    "pktLossIgnoreBurst": 0,
                    "fastOpen": "disabled",
                },
                "/Common/f5-tcp-wan": {
                    "name": "f5-tcp-wan",
                    "partition": "Common",
                    "fullPath": "/Common/f5-tcp-wan",
                    "defaultsFrom": "/Common/tcp",
                    "proxyBufferLow": 196608,
                    "proxyBufferHigh": 262144,
                    "sendBufferSize": 262144,
                    "receiveWindowSize": 131072,
                    "congestionControl": "cubic",
                    "idleTimeout": 300,
                    "keepAliveInterval": 1800,
                    "synMaxRetrans": 3,
                    "delayedAcks": "enabled",
                    "nagle": "progressive",
                    "pktLossIgnoreRate": 0,
                    "pktLossIgnoreBurst": 0,
                    "fastOpen": "disabled",
                },
                "/Common/f5-tcp-lan": {
                    "name": "f5-tcp-lan",
                    "partition": "Common",
                    "fullPath": "/Common/f5-tcp-lan",
                    "defaultsFrom": "/Common/tcp",
                    "proxyBufferLow": 98304,
                    "proxyBufferHigh": 131072,
                    "sendBufferSize": 131072,
                    "receiveWindowSize": 131072,
                    "congestionControl": "woodside",
                    "idleTimeout": 300,
                    "keepAliveInterval": 1800,
                    "synMaxRetrans": 3,
                    "delayedAcks": "enabled",
                    "nagle": "disabled",
                    "pktLossIgnoreRate": 0,
                    "pktLossIgnoreBurst": 0,
                    "fastOpen": "disabled",
                },
                "/Common/tcp_trading_api_custom": {
                    "name": "tcp_trading_api_custom",
                    "partition": "Common",
                    "fullPath": "/Common/tcp_trading_api_custom",
                    "defaultsFrom": "/Common/tcp",
                    "proxyBufferLow": 65535,
                    "proxyBufferHigh": 98304,
                    "sendBufferSize": 65535,
                    "receiveWindowSize": 65535,
                    "congestionControl": "cubic",
                    "idleTimeout": 900,
                    "keepAliveInterval": 1800,
                    "synMaxRetrans": 4,
                    "delayedAcks": "enabled",
                    "nagle": "enabled",
                    "pktLossIgnoreRate": 0,
                    "pktLossIgnoreBurst": 0,
                    "fastOpen": "disabled",
                },
            },
            "udp": {
                "/Common/udp": {
                    "name": "udp",
                    "partition": "Common",
                    "fullPath": "/Common/udp",
                    "defaultsFrom": None,
                    "idleTimeout": 60,
                    "datagramLoadBalancing": "disabled",
                    "proxyMss": "disabled",
                    "ipTtl": 255,
                    "allowNoPayload": "disabled",
                },
            },
            "http": {
                "/Common/http": {
                    "name": "http",
                    "partition": "Common",
                    "fullPath": "/Common/http",
                    "defaultsFrom": None,
                    "maxRequests": 25,
                    "pipelining": "enabled",
                    "oneconnectTransformations": "disabled",
                    "insertXforwardedFor": "disabled",
                    "enforcement": {
                        "maxHeaderCount": 64,
                        "maxHeaderSize": 32768,
                    },
                },
            },
        }
        self.virtual_servers: dict[str, dict[str, Any]] = {
            "/Common/vip_ecommerce_https": {
                "name": "vip_ecommerce_https",
                "partition": "Common",
                "fullPath": "/Common/vip_ecommerce_https",
                "destination": "/Common/10.20.10.40:443",
                "ipProtocol": "tcp",
                "pool": "/Common/pool_ecommerce_web",
                "enabled": True,
                "profiles": [
                    {"name": "tcp", "partition": "Common", "fullPath": "/Common/tcp", "context": "clientside"},
                    {"name": "f5-tcp-lan", "partition": "Common", "fullPath": "/Common/f5-tcp-lan", "context": "serverside"},
                    {"name": "http", "partition": "Common", "fullPath": "/Common/http", "context": "all"},
                ],
            },
            "/Common/vip_trading_lowlatency": {
                "name": "vip_trading_lowlatency",
                "partition": "Common",
                "fullPath": "/Common/vip_trading_lowlatency",
                "destination": "/Common/10.20.10.55:8443",
                "ipProtocol": "tcp",
                "pool": "/Common/pool_order_gateway",
                "enabled": True,
                "profiles": [
                    {
                        "name": "tcp_trading_api_custom",
                        "partition": "Common",
                        "fullPath": "/Common/tcp_trading_api_custom",
                        "context": "clientside",
                    },
                    {"name": "tcp", "partition": "Common", "fullPath": "/Common/tcp", "context": "serverside"},
                    {"name": "http", "partition": "Common", "fullPath": "/Common/http", "context": "all"},
                ],
            },
            "/Common/vip_telemetry_udp_ingest": {
                "name": "vip_telemetry_udp_ingest",
                "partition": "Common",
                "fullPath": "/Common/vip_telemetry_udp_ingest",
                "destination": "/Common/10.20.10.88:5514",
                "ipProtocol": "udp",
                "pool": "/Common/pool_udp_collectors",
                "enabled": True,
                "profiles": [
                    {"name": "udp", "partition": "Common", "fullPath": "/Common/udp", "context": "all"},
                ],
            },
        }
        self._counters: dict[str, float] = {}
        self._last_tick = time.time()

    def _inc(self, key: str, delta: float) -> float:
        val = self._counters.get(key, 0.0) + max(0.0, delta)
        self._counters[key] = val
        return val

    def _resolve_profile(self, proto: str, full_path: str) -> dict[str, Any]:
        prof = self.profiles.get(proto, {}).get(full_path)
        if prof:
            return prof
        return next(iter(self.profiles.get(proto, {}).values()), {})

    def generate_poll_samples(self, enrolled_vs: set[str] | None) -> list[dict[str, Any]]:
        now = time.time()
        dt = max(5.0, min(120.0, now - self._last_tick))
        self._last_tick = now
        wave = 1.0 + 0.15 * math.sin(now / 90.0)
        samples: list[dict[str, Any]] = []

        for vs_path, vs in self.virtual_servers.items():
            if enrolled_vs is not None and vs_path not in enrolled_vs:
                continue
            partition, vs_name = split_full_path(vs_path)
            is_udp = vs["ipProtocol"] == "udp"

            # Check whether profiles have been tuned so telemetry reflects real improvements!
            client_tcp = None
            http_prof = None
            udp_prof = None
            for p in vs["profiles"]:
                fp = p["fullPath"]
                if fp in self.profiles["tcp"] and p["context"] in ("clientside", "all"):
                    client_tcp = self.profiles["tcp"][fp]
                if fp in self.profiles["http"]:
                    http_prof = self.profiles["http"][fp]
                if fp in self.profiles["udp"]:
                    udp_prof = self.profiles["udp"][fp]

            if not is_udp:
                is_ecommerce = "ecommerce" in vs_name
                cc = (client_tcp or {}).get("congestionControl", "cubic")
                snd_buf = int((client_tcp or {}).get("sendBufferSize", 65535))
                nagle = (client_tcp or {}).get("nagle", "enabled")
                tuned_factor = 1.32 if (cc == "bbr" or snd_buf >= 262144 or nagle == "disabled") else 1.0

                base_bps_out = (145_000_000 if is_ecommerce else 58_000_000) * wave * tuned_factor
                base_bps_in = base_bps_out * 0.22
                pkts_out_rate = base_bps_out / (8.0 * (1180 if is_ecommerce else 420))
                pkts_in_rate = pkts_out_rate * 0.65
                conn_rate = (210.0 if is_ecommerce else 440.0) * wave

                samples.append(
                    {
                        "category": "virtual",
                        "bigip_host": self.host,
                        "virtual_server": vs_path,
                        "partition": partition,
                        "profile_type": "tcp",
                        "context": "clientside",
                        "profile_name": vs_name,
                        "metrics": {
                            "bigip_vs_bits_in_total": self._inc(f"{vs_path}:bi", base_bps_in * dt),
                            "bigip_vs_bits_out_total": self._inc(f"{vs_path}:bo", base_bps_out * dt),
                            "bigip_vs_pkts_in_total": self._inc(f"{vs_path}:pi", pkts_in_rate * dt),
                            "bigip_vs_pkts_out_total": self._inc(f"{vs_path}:po", pkts_out_rate * dt),
                            "bigip_vs_cur_conns": round((1850 if is_ecommerce else 3120) * wave),
                            "bigip_vs_max_conns": 4820 if is_ecommerce else 6100,
                            "bigip_vs_tot_conns_total": self._inc(f"{vs_path}:tc", conn_rate * dt),
                            "bigip_vs_syn_cookies_total": self._inc(f"{vs_path}:sc", (0.2 if is_ecommerce else 2.5) * dt),
                            "bigip_vs_ephemeral_cur_conns": round((620 if is_ecommerce else 1480) * wave),
                            "bigip_vs_ephemeral_tot_conns_total": self._inc(f"{vs_path}:ec", conn_rate * 0.7 * dt),
                        },
                    }
                )

                # Emit TCP profile metrics for attached TCP profiles
                for p in vs["profiles"]:
                    fp = p["fullPath"]
                    if fp not in self.profiles["tcp"]:
                        continue
                    prof = self.profiles["tcp"][fp]
                    ctx = "serverside" if p["context"] == "serverside" else "clientside"
                    prof_cc = prof.get("congestionControl", "cubic")
                    prof_snd = int(prof.get("sendBufferSize", 65535))
                    prof_rcv = int(prof.get("receiveWindowSize", 65535))
                    prof_nagle = prof.get("nagle", "enabled")

                    if ctx == "clientside" and is_ecommerce:
                        retrans_ratio = 0.006 if prof_cc == "bbr" else 0.031
                        rtt_ms = 58.0 if prof_cc == "bbr" else 74.0
                        rtt_var = 11.5 if prof_cc == "bbr" else 26.4
                        buf_wait_rate = 0.05 if prof_snd >= 262144 else 8.4
                        zwnd_rate = 0.1 if prof_rcv >= 131072 else 3.8
                    elif ctx == "clientside":
                        retrans_ratio = 0.008 if prof_nagle == "disabled" else 0.018
                        rtt_ms = 9.5 if prof_nagle == "disabled" else 46.0
                        rtt_var = 2.4 if prof_nagle == "disabled" else 19.2
                        buf_wait_rate = 0.1 if prof_snd >= 131072 else 4.2
                        zwnd_rate = 0.2 if prof_rcv >= 131072 else 2.1
                    else:
                        retrans_ratio = 0.0015
                        rtt_ms = 1.8
                        rtt_var = 0.5
                        buf_wait_rate = 0.0
                        zwnd_rate = 0.0

                    segs_delta = pkts_out_rate * dt
                    rxmits_delta = segs_delta * retrans_ratio * (0.92 + 0.16 * self._rng.random())

                    samples.append(
                        {
                            "category": "tcp",
                            "bigip_host": self.host,
                            "virtual_server": vs_path,
                            "partition": partition,
                            "profile_type": "tcp",
                            "context": ctx,
                            "profile_name": prof["name"],
                            "metrics": {
                                "bigip_tcp_segments_out_total": self._inc(f"{vs_path}:{fp}:seg", segs_delta),
                                "bigip_tcp_retransmits_total": self._inc(f"{vs_path}:{fp}:rxm", rxmits_delta),
                                "bigip_tcp_retransmit_rate_pct": round((rxmits_delta / max(1.0, segs_delta)) * 100.0, 3),
                                "bigip_tcp_zero_window_events_total": self._inc(f"{vs_path}:{fp}:zw", zwnd_rate * dt),
                                "bigip_tcp_sack_ok_total": self._inc(f"{vs_path}:{fp}:sack", conn_rate * 0.94 * dt),
                                "bigip_tcp_rtt_ms": round(rtt_ms + self._rng.uniform(-2.0, 2.0), 2),
                                "bigip_tcp_rtt_variance_ms": round(rtt_var + self._rng.uniform(-1.0, 1.0), 2),
                                "bigip_tcp_buffer_exhaustion_total": self._inc(f"{vs_path}:{fp}:buf", buf_wait_rate * dt),
                                "bigip_tcp_embryonic_conns": round(28 * wave if ctx == "clientside" else 4),
                                "bigip_tcp_resets_total": self._inc(
                                    f"{vs_path}:{fp}:rst", (1.2 if prof_snd >= 131072 else 6.5) * dt
                                ),
                                "bigip_tcp_profile_send_buffer_bytes": float(prof_snd),
                                "bigip_tcp_profile_recv_window_bytes": float(prof_rcv),
                                "bigip_tcp_profile_proxy_buffer_high_bytes": float(prof.get("proxyBufferHigh", 131072)),
                                "bigip_tcp_profile_idle_timeout_seconds": float(prof.get("idleTimeout", 300)),
                            },
                        }
                    )

                if http_prof:
                    max_req = int(http_prof.get("maxRequests", 25))
                    oneconnect = http_prof.get("oneconnectTransformations", "disabled") == "enabled"
                    max_hdr = int((http_prof.get("enforcement") or {}).get("maxHeaderSize", 32768))
                    reuse_ratio = 42.5 if (max_req == 0 or max_req >= 500) and oneconnect else 4.8
                    hdr_drop_rate = 0.0 if max_hdr >= 65536 else (0.0 if is_ecommerce else 2.6)
                    req_rate = conn_rate * reuse_ratio * 0.35

                    samples.append(
                        {
                            "category": "http",
                            "bigip_host": self.host,
                            "virtual_server": vs_path,
                            "partition": partition,
                            "profile_type": "http",
                            "context": "clientside",
                            "profile_name": http_prof["name"],
                            "metrics": {
                                "bigip_http_requests_total": self._inc(f"{vs_path}:hreq", req_rate * dt),
                                "bigip_http_responses_total": self._inc(f"{vs_path}:hresp", req_rate * 0.998 * dt),
                                "bigip_http_keepalive_reqs_per_conn": round(reuse_ratio + self._rng.uniform(-0.4, 0.4), 2),
                                "bigip_http_pipelined_requests_total": self._inc(
                                    f"{vs_path}:hpipe",
                                    (req_rate * 0.04 if http_prof.get("pipelining") == "enabled" else 0.0) * dt,
                                ),
                                "bigip_http_header_size_drops_total": self._inc(f"{vs_path}:hhdr", hdr_drop_rate * dt),
                                "bigip_http_compression_ratio": 2.4 if is_ecommerce else 1.15,
                                "bigip_http_server_closes_total": self._inc(
                                    f"{vs_path}:hcls", (conn_rate * (0.12 if oneconnect else 0.78)) * dt
                                ),
                            },
                        }
                    )
            else:
                # UDP Virtual Server telemetry
                dlb = (udp_prof or {}).get("datagramLoadBalancing", "disabled") == "enabled"
                idle_to = int((udp_prof or {}).get("idleTimeout", 60))
                dgram_rate = (48_000.0 if dlb else 34_000.0) * wave
                drop_rate = (18.0 if dlb else 890.0) * wave
                ephem_conns = round((2800 if idle_to <= 30 else 19400) * wave)

                samples.append(
                    {
                        "category": "virtual",
                        "bigip_host": self.host,
                        "virtual_server": vs_path,
                        "partition": partition,
                        "profile_type": "udp",
                        "context": "clientside",
                        "profile_name": vs_name,
                        "metrics": {
                            "bigip_vs_bits_in_total": self._inc(f"{vs_path}:bi", dgram_rate * 512 * 8 * dt),
                            "bigip_vs_bits_out_total": self._inc(f"{vs_path}:bo", dgram_rate * 128 * 8 * dt),
                            "bigip_vs_pkts_in_total": self._inc(f"{vs_path}:pi", dgram_rate * dt),
                            "bigip_vs_pkts_out_total": self._inc(f"{vs_path}:po", dgram_rate * 0.25 * dt),
                            "bigip_vs_cur_conns": ephem_conns,
                            "bigip_vs_max_conns": 28500,
                            "bigip_vs_tot_conns_total": self._inc(f"{vs_path}:tc", 42.0 * dt),
                            "bigip_vs_syn_cookies_total": 0.0,
                            "bigip_vs_ephemeral_cur_conns": ephem_conns,
                            "bigip_vs_ephemeral_tot_conns_total": self._inc(f"{vs_path}:ec", 42.0 * dt),
                        },
                    }
                )
                if udp_prof:
                    samples.append(
                        {
                            "category": "udp",
                            "bigip_host": self.host,
                            "virtual_server": vs_path,
                            "partition": partition,
                            "profile_type": "udp",
                            "context": "clientside",
                            "profile_name": udp_prof["name"],
                            "metrics": {
                                "bigip_udp_datagrams_in_total": self._inc(f"{vs_path}:udi", dgram_rate * dt),
                                "bigip_udp_datagrams_out_total": self._inc(f"{vs_path}:udo", dgram_rate * 0.25 * dt),
                                "bigip_udp_dropped_pkts_total": self._inc(f"{vs_path}:udrop", drop_rate * dt),
                                "bigip_udp_drop_rate_pct": round((drop_rate / max(1.0, dgram_rate)) * 100.0, 3),
                                "bigip_udp_idle_timeouts_total": self._inc(f"{vs_path}:uito", 38.0 * dt),
                                "bigip_udp_buffer_overflows_total": self._inc(
                                    f"{vs_path}:ubuf", (0.2 if dlb else 14.5) * dt
                                ),
                                "bigip_udp_datagrams_per_conn": round(dgram_rate / 42.0, 1),
                                "bigip_udp_profile_idle_timeout_seconds": float(idle_to),
                            },
                        }
                    )
        return samples


class BigIpClient:
    """Thread-safe BIG-IP iControl REST client with in-memory token management."""

    def __init__(
        self,
        *,
        session_id: str,
        host: str,
        port: int = 443,
        username: str = "admin",
        password: str = "",
        verify_ssl: bool = False,
        enable_tmctl: bool = False,
        demo_mode: bool = False,
        label: str | None = None,
    ) -> None:
        self.session_id = session_id
        self.host = host
        self.port = port
        self.username = username
        self._password = password
        self.verify_ssl = verify_ssl
        self.enable_tmctl = enable_tmctl
        self.demo_mode = demo_mode
        self.label = label or host

        self._lock = threading.RLock()
        # Auth token stored strictly in memory only
        self._auth_token: str | None = None
        self._token_expires_at: datetime | None = None
        self.connected: bool = False
        self.hostname: str | None = None
        self.version: str | None = None
        self.platform: str | None = None
        self.last_poll_at: str | None = None
        self.last_error: str | None = None
        self.cached_virtual_servers: list[VirtualServerItem] = []

        self._simulator = _DemoBigIpSimulator(host) if demo_mode else None
        self._http = httpx.Client(
            base_url=f"https://{host}:{port}",
            verify=verify_ssl,
            timeout=httpx.Timeout(20.0, connect=8.0),
        )

    def close(self) -> None:
        try:
            self._http.close()
        except Exception:
            pass

    @property
    def token_expires_iso(self) -> str | None:
        return self._token_expires_at.isoformat() if self._token_expires_at else None

    def authenticate(self) -> None:
        """Authenticate via POST /mgmt/shared/authn/login (TMOS provider) and extend lifetime to ~60m."""
        with self._lock:
            if self.demo_mode:
                self._auth_token = f"demo-token-{int(time.time())}"
                self._token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=60)
                self.connected = True
                self.hostname = f"{self.host}.lab.f5net.local"
                self.version = "17.1.1.4"
                self.platform = "BIG-IP Virtual Edition (Demo Lab)"
                self.last_error = None
                return

            resp = self._http.post(
                "/mgmt/shared/authn/login",
                json={
                    "username": self.username,
                    "password": self._password,
                    "loginProviderName": "tmos",
                },
            )
            resp.raise_for_status()
            body = resp.json()
            token_obj = body.get("token") or {}
            token = token_obj.get("token")
            if not token:
                raise RuntimeError("BIG-IP login succeeded without returning an X-F5-Auth-Token")

            self._auth_token = token
            timeout_sec = int(token_obj.get("timeout", 1200))

            # Attempt token lifetime extension to ~60 minutes (3600s)
            try:
                ext_resp = self._http.patch(
                    f"/mgmt/shared/authz/tokens/{token}",
                    headers={"X-F5-Auth-Token": token},
                    json={"timeout": 3600},
                )
                if ext_resp.status_code < 300:
                    timeout_sec = int(ext_resp.json().get("timeout", 3600))
            except Exception as exc:
                logger.debug("Token timeout extension skipped on %s: %s", self.host, exc)

            self._token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=max(60, timeout_sec - 60))
            self.connected = True
            self.last_error = None

            # Fetch device identity metadata
            try:
                dev_data = self.request("GET", "/mgmt/tm/cm/device")
                for item in dev_data.get("items", []):
                    if item.get("selfDevice") == "true" or not self.hostname:
                        self.hostname = item.get("hostname") or self.host
                        self.version = item.get("version")
                        self.platform = item.get("marketingName") or "BIG-IP TMOS"
            except Exception as exc:
                logger.debug("Device metadata lookup failed on %s: %s", self.host, exc)
                self.hostname = self.hostname or self.host

    def _ensure_token(self) -> str:
        with self._lock:
            now = datetime.now(timezone.utc)
            if not self._auth_token or (self._token_expires_at and now >= self._token_expires_at):
                self.authenticate()
            assert self._auth_token is not None
            return self._auth_token

    def request(self, method: str, path: str, *, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute authenticated iControl REST call with automatic re-authentication on HTTP 401."""
        token = self._ensure_token()
        headers = {"X-F5-Auth-Token": token, "Content-Type": "application/json"}
        try:
            resp = self._http.request(method, path, headers=headers, json=json_body)
            if resp.status_code == 401:
                logger.info("HTTP 401 on %s%s; re-authenticating BIG-IP token", self.host, path)
                self.authenticate()
                headers["X-F5-Auth-Token"] = self._auth_token or ""
                resp = self._http.request(method, path, headers=headers, json=json_body)
            resp.raise_for_status()
            self.connected = True
            self.last_error = None
            return resp.json() if resp.content else {}
        except Exception as exc:
            self.last_error = str(exc)
            raise

    def discover_virtual_servers(self, enrolled_paths: list[str] | None = None) -> list[VirtualServerItem]:
        """Discover LTM Virtual Servers and resolve attached Client/Server TCP, UDP, and HTTP profiles."""
        enrolled_set = set(enrolled_paths) if enrolled_paths is not None else None

        if self.demo_mode and self._simulator:
            items: list[VirtualServerItem] = []
            for fp, vs in self._simulator.virtual_servers.items():
                attached: list[AttachedProfileRef] = []
                for p in vs["profiles"]:
                    p_fp = p["fullPath"]
                    for proto in ("tcp", "udp", "http"):
                        if p_fp in self._simulator.profiles[proto]:
                            prof_cfg = self._simulator.profiles[proto][p_fp]
                            attached.append(
                                AttachedProfileRef(
                                    name=p["name"],
                                    partition=p.get("partition", "Common"),
                                    full_path=p_fp,
                                    protocol=proto,  # type: ignore[arg-type]
                                    context=p.get("context", "all"),
                                    defaults_from=prof_cfg.get("defaultsFrom"),
                                    is_system_default=p_fp in SYSTEM_DEFAULT_PROFILES,
                                )
                            )
                is_enrolled = True if enrolled_set is None else (fp in enrolled_set)
                items.append(
                    VirtualServerItem(
                        name=vs["name"],
                        partition=vs["partition"],
                        full_path=fp,
                        destination=vs["destination"],
                        ip_protocol=vs["ipProtocol"],
                        pool=vs.get("pool"),
                        enabled=vs.get("enabled", True),
                        availability_state="available",
                        enrolled=is_enrolled,
                        profiles=attached,
                    )
                )
            self.cached_virtual_servers = items
            return items

        # Live iControl REST discovery: fetch TCP, UDP, HTTP profile catalogs first
        profile_catalog: dict[str, tuple[ProtocolType, dict[str, Any]]] = {}
        for proto in ("tcp", "udp", "http"):
            data = self.request("GET", f"/mgmt/tm/ltm/profile/{proto}")
            for prof in data.get("items", []):
                fp = prof.get("fullPath") or f"/{prof.get('partition', 'Common')}/{prof['name']}"
                profile_catalog[fp] = (proto, prof)  # type: ignore[assignment]

        vs_data = self.request("GET", "/mgmt/tm/ltm/virtual?expandSubcollections=true")
        discovered: list[VirtualServerItem] = []
        for vs in vs_data.get("items", []):
            fp = vs.get("fullPath") or f"/{vs.get('partition', 'Common')}/{vs['name']}"
            prof_items = (vs.get("profilesReference") or {}).get("items", [])
            attached: list[AttachedProfileRef] = []
            for p in prof_items:
                p_fp = p.get("fullPath") or f"/{p.get('partition', 'Common')}/{p['name']}"
                if p_fp in profile_catalog:
                    proto, prof_meta = profile_catalog[p_fp]
                    ctx = p.get("context", "all")
                    if ctx not in ("clientside", "serverside", "all"):
                        ctx = "all"
                    attached.append(
                        AttachedProfileRef(
                            name=p["name"],
                            partition=p.get("partition", "Common"),
                            full_path=p_fp,
                            protocol=proto,
                            context=ctx,
                            defaults_from=prof_meta.get("defaultsFrom"),
                            is_system_default=p_fp in SYSTEM_DEFAULT_PROFILES,
                        )
                    )

            is_enrolled = True if enrolled_set is None else (fp in enrolled_set)
            discovered.append(
                VirtualServerItem(
                    name=vs["name"],
                    partition=vs.get("partition", "Common"),
                    full_path=fp,
                    destination=vs.get("destination", ""),
                    ip_protocol=str(vs.get("ipProtocol", "tcp")),
                    pool=vs.get("pool"),
                    enabled=bool(vs.get("enabled", True)) and not bool(vs.get("disabled", False)),
                    availability_state="available",
                    enrolled=is_enrolled,
                    profiles=attached,
                )
            )

        self.cached_virtual_servers = discovered
        return discovered

    def poll_protocol_telemetry(self, enrolled_paths: list[str] | None = None) -> list[dict[str, Any]]:
        """Poll ONLY Virtual Server flow and TCP/UDP/HTTP profile telemetry for enrolled Virtual Servers."""
        now_iso = datetime.now(timezone.utc).isoformat()
        enrolled_set = set(enrolled_paths) if enrolled_paths is not None else None

        if not self.cached_virtual_servers:
            self.discover_virtual_servers(enrolled_paths)

        if self.demo_mode and self._simulator:
            samples = self._simulator.generate_poll_samples(enrolled_set)
            self.last_poll_at = now_iso
            return samples

        active_vs = [
            vs for vs in self.cached_virtual_servers if (enrolled_set is None or vs.full_path in enrolled_set)
        ]
        if not active_vs:
            self.last_poll_at = now_iso
            return []

        vs_by_path = {vs.full_path: vs for vs in active_vs}
        samples: list[dict[str, Any]] = []

        # 1. Virtual Server flow stats (/mgmt/tm/ltm/virtual/stats)
        vs_stats_raw = self.request("GET", "/mgmt/tm/ltm/virtual/stats")
        for entry in (vs_stats_raw.get("entries") or {}).values():
            nested = (entry.get("nestedStats") or {}).get("entries") or {}
            vs_fp = _extract_stat_str(nested, "tmName")
            if vs_fp not in vs_by_path:
                continue
            vs_item = vs_by_path[vs_fp]
            proto_label = "udp" if vs_item.ip_protocol == "udp" else "tcp"
            syn_cookies = _extract_stat_val(
                nested, "synCookies.accepts", "clientside.synCookies", "synCookiesTotal"
            )
            samples.append(
                {
                    "category": "virtual",
                    "bigip_host": self.host,
                    "virtual_server": vs_fp,
                    "partition": vs_item.partition,
                    "profile_type": proto_label,
                    "context": "clientside",
                    "profile_name": vs_item.name,
                    "metrics": {
                        "bigip_vs_bits_in_total": _extract_stat_val(nested, "clientside.bitsIn"),
                        "bigip_vs_bits_out_total": _extract_stat_val(nested, "clientside.bitsOut"),
                        "bigip_vs_pkts_in_total": _extract_stat_val(nested, "clientside.pktsIn"),
                        "bigip_vs_pkts_out_total": _extract_stat_val(nested, "clientside.pktsOut"),
                        "bigip_vs_cur_conns": _extract_stat_val(nested, "clientside.curConns"),
                        "bigip_vs_max_conns": _extract_stat_val(nested, "clientside.maxConns"),
                        "bigip_vs_tot_conns_total": _extract_stat_val(nested, "clientside.totConns"),
                        "bigip_vs_syn_cookies_total": syn_cookies,
                        "bigip_vs_ephemeral_cur_conns": _extract_stat_val(nested, "ephemeral.curConns"),
                        "bigip_vs_ephemeral_tot_conns_total": _extract_stat_val(nested, "ephemeral.totConns"),
                    },
                }
            )

        # Build reverse map of attached profiles -> enrolled Virtual Servers
        needed_profiles: dict[ProtocolType, dict[str, list[tuple[VirtualServerItem, str]]]] = {
            "tcp": {},
            "udp": {},
            "http": {},
        }
        for vs_item in active_vs:
            for pref in vs_item.profiles:
                ctx = "serverside" if pref.context == "serverside" else "clientside"
                needed_profiles[pref.protocol].setdefault(pref.full_path, []).append((vs_item, ctx))

        # Optional supplemental tmctl tcp_stat scrape for RTT / buffer wait metrics
        tmctl_rtt_ms = 0.0
        tmctl_buf_wait = 0.0
        if self.enable_tmctl and needed_profiles["tcp"]:
            tmctl_rtt_ms, tmctl_buf_wait = self._poll_tmctl_tcp_supplement()

        # 2. TCP Profile Stats (/mgmt/tm/ltm/profile/tcp/stats)
        if needed_profiles["tcp"]:
            tcp_stats_raw = self.request("GET", "/mgmt/tm/ltm/profile/tcp/stats")
            for entry in (tcp_stats_raw.get("entries") or {}).values():
                nested = (entry.get("nestedStats") or {}).get("entries") or {}
                prof_fp = _extract_stat_str(nested, "tmName")
                if prof_fp not in needed_profiles["tcp"]:
                    continue
                _, prof_name = split_full_path(prof_fp)
                rxmits = _extract_stat_val(nested, "rxmits", "retransmits")
                segs = max(1.0, _extract_stat_val(nested, "pktsOut", "segmentsOut", "txPkts", default=1.0))
                resets = _extract_stat_val(nested, "rxRst") + _extract_stat_val(nested, "txRst")
                for vs_item, ctx in needed_profiles["tcp"][prof_fp]:
                    samples.append(
                        {
                            "category": "tcp",
                            "bigip_host": self.host,
                            "virtual_server": vs_item.full_path,
                            "partition": vs_item.partition,
                            "profile_type": "tcp",
                            "context": ctx,
                            "profile_name": prof_name,
                            "metrics": {
                                "bigip_tcp_segments_out_total": segs,
                                "bigip_tcp_retransmits_total": rxmits,
                                "bigip_tcp_retransmit_rate_pct": round((rxmits / segs) * 100.0, 4),
                                "bigip_tcp_zero_window_events_total": _extract_stat_val(nested, "zeroWnd", "zeroWindow"),
                                "bigip_tcp_sack_ok_total": _extract_stat_val(nested, "sackOk"),
                                "bigip_tcp_rtt_ms": _extract_stat_val(nested, "srtt", default=tmctl_rtt_ms),
                                "bigip_tcp_rtt_variance_ms": _extract_stat_val(nested, "rttvar"),
                                "bigip_tcp_buffer_exhaustion_total": _extract_stat_val(
                                    nested, "sndbufWait", "proxyBufferHighWait", default=tmctl_buf_wait
                                ),
                                "bigip_tcp_embryonic_conns": _extract_stat_val(nested, "open", "synRcvd"),
                                "bigip_tcp_resets_total": resets,
                            },
                        }
                    )

        # 3. UDP Profile Stats (/mgmt/tm/ltm/profile/udp/stats)
        if needed_profiles["udp"]:
            udp_stats_raw = self.request("GET", "/mgmt/tm/ltm/profile/udp/stats")
            for entry in (udp_stats_raw.get("entries") or {}).values():
                nested = (entry.get("nestedStats") or {}).get("entries") or {}
                prof_fp = _extract_stat_str(nested, "tmName")
                if prof_fp not in needed_profiles["udp"]:
                    continue
                _, prof_name = split_full_path(prof_fp)
                dgrams_in = _extract_stat_val(nested, "pktsIn", "datagramsIn")
                drops = _extract_stat_val(nested, "droppedPkts", "drops")
                tot_conns = max(1.0, _extract_stat_val(nested, "totConns", "accepts", default=1.0))
                for vs_item, ctx in needed_profiles["udp"][prof_fp]:
                    samples.append(
                        {
                            "category": "udp",
                            "bigip_host": self.host,
                            "virtual_server": vs_item.full_path,
                            "partition": vs_item.partition,
                            "profile_type": "udp",
                            "context": ctx,
                            "profile_name": prof_name,
                            "metrics": {
                                "bigip_udp_datagrams_in_total": dgrams_in,
                                "bigip_udp_datagrams_out_total": _extract_stat_val(nested, "pktsOut", "datagramsOut"),
                                "bigip_udp_dropped_pkts_total": drops,
                                "bigip_udp_drop_rate_pct": round((drops / max(1.0, dgrams_in)) * 100.0, 4),
                                "bigip_udp_idle_timeouts_total": _extract_stat_val(nested, "timedOut", "idleTimeouts"),
                                "bigip_udp_buffer_overflows_total": _extract_stat_val(
                                    nested, "bufOverflow", "malformedOrOverflow"
                                ),
                                "bigip_udp_datagrams_per_conn": round(dgrams_in / tot_conns, 2),
                            },
                        }
                    )

        # 4. HTTP Profile Stats (/mgmt/tm/ltm/profile/http/stats)
        if needed_profiles["http"]:
            http_stats_raw = self.request("GET", "/mgmt/tm/ltm/profile/http/stats")
            for entry in (http_stats_raw.get("entries") or {}).values():
                nested = (entry.get("nestedStats") or {}).get("entries") or {}
                prof_fp = _extract_stat_str(nested, "tmName")
                if prof_fp not in needed_profiles["http"]:
                    continue
                _, prof_name = split_full_path(prof_fp)
                tot_reqs = _extract_stat_val(nested, "totRequests") or (
                    _extract_stat_val(nested, "getReqs") + _extract_stat_val(nested, "postReqs")
                )
                tot_resps = (
                    _extract_stat_val(nested, "resp_2xx")
                    + _extract_stat_val(nested, "resp_3xx")
                    + _extract_stat_val(nested, "resp_4xx")
                    + _extract_stat_val(nested, "resp_5xx")
                )
                keepalive_conns = max(1.0, _extract_stat_val(nested, "totConn", "serverConns", default=1.0))
                pre_comp = _extract_stat_val(nested, "preCompressBytes", default=1.0)
                post_comp = max(1.0, _extract_stat_val(nested, "postCompressBytes", default=1.0))
                hdr_drops = _extract_stat_val(nested, "maxHeaderSizeExceeded") + _extract_stat_val(
                    nested, "maxHeaderCountExceeded"
                )
                for vs_item, ctx in needed_profiles["http"][prof_fp]:
                    samples.append(
                        {
                            "category": "http",
                            "bigip_host": self.host,
                            "virtual_server": vs_item.full_path,
                            "partition": vs_item.partition,
                            "profile_type": "http",
                            "context": ctx,
                            "profile_name": prof_name,
                            "metrics": {
                                "bigip_http_requests_total": tot_reqs,
                                "bigip_http_responses_total": tot_resps or tot_reqs,
                                "bigip_http_keepalive_reqs_per_conn": round(tot_reqs / keepalive_conns, 2),
                                "bigip_http_pipelined_requests_total": _extract_stat_val(nested, "pipelinedRequests"),
                                "bigip_http_header_size_drops_total": hdr_drops,
                                "bigip_http_compression_ratio": round(pre_comp / post_comp, 2) if pre_comp > 1 else 1.0,
                                "bigip_http_server_closes_total": _extract_stat_val(nested, "svrCloses"),
                            },
                        }
                    )

        self.last_poll_at = now_iso
        return samples

    def _poll_tmctl_tcp_supplement(self) -> tuple[float, float]:
        """Optionally query tmctl tcp_stat/tmm_stat via iControl bash for supplemental stack telemetry."""
        try:
            res = self.request(
                "POST",
                "/mgmt/tm/util/bash",
                json_body={"command": "run", "utilCmdArgs": "-c 'tmctl -c tcp_stat'"},
            )
            csv_out = str(res.get("commandResult") or "").strip().splitlines()
            if len(csv_out) >= 2:
                headers = [h.strip() for h in csv_out[0].split(",")]
                values = [v.strip() for v in csv_out[1].split(",")]
                row = dict(zip(headers, values))
                rtt = float(row.get("srtt", 0.0) or 0.0)
                sndbuf_wait = float(row.get("sndbuf_wait", row.get("mem_drop", 0.0)) or 0.0)
                return rtt, sndbuf_wait
        except Exception as exc:
            logger.debug("Optional tmctl poll failed on %s: %s", self.host, exc)
        return 0.0, 0.0

    # --- Configuration inspection & safe remediation primitives ---
    def get_profile_config(self, protocol: ProtocolType, full_path: str) -> dict[str, Any]:
        if self.demo_mode and self._simulator:
            prof = self._simulator.profiles.get(protocol, {}).get(full_path)
            if not prof:
                raise KeyError(f"Profile {full_path} ({protocol}) not found on {self.host}")
            return copy.deepcopy(prof)

        rest_id = full_path_to_rest_id(full_path)
        return self.request("GET", f"/mgmt/tm/ltm/profile/{protocol}/{rest_id}")

    def profile_exists(self, protocol: ProtocolType, full_path: str) -> bool:
        try:
            self.get_profile_config(protocol, full_path)
            return True
        except Exception:
            return False

    def create_profile(self, protocol: ProtocolType, payload: dict[str, Any]) -> dict[str, Any]:
        if self.demo_mode and self._simulator:
            partition = payload.get("partition", "Common")
            name = payload["name"]
            fp = f"/{partition}/{name}"
            parent_fp = payload.get("defaultsFrom") or f"/Common/{protocol}"
            base = copy.deepcopy(self._simulator.profiles[protocol].get(parent_fp, {}))
            base.update(copy.deepcopy(payload))
            base["fullPath"] = fp
            self._simulator.profiles[protocol][fp] = base
            return copy.deepcopy(base)

        return self.request("POST", f"/mgmt/tm/ltm/profile/{protocol}", json_body=payload)

    def patch_profile(self, protocol: ProtocolType, full_path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if full_path in SYSTEM_DEFAULT_PROFILES:
            raise ValueError(f"Refusing to directly mutate built-in TMOS profile {full_path}")

        if self.demo_mode and self._simulator:
            prof = self._simulator.profiles[protocol].get(full_path)
            if not prof:
                raise KeyError(f"Profile {full_path} not found")
            for k, v in payload.items():
                if isinstance(v, dict) and isinstance(prof.get(k), dict):
                    prof[k].update(v)
                else:
                    prof[k] = copy.deepcopy(v)
            return copy.deepcopy(prof)

        rest_id = full_path_to_rest_id(full_path)
        return self.request("PATCH", f"/mgmt/tm/ltm/profile/{protocol}/{rest_id}", json_body=payload)

    def get_virtual_server_raw_profiles(self, vs_full_path: str) -> list[dict[str, Any]]:
        """Return exact list of profile attachment dicts on a Virtual Server for snapshot/rebind."""
        if self.demo_mode and self._simulator:
            vs = self._simulator.virtual_servers.get(vs_full_path)
            if not vs:
                raise KeyError(f"Virtual Server {vs_full_path} not found")
            return copy.deepcopy(vs["profiles"])

        rest_id = full_path_to_rest_id(vs_full_path)
        data = self.request("GET", f"/mgmt/tm/ltm/virtual/{rest_id}/profiles")
        results: list[dict[str, Any]] = []
        for p in data.get("items", []):
            results.append(
                {
                    "name": p["name"],
                    "partition": p.get("partition", "Common"),
                    "fullPath": p.get("fullPath") or f"/{p.get('partition', 'Common')}/{p['name']}",
                    "context": p.get("context", "all"),
                }
            )
        return results

    def update_virtual_server_profiles(self, vs_full_path: str, profiles: list[dict[str, Any]]) -> dict[str, Any]:
        if self.demo_mode and self._simulator:
            vs = self._simulator.virtual_servers.get(vs_full_path)
            if not vs:
                raise KeyError(f"Virtual Server {vs_full_path} not found")
            vs["profiles"] = copy.deepcopy(profiles)
            return copy.deepcopy(vs)

        rest_id = full_path_to_rest_id(vs_full_path)
        return self.request("PATCH", f"/mgmt/tm/ltm/virtual/{rest_id}", json_body={"profiles": profiles})
