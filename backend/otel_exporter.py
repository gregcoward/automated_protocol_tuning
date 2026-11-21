"""Selective OTLP/HTTP metrics exporter for BIG-IP Virtual Server & protocol telemetry."""

from __future__ import annotations

import collections
import logging
import threading
import time
from typing import Any

import httpx

from backend.config import OTEL_COLLECTOR_OTLP_HTTP_URL

logger = logging.getLogger(__name__)

ALLOWED_METRIC_PREFIXES: tuple[str, ...] = (
    "bigip_vs_",
    "bigip_tcp_",
    "bigip_udp_",
    "bigip_http_",
    "bigip_tuning_",
)


def _otel_kv(key: str, value: str) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": str(value)}}


class OtelMetricsExporter:
    """Pushes strictly filtered BIG-IP protocol telemetry to OpenTelemetry Collector via OTLP/HTTP."""

    def __init__(self, endpoint: str = OTEL_COLLECTOR_OTLP_HTTP_URL) -> None:
        self.endpoint = endpoint
        self._start_time_unix_nano = str(time.time_ns())
        self._lock = threading.RLock()
        self.last_push_ok: bool = False
        self.last_push_error: str | None = None
        self.total_points_exported: int = 0
        # Bounded in-memory ring buffer per (bigip_host, virtual_server) for instant fallback/preview
        self._recent_points: dict[tuple[str, str], collections.deque[dict[str, Any]]] = {}

    def set_endpoint(self, endpoint: str) -> None:
        with self._lock:
            self.endpoint = endpoint.strip()

    def check_health(self) -> bool:
        """Check whether the OTel Collector OTLP HTTP endpoint is reachable."""
        try:
            with httpx.Client(timeout=3.0) as client:
                # Sending an empty OTLP export request returns 200 OK from otel-collector
                resp = client.post(
                    self.endpoint,
                    json={"resourceMetrics": []},
                    headers={"Content-Type": "application/json"},
                )
                ok = resp.status_code < 400
                self.last_push_ok = ok
                return ok
        except Exception as exc:
            self.last_push_ok = False
            self.last_push_error = str(exc)
            return False

    def record_local_buffer(self, samples: list[dict[str, Any]], ts_sec: float) -> None:
        with self._lock:
            for sample in samples:
                key = (sample.get("bigip_host", ""), sample.get("virtual_server", ""))
                buf = self._recent_points.setdefault(key, collections.deque(maxlen=240))
                buf.append({"ts": ts_sec, **sample})

    def get_local_buffer_samples(
        self, bigip_host: str, virtual_server: str, lookback_seconds: float = 86400.0
    ) -> list[dict[str, Any]]:
        cutoff = time.time() - lookback_seconds
        with self._lock:
            buf = self._recent_points.get((bigip_host, virtual_server), collections.deque())
            return [item for item in buf if item.get("ts", 0.0) >= cutoff]

    def export_samples(self, samples: list[dict[str, Any]]) -> bool:
        """Filter to protocol-tuning metrics and push via OTLP/HTTP JSON to otel-collector (:4318)."""
        if not samples:
            return True

        now_ns = str(time.time_ns())
        now_sec = time.time()
        self.record_local_buffer(samples, now_sec)

        grouped_metrics: dict[str, dict[str, Any]] = {}
        point_count = 0

        for sample in samples:
            attrs = [
                _otel_kv("bigip_host", sample.get("bigip_host", "unknown")),
                _otel_kv("virtual_server", sample.get("virtual_server", "unknown")),
                _otel_kv("partition", sample.get("partition", "Common")),
                _otel_kv("profile_type", sample.get("profile_type", "tcp")),
                _otel_kv("context", sample.get("context", "clientside")),
                _otel_kv("profile_name", sample.get("profile_name", "default")),
            ]
            for extra_k in ("action", "change_id", "summary"):
                if extra_k in sample and sample[extra_k] is not None:
                    attrs.append(_otel_kv(extra_k, str(sample[extra_k])))

            for metric_name, raw_val in (sample.get("metrics") or {}).items():
                if not metric_name.startswith(ALLOWED_METRIC_PREFIXES):
                    # Strict guardrail: drop any metric outside Virtual Server & TCP/UDP/HTTP tuning scope
                    continue
                try:
                    val = float(raw_val)
                except (TypeError, ValueError):
                    continue

                is_counter = metric_name.endswith("_total")
                dp: dict[str, Any] = {
                    "attributes": attrs,
                    "timeUnixNano": now_ns,
                    "asDouble": val,
                }
                if is_counter:
                    dp["startTimeUnixNano"] = self._start_time_unix_nano

                entry = grouped_metrics.get(metric_name)
                if not entry:
                    if is_counter:
                        entry = {
                            "name": metric_name,
                            "sum": {
                                "aggregationTemporality": 2,  # AGGREGATION_TEMPORALITY_CUMULATIVE
                                "isMonotonic": True,
                                "dataPoints": [],
                            },
                        }
                    else:
                        entry = {
                            "name": metric_name,
                            "gauge": {
                                "dataPoints": [],
                            },
                        }
                    grouped_metrics[metric_name] = entry

                if is_counter:
                    entry["sum"]["dataPoints"].append(dp)
                else:
                    entry["gauge"]["dataPoints"].append(dp)
                point_count += 1

        if not grouped_metrics:
            return True

        otlp_payload = {
            "resourceMetrics": [
                {
                    "resource": {
                        "attributes": [
                            _otel_kv("service.name", "bigip-protocol-tuner"),
                            _otel_kv("telemetry.scope", "protocol-performance-tuning"),
                        ]
                    },
                    "scopeMetrics": [
                        {
                            "scope": {"name": "bigip.icontrol.protocol_poller", "version": "1.0.0"},
                            "metrics": list(grouped_metrics.values()),
                        }
                    ],
                }
            ]
        }

        try:
            with httpx.Client(timeout=6.0) as client:
                resp = client.post(
                    self.endpoint,
                    json=otlp_payload,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
            with self._lock:
                self.last_push_ok = True
                self.last_push_error = None
                self.total_points_exported += point_count
            return True
        except Exception as exc:
            with self._lock:
                self.last_push_ok = False
                self.last_push_error = str(exc)
            logger.debug("OTLP export to %s failed (buffered locally): %s", self.endpoint, exc)
            return False

    def emit_remediation_event(
        self,
        *,
        bigip_host: str,
        virtual_server: str,
        partition: str,
        protocol: str,
        context: str,
        profile_name: str,
        action: str,
        change_id: str,
        summary: str,
    ) -> bool:
        """Emit a timestamped OTLP gauge metric marking a profile remediation or rollback event."""
        return self.export_samples(
            [
                {
                    "bigip_host": bigip_host,
                    "virtual_server": virtual_server,
                    "partition": partition,
                    "profile_type": protocol,
                    "context": context,
                    "profile_name": profile_name,
                    "action": action,
                    "change_id": change_id,
                    "summary": summary[:160],
                    "metrics": {
                        "bigip_tuning_remediation_event": 1.0,
                        "bigip_tuning_remediation_timestamp_seconds": float(int(time.time())),
                    },
                }
            ]
        )
