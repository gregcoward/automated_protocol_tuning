"""VictoriaMetrics MetricsQL query client, storage quota manager, and Grafana annotation publisher."""

from __future__ import annotations

import logging
import os
import re
import time
from typing import Any

import httpx

from backend.config import GRAFANA_INTERNAL_URL, VICTORIAMETRICS_DATA_PATH, VICTORIAMETRICS_URL
from backend.models import StorageSettings

logger = logging.getLogger(__name__)


def window_to_seconds(window: str) -> int:
    match = re.match(r"^(\d+)(m|h|d|w)$", window.strip())
    if not match:
        return 86400
    qty = int(match.group(1))
    unit = match.group(2)
    multipliers = {"m": 60, "h": 3600, "d": 86400, "w": 604800}
    return qty * multipliers[unit]


class VictoriaMetricsClient:
    """Queries VictoriaMetrics via MetricsQL and manages TSDB retention/capacity caps."""

    def __init__(
        self,
        base_url: str = VICTORIAMETRICS_URL,
        grafana_internal_url: str = GRAFANA_INTERNAL_URL,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.grafana_internal_url = grafana_internal_url.rstrip("/")

    def is_healthy(self) -> bool:
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"{self.base_url}/health")
                return resp.status_code == 200
        except Exception:
            return False

    def query_instant(self, promql: str) -> list[dict[str, Any]]:
        """Execute an instant PromQL/MetricsQL query and return result vector."""
        try:
            with httpx.Client(timeout=8.0) as client:
                resp = client.get(f"{self.base_url}/api/v1/query", params={"query": promql})
                resp.raise_for_status()
                body = resp.json()
                if body.get("status") == "success":
                    return (body.get("data") or {}).get("result") or []
        except Exception as exc:
            logger.debug("VictoriaMetrics instant query failed (%s): %s", promql, exc)
        return []

    def query_scalar(self, promql: str, default: float | None = None) -> float | None:
        results = self.query_instant(promql)
        if not results:
            return default
        try:
            val = results[0].get("value", [None, None])[1]
            if val is None or str(val).lower() == "nan":
                return default
            return float(val)
        except (IndexError, TypeError, ValueError):
            return default

    def query_range(self, promql: str, start_sec: float, end_sec: float, step: str = "60s") -> list[dict[str, Any]]:
        """Execute a range MetricsQL query for before/after time-series charts."""
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(
                    f"{self.base_url}/api/v1/query_range",
                    params={
                        "query": promql,
                        "start": f"{start_sec:.0f}",
                        "end": f"{end_sec:.0f}",
                        "step": step,
                    },
                )
                resp.raise_for_status()
                body = resp.json()
                if body.get("status") == "success":
                    return (body.get("data") or {}).get("result") or []
        except Exception as exc:
            logger.debug("VictoriaMetrics range query failed (%s): %s", promql, exc)
        return []

    def inspect_storage_usage(self) -> tuple[int, int, bool]:
        """Return (used_bytes, active_series, vm_healthy) from VictoriaMetrics internal metrics."""
        used_bytes = 0
        active_series = 0
        healthy = False
        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.get(f"{self.base_url}/metrics")
                if resp.status_code == 200:
                    healthy = True
                    for line in resp.text.splitlines():
                        if line.startswith("vm_data_size_bytes{"):
                            try:
                                used_bytes += int(float(line.rsplit(" ", 1)[-1]))
                            except ValueError:
                                pass
                        elif line.startswith("vm_cache_entries{type=\"storage/hour_metric_ids\"}"):
                            try:
                                active_series = max(active_series, int(float(line.rsplit(" ", 1)[-1])))
                            except ValueError:
                                pass
        except Exception:
            healthy = False

        # Supplement with filesystem scan if shared data path is mounted locally
        if used_bytes == 0 and VICTORIAMETRICS_DATA_PATH.exists():
            try:
                for root, _, files in os.walk(VICTORIAMETRICS_DATA_PATH):
                    for fn in files:
                        fp = os.path.join(root, fn)
                        if os.path.isfile(fp):
                            used_bytes += os.path.getsize(fp)
            except OSError:
                pass

        return used_bytes, active_series, healthy

    def enforce_storage_limits(
        self,
        settings: StorageSettings,
        active_enrolled_vs: set[str],
        force_prune: bool = False,
    ) -> list[str]:
        """Enforce max storage capacity and prune unenrolled/stale time series in VictoriaMetrics."""
        actions: list[str] = []
        used_bytes, _, healthy = self.inspect_storage_usage()
        if not healthy:
            return actions

        max_bytes = int(settings.max_storage_gb * (1024**3))
        usage_ratio = (used_bytes / max_bytes) if max_bytes > 0 else 0.0

        should_prune = force_prune or (settings.auto_prune_enabled and usage_ratio >= 0.85)
        if not should_prune:
            return actions

        try:
            with httpx.Client(timeout=10.0) as client:
                # 1. Discover all virtual_server label values stored in TSDB and prune unenrolled ones
                lbl_resp = client.get(f"{self.base_url}/api/v1/label/virtual_server/values")
                if lbl_resp.status_code == 200:
                    stored_vs = (lbl_resp.json().get("data") or [])
                    stale_vs = [v for v in stored_vs if active_enrolled_vs and v not in active_enrolled_vs]
                    for vs_fp in stale_vs:
                        del_resp = client.post(
                            f"{self.base_url}/api/v1/admin/tsdb/delete_series",
                            data={"match[]": f'{{virtual_server="{vs_fp}"}}'},
                        )
                        if del_resp.status_code < 300:
                            actions.append(f"Pruned unenrolled Virtual Server series for {vs_fp}")

                # 2. Drop any non-bigip internal scrape clutter if approaching hard cap (>= 95%) or forced
                if usage_ratio >= 0.95 or force_prune:
                    client.post(
                        f"{self.base_url}/api/v1/admin/tsdb/delete_series",
                        data={"match[]": '{__name__!~"bigip_.*"}'},
                    )
                    actions.append(
                        f"Purged non-protocol series (usage {usage_ratio * 100:.1f}% vs cap {settings.max_storage_gb} GB)"
                    )

                # 3. Trigger VictoriaMetrics force_merge to reclaim disk blocks immediately
                merge_resp = client.get(f"{self.base_url}/internal/force_merge")
                if merge_resp.status_code < 300:
                    actions.append("Triggered VictoriaMetrics TSDB compaction (/internal/force_merge)")
        except Exception as exc:
            logger.warning("VictoriaMetrics storage cap enforcement encountered error: %s", exc)

        return actions

    def post_grafana_annotation(
        self,
        *,
        text: str,
        tags: list[str],
        timestamp_ms: int | None = None,
    ) -> bool:
        """Create a Grafana annotation so before/after panels display vertical tuning markers."""
        payload = {
            "time": timestamp_ms or int(time.time() * 1000),
            "tags": tags,
            "text": text,
        }
        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.post(
                    f"{self.grafana_internal_url}/api/annotations",
                    json=payload,
                    auth=("admin", os.environ.get("GF_SECURITY_ADMIN_PASSWORD", "admin")),
                )
                return resp.status_code < 300
        except Exception as exc:
            logger.debug("Grafana HTTP annotation skipped (metric annotation still active): %s", exc)
            return False
