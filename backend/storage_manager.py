"""Background storage manager: enforces VictoriaMetrics retention period and disk quota."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from backend.session_store import SessionStore
    from backend.vm_client import VictoriaMetricsClient

from backend.config import VICTORIAMETRICS_DATA_PATH, VICTORIAMETRICS_URL

logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_victoriametrics_disk_usage(data_path: Path = VICTORIAMETRICS_DATA_PATH) -> tuple[int, bool]:
    """Return (used_bytes, path_exists). Reads from /victoria-metrics-data or VictoriaMetrics /metrics."""
    if data_path.exists():
        try:
            total_size = sum(f.stat().st_size for f in data_path.rglob("*") if f.is_file())
            if total_size > 0:
                return total_size, True
        except (OSError, PermissionError) as exc:
            logger.debug("Could not stat VM data path %s: %s", data_path, exc)

    # Fallback: query VM /metrics API (handles labeled vm_data_size_bytes{type=...} lines)
    try:
        r = httpx.get(f"{VICTORIAMETRICS_URL}/metrics", timeout=4.0)
        if r.status_code == 200:
            total = 0
            found = False
            for line in r.text.splitlines():
                if (line.startswith("vm_data_size_bytes{") or line.startswith("vm_data_size_bytes ")) and not line.startswith("#"):
                    try:
                        total += int(float(line.rsplit(" ", 1)[-1]))
                        found = True
                    except ValueError:
                        pass
            if found:
                return total, False
    except Exception:
        pass
    return 0, False


def enforce_storage_limits(
    store: "SessionStore",
    vm_client: "VictoriaMetricsClient | None" = None,
) -> list[str]:
    """Check disk usage vs configured max and attempt pruning if near/over capacity."""
    settings = store.get_storage_settings()
    max_bytes = int(settings.max_storage_gb * 1024 * 1024 * 1024)
    used_bytes, _ = get_victoriametrics_disk_usage()
    actions: list[str] = []

    if vm_client is not None:
        enrolled_union: set[str] = set()
        for rec in store.list_sessions():
            enrolled_union.update(store.get_enrolled_vs(rec["id"]) or [])
        actions.extend(vm_client.enforce_storage_limits(settings, enrolled_union))

    if max_bytes <= 0 or used_bytes <= 0:
        if actions:
            store.record_storage_enforcement(actions)
        return actions

    utilization = used_bytes / max_bytes
    used_mb = used_bytes / (1024 * 1024)

    logger.debug(
        "Storage check: %.1f MB used / %.1f GB max (%.1f%%)",
        used_mb,
        settings.max_storage_gb,
        utilization * 100,
    )

    if utilization >= 0.90 and vm_client is None:
        action_msg = (
            f"Storage at {utilization * 100:.1f}% ({used_mb:.0f} MB / {settings.max_storage_gb:.1f} GB). "
            f"Attempting series pruning."
        )
        logger.warning(action_msg)
        actions.append(action_msg)

        try:
            r = httpx.get(
                f"{VICTORIAMETRICS_URL}/internal/force_merge",
                timeout=30.0,
            )
            if r.status_code in (200, 204):
                actions.append("Triggered VictoriaMetrics force merge for storage reclaim.")
        except Exception as exc:
            logger.debug("VM force merge request failed: %s", exc)

    if utilization >= 0.95 and settings.auto_prune_enabled:
        current_days = _parse_retention_days(settings.retention_period)
        new_days = max(7, int(current_days * 0.75))
        if new_days < current_days:
            new_period = f"{new_days}d"
            msg = (
                f"Auto-pruned retention period from {settings.retention_period} to {new_period} "
                f"(storage at {utilization * 100:.1f}%)."
            )
            logger.warning(msg)
            actions.append(msg)
            settings.retention_period = new_period
            store.update_storage_settings(settings)

    if actions:
        store.record_storage_enforcement(actions)

    return actions


def _parse_retention_days(period: str) -> int:
    """Convert retention period string like '30d', '4w', '2m' to days."""
    if period.endswith("d"):
        return int(period[:-1])
    if period.endswith("w"):
        return int(period[:-1]) * 7
    if period.endswith("m"):
        return int(period[:-1]) * 30
    if period.endswith("y"):
        return int(period[:-1]) * 365
    return 30
