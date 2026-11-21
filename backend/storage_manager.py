"""Background storage manager: enforces VictoriaMetrics retention period and disk quota."""

from __future__ import annotations

import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from backend.session_store import SessionStore

from backend.config import VICTORIAMETRICS_DATA_PATH, VICTORIAMETRICS_URL

logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_victoriametrics_disk_usage(data_path: Path = VICTORIAMETRICS_DATA_PATH) -> tuple[int, bool]:
    """Return (used_bytes, path_exists). Reads from /victoria-metrics-data or env-override."""
    if data_path.exists():
        try:
            total_size = sum(f.stat().st_size for f in data_path.rglob("*") if f.is_file())
            return total_size, True
        except (OSError, PermissionError) as exc:
            logger.debug("Could not stat VM data path %s: %s", data_path, exc)
    # Fallback: query VM metrics API for storage stats
    try:
        r = httpx.get(f"{VICTORIAMETRICS_URL}/metrics", timeout=4.0)
        if r.status_code == 200:
            for line in r.text.splitlines():
                if line.startswith("vm_data_size_bytes ") and not line.startswith("#"):
                    val = float(line.split()[-1])
                    return int(val), False
    except Exception:
        pass
    return 0, False


def enforce_storage_limits(store: "SessionStore") -> list[str]:
    """Check disk usage vs configured max and attempt pruning if near/over capacity."""
    settings = store.get_storage_settings()
    max_bytes = int(settings.max_storage_gb * 1024 * 1024 * 1024)
    used_bytes, _ = get_victoriametrics_disk_usage()
    actions: list[str] = []

    if max_bytes <= 0 or used_bytes <= 0:
        return actions

    utilization = used_bytes / max_bytes
    used_mb = used_bytes / (1024 * 1024)

    logger.debug(
        "Storage check: %.1f MB used / %.1f GB max (%.1f%%)",
        used_mb,
        settings.max_storage_gb,
        utilization * 100,
    )

    if utilization >= 0.90:
        action_msg = (
            f"Storage at {utilization * 100:.1f}% ({used_mb:.0f} MB / {settings.max_storage_gb:.1f} GB). "
            f"Attempting series pruning."
        )
        logger.warning(action_msg)
        actions.append(action_msg)

        # Request a full forced merge/prune from VictoriaMetrics to reclaim stale data
        try:
            r = httpx.post(
                f"{VICTORIAMETRICS_URL}/internal/force_merge",
                params={"partition_prefix": ""},
                timeout=30.0,
            )
            if r.status_code in (200, 204):
                actions.append("Triggered VictoriaMetrics force merge for storage reclaim.")
        except Exception as exc:
            logger.debug("VM force merge request failed: %s", exc)

    if utilization >= 0.95 and settings.auto_prune_enabled:
        # Shorten retention by 25% to protect storage cap
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
