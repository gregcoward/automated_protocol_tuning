"""Runtime configuration and persistent paths for BIG-IP Protocol Performance Tuner."""

from __future__ import annotations

import os
from pathlib import Path


APP_NAME = "BIG-IP Protocol Performance Tuner"
APP_SLUG = "bigip-protocol-tuner"

# Default ~/.config/bigip-protocol-tuner locally; /config in containerized/OpenShift environments
DEFAULT_CONFIG_DIR = Path.home() / ".config" / APP_SLUG
CONFIG_DIR = Path(os.environ.get("TUNER_CONFIG_DIR", str(DEFAULT_CONFIG_DIR)))

SESSIONS_FILE = CONFIG_DIR / "sessions.json"
KEY_FILE = CONFIG_DIR / "sessions.key"
STATE_FILE = CONFIG_DIR / "tuner_state.json"
VM_RUNTIME_ENV_FILE = CONFIG_DIR / "vm-runtime.env"

# Downstream service URLs (override via environment variables in Compose / K8s / OpenShift)
OTEL_COLLECTOR_OTLP_HTTP_URL = os.environ.get(
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
    os.environ.get("OTEL_COLLECTOR_URL", "http://localhost:4318/v1/metrics"),
)
VICTORIAMETRICS_URL = os.environ.get("VICTORIAMETRICS_URL", "http://localhost:8428").rstrip("/")
VICTORIAMETRICS_DATA_PATH = Path(os.environ.get("VICTORIAMETRICS_DATA_PATH", "/victoria-metrics-data"))

GRAFANA_INTERNAL_URL = os.environ.get("GRAFANA_INTERNAL_URL", "http://localhost:3000").rstrip("/")
GRAFANA_EXTERNAL_URL = os.environ.get("GRAFANA_EXTERNAL_URL", "http://localhost:3000").rstrip("/")
GRAFANA_DASHBOARD_UID = os.environ.get("GRAFANA_DASHBOARD_UID", "bigip-protocol-tuning")

# Default storage and telemetry settings
DEFAULT_RETENTION_PERIOD = os.environ.get("VM_RETENTION_PERIOD", "30d")
DEFAULT_MAX_STORAGE_GB = float(os.environ.get("VM_MAX_STORAGE_GB", "10.0"))
DEFAULT_POLL_INTERVAL_SECONDS = int(os.environ.get("TELEMETRY_POLL_INTERVAL_SECONDS", "30"))
DEFAULT_DEDUP_MIN_SCRAPE_INTERVAL = os.environ.get("VM_DEDUP_INTERVAL", "15s")

# Frontend static build directory (served from same origin when built)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIST_DIR = PROJECT_ROOT / "frontend" / "dist"


def ensure_config_dir() -> Path:
    """Create configuration directory with safe permissions (supporting OpenShift arbitrary UIDs)."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        # Preserve group write if running under OpenShift arbitrary UID in root group (GID 0)
        if os.environ.get("OPENSHIFT_BUILD_NAMESPACE") or os.getgid() == 0:
            os.chmod(CONFIG_DIR, 0o770)
        else:
            os.chmod(CONFIG_DIR, 0o700)
    except OSError:
        pass
    return CONFIG_DIR
