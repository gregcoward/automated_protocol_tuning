# BIG-IP Protocol Performance Tuner

A complete, modular, containerized application that continuously monitors F5 BIG-IP Virtual Server traffic patterns, analyzes TCP/UDP/HTTP profile configurations against F5 best practices, and delivers one-click (or fully autonomous) protocol tuning with before/after performance visualization.

---

## Architecture

```
BIG-IP(s)
   │  iControl REST (periodic poll + on-demand)
   ▼
Backend (FastAPI + APScheduler)  ◄─── React SPA (port 8000)
   │  OTLP/HTTP metrics push
   ▼
OTel Collector (port 4318)
   │  PrometheusRemoteWrite (filtered: bigip_* only)
   ▼
VictoriaMetrics (port 8428)   ◄─── MetricsQL queries (Protocol Analyzer)
   ▼
Grafana (port 3000)           ◄─── Embedded panels in React UI
```

**Services**
| Service | Image | Purpose |
|---|---|---|
| `backend` | `bigip-protocol-tuner:latest` | FastAPI + React SPA, iControl REST client, optimizer, scheduler |
| `otel-collector` | `otel/opentelemetry-collector-contrib:0.112.0` | Receives OTLP, filters to `bigip_*` metrics, writes to VM |
| `victoriametrics` | `victoriametrics/victoria-metrics:v1.106.1` | Time-series storage (default 30d retention, 10 GB cap) |
| `grafana` | `grafana/grafana:11.4.0` | Pre-provisioned dashboards with remediation annotations |

---

## Quick Start — Docker Compose

### Prerequisites
- Docker Engine 24+ and Docker Compose v2
- Python 3.11+ (for local dev without Docker)
- Node.js 20+ (for frontend dev)

```bash
# 1. Clone
git clone https://github.com/gregcoward/automated_protocol_tuning.git
cd automated_protocol_tuning

# 2. Configure
cp .env.example .env
# Edit .env to set GRAFANA_EXTERNAL_URL, GF_SECURITY_ADMIN_PASSWORD, etc.

# 3. Launch
docker compose up -d --build

# 4. Access
open http://localhost:8000       # React UI + API
open http://localhost:3000       # Grafana (admin/admin by default)
open http://localhost:8000/api/docs  # FastAPI Swagger
```

### Services after `docker compose up`:
- **Tuner UI**: http://localhost:8000
- **Grafana**: http://localhost:3000 (admin / `GF_SECURITY_ADMIN_PASSWORD`)
- **VictoriaMetrics**: http://localhost:8428
- **OTLP Collector**: http://localhost:4318

---

## Local Development

```bash
# Backend
pip install -r requirements.txt
export TUNER_CONFIG_DIR=~/.config/bigip-protocol-tuner
export OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://localhost:4318/v1/metrics
export VICTORIAMETRICS_URL=http://localhost:8428
python run_server.py        # Serves on :8001

# Frontend (separate terminal)
cd frontend
npm install
npm run dev                 # Vite dev server on :5173, proxies /api → :8001
```

---

## UI Overview

### 1. Status Bar (always visible)
- Connected BIG-IP chips with device label, VS count, and live/disconnected status
- Storage utilization badge (MB used / GB cap, retention period)
- VictoriaMetrics health indicator
- Dark/Light theme toggle

### 2. Devices
- Register BIG-IP devices (host, port, credentials, label, demo mode, SSL toggle)
- Credentials encrypted at rest with Fernet; auth tokens kept in-memory only
- Virtual Server discovery with attached profile inventory
- Per-VS enrollment checkboxes for monitoring and tuning

### 3. Analysis & Remediation Studio
- Select target BIG-IP(s), protocols (TCP/UDP/HTTP), and historical time window (1h–30d)
- **Run Analysis** queries VictoriaMetrics MetricsQL + live iControl REST profile configs
- Side-by-side **diff view** (Current vs Recommended) with supporting metric evidence
- F5 KB article citations with direct links per recommendation
- **Apply** individual or **Apply All** recommendations with optional operator note
- Automatically creates child profiles instead of mutating system default profiles (e.g. `/Common/tcp`)

### 4. Remediations
- Full history of applied changes with rollback capability
- Shows before/after profile paths, parameter map, and status (applied/rolled_back/failed)

### 5. Automated Tuning Scheduler
- Create interval (e.g. every 6h) or cron-based schedules
- **Recommend Only** mode: logs findings to audit trail without touching BIG-IP
- **Auto-Remediate** mode: applies changes meeting the minimum confidence threshold
- Audit trail with per-run recommendation and application counts

### 6. Before/After Performance Dashboard
- Embedded Grafana panels showing all key metrics with **remediation event annotation markers**
- BIG-IP host and Virtual Server filter dropdowns
- Time range selector (1h, 6h, 24h, 7d, 30d)

### 7. Settings
- Live storage utilization bar (used MB / max GB)
- Configure retention period, max storage cap, poll interval, dedup interval
- OTLP endpoint and Grafana external URL overrides
- Auto-prune toggle (shortens retention by 25% when utilization ≥ 95%)

---

## Protocol Knowledge Base

### TCP Profiles (10 F5 KB entries)
| Trigger | Recommendation | KB |
|---|---|---|
| Legacy `/Common/tcp` with >25 Mbps or >25 ms RTT | Inherit from `f5-tcp-wan` / `f5-tcp-lan` | K75593415 |
| Retransmit >2% + RTT >30 ms or variance >10 ms | Switch congestionControl to `bbr` | K02412420 |
| Buffer waits > 0 or BDP > 80% sendBufferSize | Scale sendBufferSize, proxyBufferHigh/Low | K3422 |
| Avg packet < 680 B + nagle=enabled | Disable/progressive Nagle, enable TFO | K15812 |
| idleTimeout > 600s + >2000 active conns | Reduce idleTimeout to 300s | K7606 |

### UDP Profiles
| Trigger | Recommendation | KB |
|---|---|---|
| ≥250 datagrams/conn or >0.5% drop or buf overflow | Enable datagramLoadBalancing | K3605 |
| ≥8000 ephemeral conns + idleTimeout > 30s | Reduce idleTimeout to 15s | K3667 |

### HTTP Profiles
| Trigger | Recommendation | KB |
|---|---|---|
| maxRequests < 250 or low keep-alive reuse + oneconnect disabled | Raise maxRequests, enable oneconnectTransformations | K7208 |
| HTTP header drops > 0 | Increase enforcement.maxHeaderSize to 65536 | K13525 |
| pipelining enabled | Disable pipelining (HoL blocking) | K7208 |

---

## Kubernetes Deployment

### Local / Kind / Minikube

```bash
# Build image (ensure it's accessible to your cluster)
export REGISTRY=localhost:5000
bash scripts/k8s-build-image.sh

# Deploy with local overlay
kubectl apply -k k8s/overlays/local

# Access
kubectl port-forward svc/backend 8000:8000 -n bigip-tuner
kubectl port-forward svc/grafana 3000:3000 -n bigip-tuner
```

### Production Kubernetes

```bash
export REGISTRY=registry.example.com
export TAG=v1.0.0
bash scripts/k8s-build-image.sh
bash scripts/k8s-deploy.sh local   # or: minimal
```

---

## Red Hat OpenShift Deployment

```bash
# Log in
oc login https://api.cluster.example.com:6443

# Edit route hostnames in k8s/overlays/openshift/route-*.yaml
# Edit configMapGenerator GRAFANA_EXTERNAL_URL in k8s/overlays/openshift/kustomization.yaml

export NAMESPACE=bigip-tuner
export REGISTRY=image-registry.openshift-image-registry.svc:5000
bash scripts/oc-deploy.sh
```

**OpenShift security notes:**
- All deployments drop `runAsUser` — OCP assigns arbitrary UIDs from the project range
- `/config` volume uses `fsGroup: 0` (root group) so the arbitrary UID can write; `chmod 770` is set by the backend at startup
- Uses `anyuid` SCC for Grafana (UID 472) and VictoriaMetrics — adjust to `nonroot-v2` on restricted clusters by removing the Grafana/VM user/group patches

---

## Security

| Concern | Mitigation |
|---|---|
| Stored credentials | Fernet symmetric encryption (`~/.config/bigip-protocol-tuner/sessions.key` or `BIGIP_SESSION_ENCRYPTION_KEY` env); `chmod 0600` |
| Auth tokens | Never persisted to disk; in-memory only per `BigIpClient` instance |
| System default profiles | `SYSTEM_DEFAULT_PROFILES` guard prevents direct mutation of `/Common/tcp` etc.; child profiles created instead |
| Rollback safety | Pre-remediation snapshot stored before any `PATCH`; one-click rollback available |
| Metric privacy | OTLP filter restricts to `bigip_(vs|tcp|udp|http|tuning)_*` metrics only |

---

## Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `TUNER_CONFIG_DIR` | `~/.config/bigip-protocol-tuner` | Persistent config dir (sessions.json, key, state) |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | `http://localhost:4318/v1/metrics` | OTLP collector HTTP endpoint |
| `VICTORIAMETRICS_URL` | `http://localhost:8428` | VictoriaMetrics base URL |
| `GRAFANA_INTERNAL_URL` | `http://localhost:3000` | Grafana URL for annotation API calls (container-internal) |
| `GRAFANA_EXTERNAL_URL` | `http://localhost:3000` | Grafana URL served to browser for iframe embeds |
| `VM_RETENTION_PERIOD` | `30d` | Default retention; operator-configurable in Settings |
| `VM_MAX_STORAGE_GB` | `10.0` | Soft storage cap enforced every 15 min |
| `TELEMETRY_POLL_INTERVAL_SECONDS` | `30` | BIG-IP iControl REST poll frequency |
| `BIGIP_SESSION_ENCRYPTION_KEY` | _(auto-generated)_ | Base64-URL Fernet key for session password encryption |
| `PORT` | `8001` local / `8000` container | FastAPI listen port |
| `LOG_LEVEL` | `INFO` | Python logging level |

---

## Project Layout

```
automated_protocol_tuning/
├── backend/
│   ├── __init__.py
│   ├── bigip_client.py        # iControl REST client, VS discovery, profile polling
│   ├── config.py              # Env-driven paths and defaults
│   ├── models.py              # Pydantic v2 request/response models
│   ├── otel_exporter.py       # OTLP/HTTP metric push + ring buffer
│   ├── session_store.py       # Fernet-encrypted sessions, state persistence
│   ├── storage_manager.py     # Disk usage enforcement, VM pruning
│   ├── vm_client.py           # VictoriaMetrics MetricsQL client
│   └── optimizer/
│       ├── __init__.py
│       ├── analyzer.py        # Traffic analyzer + recommendation engine
│       └── knowledge_base.py  # F5 KB rules (10 entries, TCP/UDP/HTTP)
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx            # Root component, nav, theme
│       ├── index.css          # F5-themed design system (dark/light)
│       ├── main.jsx
│       ├── api/client.js      # Typed fetch wrappers for all API endpoints
│       ├── components/
│       │   └── StatusBar.jsx  # Top status bar (device chips, storage, theme)
│       ├── hooks/useApi.js    # useAsync loading/error hook
│       └── pages/
│           ├── Devices.jsx    # BIG-IP registration + VS enrollment
│           ├── Analysis.jsx   # On-the-fly analysis + remediation studio
│           ├── Remediations.jsx  # History + rollback table
│           ├── Schedules.jsx  # APScheduler CRUD + audit trail
│           ├── Dashboard.jsx  # Embedded Grafana before/after panels
│           └── Settings.jsx   # Storage / telemetry configuration
├── otel-collector/
│   └── config.yaml            # OTLP receiver, protocol filter, VM RemoteWrite
├── victoriametrics/
│   └── entrypoint-wrapper.sh  # Runtime env loader (retention, dedup flags)
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/victoriametrics.yaml
│   │   └── dashboards/provider.yaml
│   └── dashboards/
│       └── bigip-before-after-tuning.json  # 10-panel dashboard with annotations
├── k8s/
│   ├── base/                  # Namespace, PVCs, Deployments, Services, ConfigMaps
│   └── overlays/
│       ├── local/             # Local cluster (imagePullPolicy: Never)
│       ├── minimal/           # Grafana scaled to 0 for resource-constrained clusters
│       └── openshift/         # Drop runAsUser, fsGroup 0, Route manifests
├── scripts/
│   ├── k8s-build-image.sh     # Build + push to registry
│   ├── k8s-deploy.sh          # kubectl apply -k with rollout wait
│   └── oc-deploy.sh           # OpenShift: new-project, SCC, build, apply
├── Dockerfile                 # Multi-stage: Node build → Python runtime
├── docker-compose.yml         # 4-service stack (backend, otel, vm, grafana)
├── .env.example               # All configurable env vars with defaults
├── requirements.txt
└── README.md
```

---

## License

MIT — see [LICENSE](LICENSE).
