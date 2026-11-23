# BIG-IP Protocol Performance Tuner

A complete, modular, containerized application that continuously monitors F5 BIG-IP Virtual Server
traffic patterns, analyzes TCP/UDP/HTTP profile configurations against F5 best practices, and
delivers one-click (or fully autonomous) protocol tuning with before/after performance visualization.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Quick Start — Docker Compose](#quick-start--docker-compose)
3. [Local Development](#local-development)
4. [Building & Publishing to Docker Hub](#building--publishing-to-docker-hub)
   - [Prerequisites](#prerequisites)
   - [Log in to Docker Hub](#1-log-in-to-docker-hub)
   - [Build the image](#2-build-the-image)
   - [Push to Docker Hub](#3-push-to-docker-hub)
   - [Multi-arch buildx](#4-multi-arch-build-with-buildx-optional)
   - [Use the published image in Compose](#5-use-the-published-image-in-docker-compose)
   - [Automate with GitHub Actions](#6-automate-with-github-actions)
5. [Kubernetes Deployment — Step by Step](#kubernetes-deployment--step-by-step)
   - [Prerequisites](#prerequisites-1)
   - [Step 1 — Build and push the image](#step-1--build-and-push-the-image)
   - [Step 2 — Verify cluster context](#step-2--verify-cluster-context)
   - [Step 3 — Provision Grafana ConfigMaps](#step-3--provision-grafana-configmaps)
   - [Step 4 — Create secrets](#step-4--create-secrets)
   - [Step 5 — Update the image reference](#step-5--update-the-image-reference)
   - [Step 6 — Deploy with Kustomize](#step-6--deploy-with-kustomize)
   - [Step 7 — Verify rollouts](#step-7--verify-rollouts)
   - [Step 8 — Access the application](#step-8--access-the-application)
   - [Step 9 — Day-2 operations](#step-9--day-2-operations)
6. [Red Hat OpenShift Deployment](#red-hat-openshift-deployment)
7. [UI Overview](#ui-overview)
8. [Protocol Knowledge Base](#protocol-knowledge-base)
9. [Security](#security)
10. [Configuration Reference](#configuration-reference)
11. [Project Layout](#project-layout)

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
# Edit .env — at minimum set GF_SECURITY_ADMIN_PASSWORD

# 3. Launch
docker compose up -d --build

# 4. Access
open http://localhost:8010        # React UI + API
open http://localhost:3010        # Grafana  (admin / value from .env)
open http://localhost:8010/api/docs   # FastAPI Swagger
```

**Default host port mapping** (shifted +10 to coexist with BIG-IP Telemetry Exporter on the same host):

| Service | Host port | Container port |
|---|---|---|
| Tuner UI / API | **8010** | 8000 |
| Grafana | **3010** | 3000 |
| VictoriaMetrics | **8438** | 8428 |
| OTLP HTTP | **4328** | 4318 |

> To use the standard ports, edit the left side of each `ports:` mapping in `docker-compose.yml`.

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

## Building & Publishing to Docker Hub

### Prerequisites

- Docker Engine 24+
- A Docker Hub account — sign up free at [hub.docker.com](https://hub.docker.com)
- `docker login` completed on your workstation

### 1. Log in to Docker Hub

```bash
docker login
# Enter your Docker Hub username and password or access token
```

Using a personal access token (recommended — generate one at
hub.docker.com → Account Settings → Security → New Access Token):

```bash
docker login -u <your-dockerhub-username>
# Paste your personal access token when prompted
```

### 2. Build the image

The `Dockerfile` uses a multi-stage build: Node 20 compiles the React frontend, then a
Python 3.12-slim runtime bundles everything into a single image.

```bash
# Set your Docker Hub username and desired version tag
export DOCKER_USER=<your-dockerhub-username>
export TAG=1.0.0

# Build from the repository root
docker build \
  --platform linux/amd64 \
  -t ${DOCKER_USER}/bigip-protocol-tuner:latest \
  -t ${DOCKER_USER}/bigip-protocol-tuner:${TAG} \
  .
```

> **Apple Silicon note:** if you are on an M-series Mac and targeting AMD64 clusters, the
> `--platform linux/amd64` flag cross-compiles correctly via QEMU emulation.
> For a native multi-arch manifest that works on both architectures, use `docker buildx` (Step 4).

Verify the image:

```bash
docker images | grep bigip-protocol-tuner

# Smoke-test: check Python imports start cleanly
docker run --rm \
  ${DOCKER_USER}/bigip-protocol-tuner:${TAG} \
  python -c "from backend.optimizer.analyzer import ProtocolAnalyzer; print('OK')"
```

### 3. Push to Docker Hub

```bash
docker push ${DOCKER_USER}/bigip-protocol-tuner:latest
docker push ${DOCKER_USER}/bigip-protocol-tuner:${TAG}
```

After pushing the image is publicly accessible at:
`https://hub.docker.com/r/<your-dockerhub-username>/bigip-protocol-tuner`

### 4. Multi-arch build with buildx (optional)

```bash
# One-time setup: create a builder that supports cross-compilation
docker buildx create --name tuner-builder --use --bootstrap

# Build and push amd64 + arm64 in a single manifest (no separate push needed)
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ${DOCKER_USER}/bigip-protocol-tuner:latest \
  -t ${DOCKER_USER}/bigip-protocol-tuner:${TAG} \
  --push \
  .
```

### 5. Use the published image in Docker Compose

Edit `docker-compose.yml`: replace the `build:` block in the `backend` service with the
published image reference so Docker pulls from Hub instead of building locally.

```yaml
  backend:
    image: <your-dockerhub-username>/bigip-protocol-tuner:1.0.0
    # build:           ← remove or comment out these lines
    #   context: .
    #   dockerfile: Dockerfile
```

Then run:

```bash
docker compose pull backend
docker compose up -d
```

### 6. Automate with GitHub Actions

Create `.github/workflows/docker-publish.yml` in your fork:

```yaml
name: Build and push to Docker Hub

on:
  push:
    tags: ["v*.*.*"]

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Docker Hub
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}

      - name: Build and push
        uses: docker/build-push-action@v6
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          tags: |
            ${{ secrets.DOCKERHUB_USERNAME }}/bigip-protocol-tuner:latest
            ${{ secrets.DOCKERHUB_USERNAME }}/bigip-protocol-tuner:${{ github.ref_name }}
```

Add `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` as repository secrets under
**GitHub → Settings → Secrets and variables → Actions**.

---

## Kubernetes Deployment — Step by Step

The Kubernetes manifests use **Kustomize** (built into `kubectl` v1.14+).
Three overlays are provided:

| Overlay | Use case |
|---|---|
| `k8s/overlays/local` | Kind, Minikube, Docker Desktop — `imagePullPolicy: Never`, inline secrets |
| `k8s/overlays/minimal` | Resource-constrained clusters — Grafana scaled to 0 |
| `k8s/overlays/openshift` | Red Hat OpenShift — arbitrary UIDs, `fsGroup: 0`, Route manifests |

### Prerequisites

- `kubectl` v1.25+ with Kustomize built in
- A running cluster (EKS, GKE, AKS, Kind, Minikube, etc.)
- `kubectl` context pointing at your target cluster:
  ```bash
  kubectl config current-context
  ```
- The image published to Docker Hub (see [Building & Publishing to Docker Hub](#building--publishing-to-docker-hub))
- A default StorageClass that provisions PVCs dynamically, or three pre-created PersistentVolumes

**Minimum cluster resources across all pods:**

| Pod | CPU request | Memory request |
|---|---|---|
| backend | 250m | 256 Mi |
| otel-collector | 100m | 128 Mi |
| victoriametrics | 250m | 512 Mi |
| grafana | 100m | 256 Mi |
| **Total** | **700m** | **~1.2 Gi** |

---

### Step 1 — Build and push the image

```bash
export DOCKER_USER=<your-dockerhub-username>
export TAG=1.0.0

docker build --platform linux/amd64 \
  -t ${DOCKER_USER}/bigip-protocol-tuner:${TAG} \
  -t ${DOCKER_USER}/bigip-protocol-tuner:latest .

docker push ${DOCKER_USER}/bigip-protocol-tuner:${TAG}
docker push ${DOCKER_USER}/bigip-protocol-tuner:latest
```

---

### Step 2 — Verify cluster context

```bash
kubectl config current-context
kubectl get nodes -o wide
kubectl version --short
```

Ensure the cluster has a default StorageClass:

```bash
kubectl get storageclass
# Look for one marked (default)
```

---

### Step 3 — Provision Grafana ConfigMaps

The Grafana container mounts datasource and dashboard provisioning files from ConfigMaps.
Run these from the repository root:

```bash
# Create the namespace first
kubectl create namespace bigip-tuner --dry-run=client -o yaml | kubectl apply -f -

# Grafana provisioning files (datasource + dashboard provider config)
kubectl create configmap grafana-provisioning \
  --from-file=datasources/victoriametrics.yaml=grafana/provisioning/datasources/victoriametrics.yaml \
  --from-file=dashboards/provider.yaml=grafana/provisioning/dashboards/provider.yaml \
  -n bigip-tuner \
  --dry-run=client -o yaml | kubectl apply -f -

# Pre-built dashboard JSON
kubectl create configmap grafana-dashboards \
  --from-file=bigip-before-after-tuning.json=grafana/dashboards/bigip-before-after-tuning.json \
  -n bigip-tuner \
  --dry-run=client -o yaml | kubectl apply -f -

# Verify
kubectl get configmap -n bigip-tuner
```

---

### Step 4 — Create secrets

```bash
# Grafana admin password (change the value)
kubectl create secret generic tuner-secrets \
  --from-literal=GF_SECURITY_ADMIN_PASSWORD='changeme_strong_password' \
  -n bigip-tuner \
  --dry-run=client -o yaml | kubectl apply -f -
```

Optionally supply a persistent Fernet encryption key so session credentials survive pod
restarts. Generate one with:

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Then include it in the secret:

```bash
kubectl create secret generic tuner-secrets \
  --from-literal=GF_SECURITY_ADMIN_PASSWORD='changeme_strong_password' \
  --from-literal=BIGIP_SESSION_ENCRYPTION_KEY='<output-from-command-above>' \
  -n bigip-tuner \
  --dry-run=client -o yaml | kubectl apply -f -
```

---

### Step 5 — Update the image reference

Edit `k8s/base/deployment-backend.yaml` and replace the placeholder with your Docker Hub image:

```bash
# macOS
sed -i '' \
  "s|image: bigip-protocol-tuner:latest|image: ${DOCKER_USER}/bigip-protocol-tuner:${TAG}|g" \
  k8s/base/deployment-backend.yaml

# Linux
sed -i \
  "s|image: bigip-protocol-tuner:latest|image: ${DOCKER_USER}/bigip-protocol-tuner:${TAG}|g" \
  k8s/base/deployment-backend.yaml

# Confirm
grep "image:" k8s/base/deployment-backend.yaml
```

**Alternative — Kustomize images transformer** (keeps the base manifest untouched):

Add an `images:` block to your overlay's `kustomization.yaml`:

```yaml
# k8s/overlays/local/kustomization.yaml
images:
  - name: bigip-protocol-tuner
    newName: <your-dockerhub-username>/bigip-protocol-tuner
    newTag: "1.0.0"
```

---

### Step 6 — Deploy with Kustomize

Preview what will be applied before committing:

```bash
kubectl apply -k k8s/overlays/local --dry-run=client
```

Apply:

```bash
kubectl apply -k k8s/overlays/local
```

This creates in the `bigip-tuner` namespace:

- 1 Namespace
- 3 PersistentVolumeClaims (`tuner-config-pvc` 100 Mi, `vm-data-pvc` 20 Gi, `grafana-data-pvc` 1 Gi)
- 1 ConfigMap for OTel Collector config
- 4 Deployments (`bigip-tuner-backend`, `otel-collector`, `victoriametrics`, `grafana`)
- 4 Services (`backend`, `otel-collector`, `victoriametrics`, `grafana`)

---

### Step 7 — Verify rollouts

Watch pods appear:

```bash
kubectl get pods -n bigip-tuner -w
# Ctrl-C once all show Running
```

Wait for each deployment to report `successfully rolled out`:

```bash
kubectl rollout status deployment/bigip-tuner-backend   -n bigip-tuner --timeout=180s
kubectl rollout status deployment/victoriametrics        -n bigip-tuner --timeout=180s
kubectl rollout status deployment/otel-collector         -n bigip-tuner --timeout=120s
kubectl rollout status deployment/grafana                -n bigip-tuner --timeout=120s
```

Confirm PVCs are bound:

```bash
kubectl get pvc -n bigip-tuner
# All three should show STATUS=Bound
```

Check logs if any pod is not reaching `Running`:

```bash
kubectl logs -n bigip-tuner deployment/bigip-tuner-backend --tail=40
kubectl logs -n bigip-tuner deployment/victoriametrics --tail=20
kubectl logs -n bigip-tuner deployment/otel-collector --tail=20
kubectl logs -n bigip-tuner deployment/grafana --tail=20

# Describe a stuck pod for events
kubectl describe pod -n bigip-tuner -l app=bigip-tuner-backend
```

---

### Step 8 — Access the application

#### Option A — Port-forward (development / quick access)

```bash
# Tuner UI + API  →  http://localhost:8000
kubectl port-forward svc/backend 8000:8000 -n bigip-tuner &

# Grafana         →  http://localhost:3000
kubectl port-forward svc/grafana 3000:3000 -n bigip-tuner &

# VictoriaMetrics →  http://localhost:8428  (optional direct queries)
kubectl port-forward svc/victoriametrics 8428:8428 -n bigip-tuner &
```

Open **http://localhost:8000** in your browser.

#### Option B — LoadBalancer Service (cloud clusters)

```bash
kubectl patch svc backend -n bigip-tuner \
  -p '{"spec":{"type":"LoadBalancer"}}'
kubectl patch svc grafana -n bigip-tuner \
  -p '{"spec":{"type":"LoadBalancer"}}'

# Wait for external IPs to be assigned
kubectl get svc -n bigip-tuner -w

# Once assigned, capture them
LB_TUNER=$(kubectl get svc backend -n bigip-tuner \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
LB_GRAFANA=$(kubectl get svc grafana -n bigip-tuner \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

echo "Tuner UI:  http://${LB_TUNER}:8000"
echo "Grafana:   http://${LB_GRAFANA}:3000"

# Update backend so React iframe panels resolve the correct Grafana URL
kubectl set env deployment/bigip-tuner-backend \
  GRAFANA_EXTERNAL_URL="http://${LB_GRAFANA}:3000" \
  -n bigip-tuner
```

#### Option C — Ingress (NGINX / cloud-native)

```bash
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: bigip-tuner
  namespace: bigip-tuner
  annotations:
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
spec:
  ingressClassName: nginx
  rules:
    - host: tuner.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: backend
                port:
                  number: 8000
    - host: grafana.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: grafana
                port:
                  number: 3000
EOF

# Point the backend at the public Grafana hostname
kubectl set env deployment/bigip-tuner-backend \
  GRAFANA_EXTERNAL_URL="https://grafana.example.com" \
  -n bigip-tuner
```

---

### Step 9 — Day-2 operations

**Scale down for maintenance, then restore:**

```bash
kubectl scale deployment/bigip-tuner-backend --replicas=0 -n bigip-tuner
kubectl scale deployment/bigip-tuner-backend --replicas=1 -n bigip-tuner
```

**Update the backend to a new image version:**

```bash
kubectl set image deployment/bigip-tuner-backend \
  backend=${DOCKER_USER}/bigip-protocol-tuner:1.1.0 \
  -n bigip-tuner
kubectl rollout status deployment/bigip-tuner-backend -n bigip-tuner
```

**Roll back a bad deployment:**

```bash
kubectl rollout undo deployment/bigip-tuner-backend -n bigip-tuner
```

**Check VictoriaMetrics storage utilization:**

```bash
kubectl exec -n bigip-tuner deployment/victoriametrics -- \
  wget -qO- http://127.0.0.1:8428/-/metrics | grep vm_data_size_bytes
```

**Delete the stack but keep persistent data (PVCs survive):**

```bash
kubectl delete -k k8s/overlays/local
```

**Full teardown including all data:**

```bash
kubectl delete -k k8s/overlays/local
kubectl delete pvc --all -n bigip-tuner
kubectl delete namespace bigip-tuner
```

---

## Red Hat OpenShift Deployment

```bash
# Log in to your cluster
oc login https://api.cluster.example.com:6443

# Edit route hostnames before deploying:
#   k8s/overlays/openshift/route-backend.yaml  →  set spec.host
#   k8s/overlays/openshift/route-grafana.yaml  →  set spec.host
#   k8s/overlays/openshift/kustomization.yaml  →  set GRAFANA_EXTERNAL_URL

export NAMESPACE=bigip-tuner
export REGISTRY=image-registry.openshift-image-registry.svc:5000
bash scripts/oc-deploy.sh
```

**OpenShift security notes:**

- All deployments drop `runAsUser` — OCP assigns arbitrary UIDs from the project's UID range
- `/config` volume uses `fsGroup: 0` (root group) so the arbitrary UID can write; `chmod 770`
  is applied by the backend at startup
- The script grants `anyuid` SCC for Grafana (UID 472) and VictoriaMetrics (UID 1000); on
  restricted clusters use `nonroot-v2` instead and remove the user/fsGroup patches

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
- Automatically creates child profiles instead of mutating system default profiles

### 4. Remediations
- Full history of applied changes with rollback capability
- Shows before/after profile paths, parameter map, and status (applied / rolled_back / failed)

### 5. Automated Tuning Scheduler
- Create interval (e.g. every 6h) or cron-based schedules
- **Recommend Only** mode — logs findings to audit trail without touching BIG-IP
- **Auto-Remediate** mode — applies changes meeting the minimum confidence threshold
- Audit trail with per-run recommendation and application counts

### 6. Before/After Performance Dashboard
- Embedded Grafana panels with **remediation event annotation markers**
- BIG-IP host and Virtual Server filter dropdowns
- Time range selector (1h, 6h, 24h, 7d, 30d)

### 7. Settings
- Live storage utilization bar (used MB / max GB)
- Configure retention period, max storage cap, poll interval, dedup interval
- OTLP endpoint and Grafana external URL overrides
- Auto-prune toggle (shortens retention by 25% when utilization ≥ 95%)

---

## Protocol Knowledge Base

### TCP Profiles

| Trigger | Recommendation | F5 KB |
|---|---|---|
| Legacy `/Common/tcp` with >25 Mbps or >25 ms RTT | Inherit from `f5-tcp-wan` / `f5-tcp-lan` | [K75593415](https://my.f5.com/manage/s/article/K75593415) |
| Retransmit >2% + RTT >30 ms or variance >10 ms | Switch `congestionControl` to `bbr` | [K02412420](https://my.f5.com/manage/s/article/K02412420) |
| Buffer waits > 0 or BDP > 80% sendBufferSize | Scale `sendBufferSize`, `proxyBufferHigh/Low` | [K3422](https://my.f5.com/manage/s/article/K3422) |
| Avg packet < 680 B + `nagle=enabled` | Disable/progressive Nagle, enable TCP Fast Open | [K15812](https://my.f5.com/manage/s/article/K15812) |
| `idleTimeout` > 600s + >2000 active conns | Reduce `idleTimeout` to 300s | [K7606](https://my.f5.com/manage/s/article/K7606) |

### UDP Profiles

| Trigger | Recommendation | F5 KB |
|---|---|---|
| ≥250 datagrams/conn or >0.5% drop or buf overflow | Enable `datagramLoadBalancing` | [K3605](https://my.f5.com/manage/s/article/K3605) |
| ≥8000 ephemeral conns + `idleTimeout` > 30s | Reduce `idleTimeout` to 15s | [K3667](https://my.f5.com/manage/s/article/K3667) |

### HTTP Profiles

| Trigger | Recommendation | F5 KB |
|---|---|---|
| `maxRequests` < 250 or low keep-alive reuse + `oneconnect` disabled | Raise `maxRequests`, enable `oneconnectTransformations` | [K7208](https://my.f5.com/manage/s/article/K7208) |
| HTTP header drops > 0 | Increase `enforcement.maxHeaderSize` to 65536 | [K13525](https://my.f5.com/manage/s/article/K13525) |
| `pipelining` enabled | Disable pipelining (HoL blocking) | [K7208](https://my.f5.com/manage/s/article/K7208) |

---

## Security

| Concern | Mitigation |
|---|---|
| Stored credentials | Fernet symmetric encryption (`sessions.key` or `BIGIP_SESSION_ENCRYPTION_KEY` env); `chmod 0600` |
| Auth tokens | Never persisted to disk; in-memory only per `BigIpClient` instance |
| System default profiles | `SYSTEM_DEFAULT_PROFILES` guard prevents direct mutation of `/Common/tcp`; child profiles created instead |
| Rollback safety | Pre-remediation snapshot stored before every `PATCH`; one-click rollback available |
| Metric privacy | OTLP filter restricts storage to `bigip_(vs|tcp|udp|http|tuning)_*` metrics only |

---

## Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `TUNER_CONFIG_DIR` | `~/.config/bigip-protocol-tuner` | Persistent config dir (sessions.json, key, state) |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | `http://localhost:4318/v1/metrics` | OTLP collector HTTP endpoint |
| `VICTORIAMETRICS_URL` | `http://localhost:8428` | VictoriaMetrics base URL |
| `GRAFANA_INTERNAL_URL` | `http://localhost:3000` | Grafana URL for annotation API calls (container-internal) |
| `GRAFANA_EXTERNAL_URL` | `http://localhost:3010` | Grafana URL served to browser for iframe embeds |
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
│       ├── knowledge_base.py  # F5 KB rules (TCP/UDP/HTTP)
│       └── remediator.py      # Child profile creation, VS swap, rollback
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
│           ├── Devices.jsx       # BIG-IP registration + VS enrollment
│           ├── Analysis.jsx      # On-the-fly analysis + remediation studio
│           ├── Remediations.jsx  # History + rollback table
│           ├── Schedules.jsx     # APScheduler CRUD + audit trail
│           ├── Dashboard.jsx     # Embedded Grafana before/after panels
│           └── Settings.jsx      # Storage / telemetry configuration
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
├── docker-compose.yml         # 4-service stack with offset host ports
├── .env.example               # All configurable env vars with defaults
├── requirements.txt
└── README.md
```

---

## License

MIT — see [LICENSE](LICENSE).
