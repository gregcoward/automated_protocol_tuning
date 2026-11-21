#!/usr/bin/env bash
# Deploy BIG-IP Protocol Tuner to Kubernetes using Kustomize
set -euo pipefail

OVERLAY="${1:-local}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KUSTOMIZE_PATH="${REPO_ROOT}/k8s/overlays/${OVERLAY}"

if [[ ! -d "${KUSTOMIZE_PATH}" ]]; then
  echo "ERROR: Overlay not found: ${KUSTOMIZE_PATH}"
  echo "  Available overlays: local, minimal, openshift"
  exit 1
fi

echo "→ Deploying with overlay: ${OVERLAY}"
kubectl apply -k "${KUSTOMIZE_PATH}"

echo "→ Waiting for rollout…"
kubectl rollout status deployment/bigip-tuner-backend -n bigip-tuner --timeout=120s
kubectl rollout status deployment/victoriametrics -n bigip-tuner --timeout=120s
kubectl rollout status deployment/otel-collector -n bigip-tuner --timeout=120s

echo "✓ Deployment complete"
echo "  Backend URL: $(kubectl get svc backend -n bigip-tuner -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo 'kubectl port-forward svc/backend 8000:8000 -n bigip-tuner')"
