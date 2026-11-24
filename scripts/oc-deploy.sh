#!/usr/bin/env bash
# Deploy BIG-IP Protocol Tuner to Red Hat OpenShift
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NAMESPACE="${NAMESPACE:-bigip-tuner}"
REGISTRY="${REGISTRY:-image-registry.openshift-image-registry.svc:5000}"
IMAGE_NAME="${IMAGE_NAME:-bigip-protocol-tuner}"
TAG="${TAG:-latest}"

echo "=== BIG-IP Protocol Tuner — OpenShift Deployment ==="
echo "  Namespace : ${NAMESPACE}"
echo "  Registry  : ${REGISTRY}"
echo ""

# 1. Create/switch project
oc get project "${NAMESPACE}" >/dev/null 2>&1 || oc new-project "${NAMESPACE}"
oc project "${NAMESPACE}"

# 2. Provision Grafana ConfigMaps
oc create configmap grafana-provisioning \
  --from-file=victoriametrics.yaml="${REPO_ROOT}/grafana/provisioning/datasources/victoriametrics.yaml" \
  --from-file=provider.yaml="${REPO_ROOT}/grafana/provisioning/dashboards/provider.yaml" \
  -n "${NAMESPACE}" \
  --dry-run=client -o yaml | oc apply -f -

oc create configmap grafana-dashboards \
  --from-file=bigip-before-after-tuning.json="${REPO_ROOT}/grafana/dashboards/bigip-before-after-tuning.json" \
  -n "${NAMESPACE}" \
  --dry-run=client -o yaml | oc apply -f -

# 3. Grant anyuid SCC to service account (required for Grafana UID 472 and VictoriaMetrics UID 1000)
echo "→ Granting anyuid SCC (adjust for your cluster policy)"
oc adm policy add-scc-to-user anyuid -z default -n "${NAMESPACE}" || true

# 4. Build and push image via OpenShift internal registry
FULL_IMAGE="${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:${TAG}"
echo "→ Building and pushing ${FULL_IMAGE}"
docker build -t "${FULL_IMAGE}" "${REPO_ROOT}"
docker push "${FULL_IMAGE}"

# 5. Patch backend deployment with the internal registry image
sed -i.bak "s|image: .*bigip-protocol-tuner:.*|image: ${FULL_IMAGE}|g" \
  "${REPO_ROOT}/k8s/base/deployment-backend.yaml"

# 6. Apply OpenShift overlay
echo "→ Applying OpenShift Kustomize overlay"
oc apply -k "${REPO_ROOT}/k8s/overlays/openshift"

# Restore patched file
mv "${REPO_ROOT}/k8s/base/deployment-backend.yaml.bak" \
   "${REPO_ROOT}/k8s/base/deployment-backend.yaml"

# 7. Wait for rollouts
echo "→ Waiting for rollouts…"
oc rollout status deployment/bigip-tuner-backend -n "${NAMESPACE}" --timeout=180s
oc rollout status deployment/victoriametrics -n "${NAMESPACE}" --timeout=180s
oc rollout status deployment/otel-collector -n "${NAMESPACE}" --timeout=120s

# 8. Print access URLs
echo ""
echo "✓ Deployment complete"
echo "  Tuner UI  : $(oc get route bigip-tuner -n "${NAMESPACE}" -o jsonpath='{.spec.host}' 2>/dev/null | xargs -I{} echo 'https://{}')"
echo "  Grafana   : $(oc get route grafana -n "${NAMESPACE}" -o jsonpath='{.spec.host}' 2>/dev/null | xargs -I{} echo 'https://{}')"
