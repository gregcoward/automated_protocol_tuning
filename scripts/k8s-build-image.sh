#!/usr/bin/env bash
# Build the BIG-IP Protocol Tuner container image for Kubernetes
set -euo pipefail

REGISTRY="${REGISTRY:-localhost:5000}"
IMAGE_NAME="${IMAGE_NAME:-bigip-protocol-tuner}"
TAG="${TAG:-latest}"
FULL_IMAGE="${REGISTRY}/${IMAGE_NAME}:${TAG}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "→ Building ${FULL_IMAGE} from ${REPO_ROOT}"
docker build -t "${IMAGE_NAME}:${TAG}" -t "${FULL_IMAGE}" "${REPO_ROOT}"

echo "→ Pushing ${FULL_IMAGE}"
docker push "${FULL_IMAGE}"

echo "✓ Image pushed: ${FULL_IMAGE}"
echo "  Update k8s/base/deployment-backend.yaml image to: ${FULL_IMAGE}"
