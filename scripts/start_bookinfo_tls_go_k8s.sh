#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${NAMESPACE:-bookinfo-tls-go}"
IMAGE="${IMAGE:-docker.io/library/trace-fusion-bookinfo-tls-go:latest}"
MANIFEST="${MANIFEST:-$ROOT_DIR/services/bookinfo-tls-go/kube/bookinfo-tls-go-xmark.yaml}"
LOCAL_PORT="${LOCAL_PORT:-9460}"
BUILD_IMAGE="${BUILD_IMAGE:-1}"
WAIT_ROLLOUT="${WAIT_ROLLOUT:-1}"
USE_MINIKUBE_DOCKER="${USE_MINIKUBE_DOCKER:-auto}"
MINIKUBE_IMAGE_MODE="${MINIKUBE_IMAGE_MODE:-auto}"

usage() {
  cat <<EOF
Usage: $0 [--no-build] [--no-wait] [--port-forward]

Deploy services/bookinfo-tls-go to Kubernetes.

Environment:
  NAMESPACE=$NAMESPACE
  IMAGE=$IMAGE
  LOCAL_PORT=$LOCAL_PORT
  BUILD_IMAGE=$BUILD_IMAGE
  MINIKUBE_IMAGE_MODE=$MINIKUBE_IMAGE_MODE
  USE_MINIKUBE_DOCKER=$USE_MINIKUBE_DOCKER

Examples:
  $0
  $0 --port-forward
  BUILD_IMAGE=0 $0
EOF
}

PORT_FORWARD=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build)
      BUILD_IMAGE=0
      shift
      ;;
    --no-wait)
      WAIT_ROLLOUT=0
      shift
      ;;
    --port-forward)
      PORT_FORWARD=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$BUILD_IMAGE" != "0" ]]; then
  if [[ "$MINIKUBE_IMAGE_MODE" == "auto" ]]; then
    if command -v minikube >/dev/null 2>&1 && minikube status >/dev/null 2>&1; then
      MINIKUBE_IMAGE_MODE=load
    else
      MINIKUBE_IMAGE_MODE=docker
    fi
  fi

  if [[ "$MINIKUBE_IMAGE_MODE" == "load" ]]; then
    if docker image inspect "$IMAGE" >/dev/null 2>&1; then
      echo "[bookinfo-tls-go] loading existing local image $IMAGE into minikube"
    else
      echo "[bookinfo-tls-go] local image $IMAGE not found; building with current docker daemon"
      docker build -t "$IMAGE" "$ROOT_DIR/services/bookinfo-tls-go"
    fi
    minikube image load "$IMAGE"
  elif [[ "$MINIKUBE_IMAGE_MODE" == "build" ]]; then
    echo "[bookinfo-tls-go] building $IMAGE with minikube image build"
    minikube image build -t "$IMAGE" "$ROOT_DIR/services/bookinfo-tls-go"
  elif [[ "$USE_MINIKUBE_DOCKER" == "1" ]]; then
    eval "$(minikube docker-env)"
    echo "[bookinfo-tls-go] building $IMAGE inside minikube docker daemon"
    docker build -t "$IMAGE" "$ROOT_DIR/services/bookinfo-tls-go"
  else
    echo "[bookinfo-tls-go] building $IMAGE with current docker daemon"
    docker build -t "$IMAGE" "$ROOT_DIR/services/bookinfo-tls-go"
  fi
fi

echo "[bookinfo-tls-go] applying $MANIFEST"
kubectl apply -f "$MANIFEST"

if [[ "$BUILD_IMAGE" != "0" ]]; then
  for deploy in details-v1 ratings-v1 reviews-v1 productpage-v1; do
    kubectl -n "$NAMESPACE" rollout restart "deploy/$deploy" >/dev/null 2>&1 || true
  done
fi

if [[ "$WAIT_ROLLOUT" != "0" ]]; then
  for deploy in details-v1 ratings-v1 reviews-v1 productpage-v1; do
    kubectl -n "$NAMESPACE" rollout status "deploy/$deploy"
  done
fi

echo
echo "[bookinfo-tls-go] pods:"
kubectl -n "$NAMESPACE" get pods -o wide

cat <<EOF

Bookinfo TLS Go is deployed in namespace: $NAMESPACE

Manual access:
  kubectl -n $NAMESPACE port-forward svc/productpage $LOCAL_PORT:9080
  curl -k -H 'X-Mark: manual-check' 'https://127.0.0.1:$LOCAL_PORT/productpage?id=7'

Load example:
  python3 services/bookinfo/uniform_bookinfo_load.py https://127.0.0.1:$LOCAL_PORT -R 20 -c 2 -d 3s --mark-prefix tls-go-k8s
EOF

if [[ "$PORT_FORWARD" == "1" ]]; then
  echo
  echo "[bookinfo-tls-go] starting foreground port-forward on https://127.0.0.1:$LOCAL_PORT"
  exec kubectl -n "$NAMESPACE" port-forward svc/productpage "$LOCAL_PORT:9080"
fi
