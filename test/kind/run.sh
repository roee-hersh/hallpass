#!/usr/bin/env bash
# End-to-end test against a kind cluster.
#
#   test/kind/run.sh            create a cluster, seed it, run the e2e tests, delete it
#   KEEP=1 test/kind/run.sh     keep the cluster afterwards
#
# Needs: kind, kubectl, docker, go.
set -euo pipefail

cd "$(dirname "$0")/../.."
CLUSTER="${CLUSTER:-hallpass-e2e}"

cleanup() {
  if [ -z "${KEEP:-}" ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --wait 120s
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null

kubectl apply -f test/kind/hallpass-rbac.yaml
kubectl apply -f test/kind/fixtures.yaml

TMP="$(mktemp -d)"
kubectl create token hallpass -n hallpass --duration=1h > "$TMP/token"
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$TMP/ca.pem"
URL="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"

export HALLPASS_E2E_KUBERNETES_URL="$URL"
export HALLPASS_E2E_KUBERNETES_TOKEN_FILE="$TMP/token"
export HALLPASS_E2E_KUBERNETES_CA_FILE="$TMP/ca.pem"

go test -tags e2e -count=1 -v ./test/e2e/ -run Kubernetes
