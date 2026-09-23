#!/usr/bin/env bash
# Install the Helm chart on a kind cluster and ask it real questions.
#
#   test/kind/helm.sh            create a cluster, install the chart, check, delete the cluster
#   KEEP=1 test/kind/helm.sh     keep the cluster afterwards
#
# The release runs the local image with a `kubernetes` connection pointing at
# the cluster it runs in, so the chart's ServiceAccount, ClusterRole and token
# mount are exercised, not only the demo connection. The fixtures come from
# test/kind/fixtures.yaml.
#
# Needs: kind, kubectl, helm, docker.
set -euo pipefail

cd "$(dirname "$0")/../.."
CLUSTER="${CLUSTER:-hallpass-e2e}"
RELEASE=hallpass
NS=hallpass-helm
KEY=ci-key
PF_PID=

cleanup() {
  [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true
  if [ -z "${KEEP:-}" ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --wait 120s
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null
kubectl apply -f test/kind/fixtures.yaml

docker build -t hallpass:e2e .
kind load docker-image hallpass:e2e --name "$CLUSTER"

helm lint deploy/helm/hallpass --strict --set apiKey.value=x
helm upgrade --install "$RELEASE" deploy/helm/hallpass \
  --namespace "$NS" --create-namespace --wait --timeout 120s \
  --set image.repository=hallpass --set image.tag=e2e --set image.pullPolicy=Never \
  --set apiKey.value="$KEY" \
  --set serviceAccount.automountToken=true \
  --set rbac.subjectAccessReview.create=true \
  --set 'config.connections[0].id=kind' \
  --set 'config.connections[0].integration=kubernetes' \
  --set 'config.connections[0].url=https://kubernetes.default.svc' \
  --set 'config.connections[0].ca_file=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt' \
  --set 'config.connections[0].credential=file:/var/run/secrets/kubernetes.io/serviceaccount/token'
helm test "$RELEASE" --namespace "$NS"

kubectl -n "$NS" port-forward "svc/$RELEASE" 18080:8080 >/dev/null 2>&1 &
PF_PID=$!
for i in $(seq 1 30); do curl -fsS http://localhost:18080/healthz >/dev/null 2>&1 && break; sleep 1; done

ask() { # user action resource
  curl -fsS -X POST http://localhost:18080/check \
    -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
    -d "{\"user\":\"$1\",\"connection\":\"kind\",\"action\":\"$2\",\"resource\":\"$3\"}"
}
expect() { # want user action resource
  local want="$1"; shift
  local out
  out="$(ask "$@")"
  echo "$* -> $out"
  echo "$out" | grep -q "\"decision\":\"$want\"" || { echo "want $want"; exit 1; }
}
expect allow dana@example.com raw:get:pods namespace:payments
expect deny  bob@example.com  pods.logs   namespace:payments
expect deny  dana@example.com raw:get:pods namespace:billing
echo "helm chart ok"
