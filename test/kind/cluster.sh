# Shared by test/kind/run.sh and test/kind/helm.sh: create (or reuse) the kind
# cluster named by $CLUSTER, select its context, and delete it on exit unless
# KEEP is set. Source it after `set -euo pipefail`.
CLUSTER="${CLUSTER:-hallpass-e2e}"

kind_cleanup() {
  if [ -z "${KEEP:-}" ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap kind_cleanup EXIT

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --wait 120s
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null
