#!/usr/bin/env bash
# End-to-end test against a kind cluster.
#
#   test/kind/run.sh            create a cluster, seed it, run the e2e tests, delete it
#   KEEP=1 test/kind/run.sh     keep the cluster afterwards
#
# Needs: kind, kubectl, docker, python3 (3.10+) with hallpass-py and pytest installed.
set -euo pipefail

cd "$(dirname "$0")/../.."
. test/kind/cluster.sh

kubectl apply -f test/kind/hallpass-rbac.yaml
kubectl apply -f test/kind/fixtures.yaml
# The argocd Role needs the namespace to exist; Argo CD itself is not installed.
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f test/kind/argocd-rbac.yaml

TMP="$(mktemp -d)"
kubectl create token hallpass -n hallpass --duration=1h > "$TMP/token"
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$TMP/ca.pem"
URL="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"

export HALLPASS_E2E_KUBERNETES_URL="$URL"
export HALLPASS_E2E_KUBERNETES_TOKEN_FILE="$TMP/token"
export HALLPASS_E2E_KUBERNETES_CA_FILE="$TMP/ca.pem"

(cd hallpass-py && python3 -m pytest -v tests/e2e/test_kubernetes.py)
