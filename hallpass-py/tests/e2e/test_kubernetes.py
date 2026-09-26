"""Port of test/e2e/kubernetes_test.go: tests that run against a real
Kubernetes API server. Skipped unless the environment names one
(HALLPASS_E2E_KUBERNETES_URL, _TOKEN_FILE and _CA_FILE); test/kind/run.sh
sets up a kind cluster and exports them."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import pytest

from hallpass.core.config import parse as parse_config
from hallpass.core.context import background
from hallpass.core.engine import Options, build
from hallpass.integrations import registry
from hallpass.server import Server

CASES = [
    ("dana@example.com", None, "raw:get:pods", "namespace:payments", "allow"),
    ("dana@example.com", None, "raw:list:pods", "namespace:payments", "allow"),
    ("dana@example.com", None, "pods.logs", "namespace:payments?name=api-0", "allow"),
    ("dana@example.com", None, "raw:delete:pods", "namespace:payments", "deny"),
    ("dana@example.com", None, "raw:get:pods", "namespace:billing", "deny"),
    ("dana@example.com", None, "deployment.create", "namespace:payments", "deny"),
    ("dana@example.com", ["platform-team"], "deployment.create", "namespace:payments", "allow"),
    ("dana@example.com", ["platform-team"], "scale", "namespace:payments?resource=deployments.apps&name=api", "allow"),
    ("dana@example.com", ["platform-team"], "pods.exec", "namespace:payments?name=api-0", "allow"),
    ("dana@example.com", ["platform-team"], "deployment.delete", "namespace:payments?name=api", "deny"),
    ("bob@example.com", None, "raw:get:pods", "namespace:payments", "allow"),
    ("bob@example.com", None, "raw:list:pods", "namespace:payments", "deny"),
    ("bob@example.com", None, "pods.logs", "namespace:payments", "deny"),
    ("nobody@example.com", None, "raw:get:pods", "namespace:payments", "deny"),
    ("nobody@example.com", None, "raw:get", "nonresource:/version", "allow"),
    ("nobody@example.com", None, "raw:get", "nonresource:/api", "allow"),
    ("nobody@example.com", None, "raw:post", "nonresource:/api", "deny"),
    ("nobody@example.com", None, "raw:get:nodes", "cluster", "deny"),
    ("nobody@example.com", None, "secrets.read", "namespace:kube-system?name=x", "deny"),
]


def test_kubernetes(monkeypatch: pytest.MonkeyPatch) -> None:
    url = os.environ.get("HALLPASS_E2E_KUBERNETES_URL", "")
    token_file = os.environ.get("HALLPASS_E2E_KUBERNETES_TOKEN_FILE", "")
    ca_file = os.environ.get("HALLPASS_E2E_KUBERNETES_CA_FILE", "")
    if url == "" or token_file == "" or ca_file == "":
        pytest.skip("HALLPASS_E2E_KUBERNETES_* not set")
    monkeypatch.setenv("HALLPASS_API_KEY", "e2e")
    yml = (
        "api_key: env:HALLPASS_API_KEY\ndecision_log: none\nconnections:\n"
        f"  - id: kind\n    integration: kubernetes\n    url: {url}\n    ca_file: {ca_file}\n    credential: file:{token_file}\n"
    )
    cfg = parse_config("e2e.yaml", yml, registry())
    eng = build(background(), cfg, Options())
    for p in eng.probe(background()):
        assert p.err is None, f"probe {p.id}: {p.err}"
        print(f"probe {p.id}: {p.result.summary} {list(p.result.warnings)}")
    srv = Server(eng, cfg.api_key)
    host, port = srv.listen("127.0.0.1:0")
    srv.serve_in_thread()
    base = f"http://{host}:{port}"

    def check(user: str, groups: list[str] | None, action: str, resource: str) -> tuple[str, str]:
        body = json.dumps({"user": user, "groups": groups, "connection": "kind", "action": action, "resource": resource}).encode()
        req = urllib.request.Request(base + "/check", data=body, method="POST", headers={"Authorization": "Bearer e2e"})
        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                status, data = res.status, res.read()
        except urllib.error.HTTPError as e:
            status, data = e.code, e.read()
        out = json.loads(data)
        assert status == 200, f"{user} {action} {resource}: HTTP {status} {out.get('reason')}"
        return out.get("decision", ""), out.get("reason", "")

    errors = []
    try:
        for user, groups, action, resource, want in CASES:
            got, reason = check(user, groups, action, resource)
            if got != want:
                errors.append(f"{user} {groups} {action} {resource}: got {got} ({reason}), want {want}")
            else:
                print(f"{user} {groups} {action} {resource}: {got} ({reason})")
    finally:
        srv.shutdown()
    assert not errors, "\n".join(errors)
