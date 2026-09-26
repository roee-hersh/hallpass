"""Port of internal/integrations/kubernetes/kubernetes_test.go."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from hallpass.core.catalog import parse_resource
from hallpass.core.context import background
from hallpass.core.decision import Code, Decision
from hallpass.core.integration import Connection, User, find_action
from hallpass.core.template import validate_template
from hallpass.integrations.kubernetes import Integration
from hallpass.integrations.kubernetes.actions import ALIAS_LIST, build_attributes, join_res
from tests import harness as itest

SAR = "/apis/authorization.k8s.io/v1/subjectaccessreviews"
RULES = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"


class FakeAPI:
    """The fake API server's RBAC: subject (user or group) -> allowed
    "verb resource[.group][/sub] ns name" prefixes."""

    def __init__(self, allow: dict[str, list[str]]) -> None:
        self.allow = allow
        self.eval_err = ""
        self.errors: list[str] = []

    def handler(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.header.get("Authorization") != "Bearer " + itest.CANARY + "k8s":
            w.write_header(401)
            return
        try:
            req = r.json()
        except ValueError as e:
            self.errors.append(f"bad SAR body: {e}")
            w.write_header(400)
            return
        status: dict[str, Any] = {"allowed": False, "denied": False, "reason": "", "evaluationError": ""}
        if self.eval_err:
            status["evaluationError"] = self.eval_err
        else:
            spec = req["spec"]
            subjects = [spec["user"], *(spec.get("groups") or [])]
            ra = spec.get("resourceAttributes")
            if ra is not None:
                key = ra["verb"] + " " + join_res(ra["resource"], ra.get("group", ""))
                if ra.get("subresource"):
                    key += "/" + ra["subresource"]
                key += " " + ra.get("namespace", "") + " " + ra.get("name", "")
            else:
                nra = spec["nonResourceAttributes"]
                key = nra["verb"] + " " + nra["path"]
            for s in subjects:
                for p in self.allow.get(s) or []:
                    if key.startswith(p):
                        status["allowed"] = True
                        status["reason"] = "RBAC: allowed by " + s
            if not status["allowed"]:
                status["reason"] = "RBAC: no rule matched " + key
        w.header().set("Content-Type", "application/json")
        w.write_header(201)
        w.write(json.dumps({"status": status}))


def rules_handler(extra: list[dict[str, Any]] | None) -> itest.Handler:
    """Serve SelfSubjectRulesReview with the given extra rules."""

    def h(w: itest.ResponseWriter, r: itest.Request) -> None:
        rules: list[dict[str, Any]] = [
            {"verbs": ["create"], "apiGroups": ["authorization.k8s.io"], "resources": ["selfsubjectaccessreviews", "selfsubjectrulesreviews"]},
            {"verbs": ["create"], "apiGroups": ["authorization.k8s.io"], "resources": ["subjectaccessreviews"]},
        ]
        rules.extend(extra or [])
        w.write_header(201)
        w.write(json.dumps({"status": {"resourceRules": rules, "nonResourceRules": [{"verbs": ["get"], "nonResourceURLs": ["/api", "/healthz"]}]}}))

    return h


Setup = Callable[..., "tuple[itest.Server, FakeAPI, Connection]"]


@pytest.fixture
def setup() -> Iterator[Setup]:
    servers: list[itest.Server] = []
    apis: list[FakeAPI] = []

    def make(values: dict[str, str] | None = None) -> tuple[itest.Server, FakeAPI, Connection]:
        srv = itest.Server()
        servers.append(srv)
        srv.handle("POST", RULES, rules_handler(None))
        api = FakeAPI(
            {
                "dana@example.com": [
                    "get pods payments ",
                    "create deployments.apps payments ",
                    "get pods/log payments ",
                    "update deployments.apps/scale payments api",
                ],
                "bob@example.com": ["get pods payments "],
                "oidc:dana@example.com": ["get pods payments "],
                "oidc:platform-team": ["create pods/exec payments "],
                "system:authenticated": ["get /version", "get /healthz"],
                "admin@example.com": [""],
            }
        )
        apis.append(api)
        srv.handle("POST", SAR, api.handler)
        deps, _ = itest.deps(srv)
        v = {"url": srv.url, "username_template": "{email}", "add_authenticated_group": "true"}
        v.update(values or {})
        s = itest.settings("k8s", "kubernetes", v, {"credential": itest.literal("k8s")})
        c = Integration().new(background(), s, deps)
        return srv, api, c

    yield make
    for s in servers:
        s.close()
    for a in apis:
        assert not a.errors, a.errors


dana = User(email="dana@example.com", groups=("platform-team",))
bob = User(email="bob@example.com")
admin = User(email="admin@example.com")


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, Integration(), u, action, resource)


def test_raw_allow_deny_and_body(setup: Setup) -> None:
    srv, _, c = setup()
    d = check(c, dana, "raw:get:pods", "namespace:payments?name=api-0")
    itest.expect_code(d, Code.ALLOWED)
    req = srv.last_call().json()
    assert req["apiVersion"] == "authorization.k8s.io/v1" and req["kind"] == "SubjectAccessReview", req
    spec = req["spec"]
    assert spec["user"] == "dana@example.com" and spec.get("groups") == ["platform-team", "system:authenticated"], spec
    ra = spec.get("resourceAttributes")
    assert ra is not None, spec
    assert ra.get("namespace") == "payments" and ra["verb"] == "get" and ra["resource"] == "pods" and ra.get("name") == "api-0" and ra.get("group", "") == "", (
        ra
    )
    itest.expect_code(check(c, dana, "raw:delete:pods", "namespace:payments"), Code.DENIED)
    itest.expect_code(check(c, dana, "raw:get:pods", "namespace:other"), Code.DENIED)
    itest.expect_code(check(c, bob, "raw:get:pods", "namespace:billing"), Code.DENIED)
    itest.expect_code(check(c, admin, "raw:delete:nodes", "cluster"), Code.ALLOWED)

    d = check(c, dana, "raw:create:deployments.apps", "namespace:payments")
    itest.expect_code(d, Code.ALLOWED)
    ra = srv.last_call().json()["spec"]["resourceAttributes"]
    assert ra.get("group") == "apps" and ra["resource"] == "deployments", f"group split: {ra}"
    d = check(c, dana, "raw:get:pods/log", "namespace:payments")
    itest.expect_code(d, Code.ALLOWED)
    ra = srv.last_call().json()["spec"]["resourceAttributes"]
    assert ra.get("subresource") == "log", f"subresource: {ra}"
    d = check(c, dana, "raw:get:pods", "namespace:payments?resource=pods&name=x")
    itest.expect_code(d, Code.ALLOWED)


def test_non_resource(setup: Setup) -> None:
    srv, _, c = setup()
    d = check(c, bob, "raw:get", "nonresource:/version")
    itest.expect_code(d, Code.ALLOWED)
    spec = srv.last_call().json()["spec"]
    nra = spec.get("nonResourceAttributes")
    assert "resourceAttributes" not in spec and nra is not None and nra["path"] == "/version" and nra["verb"] == "get", spec
    itest.expect_code(check(c, bob, "raw:post", "nonresource:/version"), Code.DENIED)
    itest.expect_code(check(c, bob, "raw:get:x", "nonresource:/version"), Code.INVALID_REQUEST)
    itest.expect_code(check(c, bob, "raw:get", "namespace:payments"), Code.INVALID_REQUEST)
    itest.expect_code(check(c, bob, "raw:get", "namespace:payments?resource=pods"), Code.ALLOWED)


def test_reserved_groups_need_prefix(setup: Setup) -> None:
    masters = User(email="dana@example.com", groups=("platform-team", "system:masters"))
    srv, _, c = setup()
    d = check(c, masters, "raw:get:pods", "namespace:payments")
    itest.expect_code(d, Code.INVALID_REQUEST)
    assert "system:masters" in d.text, d
    for call in srv.calls():
        assert not call.path.endswith("/subjectaccessreviews"), f"review sent with a reserved group: {call}"
    # With a prefix the value cannot name a built-in group.
    srv, _, c = setup({"group_prefix": "oidc:"})
    itest.expect_code(check(c, masters, "raw:delete:secrets", "namespace:kube-system"), Code.DENIED)
    spec = srv.last_call().json()["spec"]
    assert len(spec["groups"]) == 3 and spec["groups"][1] == "oidc:system:masters", spec


def test_template_and_prefix(setup: Setup) -> None:
    srv, _, c = setup({"username_template": "oidc:{email}", "group_prefix": "oidc:", "add_authenticated_group": "false"})
    itest.expect_code(check(c, dana, "raw:get:pods", "namespace:payments"), Code.ALLOWED)
    spec = srv.last_call().json()["spec"]
    assert spec["user"] == "oidc:dana@example.com" and spec.get("groups") == ["oidc:platform-team"], spec
    itest.expect_code(check(c, dana, "pods.exec", "namespace:payments?name=api-0"), Code.ALLOWED)
    itest.expect_code(check(c, bob, "pods.exec", "namespace:payments?name=api-0"), Code.DENIED)

    _, _, c2 = setup({"username_template": "{local}@corp"})
    ident = c2.resolve_identity(background(), dana)
    assert ident.id == "dana@corp", ident.id
    for bad in ("static", "{user}", "{email"):
        with pytest.raises(ValueError):
            validate_template(bad)
    validate_template("{domain}/{local}")


def test_template_validation_shared() -> None:
    """username_template is validated by the shared helper both through the
    field declaration and in new(), and an unset value falls back to {email}."""
    field = next((f for f in Integration().fields() if f.name == "username_template"), None)
    assert field is not None and field.validate is not None and field.default == "{email}", f"username_template field: {field}"
    for bad in ("static", "{user}", "{local}{", "{local}}"):
        with pytest.raises(ValueError):
            field.validate(bad)
    with itest.Server() as srv:
        deps, _ = itest.deps(srv)

        def build(tpl: str) -> Connection:
            v = {"url": srv.url}
            if tpl != "":
                v["username_template"] = tpl
            return Integration().new(background(), itest.settings("k8s", "kubernetes", v, {"credential": itest.literal("sa")}), deps)

        with pytest.raises(ValueError, match="username_template"):
            build("{local}{")
        c = build("")
        ident = c.resolve_identity(background(), dana)
        assert ident.id == dana.email, f"default template: {ident.id!r}"


def test_evaluation_error_and_statuses(setup: Setup) -> None:
    srv, api, c = setup()
    api.eval_err = "webhook unavailable"
    itest.expect_code(check(c, dana, "raw:get:pods", "namespace:payments"), Code.UNSUPPORTED)
    api.eval_err = ""
    srv.json("POST", SAR, 403, '{"kind":"Status","message":"forbidden"}')
    itest.expect_code(check(c, dana, "raw:get:pods", "namespace:payments"), Code.CREDENTIAL_REJECTED)
    with pytest.raises(Exception, match="subjectaccessreviews"):
        c.probe(background())


def test_failures(setup: Setup) -> None:
    srv, _, c = setup()
    itest.failure_cases(srv, lambda: check(c, dana, "raw:get:pods", "namespace:payments"))


def test_probe(setup: Setup) -> None:
    srv, api, c = setup()
    r = c.probe(background())
    assert r.summary != "" and len(r.warnings) == 0, r
    api.allow["hallpass:probe"] = [""]
    r = c.probe(background())
    assert len(r.warnings) == 1, "expected warning for permissive cluster"
    api.allow["hallpass:probe"] = []
    # An over-privileged token is reported with the extra rules.
    srv.handle(
        "POST",
        RULES,
        rules_handler(
            [
                {"verbs": ["get", "list"], "apiGroups": [""], "resources": ["secrets"]},
                {"verbs": ["*"], "apiGroups": ["apps"], "resources": ["deployments"]},
            ]
        ),
    )
    r = c.probe(background())
    assert len(r.warnings) == 1 and "get,list secrets" in r.warnings[0] and "* deployments.apps" in r.warnings[0], r
    # A failing rules review is a warning, not an error.
    srv.json("POST", RULES, 403, "{}")
    r = c.probe(background())
    assert len(r.warnings) == 1 and "could not list" in r.warnings[0], r


@pytest.mark.parametrize(
    ("action", "resource"),
    [
        ("raw:get:pods", "pod:x"),
        ("raw:get:pods", "namespace:Bad_NS"),
        ("raw:get:pods", "cluster:x"),
        ("raw:get:pods", "namespace:payments?name=bad name"),
        ("raw:get:pods", "namespace:payments?resource=deployments.apps"),
        ("raw:get:pods/log", "namespace:payments?subresource=exec"),
        ("scale", "namespace:payments"),
        ("raw:get:pods", "nonresource:/metrics"),
        ("raw:get:pods", "nonresource:metrics"),
        ("raw:get:pods", "namespace:payments?namespace=other"),
        ("raw:get:pods", "namespace:payments?resource=Bad"),
    ],
)
def test_bad_resources(setup: Setup, action: str, resource: str) -> None:
    _, _, c = setup()
    d = check(c, dana, action, resource)
    assert d.code == Code.INVALID_REQUEST, f"{action} {resource} -> {d.code}: {d.text}"


@pytest.mark.parametrize("bad", ["raw:", "raw:Get:pods", "raw:get:Pods", "raw:get:pods/Log", "raw:get:pods.-bad", "raw::pods", "get:pods", "raw:get:"])
def test_bad_resources_match_action_rejects(bad: str) -> None:
    # Go: TestBadResources, second loop.
    assert Integration().match_action(bad) is None, f"match_action({bad!r}) accepted"


@pytest.mark.parametrize(
    "ok", ["raw:get:pods", "raw:create:deployments.apps", "raw:get:pods/log", "raw:impersonate:users", "raw:use:podsecuritypolicies.policy"]
)
def test_bad_resources_match_action_accepts(ok: str) -> None:
    # Go: TestBadResources, third loop.
    assert Integration().match_action(ok) is not None, f"match_action({ok!r}) rejected"


def test_aliases() -> None:
    for a in ALIAS_LIST:
        assert find_action(Integration(), a.name) is not None, f"alias {a.name} not listed"
    a = build_attributes("scale", parse_resource("namespace:payments?resource=deployments.apps&name=api"))
    assert a.verb == "update" and a.resource == "deployments" and a.group == "apps" and a.subresource == "scale" and a.name == "api", f"scale: {a}"
    a = build_attributes("impersonate", parse_resource("cluster?name=admin"))
    assert a.verb == "impersonate" and a.resource == "users" and a.name == "admin", f"impersonate: {a}"
    a = build_attributes("impersonate", parse_resource("cluster?resource=groups&name=admins"))
    assert a.resource == "groups", f"impersonate groups: {a}"
    with pytest.raises(ValueError):
        build_attributes("raw:get:x", parse_resource("nonresource:/metrics"))


# Allow/deny tests per alias action (coverage gate).


def alias_allow(setup: Setup, action: str, resource: str) -> None:
    _, api, c = setup()
    api.allow["dana@example.com"] = [""]
    itest.expect_code(check(c, dana, action, resource), Code.ALLOWED)


def alias_deny(setup: Setup, action: str, resource: str) -> None:
    _, _, c = setup()
    itest.expect_code(check(c, bob, action, resource), Code.DENIED)


def test_action_pods_exec_allow(setup: Setup) -> None:
    alias_allow(setup, "pods.exec", "namespace:payments?name=api-0")


def test_action_pods_exec_deny(setup: Setup) -> None:
    alias_deny(setup, "pods.exec", "namespace:payments?name=api-0")


def test_action_pods_logs_allow(setup: Setup) -> None:
    alias_allow(setup, "pods.logs", "namespace:payments")


def test_action_pods_logs_deny(setup: Setup) -> None:
    alias_deny(setup, "pods.logs", "namespace:payments")


def test_action_pods_portforward_allow(setup: Setup) -> None:
    alias_allow(setup, "pods.portforward", "namespace:payments")


def test_action_pods_portforward_deny(setup: Setup) -> None:
    alias_deny(setup, "pods.portforward", "namespace:payments")


def test_action_pods_attach_allow(setup: Setup) -> None:
    alias_allow(setup, "pods.attach", "namespace:payments")


def test_action_pods_attach_deny(setup: Setup) -> None:
    alias_deny(setup, "pods.attach", "namespace:payments")


def test_action_scale_allow(setup: Setup) -> None:
    alias_allow(setup, "scale", "namespace:payments?resource=deployments.apps&name=api")


def test_action_scale_deny(setup: Setup) -> None:
    alias_deny(setup, "scale", "namespace:payments?resource=deployments.apps&name=api")


def test_action_secrets_read_allow(setup: Setup) -> None:
    alias_allow(setup, "secrets.read", "namespace:payments?name=db")


def test_action_secrets_read_deny(setup: Setup) -> None:
    alias_deny(setup, "secrets.read", "namespace:payments?name=db")


def test_action_secrets_list_allow(setup: Setup) -> None:
    alias_allow(setup, "secrets.list", "namespace:payments")


def test_action_secrets_list_deny(setup: Setup) -> None:
    alias_deny(setup, "secrets.list", "namespace:payments")


def test_action_impersonate_allow(setup: Setup) -> None:
    alias_allow(setup, "impersonate", "cluster?name=admin")


def test_action_impersonate_deny(setup: Setup) -> None:
    alias_deny(setup, "impersonate", "cluster?name=admin")


def test_action_deployment_create_allow(setup: Setup) -> None:
    alias_allow(setup, "deployment.create", "namespace:payments")


def test_action_deployment_create_deny(setup: Setup) -> None:
    alias_deny(setup, "deployment.create", "namespace:payments")


def test_action_deployment_update_allow(setup: Setup) -> None:
    alias_allow(setup, "deployment.update", "namespace:payments?name=api")


def test_action_deployment_update_deny(setup: Setup) -> None:
    alias_deny(setup, "deployment.update", "namespace:payments?name=api")


def test_action_deployment_delete_allow(setup: Setup) -> None:
    alias_allow(setup, "deployment.delete", "namespace:payments?name=api")


def test_action_deployment_delete_deny(setup: Setup) -> None:
    alias_deny(setup, "deployment.delete", "namespace:payments?name=api")


def test_action_deployment_restart_allow(setup: Setup) -> None:
    alias_allow(setup, "deployment.restart", "namespace:payments?name=api")


def test_action_deployment_restart_deny(setup: Setup) -> None:
    alias_deny(setup, "deployment.restart", "namespace:payments?name=api")


def test_action_namespace_create_allow(setup: Setup) -> None:
    alias_allow(setup, "namespace.create", "cluster")


def test_action_namespace_create_deny(setup: Setup) -> None:
    alias_deny(setup, "namespace.create", "cluster")


def test_action_namespace_delete_allow(setup: Setup) -> None:
    alias_allow(setup, "namespace.delete", "cluster?name=payments")


def test_action_namespace_delete_deny(setup: Setup) -> None:
    alias_deny(setup, "namespace.delete", "cluster?name=payments")


def test_action_rbac_bind_allow(setup: Setup) -> None:
    alias_allow(setup, "rbac.bind", "namespace:payments")


def test_action_rbac_bind_deny(setup: Setup) -> None:
    alias_deny(setup, "rbac.bind", "namespace:payments")
