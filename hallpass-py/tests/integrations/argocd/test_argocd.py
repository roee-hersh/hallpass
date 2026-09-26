"""Port of internal/integrations/argocd/argocd_test.go."""

from __future__ import annotations

import json
import queue
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from hallpass.core import evidence
from hallpass.core.cache import PanicError
from hallpass.core.context import Cancelled, background, with_cancel, with_timeout
from hallpass.core.decision import Code, Decision
from hallpass.core.errors import as_error, is_error
from hallpass.core.integration import Connection, Settings, User
from hallpass.integrations import kubernetes
from hallpass.integrations.argocd import POLICY_CACHE_TTL, Bundle, Integration
from hallpass.integrations.argocd import Connection as ArgoConnection
from tests import harness as itest


class Cluster:
    """The fake API server state."""

    def __init__(
        self,
        rbac_cm: dict[str, str] | None = None,
        argocd_cm: dict[str, str] | None = None,
        projects: list[dict[str, Any]] | None = None,
    ) -> None:
        self.rbac_cm = rbac_cm  # None = 404
        self.argocd_cm = argocd_cm  # None = 404
        self.projects = projects or []
        self.reads = 0

    def install(self, srv: itest.Server) -> None:
        def cm(get: Callable[[], dict[str, str] | None]) -> itest.Handler:
            def h(w: itest.ResponseWriter, r: itest.Request) -> None:
                self.reads += 1
                if r.header.get("Authorization") != "Bearer " + itest.CANARY + "k8s":
                    w.write_header(401)
                    return
                data = get()
                if data is None:
                    w.write_header(404)
                    w.write(b'{"kind":"Status","code":404}')
                    return
                w.write(json.dumps({"data": data}))

            return h

        def projects(w: itest.ResponseWriter, r: itest.Request) -> None:
            self.reads += 1
            w.write(json.dumps({"items": self.projects}))

        srv.handle("GET", "/api/v1/namespaces/argocd/configmaps/argocd-rbac-cm", cm(lambda: self.rbac_cm))
        srv.handle("GET", "/api/v1/namespaces/argocd/configmaps/argocd-cm", cm(lambda: self.argocd_cm))
        srv.handle("GET", "/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects", projects)


def project(name: str, *roles: dict[str, Any]) -> dict[str, Any]:
    return {"metadata": {"name": name}, "spec": {"roles": list(roles)}}


class Clock:
    """A settable clock (Go: the *time.Time setup returns)."""

    def __init__(self) -> None:
        self.now = time.time()

    def __call__(self) -> float:
        return self.now

    def add(self, d: float) -> None:
        self.now += d


Setup = Callable[..., "tuple[itest.Server, Connection, Clock]"]


@pytest.fixture
def setup() -> Iterator[Setup]:
    servers: list[itest.Server] = []

    def make(cl: Cluster, user_subject: str) -> tuple[itest.Server, Connection, Clock]:
        srv = itest.Server()
        servers.append(srv)
        cl.install(srv)
        clock = Clock()
        deps, _ = itest.deps(srv, now=clock)
        ks = itest.settings(
            "k8s",
            "kubernetes",
            {"url": srv.url, "username_template": "{email}", "add_authenticated_group": "true"},
            {"credential": itest.literal("k8s")},
        )
        kc = kubernetes.Integration().new(background(), ks, deps)
        deps.connection = lambda _id: kc
        s = itest.settings(
            "argo",
            "argocd",
            {"kubernetes_connection": "k8s", "namespace": "argocd", "rbac_configmap": "argocd-rbac-cm", "user_subject": user_subject},
        )
        c = Integration().new(background(), s, deps)
        return srv, c, clock

    yield make
    for s in servers:
        s.close()


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, Integration(), u, action, resource)


POLICY = """
p, role:dev, applications, get, dev/*, allow
p, role:dev, applications, sync, dev/*, allow
p, role:dev, logs, get, dev/*, allow
p, role:ops, applications, get, */*, allow
p, role:ops, applications, create, */*, allow
p, role:ops, applications, update, */*, allow
p, role:ops, applications, delete, */*, allow
p, role:ops, applications, sync, */*, allow
p, role:ops, applications, override, */*, allow
p, role:ops, applications, delete, prod/*, deny
p, role:ops, clusters, get, *, allow
p, role:ops, projects, get, *, allow
p, role:ops, applications, action/apps/Deployment/*, */*, allow
p, role:ops, applications, update/apps/Deployment/*, */*, allow
g, developers, role:dev
g, sre, role:ops
g, dana@example.com, role:ops
"""


def default_cluster() -> Cluster:
    return Cluster(
        rbac_cm={"policy.csv": POLICY, "policy.default": "", "scopes": "[groups, email]"},
        argocd_cm={},
        projects=[
            project("dev"),
            project("prod"),
            project(
                "team-a",
                {
                    "name": "deployer",
                    "policies": ["p, proj:team-a:deployer, applications, sync, team-a/*, allow"],
                    "groups": ["team-a-devs"],
                },
            ),
        ],
    )


dev = User(email="dev@example.com", groups=("developers",))
sre = User(email="sre@example.com", groups=("sre",))
dana = User(email="dana@example.com")
none = User(email="nobody@example.com")
team_a = User(email="a@example.com", groups=("team-a-devs",))


def test_groups_and_roles(setup: Setup) -> None:
    _, c, _ = setup(default_cluster(), "none")
    itest.expect_code(check(c, dev, "app.get", "applications:dev/web"), Code.ALLOWED)
    itest.expect_code(check(c, dev, "app.sync", "applications:dev/web"), Code.ALLOWED)
    itest.expect_code(check(c, dev, "logs.get", "applications:dev/web"), Code.ALLOWED)
    itest.expect_code(check(c, dev, "logs.get", "logs:dev/web"), Code.ALLOWED)
    itest.expect_code(check(c, dev, "app.delete", "applications:dev/web"), Code.DENIED)
    itest.expect_code(check(c, dev, "app.get", "applications:prod/web"), Code.DENIED)
    itest.expect_code(check(c, sre, "app.delete", "applications:dev/web"), Code.ALLOWED)
    itest.expect_code(check(c, sre, "app.delete", "applications:prod/web"), Code.DENIED)
    itest.expect_code(check(c, sre, "cluster.get", "clusters:https://kubernetes.default.svc"), Code.ALLOWED)
    itest.expect_code(check(c, none, "app.get", "applications:dev/web"), Code.DENIED)


def test_email_as_group_and_subject(setup: Setup) -> None:
    # scopes include email, so the email is a group value even with user_subject none.
    _, c, _ = setup(default_cluster(), "none")
    itest.expect_code(check(c, dana, "app.sync", "applications:prod/web"), Code.ALLOWED)

    cl = default_cluster()
    assert cl.rbac_cm is not None
    cl.rbac_cm["policy.csv"] = POLICY + "\np, dana@example.com, projects, update, dev, allow\n"
    cl.rbac_cm["scopes"] = "[groups]"
    _, c, _ = setup(cl, "email")
    itest.expect_code(check(c, dana, "project.update", "projects:dev"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "app.sync", "applications:prod/web"), Code.ALLOWED)  # via g dana -> role:ops
    itest.expect_code(check(c, none, "app.get", "applications:dev/web"), Code.DENIED)  # subject known: real deny
    _, c, _ = setup(cl, "none")
    # without the email scope and user_subject none, dana's user-level rules are invisible: unknown, not deny
    itest.expect_code(check(c, dana, "project.update", "projects:dev"), Code.UNSUPPORTED)


def test_project_roles(setup: Setup) -> None:
    _, c, _ = setup(default_cluster(), "none")
    itest.expect_code(check(c, team_a, "app.sync", "applications:team-a/api"), Code.ALLOWED)
    itest.expect_code(check(c, team_a, "project.get", "projects:team-a"), Code.ALLOWED)
    itest.expect_code(check(c, team_a, "app.sync", "applications:dev/api"), Code.DENIED)
    # The group is only bound inside team-a: for another project the g line is absent.
    cl = default_cluster()
    assert cl.rbac_cm is not None
    cl.rbac_cm["policy.csv"] = "p, role:x, applications, get, */*, allow\ng, some-group, role:x"
    _, c, _ = setup(cl, "none")
    itest.expect_code(check(c, team_a, "app.sync", "applications:dev/api"), Code.DENIED)
    itest.expect_code(check(c, team_a, "app.sync", "applications:team-a/api"), Code.ALLOWED)


def test_default_role_and_builtin(setup: Setup) -> None:
    cl = default_cluster()
    assert cl.rbac_cm is not None
    cl.rbac_cm["policy.default"] = "role:readonly"
    _, c, _ = setup(cl, "none")
    itest.expect_code(check(c, none, "app.get", "applications:prod/web"), Code.ALLOWED)
    itest.expect_code(check(c, none, "app.sync", "applications:prod/web"), Code.DENIED)
    cl = default_cluster()
    assert cl.rbac_cm is not None
    cl.rbac_cm["policy.csv"] = "g, admins, role:admin"
    _, c, _ = setup(cl, "none")
    admin = User(email="x@example.com", groups=("admins",))
    itest.expect_code(check(c, admin, "app.delete", "applications:prod/web"), Code.ALLOWED)
    itest.expect_code(check(c, admin, "app.rollback", "applications:prod/web"), Code.ALLOWED)
    itest.expect_code(check(c, admin, "exec.create", "applications:prod/web"), Code.ALLOWED)
    itest.expect_code(check(c, admin, "extension.invoke", "extensions:metrics"), Code.DENIED)
    itest.expect_code(check(c, none, "app.get", "applications:prod/web"), Code.DENIED)


def test_no_rbac_config_map(setup: Setup) -> None:
    cl = Cluster()
    _, c, _ = setup(cl, "email")
    # Only the builtin policy: the local "admin" account.
    itest.expect_code(check(c, User(email="admin@x"), "app.get", "applications:a/b"), Code.DENIED)
    r = c.probe(background())
    assert "0 policy lines" in r.summary and len(r.warnings) == 1, r


def test_fine_grained_and_rollback_flags(setup: Setup) -> None:
    cl = default_cluster()
    _, c, _ = setup(cl, "none")
    # v3 default: update does not imply update/<resource>.
    itest.expect_code(check(c, sre, "app.update/apps/Deployment/default/web", "applications:dev/web"), Code.ALLOWED)
    itest.expect_code(check(c, sre, "app.update/apps/StatefulSet/default/db", "applications:dev/web"), Code.DENIED)
    itest.expect_code(check(c, sre, "app.delete/apps/StatefulSet/default/db", "applications:dev/web"), Code.DENIED)
    itest.expect_code(check(c, sre, "app.action/apps/Deployment/restart", "applications:dev/web"), Code.ALLOWED)
    itest.expect_code(check(c, sre, "app.action/apps/StatefulSet/restart", "applications:dev/web"), Code.DENIED)
    # rollback checks sync by default; sre has applications * so both pass, dev has sync only.
    itest.expect_code(check(c, dev, "app.rollback", "applications:dev/web"), Code.ALLOWED)

    cl = default_cluster()
    cl.argocd_cm = {"server.rbac.disableApplicationFineGrainedRBACInheritance": "false", "server.rbac.rollback.enforce.enable": "true"}
    _, c, _ = setup(cl, "none")
    itest.expect_code(check(c, sre, "app.update/apps/StatefulSet/default/db", "applications:dev/web"), Code.ALLOWED)
    # v2 inheritance: delete on dev/* is allowed, so the fine-grained delete is too; on prod the explicit deny wins.
    itest.expect_code(check(c, sre, "app.delete/apps/StatefulSet/default/db", "applications:dev/web"), Code.ALLOWED)
    itest.expect_code(check(c, sre, "app.delete/apps/StatefulSet/default/db", "applications:prod/web"), Code.DENIED)
    itest.expect_code(check(c, dev, "app.rollback", "applications:dev/web"), Code.DENIED)


def test_invalid_policy(setup: Setup) -> None:
    cl = default_cluster()
    assert cl.rbac_cm is not None
    cl.rbac_cm["policy.csv"] = "this, is, not, a, good, policy"
    _, c, _ = setup(cl, "none")
    itest.expect_code(check(c, sre, "app.get", "applications:dev/web"), Code.UNSUPPORTED)
    r = c.probe(background())
    assert len(r.warnings) > 0 and "invalid" in r.warnings[0], r
    # An invalid project policy falls back to the policy without the project, as Argo CD does.
    cl = default_cluster()
    cl.projects.append(project("broken", {"name": "r", "policies": ["garbage"], "groups": ["sre"]}))
    _, c, _ = setup(cl, "none")
    itest.expect_code(check(c, sre, "app.get", "applications:broken/x"), Code.ALLOWED)


def test_policy_cache_and_failures(setup: Setup) -> None:
    cl = default_cluster()
    srv, c, now = setup(cl, "none")
    check(c, dev, "app.get", "applications:dev/web")
    reads = cl.reads
    check(c, dev, "app.sync", "applications:dev/web")
    assert cl.reads == reads, "policy re-read within the cache window"
    # A fresh check re-reads the policy inside the window (once it is more
    # than a second old) and the next check is served from what it read.
    now.add(2)
    assert isinstance(c, ArgoConnection)
    c.load(evidence.with_fresh(background()))
    assert cl.reads != reads, "policy not re-read for a fresh check"
    reads = cl.reads
    check(c, dev, "app.sync", "applications:dev/web")
    assert cl.reads == reads, "fresh read not stored"
    now.add(POLICY_CACHE_TTL + 1)
    check(c, dev, "app.sync", "applications:dev/web")
    assert cl.reads != reads, "policy not re-read after expiry"
    now.add(POLICY_CACHE_TTL + 1)

    def fail_check() -> Decision:
        now.add(POLICY_CACHE_TTL + 1)
        return check(c, dev, "app.get", "applications:dev/web")

    itest.failure_cases(srv, fail_check)
    srv.json("GET", "/api/v1/namespaces/argocd/configmaps/argocd-rbac-cm", 403, '{"kind":"Status","code":403}')
    now.add(POLICY_CACHE_TTL + 1)
    itest.expect_code(check(c, dev, "app.get", "applications:dev/web"), Code.CREDENTIAL_REJECTED)


@pytest.mark.parametrize(
    ("action", "resource"),
    [
        ("app.get", "projects:dev"),
        ("app.get", "applications:noslash"),
        ("app.get", "things:dev/web"),
        ("project.get", "projects:"),
        ("app.get", "applications:dev/we b"),
    ],
)
def test_bad_requests(setup: Setup, action: str, resource: str) -> None:
    _, c, _ = setup(default_cluster(), "none")
    itest.expect_code(check(c, dev, action, resource), Code.INVALID_REQUEST)


@pytest.mark.parametrize("bad", ["app.action/apps", "app.action/apps/Deployment/", "app.update/apps/Deployment/x", "app.get/x", "app.action/a b/c/d"])
def test_bad_requests_match_action_rejects(bad: str) -> None:
    # Go: TestBadRequests, second loop.
    assert Integration().match_action(bad) is None, f"match_action({bad!r}) accepted"


@pytest.mark.parametrize(
    "ok",
    ["app.action/apps/Deployment/restart", "app.update/apps/Deployment/default/web", "app.delete//Pod/default/web-0", "app.action/argoproj.io/Rollout/resume"],
)
def test_bad_requests_match_action_accepts(ok: str) -> None:
    # Go: TestBadRequests, third loop.
    assert Integration().match_action(ok) is not None, f"match_action({ok!r}) rejected"


class PanicTransport:
    """A transport whose every request crashes (Go: a RoundTripper that
    panics). TypeError is one of the exception types the cache treats as a
    panic."""

    def send(self, ctx: Any, req: Any, max_body: int = 0) -> Any:
        raise TypeError("fetch")

    def close(self) -> None:
        pass


def panicking_k8s(srv: itest.Server) -> kubernetes.Connection:
    """A kubernetes connection whose every request crashes in its transport."""
    deps, _ = itest.deps(srv)

    def http_client(s: Settings) -> Any:
        return PanicTransport()

    deps.http_client = http_client
    ks = itest.settings("k8s", "kubernetes", {"url": srv.url, "username_template": "{email}"}, {"credential": itest.literal("k8s")})
    return kubernetes.Integration().new(background(), ks, deps)


def test_load_fetch_panic_does_not_wedge(setup: Setup) -> None:
    srv, ic, _ = setup(default_cluster(), "none")
    assert isinstance(ic, ArgoConnection)
    c = ic
    k8s = c.k8s
    c.k8s = panicking_k8s(srv)
    errs: queue.Queue[BaseException | None] = queue.Queue()

    def load() -> None:
        try:
            c.load(background())
            errs.put(None)
        except BaseException as e:
            errs.put(e)

    for _ in range(4):
        threading.Thread(target=load, daemon=True).start()
    for _ in range(4):
        try:
            err = errs.get(timeout=2)
        except queue.Empty:
            pytest.fail("load wedged after fetch panic")
        assert as_error(err, PanicError) is not None, f"err = {err!r}, want PanicError"
    c.k8s = k8s
    ctx, cancel = with_timeout(background(), 2)
    try:
        b = c.load(ctx)
    finally:
        cancel()
    assert isinstance(b, Bundle), f"after panic: {b}"


def test_load_leader_cancel_does_not_abort_waiters(setup: Setup) -> None:
    cl = default_cluster()
    srv, ic, _ = setup(cl, "none")
    assert isinstance(ic, ArgoConnection)
    c = ic
    entered = threading.Event()
    release = threading.Event()
    hits_lock = threading.Lock()
    hits = [0]

    def rbac_cm(w: itest.ResponseWriter, r: itest.Request) -> None:
        with hits_lock:
            hits[0] += 1
        entered.set()
        # Go also returns when the request's context ends; the fetch here
        # is never cancelled, so waiting for release (bounded) is the same.
        release.wait(5)
        w.write(json.dumps({"data": cl.rbac_cm}))

    srv.handle("GET", "/api/v1/namespaces/argocd/configmaps/argocd-rbac-cm", rbac_cm)
    leader_ctx, cancel_leader = with_cancel(background())
    leader_err: queue.Queue[BaseException | None] = queue.Queue()

    def leader() -> None:
        try:
            c.load(leader_ctx)
            leader_err.put(None)
        except BaseException as e:
            leader_err.put(e)

    threading.Thread(target=leader, daemon=True).start()
    assert entered.wait(5)
    waiter_done = threading.Event()
    result: dict[str, Any] = {}

    def waiter() -> None:
        try:
            result["b"] = c.load(background())
        except BaseException as e:
            result["err"] = e
        finally:
            waiter_done.set()

    threading.Thread(target=waiter, daemon=True).start()
    time.sleep(0.01)
    cancel_leader()
    err = leader_err.get(timeout=5)
    assert is_error(err, Cancelled), f"leader err = {err!r}"
    assert not waiter_done.wait(0.02), "waiter returned before the fetch finished"
    release.set()
    assert waiter_done.wait(5)
    wb = result.get("b")
    assert result.get("err") is None and wb is not None, f"waiter got {wb} {result.get('err')}; the leader's cancellation aborted the shared fetch"
    assert wb.user_policy != "", "waiter's bundle has no policy"
    # The abandoned leader's fetch was reused, not aborted and repeated.
    assert hits[0] == 1, f"rbac config map fetched {hits[0]} times, want 1"


# Per-action allow/deny tests (coverage gate). role:ops is applications *,
# plus clusters/projects get; sre is in role:ops. "none" has nothing and the
# policy has user-level rules, so plain denies use a cluster without them.


def ops_cluster() -> Cluster:
    cl = default_cluster()
    assert cl.rbac_cm is not None
    cl.rbac_cm["policy.csv"] = """
p, role:ops, *, *, *, allow
p, role:ops, *, *, */*, allow
p, role:limited, applications, get, dev/*, allow
g, sre, role:ops
g, limited, role:limited
"""
    cl.rbac_cm["scopes"] = "[groups]"
    return cl


limited = User(email="l@example.com", groups=("limited",))


def allow_deny(setup: Setup, action: str, resource: str) -> None:
    _, c, _ = setup(ops_cluster(), "none")
    itest.expect_code(check(c, sre, action, resource), Code.ALLOWED)
    itest.expect_code(check(c, limited, action, resource), Code.DENIED)


def test_action_app_get_allow(setup: Setup) -> None:
    allow_deny(setup, "app.get", "applications:prod/web")


def test_action_app_get_deny(setup: Setup) -> None:
    allow_deny(setup, "app.get", "applications:prod/web")


def test_action_app_create_allow(setup: Setup) -> None:
    allow_deny(setup, "app.create", "applications:dev/web")


def test_action_app_create_deny(setup: Setup) -> None:
    allow_deny(setup, "app.create", "applications:dev/web")


def test_action_app_update_allow(setup: Setup) -> None:
    allow_deny(setup, "app.update", "applications:dev/web")


def test_action_app_update_deny(setup: Setup) -> None:
    allow_deny(setup, "app.update", "applications:dev/web")


def test_action_app_delete_allow(setup: Setup) -> None:
    allow_deny(setup, "app.delete", "applications:dev/web")


def test_action_app_delete_deny(setup: Setup) -> None:
    allow_deny(setup, "app.delete", "applications:dev/web")


def test_action_app_sync_allow(setup: Setup) -> None:
    allow_deny(setup, "app.sync", "applications:dev/web")


def test_action_app_sync_deny(setup: Setup) -> None:
    allow_deny(setup, "app.sync", "applications:dev/web")


def test_action_app_rollback_allow(setup: Setup) -> None:
    allow_deny(setup, "app.rollback", "applications:dev/web")


def test_action_app_rollback_deny(setup: Setup) -> None:
    allow_deny(setup, "app.rollback", "applications:dev/web")


def test_action_app_override_allow(setup: Setup) -> None:
    allow_deny(setup, "app.override", "applications:dev/web")


def test_action_app_override_deny(setup: Setup) -> None:
    allow_deny(setup, "app.override", "applications:dev/web")


def test_action_logs_get_allow(setup: Setup) -> None:
    allow_deny(setup, "logs.get", "logs:dev/web")


def test_action_logs_get_deny(setup: Setup) -> None:
    allow_deny(setup, "logs.get", "logs:dev/web")


def test_action_exec_create_allow(setup: Setup) -> None:
    allow_deny(setup, "exec.create", "exec:dev/web")


def test_action_exec_create_deny(setup: Setup) -> None:
    allow_deny(setup, "exec.create", "exec:dev/web")


def test_action_appset_get_allow(setup: Setup) -> None:
    allow_deny(setup, "appset.get", "applicationsets:dev/s")


def test_action_appset_get_deny(setup: Setup) -> None:
    allow_deny(setup, "appset.get", "applicationsets:dev/s")


def test_action_appset_create_allow(setup: Setup) -> None:
    allow_deny(setup, "appset.create", "applicationsets:dev/s")


def test_action_appset_create_deny(setup: Setup) -> None:
    allow_deny(setup, "appset.create", "applicationsets:dev/s")


def test_action_appset_update_allow(setup: Setup) -> None:
    allow_deny(setup, "appset.update", "applicationsets:dev/s")


def test_action_appset_update_deny(setup: Setup) -> None:
    allow_deny(setup, "appset.update", "applicationsets:dev/s")


def test_action_appset_delete_allow(setup: Setup) -> None:
    allow_deny(setup, "appset.delete", "applicationsets:dev/s")


def test_action_appset_delete_deny(setup: Setup) -> None:
    allow_deny(setup, "appset.delete", "applicationsets:dev/s")


def test_action_project_get_allow(setup: Setup) -> None:
    allow_deny(setup, "project.get", "projects:dev")


def test_action_project_get_deny(setup: Setup) -> None:
    allow_deny(setup, "project.get", "projects:dev")


def test_action_project_create_allow(setup: Setup) -> None:
    allow_deny(setup, "project.create", "projects:new")


def test_action_project_create_deny(setup: Setup) -> None:
    allow_deny(setup, "project.create", "projects:new")


def test_action_project_update_allow(setup: Setup) -> None:
    allow_deny(setup, "project.update", "projects:dev")


def test_action_project_update_deny(setup: Setup) -> None:
    allow_deny(setup, "project.update", "projects:dev")


def test_action_project_delete_allow(setup: Setup) -> None:
    allow_deny(setup, "project.delete", "projects:dev")


def test_action_project_delete_deny(setup: Setup) -> None:
    allow_deny(setup, "project.delete", "projects:dev")


def test_action_cluster_get_allow(setup: Setup) -> None:
    allow_deny(setup, "cluster.get", "clusters:https://k")


def test_action_cluster_get_deny(setup: Setup) -> None:
    allow_deny(setup, "cluster.get", "clusters:https://k")


def test_action_cluster_create_allow(setup: Setup) -> None:
    allow_deny(setup, "cluster.create", "clusters:https://k")


def test_action_cluster_create_deny(setup: Setup) -> None:
    allow_deny(setup, "cluster.create", "clusters:https://k")


def test_action_cluster_update_allow(setup: Setup) -> None:
    allow_deny(setup, "cluster.update", "clusters:https://k")


def test_action_cluster_update_deny(setup: Setup) -> None:
    allow_deny(setup, "cluster.update", "clusters:https://k")


def test_action_cluster_delete_allow(setup: Setup) -> None:
    allow_deny(setup, "cluster.delete", "clusters:https://k")


def test_action_cluster_delete_deny(setup: Setup) -> None:
    allow_deny(setup, "cluster.delete", "clusters:https://k")


def test_action_repo_get_allow(setup: Setup) -> None:
    allow_deny(setup, "repo.get", "repositories:https://r")


def test_action_repo_get_deny(setup: Setup) -> None:
    allow_deny(setup, "repo.get", "repositories:https://r")


def test_action_repo_create_allow(setup: Setup) -> None:
    allow_deny(setup, "repo.create", "repositories:https://r")


def test_action_repo_create_deny(setup: Setup) -> None:
    allow_deny(setup, "repo.create", "repositories:https://r")


def test_action_repo_update_allow(setup: Setup) -> None:
    allow_deny(setup, "repo.update", "repositories:https://r")


def test_action_repo_update_deny(setup: Setup) -> None:
    allow_deny(setup, "repo.update", "repositories:https://r")


def test_action_repo_delete_allow(setup: Setup) -> None:
    allow_deny(setup, "repo.delete", "repositories:https://r")


def test_action_repo_delete_deny(setup: Setup) -> None:
    allow_deny(setup, "repo.delete", "repositories:https://r")


def test_action_writerepo_get_allow(setup: Setup) -> None:
    allow_deny(setup, "writerepo.get", "write_repositories:https://r")


def test_action_writerepo_get_deny(setup: Setup) -> None:
    allow_deny(setup, "writerepo.get", "write_repositories:https://r")


def test_action_writerepo_create_allow(setup: Setup) -> None:
    allow_deny(setup, "writerepo.create", "write_repositories:https://r")


def test_action_writerepo_create_deny(setup: Setup) -> None:
    allow_deny(setup, "writerepo.create", "write_repositories:https://r")


def test_action_writerepo_update_allow(setup: Setup) -> None:
    allow_deny(setup, "writerepo.update", "write_repositories:https://r")


def test_action_writerepo_update_deny(setup: Setup) -> None:
    allow_deny(setup, "writerepo.update", "write_repositories:https://r")


def test_action_writerepo_delete_allow(setup: Setup) -> None:
    allow_deny(setup, "writerepo.delete", "write_repositories:https://r")


def test_action_writerepo_delete_deny(setup: Setup) -> None:
    allow_deny(setup, "writerepo.delete", "write_repositories:https://r")


def test_action_certificate_get_allow(setup: Setup) -> None:
    allow_deny(setup, "certificate.get", "certificates:h")


def test_action_certificate_get_deny(setup: Setup) -> None:
    allow_deny(setup, "certificate.get", "certificates:h")


def test_action_certificate_create_allow(setup: Setup) -> None:
    allow_deny(setup, "certificate.create", "certificates:h")


def test_action_certificate_create_deny(setup: Setup) -> None:
    allow_deny(setup, "certificate.create", "certificates:h")


def test_action_certificate_update_allow(setup: Setup) -> None:
    allow_deny(setup, "certificate.update", "certificates:h")


def test_action_certificate_update_deny(setup: Setup) -> None:
    allow_deny(setup, "certificate.update", "certificates:h")


def test_action_certificate_delete_allow(setup: Setup) -> None:
    allow_deny(setup, "certificate.delete", "certificates:h")


def test_action_certificate_delete_deny(setup: Setup) -> None:
    allow_deny(setup, "certificate.delete", "certificates:h")


def test_action_account_get_allow(setup: Setup) -> None:
    allow_deny(setup, "account.get", "accounts:admin")


def test_action_account_get_deny(setup: Setup) -> None:
    allow_deny(setup, "account.get", "accounts:admin")


def test_action_account_update_allow(setup: Setup) -> None:
    allow_deny(setup, "account.update", "accounts:admin")


def test_action_account_update_deny(setup: Setup) -> None:
    allow_deny(setup, "account.update", "accounts:admin")


def test_action_gpgkey_get_allow(setup: Setup) -> None:
    allow_deny(setup, "gpgkey.get", "gpgkeys:ABCD")


def test_action_gpgkey_get_deny(setup: Setup) -> None:
    allow_deny(setup, "gpgkey.get", "gpgkeys:ABCD")


def test_action_gpgkey_create_allow(setup: Setup) -> None:
    allow_deny(setup, "gpgkey.create", "gpgkeys:ABCD")


def test_action_gpgkey_create_deny(setup: Setup) -> None:
    allow_deny(setup, "gpgkey.create", "gpgkeys:ABCD")


def test_action_gpgkey_delete_allow(setup: Setup) -> None:
    allow_deny(setup, "gpgkey.delete", "gpgkeys:ABCD")


def test_action_gpgkey_delete_deny(setup: Setup) -> None:
    allow_deny(setup, "gpgkey.delete", "gpgkeys:ABCD")


def test_action_extension_invoke_allow(setup: Setup) -> None:
    allow_deny(setup, "extension.invoke", "extensions:x")


def test_action_extension_invoke_deny(setup: Setup) -> None:
    allow_deny(setup, "extension.invoke", "extensions:x")
