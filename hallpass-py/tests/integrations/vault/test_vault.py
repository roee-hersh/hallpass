"""Port of internal/integrations/vault/vault_test.go."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from hallpass.core.context import background
from hallpass.core.decision import Code, Decision, HallpassError
from hallpass.core.integration import Connection, User
from hallpass.core.secret import literal
from hallpass.integrations.vault import Vault
from hallpass.integrations.vault.policy import less_priority, match_pattern
from tests import harness as itest
from tests.harness.spec import SpecOptions, spec_from_env

ACC_OIDC = "auth_oidc_1a2b3c4d"
ACC_TOK = "auth_token_0000aaaa"

ENT_DANA = "e1000000-0000-4000-8000-000000000001"  # dev policy, group team, metadata team=payments
ENT_BOB = "e1000000-0000-4000-8000-000000000002"  # default only
ENT_ROOT = "e1000000-0000-4000-8000-000000000003"  # root
ENT_OPS = "e1000000-0000-4000-8000-000000000004"  # ops
ENT_OFF = "e1000000-0000-4000-8000-000000000005"  # disabled
GRP_TEAM = "g1000000-0000-4000-8000-000000000001"  # team-readers
GRP_EXT = "g1000000-0000-4000-8000-000000000002"  # external group, policy missing in Vault

dana = User(email="dana@example.com")
bob = User(email="bob@example.com")
root = User(email="root@example.com")
ops = User(email="ops@example.com")

DEV_POLICY = """
# Developers: their own space, shared configs, their team's space.
path "secret/data/dev/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/dev/*" { capabilities = ["list", "read", "delete"] }
path "secret/destroy/dev/*" { capabilities = ["update"] }
path "secret/data/dev/locked" {
  capabilities = ["deny"]
}
path "secret/data/shared/+/config" {
  capabilities = ["read"]
}
path "secret/data/teams/{{identity.entity.metadata.team}}/*" {
  capabilities = ["read", "create", "update"]
}
path "secret/data/x/{{identity.entity.metadata.missing}}/*" {
  capabilities = ["deny"]
}
path "kv1/legacy/*" {
  policy = "read"
}
path "secret/data/dev/params" {
  capabilities = ["create", "update"]
  allowed_parameters = {
    "key" = []
  }
}
path "secret/data/dev/wrapped" {
  capabilities = ["read"]
  min_wrapping_ttl = "1s"
}
path "secret/data/dev/half" { capabilities = ["update"] }
path "team/secrets/data/*" { capabilities = ["read"] }
"""

TEAM_POLICY = '{"path": {"secret/data/shared/*": {"capabilities": ["read", "list"]}, "secret/metadata/shared/*": {"capabilities": ["list"]}}}'

OPS_POLICY = """
path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "secret/data/prod/*" { capabilities = ["deny"] }
path "sys/*" { capabilities = ["sudo", "read"] }
path "pki/issue/web" { capabilities = ["update"] }
"""

DEFAULT_POLICY = """
path "auth/token/lookup-self" { capabilities = ["read"] }
path "sys/capabilities-self" { capabilities = ["update"] }
"""


@dataclass
class FakeEntity:
    id: str
    name: str
    email: str
    disabled: bool
    policies: list[str] | None
    groups: list[str] | None
    metadata: dict[str, str] | None


@dataclass
class Fake:
    mu: threading.Lock = field(default_factory=threading.Lock)
    errors: list[str] = field(default_factory=list)
    token: str = itest.CANARY + "tok"
    role_id: str = "r0le-id"
    secret_id: str = itest.CANARY + "sid"
    entities: list[FakeEntity] = field(default_factory=list)
    groups: dict[str, dict[str, Any]] = field(default_factory=dict)
    policies: dict[str, str] = field(default_factory=dict)
    mounts: dict[str, dict[str, Any]] = field(default_factory=dict)
    logins: int = 0
    policy_reads: int = 0
    status: int = 0
    forbidden: dict[str, bool] = field(default_factory=dict)

    def api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        with self.mu:
            self._api(w, r)

    def _api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        p = r.path.removeprefix("/v1")
        if p == "/auth/approle/login":
            body = _decode(r.body)
            if body.get("role_id") != self.role_id or body.get("secret_id") != self.secret_id:
                vault_err(w, 400, "invalid role or secret ID")
                return
            self.logins += 1
            write(w, 200, {"auth": {"client_token": self.token, "lease_duration": 3600, "renewable": True, "policies": ["hallpass"]}})
            return
        if r.header.get("X-Vault-Token") != self.token:
            vault_err(w, 403, "permission denied")
            return
        if self.status != 0:
            vault_err(w, self.status, "boom")
            return
        if self.forbidden.get(p):
            vault_err(w, 403, "1 error occurred: permission denied")
            return
        if p == "/sys/auth":
            write(
                w,
                200,
                wrap(
                    {
                        "oidc/": {"accessor": ACC_OIDC, "type": "oidc", "description": itest.CANARY, "config": {"default_lease_ttl": 0}},
                        "token/": {"accessor": ACC_TOK, "type": "token"},
                    }
                ),
            )
        elif p == "/sys/mounts":
            write(w, 200, wrap(dict(self.mounts)))
        elif p == "/identity/lookup/entity":
            body = _decode(r.body)
            if body.get("alias_mount_accessor") != ACC_OIDC:
                self.errors.append(f"lookup with accessor {body.get('alias_mount_accessor')!r}")
            for e in self.entities:
                if e.email.lower() == str(body.get("alias_name", "")).lower():
                    write(
                        w,
                        200,
                        wrap({"id": e.id, "name": e.name, "policies": e.policies, "aliases": [], "metadata": e.metadata, "group_ids": e.groups}),
                    )
                    return
            w.write_header(204)
        elif p.startswith("/identity/entity/id/"):
            eid = p.removeprefix("/identity/entity/id/")
            for e in self.entities:
                if e.id == eid:
                    direct: list[str] | None = None
                    inherited: list[str] | None = None
                    for i, g in enumerate(e.groups or []):
                        if i == 0:
                            direct = [*(direct or []), g]
                        else:
                            inherited = [*(inherited or []), g]
                    write(
                        w,
                        200,
                        wrap(
                            {
                                "id": e.id,
                                "name": e.name,
                                "disabled": e.disabled,
                                "policies": e.policies,
                                "metadata": e.metadata,
                                "group_ids": e.groups,
                                "direct_group_ids": direct,
                                "inherited_group_ids": inherited,
                                "aliases": [
                                    {
                                        "id": "alias-" + e.id,
                                        "name": e.email,
                                        "mount_accessor": ACC_OIDC,
                                        "mount_path": "auth/oidc/",
                                        "mount_type": "oidc",
                                        "metadata": {"role": "dev"},
                                    }
                                ],
                            }
                        ),
                    )
                    return
            vault_err(w, 404, "")
        elif p.startswith("/identity/group/id/"):
            g = self.groups.get(p.removeprefix("/identity/group/id/"))
            if g is None:
                vault_err(w, 404, "")
                return
            write(w, 200, wrap(g))
        elif p.startswith("/sys/policies/acl/"):
            name = p.removeprefix("/sys/policies/acl/")
            text = self.policies.get(name)
            if text is None:
                vault_err(w, 404, "")
                return
            self.policy_reads += 1
            write(w, 200, wrap({"name": name, "policy": text}))
        elif p == "/auth/token/lookup-self":
            write(
                w,
                200,
                wrap({"display_name": "approle-hallpass", "policies": ["default", "hallpass"], "entity_id": "", "meta": {"x": itest.CANARY}}),
            )
        else:
            self.errors.append(f"fake: no route for {r.method} {p}")
            vault_err(w, 404, "")


def _decode(body: bytes) -> dict[str, Any]:
    try:
        v = json.loads(body)
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def new_fake() -> Fake:
    return Fake(
        entities=[
            FakeEntity(ENT_DANA, "dana", "dana@example.com", False, ["dev"], [GRP_TEAM, GRP_EXT], {"team": "payments", "note": itest.CANARY}),
            FakeEntity(ENT_BOB, "bob", "bob@example.com", False, None, None, None),
            FakeEntity(ENT_ROOT, "rooty", "root@example.com", False, ["root"], None, None),
            FakeEntity(ENT_OPS, "ops", "ops@example.com", False, ["ops"], None, None),
            FakeEntity(ENT_OFF, "off", "off@example.com", True, ["dev"], None, None),
        ],
        groups={
            GRP_TEAM: {"id": GRP_TEAM, "name": "team", "type": "internal", "policies": ["team-readers"], "metadata": {"x": itest.CANARY}},
            GRP_EXT: {"id": GRP_EXT, "name": "ext", "type": "external", "policies": ["gone-policy"]},
        },
        policies={"dev": DEV_POLICY, "team-readers": TEAM_POLICY, "ops": OPS_POLICY, "default": DEFAULT_POLICY, "root": ""},
        mounts={
            "secret/": {"type": "kv", "options": {"version": "2"}, "description": itest.CANARY},
            "kv1/": {"type": "kv", "options": {"version": "1"}},
            "team/secrets/": {"type": "kv", "options": {"version": "2"}},
            "pki/": {"type": "pki", "options": None},
        },
    )


def write(w: itest.ResponseWriter, status: int, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    if v is not None:
        w.write(json.dumps(v) + "\n")


def vault_err(w: itest.ResponseWriter, status: int, msg: str) -> None:
    write(w, status, {"errors": [msg + " " + itest.CANARY]})


def wrap(data: Any) -> dict[str, Any]:
    return {"request_id": "r", "lease_id": "", "renewable": False, "lease_duration": 0, "data": data, "wrap_info": None, "warnings": None, "auth": None}


class Env:
    """Makes fake servers and connections, and checks them when the test ends."""

    def __init__(self) -> None:
        self.made: list[tuple[itest.Server, Fake | None]] = []

    def new_server(self) -> tuple[itest.Server, Fake]:
        srv = itest.Server()
        srv.use_spec(spec_from_env("vault"), SpecOptions(strip_prefix=[r"/v1"]))
        f = new_fake()
        srv.handle("", "/v1/*", f.api)
        self.made.append((srv, f))
        return srv, f

    def bare_server(self) -> itest.Server:
        srv = itest.Server()
        self.made.append((srv, None))
        return srv

    def setup_values(self, values: dict[str, str] | None, cred: str) -> tuple[itest.Server, Fake, Connection]:
        srv, f = self.new_server()
        deps, _ = itest.deps(srv)
        base = {"url": srv.url, "alias_mount": "oidc/"}
        base.update(values or {})
        if cred == "":
            cred = f.token
        s = itest.settings("vault", "vault", base, {"credential": literal(cred)})
        c = Vault().new(background(), s, deps)
        return srv, f, c

    def setup(self) -> tuple[itest.Server, Fake, Connection]:
        return self.setup_values(None, "")

    def close(self) -> None:
        for srv, f in self.made:
            srv.close()
            if f is not None:
                assert not f.errors, "\n".join(f.errors)
            assert not srv.spec_errors, "requests did not match the API description:\n" + "\n".join(srv.spec_errors)


@pytest.fixture
def env() -> Iterator[Env]:
    e = Env()
    yield e
    e.close()


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, Vault(), u, action, resource)


def expect(d: Decision, code: Code, text: str) -> None:
    itest.expect_code(d, code)
    if text != "":
        assert text in d.text, f"text {d.text!r} does not contain {text!r}"
    itest.assert_no_canary(d.text)


# -- the action table ------------------------------------------------------------


def test_action_secret_read_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.ALLOWED, 'policy dev grants read on "secret/data/dev/*", covering secret/data/dev/app')
    # A group's policy.
    expect(check(c, dana, "secret.read", "kv:secret/shared/db"), Code.ALLOWED, "team-readers")
    # + spans one segment; the more specific pattern wins over shared/*.
    expect(check(c, dana, "secret.read", "kv:secret/shared/a/config"), Code.ALLOWED, '"secret/data/shared/+/config"')
    # A template resolved from entity metadata.
    expect(check(c, dana, "secret.read", "kv:secret/teams/payments/db"), Code.ALLOWED, "secret/data/teams/payments/*")
    # KV v1 keeps the logical path; the legacy policy attribute maps to read.
    expect(check(c, dana, "secret.read", "kv:kv1/legacy/x"), Code.ALLOWED, '"kv1/legacy/*", covering kv1/legacy/x')
    # root is not evaluated: Vault refuses it next to other policies.
    expect(check(c, root, "secret.read", "kv:secret/prod/db"), Code.UNSUPPORTED, "root policy")
    # path: takes the API path as is.
    expect(check(c, ops, "secret.read", "path:secret/data/dev/x"), Code.ALLOWED, "ops")
    # A mount spanning two segments.
    expect(check(c, dana, "secret.read", "kv:team/secrets/app"), Code.ALLOWED, "team/secrets/data/*")


def test_action_secret_read_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "secret.read", "kv:secret/dev/app"), Code.DENIED, "no path in bob@example.com's policies (default) matches secret/data/dev/app")
    # An explicit deny on the exact path beats the glob.
    expect(check(c, dana, "secret.read", "kv:secret/dev/locked"), Code.DENIED, 'policy path "secret/data/dev/locked" denies')
    # ops: secret/* grants, secret/data/prod/* denies and is more specific.
    expect(check(c, ops, "secret.read", "kv:secret/prod/db"), Code.DENIED, "denies")
    # The template resolves to another team.
    expect(check(c, dana, "secret.read", "kv:secret/teams/other/db"), Code.DENIED, "")
    # shared/+/config grants read only; a deeper path falls to shared/*, read+list.
    expect(check(c, dana, "secret.read", "kv:secret/shared/a/b/config"), Code.ALLOWED, "")


def test_action_secret_write_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "secret.write", "kv:secret/dev/app"), Code.ALLOWED, "create+update")
    expect(check(c, dana, "secret.write", "kv:secret/teams/payments/x"), Code.ALLOWED, "")


def test_action_secret_write_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "secret.write", "kv:secret/shared/a/config"), Code.DENIED, "grants neither create nor update")
    expect(check(c, dana, "secret.write", "kv:kv1/legacy/x"), Code.DENIED, "")
    expect(check(c, bob, "secret.write", "kv:secret/dev/app"), Code.DENIED, "")


def test_write_half_granted(env: Env) -> None:
    _, _, c = env.setup()
    expect(
        check(c, dana, "secret.write", "kv:secret/dev/half"),
        Code.UNSUPPORTED,
        "grants update but not create, so the write succeeds only if the secret already exists",
    )


def test_action_secret_delete_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "secret.delete", "kv:secret/dev/app"), Code.ALLOWED, "delete")


def test_action_secret_delete_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "secret.delete", "kv:secret/shared/db"), Code.DENIED, "grants list, read but not delete")


def test_action_secret_list_allow(env: Env) -> None:
    _, _, c = env.setup()
    # LIST is matched as a prefix: secret/metadata/dev/ against secret/metadata/dev/*.
    expect(check(c, dana, "secret.list", "kv:secret/dev"), Code.ALLOWED, '"secret/metadata/dev/*", covering secret/metadata/dev')
    expect(check(c, dana, "secret.list", "kv:secret/shared/a"), Code.ALLOWED, "team-readers")


def test_action_secret_list_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "secret.list", "kv:secret/teams/payments"), Code.DENIED, "")
    expect(check(c, bob, "secret.list", "kv:secret/dev"), Code.DENIED, "")


def test_action_secret_metadata_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "secret.metadata", "kv:secret/dev/app"), Code.ALLOWED, "secret/metadata/dev/*")


def test_action_secret_metadata_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "secret.metadata", "kv:secret/shared/db"), Code.DENIED, "")
    expect(check(c, dana, "secret.metadata", "kv:kv1/legacy/x"), Code.UNSUPPORTED, "KV v1 mount")


def test_action_secret_destroy_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "secret.destroy", "kv:secret/dev/app"), Code.ALLOWED, "secret/destroy/dev/*")


def test_action_secret_destroy_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "secret.destroy", "kv:secret/shared/db"), Code.DENIED, "")


def test_raw_capabilities(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, ops, "raw:sudo", "path:sys/seal"), Code.ALLOWED, '"sys/*"')
    expect(check(c, ops, "raw:update", "path:pki/issue/web"), Code.ALLOWED, "")
    expect(check(c, dana, "raw:sudo", "path:sys/seal"), Code.DENIED, "")
    expect(check(c, ops, "raw:delete", "path:pki/issue/web"), Code.DENIED, "grants update but not delete")
    # LIST with raw is a prefix match too.
    expect(check(c, dana, "raw:list", "path:secret/metadata/dev"), Code.ALLOWED, "")
    expect(check(c, bob, "raw:read", "path:auth/token/lookup-self"), Code.ALLOWED, "default")


def test_unknowns(env: Env) -> None:
    _, _, c = env.setup()
    # A parameter constraint on a write.
    expect(check(c, dana, "secret.write", "kv:secret/dev/params"), Code.UNSUPPORTED, "request parameters")
    # A wrapping requirement.
    expect(check(c, dana, "secret.read", "kv:secret/dev/wrapped"), Code.UNSUPPORTED, "response wrapping")
    # A template that does not resolve, on a deny stanza that could match.
    expect(check(c, dana, "secret.read", "kv:secret/x/anything/z"), Code.UNSUPPORTED, "template hallpass could not resolve")
    # A mount that is not KV.
    expect(check(c, ops, "secret.read", "kv:pki/issue/web"), Code.UNSUPPORTED, "not kv")
    # A mount that does not exist, and a mount without a key.
    expect(check(c, ops, "secret.read", "kv:nope/x"), Code.RESOURCE_NOT_VISIBLE, "no secrets engine")
    expect(check(c, ops, "secret.read", "kv:team/secrets"), Code.RESOURCE_NOT_VISIBLE, "")


def test_unresolved_template_outside_winner(env: Env) -> None:
    _, f, c = env.setup()
    with f.mu:
        # Rendered by Vault this may become secret/data/dev/* and add a deny.
        f.policies["dev"] = (
            DEV_POLICY
            + """
path "secret/data/{{identity.groups.names.team.metadata.region}}/*" { capabilities = ["deny"] }
"""
        )
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.UNSUPPORTED, "template hallpass could not resolve")


def test_list_deny_without_slash(env: Env) -> None:
    _, f, c = env.setup()
    with f.mu:
        f.policies["dev"] = """
path "secret/metadata/*" { capabilities = ["list"] }
path "secret/metadata/prod" { capabilities = ["deny"] }
path "secret/metadata/+" { capabilities = ["deny"] }
path "secret/metadata/dev/*" { capabilities = ["list"] }
"""
    # The exact deny is written without the trailing slash Vault adds.
    expect(check(c, dana, "secret.list", "kv:secret/prod"), Code.DENIED, "denies")
    # A + rule matches the slash-less form too.
    expect(check(c, dana, "secret.list", "kv:secret/other"), Code.DENIED, "denies")
    expect(check(c, dana, "secret.list", "kv:secret/dev/a"), Code.ALLOWED, "")


def test_leading_slash_in_stanza(env: Env) -> None:
    _, f, c = env.setup()
    with f.mu:
        f.policies["dev"] = """
path "secret/*" { capabilities = ["read"] }
path "/secret/data/prod/*" { capabilities = ["deny"] }
"""
    expect(check(c, dana, "secret.read", "kv:secret/prod/db"), Code.DENIED, "denies")
    expect(check(c, dana, "secret.read", "kv:secret/dev/db"), Code.ALLOWED, "")


def test_template_value_with_slash(env: Env) -> None:
    _, f, c = env.setup()
    with f.mu:
        f.policies["dev"] = """
path "secret/*" { capabilities = ["read"] }
path "secret/data/{{identity.entity.metadata.scope}}" { capabilities = ["deny"] }
"""
        for e in f.entities:
            if e.id == ENT_DANA:
                e.metadata = {"scope": "a/b"}
    # Rendered, the deny is secret/data/a/b; a value with a slash cannot be
    # placed, so anything under secret/data/ is unknown.
    expect(check(c, dana, "secret.read", "kv:secret/a/b"), Code.UNSUPPORTED, "template")
    expect(check(c, dana, "secret.read", "kv:secret/zzz"), Code.UNSUPPORTED, "template")
    expect(check(c, dana, "raw:read", "path:secret/other"), Code.ALLOWED, "")


def test_parameters_on_read(env: Env) -> None:
    _, f, c = env.setup()
    with f.mu:
        f.policies["dev"] = 'path "secret/data/dev/*" { capabilities = ["read"] required_parameters = ["version"] }'
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.UNSUPPORTED, "request parameters")


def test_control_group_blocks_parse(env: Env) -> None:
    _, f, c = env.setup()
    with f.mu:
        f.policies["dev"] = """
path "secret/data/dev/*" {
  capabilities = ["read"]
  control_group = {
    factor "managers" {
      identity {
        group_names = ["managers"]
        approvals = 1
      }
    }
  }
}"""
    # The control group itself is not modelled; the stanza still parses and
    # grants read.
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.ALLOWED, "")


def test_policy_syntax_unknown(env: Env) -> None:
    _, f, c = env.setup()
    with f.mu:
        f.policies["dev"] = """path "secret/*" { capabilities = <<EOF
read
EOF
}"""
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.UNSUPPORTED, "syntax hallpass does not parse")


def test_token_policies(env: Env) -> None:
    _, _, c = env.setup_values({"token_policies": "ops, default"}, "")
    # bob has nothing on the entity, but every login through oidc/ gets ops.
    expect(check(c, bob, "secret.read", "kv:secret/dev/app"), Code.ALLOWED, "ops")


@pytest.mark.parametrize(
    ("low", "high"),
    [
        ("secret/*", "secret/data/*"),  # earlier glob is lower
        ("secret/+/+/foo/*", "secret/*"),  # rules 1 and 2 tie; more + segments is lower
        ("secret/data/*", "secret/data/foo"),  # glob is lower than exact
        ("secret/data/foo", "secret/data/foobar"),  # shorter is lower
        ("secret/data/abc", "secret/data/abd"),  # lexicographic
        ("secret/+/config", "secret/data/config"),  # wildcard earlier is lower
        ("secret/data/+/+", "secret/data/+/x"),  # more + is lower
    ],
)
def test_priority_rules(low: str, high: str) -> None:
    assert less_priority(low, high) and not less_priority(high, low), f"{low!r} should be lower priority than {high!r}"


def test_priority_rules_documented_example() -> None:
    # Go: TestPriorityRules (its trailing assertion). The documented
    # example: secret/* and secret/+/+/foo/* tie on rules 1 and 2 and end at
    # rule 3, which gives secret/+/+/foo/* lower priority.
    assert less_priority("secret/+/+/foo/*", "secret/*"), "secret/+/+/foo/* should be lower than secret/*"


@pytest.mark.parametrize(
    ("pattern", "path", "want"),
    [
        ("secret/*", "secret/data/foo", True),
        ("secret/*", "secret/", True),
        ("secret/*", "secrets/x", False),
        ("secret/data/foo", "secret/data/foo", True),
        ("secret/data/foo", "secret/data/foobar", False),
        ("secret/+/foo", "secret/a/foo", True),
        ("secret/+/foo", "secret/a/b/foo", False),
        ("secret/+/foo", "secret//foo", True),
        ("secret/ab+/foo", "secret/abc/foo", False),  # + is a wildcard only as a whole segment
        ("secret/ab+/foo", "secret/ab+/foo", True),
        ("secret/+", "secret/a", True),
        ("secret/+", "secret", False),
        ("*", "anything/at/all", True),
        ("secret/+/+/foo/*", "secret/a/b/foo/bar", True),
        ("secret/+/+/foo/*", "secret/a/foo/bar", False),
        ("a*b", "axb", False),  # * only globs at the end; elsewhere it is literal
        ("a*b", "a*b", True),
        ("sys/*", "sys/seal", True),
    ],
)
def test_match_pattern(pattern: str, path: str, want: bool) -> None:
    assert match_pattern(pattern, path) == want, f"match({pattern!r}, {path!r}) = {not want}"


# -- identity --------------------------------------------------------------------


def test_identity(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, User(email="nobody@example.com"), "secret.read", "kv:secret/dev/app"), Code.USER_NOT_FOUND, "no Vault entity has an alias")
    expect(check(c, User(email="off@example.com"), "secret.read", "kv:secret/dev/app"), Code.DENIED, "disabled")
    expect(check(c, User(email="not an email"), "secret.read", "kv:secret/dev/app"), Code.INVALID_REQUEST, "")


def test_identity_attrs(env: Env) -> None:
    _, _, c = env.setup()
    ident = c.resolve_identity(background(), dana)
    assert (
        ident.id == ENT_DANA
        and ident.attr("entity_name") == "dana"
        and ident.attr("policies") == "dev,gone-policy,team-readers"
        and ident.attr("meta:team") == "payments"
        and ident.attr("group:" + GRP_TEAM) == "team"
        and ident.attr("alias:" + ACC_OIDC + ":name") == "dana@example.com"
    ), f"identity {ident}"
    assert len(ident.groups) == 2, f"groups {ident.groups}"
    # Metadata values are the operator's, not secrets; the canary sits in
    # fields hallpass does not copy.
    for k, v in ident.attrs.items():
        if k != "meta:note":
            itest.assert_no_canary(k + "=" + v)


def test_caller_groups_ignored(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, User(email="bob@example.com", groups=(GRP_TEAM, "team")), "secret.read", "kv:secret/shared/db"), Code.DENIED, "")


def test_missing_policy_is_skipped(env: Env) -> None:
    srv, _, c = env.setup()
    # dana's external group names gone-policy, which Vault does not have.
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.ALLOWED, "")
    seen = any(call.path.endswith("/sys/policies/acl/gone-policy") for call in srv.calls())
    assert seen, "the missing policy was not read"


def test_policies_are_cached(env: Env) -> None:
    _, f, c = env.setup()
    check(c, dana, "secret.read", "kv:secret/dev/app")
    check(c, dana, "secret.write", "kv:secret/dev/app")
    with f.mu:
        # dev, team-readers, default read once each; gone-policy is 404.
        assert f.policy_reads == 3, f"policies read {f.policy_reads} times, want 3"


def test_wrong_alias_mount(env: Env) -> None:
    _, _, c = env.setup_values({"alias_mount": "ldap/"}, "")
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.INVALID_REQUEST, "not an enabled auth method")


def test_forbidden(env: Env) -> None:
    _, f, c = env.setup()
    with f.mu:
        f.forbidden["/sys/policies/acl/dev"] = True
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.CREDENTIAL_REJECTED, "permission denied")
    _, _, c = env.setup_values(None, "wrong")
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.CREDENTIAL_REJECTED, "")


def test_app_role(env: Env) -> None:
    srv, f, c = env.setup_values({"auth_mode": "approle", "role_id": "r0le-id"}, itest.CANARY + "sid")
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.ALLOWED, "")
    expect(check(c, ops, "secret.read", "kv:secret/dev/app"), Code.ALLOWED, "")
    with f.mu:
        logins = f.logins
    assert logins == 1, f"{logins} logins, want 1 (token cached)"
    for call in srv.calls():
        if call.path.endswith("/login"):
            assert b'"role_id":"r0le-id"' in call.body, f"login body {call.body!r}"
    # A revoked token: one re-login, then success.
    with f.mu:
        f.token = itest.CANARY + "tok2"
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.ALLOWED, "")
    # A path hallpass may not read: at most one re-login per token, not one
    # per denied request.
    with f.mu:
        f.forbidden["/identity/lookup/entity"] = True  # never cached
        before = f.logins
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.CREDENTIAL_REJECTED, "")
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.CREDENTIAL_REJECTED, "")
    with f.mu:
        extra = f.logins - before
    assert extra <= 1, f"{extra} re-logins for a permission denial, want at most 1"
    # A wrong secret id.
    _, _, c = env.setup_values({"auth_mode": "approle", "role_id": "r0le-id"}, "bad")
    expect(check(c, dana, "secret.read", "kv:secret/dev/app"), Code.CREDENTIAL_REJECTED, "AppRole login")


def test_namespace_header(env: Env) -> None:
    srv, _, c = env.setup_values({"namespace": "admin/team"}, "")
    check(c, dana, "secret.read", "kv:secret/dev/app")
    for call in srv.calls():
        assert call.header.get("X-Vault-Namespace") == "admin/team", f"{call.path} without namespace header"


INVALID_CASES = [
    ("secret.read", "kv:secret"),
    ("secret.read", "kv:secret/"),
    ("secret.read", "kv:secret/a b"),
    ("secret.read", "kv:secret/*"),
    ("secret.read", "kv:secret/+/x"),
    ("secret.read", "kv:secret/../x"),
    ("secret.read", "kv:secret/./x"),
    ("secret.read", "kv:secret/x?v=1"),
    ("secret.read", "path:"),
    ("secret.read", "mount:x"),
    ("secret.destroy", "path:secret/destroy/x"),
    ("secret.metadata", "path:secret/metadata/x"),
    ("raw:read", "kv:secret/x"),
    ("secret.read", "kv:secret//x"),
]


def test_invalid_requests(env: Env) -> None:
    _, _, c = env.setup()
    for action, resource in INVALID_CASES:
        d = check(c, dana, action, resource)
        assert d.code == Code.INVALID_REQUEST, f"{action} {resource}: {d.code} {d.text}"
    for bad in ("raw:deny", "raw:root", "raw:READ", "raw:"):
        assert Vault().match_action(bad) is None, f"{bad!r} accepted"


def test_failures(env: Env) -> None:
    srv, _, c = env.setup()
    itest.failure_cases(srv, lambda: check(c, dana, "secret.read", "kv:secret/dev/app"))


def test_new_validation(env: Env) -> None:
    srv = env.bare_server()
    deps, _ = itest.deps(srv)
    cases: list[tuple[dict[str, str], bool]] = [
        ({"url": srv.url, "alias_mount": "oidc/"}, False),
        ({"alias_mount": "oidc/"}, True),
        ({"url": srv.url}, True),
        ({"url": srv.url, "alias_mount": "oidc/", "auth_mode": "approle"}, True),
        ({"url": srv.url, "alias_mount": "oidc/", "auth_mode": "magic"}, True),
        ({"url": srv.url, "alias_mount": "oidc/", "token_policies": "a b"}, True),
        ({"url": srv.url, "alias_mount": "oidc/", "token_policies": "root"}, True),
        ({"url": srv.url, "alias_mount": "oidc/", "namespace": "a b"}, True),
    ]
    for values, secret in cases:
        secrets = {"credential": literal("x")} if secret else {}
        with pytest.raises(Exception):  # noqa: B017 - Go: any error
            Vault().new(background(), itest.settings("vault", "vault", values, secrets), deps)


def test_probe(env: Env) -> None:
    _, _, c = env.setup()
    res = c.probe(background())
    assert "approle-hallpass" in res.summary and ACC_OIDC in res.summary and len(res.warnings) == 2, f"probe {res}"
    itest.assert_no_canary(res.summary)
    _, _, c = env.setup_values(None, "wrong")
    with pytest.raises(HallpassError) as ei:
        c.probe(background())
    assert ei.value.code == Code.CREDENTIAL_REJECTED, f"bad token: {ei.value}"


def test_no_secret_in_logs(env: Env) -> None:
    srv, f = env.new_server()
    deps, logs = itest.deps(srv)
    s = itest.settings("vault", "vault", {"url": srv.url, "alias_mount": "oidc/"}, {"credential": literal(f.token)})
    c = Vault().new(background(), s, deps)
    check(c, dana, "secret.read", "kv:secret/dev/app")
    check(c, dana, "secret.read", "kv:nope/x")
    itest.assert_no_canary(logs.text())
