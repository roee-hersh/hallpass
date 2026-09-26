"""The vault integration against a real Vault.

Starts ``vault server -dev`` (hashicorp/vault:1.17) in Docker on a random
localhost port, configures it through its HTTP API (ACL policies in HCL and
JSON with path globs, "+" segments, deny, the legacy ``policy`` attribute,
identity templates; entities, entity aliases on the token auth mount,
nested identity groups, a token role), then asks the Python vault
integration through the real engine (``hallpass.Hallpass``) and checks
every answer against Vault's own: ``sys/capabilities`` for a token issued
to the same entity through ``auth/token/create/<role>`` with
``entity_alias``, which carries exactly the entity's, its groups' and the
role's policies plus default.

hallpass maps a user to the entity whose alias on ``alias_mount`` is the
user's email; the token auth mount is used as that mount because a token
role can mint tokens bound to such an alias, which gives the ground truth.

Runs when Docker is reachable and the image is present locally (it is never
pulled). HALLPASS_REAL=1 turns a missing Docker or image into a failure
instead of a skip; HALLPASS_REAL=0 skips.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

import hallpass

IMAGE = os.environ.get("HALLPASS_VAULT_IMAGE", "hashicorp/vault:1.17")
ROOT_TOKEN = "hallpass-real-root"
CONNECTION = "vault-real"

# -- the policies ---------------------------------------------------------------
#
# @ACC@ is the token auth mount's accessor, known once Vault runs.

TEAM_POLICY = json.dumps(
    {
        "path": {
            "secret/data/shared/*": {"capabilities": ["read", "list"]},
            "secret/metadata/shared/*": {"capabilities": ["list"]},
            "secret/data/g/{{identity.groups.names.team.id}}/*": {"capabilities": ["read"]},
        }
    }
)

ORG_POLICY = 'path "secret/data/org/*" { capabilities = ["read"] }'

OPS_POLICY = """
path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "secret/data/prod/*" { capabilities = ["deny"] }
path "sys/*" { capabilities = ["sudo", "read"] }
path "pki/issue/web" { capabilities = ["update"] }
path "kv1/+/app" { capabilities = ["read"] }
path "kv1/w/*" { policy = "write" }
"""

LISTER_POLICY = """
path "secret/metadata/*" { capabilities = ["list"] }
path "secret/metadata/prod" { capabilities = ["deny"] }
path "secret/metadata/+" { capabilities = ["deny"] }
path "secret/metadata/dev/*" { capabilities = ["list"] }
path "/secret/data/lead/*" { capabilities = ["read"] }
"""

# Every token through the role gets it; the connection declares it in
# token_policies, as the auth role's policies are not on the entity.
BASE_POLICY = 'path "secret/data/base/*" { capabilities = ["read"] }'


DEV_POLICY_TEXT = """
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
path "secret/data/users/{{identity.entity.aliases.@ACC@.name}}/*" {
  capabilities = ["read"]
}
path "kv1/legacy/*" {
  policy = "read"
}
path "secret/data/dev/half" { capabilities = ["update"] }
path "secret/data/dev/createonly" { capabilities = ["create"] }
path "secret/data/+/+/deep" { capabilities = ["read"] }
"""


@dataclass
class Person:
    email: str
    policies: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)
    # Disabled after its token is minted.
    disabled: bool = False


PEOPLE = [
    Person("dana@example.com", ["dev"], {"team": "payments"}),
    Person("bob@example.com"),
    Person("ops@example.com", ["ops"]),
    Person("lister@example.com", ["lister"]),
    Person("off@example.com", ["dev"], disabled=True),
]


@dataclass(frozen=True)
class Case:
    user: str
    action: str
    resource: str
    # What the scenario is built to show; hallpass and Vault must both agree.
    want: str


CASES = [
    # dana: entity policy dev, group team (team-readers), parent group org (orgp).
    Case("dana@example.com", "secret.read", "kv:secret/dev/app", "allowed"),
    Case("dana@example.com", "secret.read", "kv:secret/dev/locked", "denied"),
    Case("dana@example.com", "secret.read", "kv:secret/shared/a/config", "allowed"),
    Case("dana@example.com", "secret.read", "kv:secret/shared/db", "allowed"),
    Case("dana@example.com", "secret.read", "kv:secret/teams/payments/db", "allowed"),
    Case("dana@example.com", "secret.read", "kv:secret/teams/other/db", "denied"),
    Case("dana@example.com", "secret.read", "kv:secret/users/dana@example.com/x", "allowed"),
    Case("dana@example.com", "secret.read", "kv:secret/users/bob@example.com/x", "denied"),
    Case("dana@example.com", "secret.read", "kv:secret/g/{team}/x", "allowed"),
    Case("dana@example.com", "secret.read", "kv:secret/g/{org}/x", "denied"),
    Case("dana@example.com", "secret.read", "kv:secret/org/a", "allowed"),
    Case("dana@example.com", "secret.read", "kv:secret/a/b/deep", "allowed"),
    Case("dana@example.com", "secret.read", "kv:secret/a/deep", "denied"),
    Case("dana@example.com", "secret.read", "kv:kv1/legacy/x", "allowed"),
    Case("dana@example.com", "secret.write", "kv:kv1/legacy/x", "denied"),
    Case("dana@example.com", "secret.list", "kv:kv1/legacy", "allowed"),
    Case("dana@example.com", "secret.write", "kv:secret/dev/app", "allowed"),
    Case("dana@example.com", "secret.write", "kv:secret/dev/half", "unsupported"),
    Case("dana@example.com", "secret.write", "kv:secret/dev/createonly", "unsupported"),
    Case("dana@example.com", "secret.write", "kv:secret/shared/a/config", "denied"),
    Case("dana@example.com", "secret.delete", "kv:secret/dev/app", "allowed"),
    Case("dana@example.com", "secret.delete", "kv:secret/shared/db", "denied"),
    Case("dana@example.com", "secret.list", "kv:secret/dev", "allowed"),
    Case("dana@example.com", "secret.list", "kv:secret/shared/a", "allowed"),
    Case("dana@example.com", "secret.list", "kv:secret/teams/payments", "denied"),
    Case("dana@example.com", "secret.metadata", "kv:secret/dev/app", "allowed"),
    Case("dana@example.com", "secret.metadata", "kv:secret/shared/db", "denied"),
    Case("dana@example.com", "secret.destroy", "kv:secret/dev/app", "allowed"),
    Case("dana@example.com", "secret.destroy", "kv:secret/shared/db", "denied"),
    Case("dana@example.com", "raw:sudo", "path:sys/seal", "denied"),
    Case("dana@example.com", "raw:list", "path:secret/metadata/dev", "allowed"),
    # bob: nothing on the entity; default, and base through token_policies.
    Case("bob@example.com", "secret.read", "kv:secret/dev/app", "denied"),
    Case("bob@example.com", "secret.read", "kv:secret/base/x", "allowed"),
    Case("bob@example.com", "secret.list", "kv:secret/dev", "denied"),
    Case("bob@example.com", "raw:read", "path:auth/token/lookup-self", "allowed"),
    Case("bob@example.com", "raw:update", "path:sys/capabilities-self", "allowed"),
    Case("bob@example.com", "raw:create", "path:cubbyhole/x", "allowed"),
    Case("bob@example.com", "raw:sudo", "path:cubbyhole/x", "denied"),
    # ops: broad globs, a more specific deny, sudo, "+", the legacy write.
    Case("ops@example.com", "secret.read", "kv:secret/dev/x", "allowed"),
    Case("ops@example.com", "secret.read", "kv:secret/prod/db", "denied"),
    Case("ops@example.com", "secret.list", "kv:secret/prod", "allowed"),
    Case("ops@example.com", "raw:sudo", "path:sys/seal", "allowed"),
    Case("ops@example.com", "raw:update", "path:pki/issue/web", "allowed"),
    Case("ops@example.com", "raw:delete", "path:pki/issue/web", "denied"),
    Case("ops@example.com", "secret.read", "kv:kv1/team/app", "allowed"),
    Case("ops@example.com", "secret.read", "kv:kv1/team/other", "denied"),
    Case("ops@example.com", "secret.write", "kv:kv1/w/x", "allowed"),
    Case("ops@example.com", "secret.delete", "kv:kv1/w/x", "allowed"),
    Case("ops@example.com", "raw:sudo", "path:kv1/w/x", "denied"),
    # lister: LIST against denies written with and without the slash, and a
    # stanza with a leading slash.
    Case("lister@example.com", "secret.list", "kv:secret/prod", "denied"),
    Case("lister@example.com", "secret.list", "kv:secret/other", "denied"),
    Case("lister@example.com", "secret.list", "kv:secret/dev/a", "allowed"),
    Case("lister@example.com", "secret.read", "kv:secret/lead/x", "allowed"),
    Case("lister@example.com", "secret.read", "kv:secret/dev/a", "denied"),
    # A disabled entity, and an email no entity carries.
    Case("off@example.com", "secret.read", "kv:secret/dev/app", "denied"),
    Case("nobody@example.com", "secret.read", "kv:secret/dev/app", "user_not_found"),
]

# kv: resources: the mounts and their KV versions.
KV_MOUNTS = {"secret": 2, "kv1": 1}
# action -> (KV v2 sub-path, capabilities needed, LIST)
ACTIONS = {
    "secret.read": ("data", ("read",), False),
    "secret.write": ("data", ("create", "update"), False),
    "secret.delete": ("data", ("delete",), False),
    "secret.list": ("metadata", ("list",), True),
    "secret.metadata": ("metadata", ("read",), False),
    "secret.destroy": ("destroy", ("update",), False),
}


# -- Docker ----------------------------------------------------------------------


def _docker_problem() -> str | None:
    """Why the test cannot run here, or None."""
    if shutil.which("docker") is None:
        return "docker is not installed"
    try:
        info = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"docker is not reachable: {e}"
    if info.returncode != 0:
        return f"docker daemon is not reachable: {info.stderr.strip()[:200]}"
    img = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, text=True, timeout=20)
    if img.returncode != 0:
        return f"image {IMAGE} is not present locally (docker pull {IMAGE}); the test never pulls it"
    return None


_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class RealVault:
    """A running dev Vault and the world configured in it."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.accessor = ""
        self.tokens: dict[str, str] = {}
        self.entities: dict[str, str] = {}
        self.groups: dict[str, str] = {}

    def call(self, method: str, path: str, body: Any = None, token: str = ROOT_TOKEN) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + "/v1/" + path, method=method, data=data, headers={"X-Vault-Token": token})
        try:
            with _NO_PROXY.open(req, timeout=10) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw.decode("utf-8", "replace")

    def must(self, method: str, path: str, body: Any = None) -> Any:
        st, out = self.call(method, path, body)
        assert st in (200, 204), f"{method} {path}: HTTP {st} {out}"
        return out

    def configure(self) -> None:
        self.accessor = self.must("GET", "sys/auth")["data"]["token/"]["accessor"]
        mounts = self.must("GET", "sys/mounts")["data"]
        assert mounts["secret/"]["type"] == "kv" and mounts["secret/"]["options"]["version"] == "2", mounts["secret/"]
        self.must("POST", "sys/mounts/kv1", {"type": "kv", "options": {"version": "1"}})
        policies = {
            "dev": DEV_POLICY_TEXT.replace("@ACC@", self.accessor),
            "team-readers": TEAM_POLICY,
            "orgp": ORG_POLICY,
            "ops": OPS_POLICY,
            "lister": LISTER_POLICY,
            "base": BASE_POLICY,
        }
        for name, text in policies.items():
            self.must("PUT", "sys/policies/acl/" + name, {"policy": text})
        self.must("PUT", "auth/token/roles/hallpass-real", {"allowed_entity_aliases": ["*"], "orphan": True, "allowed_policies": ["base"]})
        for p in PEOPLE:
            out = self.must("POST", "identity/entity", {"name": p.email.split("@")[0], "policies": p.policies, "metadata": p.metadata})
            eid = out["data"]["id"]
            self.entities[p.email] = eid
            self.must("POST", "identity/entity-alias", {"name": p.email, "canonical_id": eid, "mount_accessor": self.accessor})
        team = self.must("POST", "identity/group", {"name": "team", "policies": ["team-readers"], "member_entity_ids": [self.entities["dana@example.com"]]})
        self.groups["team"] = team["data"]["id"]
        org = self.must("POST", "identity/group", {"name": "org", "policies": ["orgp"], "member_group_ids": [self.groups["team"]]})
        self.groups["org"] = org["data"]["id"]
        for p in PEOPLE:
            out = self.must("POST", "auth/token/create/hallpass-real", {"entity_alias": p.email})
            assert out["auth"]["entity_id"] == self.entities[p.email], out["auth"]
            self.tokens[p.email] = out["auth"]["client_token"]
        for p in PEOPLE:
            if p.disabled:
                self.must("POST", "identity/entity/id/" + self.entities[p.email], {"disabled": True})

    def capabilities(self, email: str, path: str) -> list[str]:
        out = self.must("POST", "sys/capabilities", {"token": self.tokens[email], "paths": [path]})
        return list(out["data"][path])


@pytest.fixture(scope="module")
def vault() -> Iterator[RealVault]:
    real = os.environ.get("HALLPASS_REAL", "")
    if real == "0":
        pytest.skip("HALLPASS_REAL=0")
    problem = _docker_problem()
    if problem is not None:
        if real == "1":
            pytest.fail(f"HALLPASS_REAL=1 but {problem}")
        pytest.skip(problem)
    run = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--cap-add=IPC_LOCK",
            "-e",
            "VAULT_DEV_ROOT_TOKEN_ID=" + ROOT_TOKEN,
            "-e",
            "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
            "-p",
            "127.0.0.1::8200",
            IMAGE,
            "server",
            "-dev",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert run.returncode == 0, f"docker run failed: {run.stderr}"
    cid = run.stdout.strip()
    try:
        port = subprocess.run(["docker", "port", cid, "8200/tcp"], capture_output=True, text=True, timeout=20).stdout.split()[0].rsplit(":", 1)[1]
        v = RealVault(f"http://127.0.0.1:{port}")
        deadline = time.monotonic() + 60
        while True:
            try:
                st, out = v.call("GET", "sys/health")
                if st == 200 and not out.get("sealed"):
                    break
            except (OSError, urllib.error.URLError):
                pass
            if time.monotonic() > deadline:
                logs = subprocess.run(["docker", "logs", cid], capture_output=True, text=True, timeout=20)
                pytest.fail(f"vault did not come up: {logs.stdout[-2000:]}{logs.stderr[-2000:]}")
            time.sleep(0.25)
        v.configure()
        yield v
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=60)


@pytest.fixture(scope="module")
def hp(vault: RealVault) -> hallpass.Hallpass:
    return hallpass.Hallpass(
        connections=[
            {
                "id": CONNECTION,
                "integration": "vault",
                "url": vault.url,
                "alias_mount": "token/",
                "credential": hallpass.literal(ROOT_TOKEN),
                "token_policies": "base",
            }
        ]
    )


# -- Vault's own answer ----------------------------------------------------------


def _request_path(action: str, resource: str) -> tuple[str, tuple[str, ...]]:
    """The API path a request for the action goes to, and the capabilities
    it needs there, as Vault's documentation states them."""
    kind, _, path = resource.partition(":")
    if action.startswith("raw:"):
        cap = action.removeprefix("raw:")
        return (path + "/" if cap == "list" else path), (cap,)
    sub, need, is_list = ACTIONS[action]
    assert kind == "kv", resource
    mount, _, key = path.partition("/")
    api = f"{mount}/{sub}/{key}" if KV_MOUNTS[mount] == 2 else path
    # A LIST is authorised against the path with its trailing slash.
    return (api + "/" if is_list else api), need


def vault_answer(v: RealVault, case: Case) -> tuple[str, str]:
    """The code Vault's own evaluation stands for, and the evidence."""
    person = next((p for p in PEOPLE if p.email == case.user), None)
    if person is None:
        st, _ = v.call("POST", "identity/lookup/entity", {"alias_name": case.user, "alias_mount_accessor": v.accessor})
        return ("user_not_found" if st == 204 else f"lookup answered HTTP {st}"), f"identity/lookup/entity: HTTP {st}"
    if person.disabled:
        # Vault refuses every request made with a disabled entity's token.
        path, _ = _request_path(case.action, case.resource)
        st, body = v.call("POST", "sys/capabilities-self", {"paths": [path]}, v.tokens[case.user])
        return ("denied" if st == 403 else f"disabled entity's token got HTTP {st}"), f"sys/capabilities-self with its token: HTTP {st} {body}"
    path, need = _request_path(case.action, case.resource)
    caps = v.capabilities(case.user, path)
    evidence = f"sys/capabilities {path} = {caps}"
    if "root" in caps:
        return "allowed", evidence
    if "deny" in caps:
        return "denied", evidence
    held = [c in caps for c in need]
    if all(held):
        return "allowed", evidence
    if not any(held):
        return "denied", evidence
    # A write needs create for a new secret and update for an existing one.
    return "unsupported", evidence


def _render(case: Case, v: RealVault) -> str:
    return case.resource.replace("{team}", v.groups["team"]).replace("{org}", v.groups["org"])


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c.user.split('@')[0]}-{c.action}-{c.resource}")
def test_matches_vault(vault: RealVault, hp: hallpass.Hallpass, case: Case) -> None:
    case = Case(case.user, case.action, _render(case, vault), case.want)
    want, evidence = vault_answer(vault, case)
    d = hp.check(case.user, CONNECTION, case.action, case.resource)
    assert d.code == want, f"hallpass: {d.reason}\nvault: {want} ({evidence})"
    assert want == case.want, f"the scenario expected {case.want}, Vault says {want} ({evidence})"


def test_scenario_covers_every_answer() -> None:
    """The cases exercise allow, deny, the half-granted write and a user
    Vault has no entity for."""
    assert {c.want for c in CASES} == {"allowed", "denied", "unsupported", "user_not_found"}


def test_probe(vault: RealVault, hp: hallpass.Hallpass) -> None:
    [(cid, ok, summary)] = hp.probe()
    assert cid == CONNECTION and ok, summary
    assert vault.accessor in summary, summary


def test_policies_parse_as_vault_stores_them(vault: RealVault) -> None:
    """Every ACL policy the dev server holds, default included, parses."""
    from hallpass.integrations.vault.policy import parse_policy

    names = vault.must("LIST", "sys/policies/acl")["data"]["keys"]
    for name in names:
        if name == "root":
            continue
        text = vault.must("GET", "sys/policies/acl/" + name)["data"]["policy"]
        assert parse_policy(name, text, None) or name == "root", f"policy {name} yielded no rules"
