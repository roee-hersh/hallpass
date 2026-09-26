"""Port of internal/integrations/azure/azure_test.go."""

from __future__ import annotations

import json
import threading
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from hallpass.core.context import Context, background
from hallpass.core.decision import Code, Decision
from hallpass.core.integration import CheckRequest, Connection, Identity, ProbeResult, User
from hallpass.core.secret import literal
from hallpass.integrations.azure import Azure
from hallpass.integrations.azure.azure import API_VERSION, match_operation
from tests import harness as itest
from tests.harness.spec import SpecOptions, any_spec, spec_from_env

TENANT_ID = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
SUB_ID = "33333333-3333-3333-3333-333333333333"

OID_DANA = "aaaaaaaa-0000-0000-0000-000000000001"
OID_BOB = "aaaaaaaa-0000-0000-0000-000000000002"
OID_LEAD = "aaaaaaaa-0000-0000-0000-000000000003"
OID_OFF = "aaaaaaaa-0000-0000-0000-000000000004"
OID_NONE = "aaaaaaaa-0000-0000-0000-000000000005"
GROUP_G1 = "bbbbbbbb-0000-0000-0000-000000000001"
GROUP_G2 = "bbbbbbbb-0000-0000-0000-000000000002"

ROLE_READER = "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
ROLE_CONTRIBUTOR = "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
ROLE_OWNER = "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
ROLE_BLOB_READER = "/providers/Microsoft.Authorization/roleDefinitions/2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
ROLE_VM_OPERATOR = "/subscriptions/" + SUB_ID + "/providers/Microsoft.Authorization/roleDefinitions/cccccccc-0000-0000-0000-000000000001"

SCOPE_SUB = "/subscriptions/" + SUB_ID
SCOPE_PROD = SCOPE_SUB + "/resourceGroups/prod"
SCOPE_OTHER = SCOPE_SUB + "/resourceGroups/other"
SCOPE_COND = SCOPE_SUB + "/resourceGroups/cond"
SCOPE_VM = SCOPE_PROD + "/providers/Microsoft.Compute/virtualMachines/web-1"
SCOPE_STOR = SCOPE_PROD + "/providers/Microsoft.Storage/storageAccounts/prodstore"
SCOPE_PAREN = SCOPE_SUB + "/resourceGroups/rg(1)"
SCOPE_MG = "/providers/Microsoft.Management/managementGroups/corp"
SCOPE_MG2 = "/providers/Microsoft.Management/managementGroups/other-mg"
ALL_PRINCES = "00000000-0000-0000-0000-000000000000"

dana = User(email="dana@example.com")  # Reader at sub, VM Operator at prod via G1, Blob Reader on prodstore, conditional Contributor at cond
bob = User(email="bob@example.com")  # Owner at management group corp; Contributor at other
lead = User(email="lead@example.com")  # Contributor at sub; denied vm delete in prod
none = User(email="none@example.com")  # no assignments


@dataclass
class FakeUser:
    oid: str
    mail: str
    upn: str
    enabled: bool
    groups: list[str] = field(default_factory=list)


@dataclass
class Assignment:
    id: str
    scope: str
    role: str
    principal: str
    ptype: str
    condition: str = ""


@dataclass
class Deny:
    id: str
    name: str
    scope: str
    exact: bool = False
    actions: list[str] = field(default_factory=list)
    not_acts: list[str] | None = None
    data_actions: list[str] | None = None
    principals: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)
    condition: str = ""


def _perm(actions: list[str], not_actions: list[str], data_actions: list[str], not_data_actions: list[str]) -> list[dict[str, Any]]:
    return [{"actions": actions, "notActions": not_actions, "dataActions": data_actions, "notDataActions": not_data_actions}]


class Fake:
    def __init__(self) -> None:
        self.mu = threading.RLock()
        self.errors: list[str] = []
        self.secret = itest.CANARY + "secret"
        self.page_size = 100
        self.tokens = 0
        self.status = 0
        self.users = [
            FakeUser(OID_DANA, "dana@example.com", "dana@corp.example", True, [GROUP_G1]),
            FakeUser(OID_BOB, "bob@example.com", "bob@corp.example", True),
            FakeUser(OID_LEAD, "lead@example.com", "lead@corp.example", True, [GROUP_G2]),
            FakeUser(OID_OFF, "off@example.com", "off@corp.example", False),
            FakeUser(OID_NONE, "none@example.com", "none@corp.example", True),
            # A mail that contains another; filters are exact so it never matches.
            FakeUser("aaaaaaaa-0000-0000-0000-000000000009", "dana@example.com.au", "danaau@corp.example", True),
        ]
        c = itest.CANARY
        self.roles: dict[str, dict[str, Any]] = {  # role definition id (lower) -> properties
            ROLE_READER.lower(): {
                "roleName": "Reader",
                "type": "BuiltInRole",
                "description": c,
                "permissions": _perm(["*/read"], [], [], []),
                "assignableScopes": ["/"],
            },
            ROLE_CONTRIBUTOR.lower(): {
                "roleName": "Contributor",
                "type": "BuiltInRole",
                "description": c,
                "permissions": _perm(
                    ["*"], ["Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write", "Microsoft.Authorization/elevateAccess/Action"], [], []
                ),
                "assignableScopes": ["/"],
            },
            ROLE_OWNER.lower(): {
                "roleName": "Owner",
                "type": "BuiltInRole",
                "description": c,
                "permissions": _perm(["*"], [], [], []),
                "assignableScopes": ["/"],
            },
            ROLE_BLOB_READER.lower(): {
                "roleName": "Storage Blob Data Reader",
                "type": "BuiltInRole",
                "description": c,
                "permissions": _perm(
                    ["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
                    [],
                    ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
                    [],
                ),
                "assignableScopes": ["/"],
            },
            ROLE_VM_OPERATOR.lower(): {
                "roleName": "VM Operator",
                "type": "CustomRole",
                "description": c,
                "permissions": _perm(
                    ["Microsoft.Compute/virtualMachines/start/action", "Microsoft.Compute/virtualMachines/restart/action", "Microsoft.Compute/*/read"],
                    [],
                    [],
                    [],
                ),
                "assignableScopes": [SCOPE_SUB],
            },
        }
        self.assignments = [
            Assignment("ra-1", SCOPE_SUB, ROLE_READER, OID_DANA, "User"),
            Assignment("ra-2", SCOPE_PROD, ROLE_VM_OPERATOR, GROUP_G1, "Group"),
            Assignment("ra-3", SCOPE_STOR, ROLE_BLOB_READER, OID_DANA, "User"),
            Assignment(
                "ra-4",
                SCOPE_COND,
                ROLE_CONTRIBUTOR,
                OID_DANA,
                "User",
                "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'x'",
            ),
            Assignment("ra-5", SCOPE_MG, ROLE_OWNER, OID_BOB, "User"),
            Assignment("ra-6", SCOPE_OTHER, ROLE_CONTRIBUTOR, OID_BOB, "User"),
            Assignment("ra-7", SCOPE_SUB, ROLE_CONTRIBUTOR, OID_LEAD, "User"),
        ]
        self.denies = [
            Deny("da-1", "no-vm-delete-prod", SCOPE_PROD, actions=["Microsoft.Compute/virtualMachines/delete"], principals=[ALL_PRINCES]),
            # Excludes a group: whether it holds the user is not readable.
            Deny(
                "da-2", "no-listkeys", SCOPE_SUB, actions=["Microsoft.Storage/storageAccounts/listkeys/action"], principals=[ALL_PRINCES], excludes=[GROUP_G2]
            ),
            # Conditional deny.
            Deny(
                "da-3",
                "cond-deny",
                SCOPE_OTHER,
                actions=["Microsoft.Compute/virtualMachines/deallocate/action"],
                principals=[ALL_PRINCES],
                condition="@Resource[Microsoft.Compute/virtualMachines:name] StringEquals 'x'",
            ),
            # Excludes the user directly.
            Deny(
                "da-4",
                "no-restart-except-dana",
                SCOPE_PROD,
                actions=["Microsoft.Compute/virtualMachines/restart/action"],
                principals=[ALL_PRINCES],
                excludes=[OID_DANA],
            ),
            # Deny only at the exact scope.
            Deny("da-5", "no-deploy-sub-exact", SCOPE_SUB, exact=True, actions=["Microsoft.Resources/deployments/write"], principals=[ALL_PRINCES]),
            # A scope with parentheses, spelled by ARM as it is.
            Deny("da-6", "no-vm-delete-paren", SCOPE_PAREN, actions=["Microsoft.Compute/virtualMachines/delete"], principals=[ALL_PRINCES]),
        ]
        self.forbidden: dict[str, bool] = {}  # scopes the app may not read

    def token(self, w: Any, r: Any) -> None:
        with self.mu:
            form = r.form()

            def get(k: str) -> str:
                vs = form.get(k)
                return vs[0] if vs else ""

            if get("client_secret") != self.secret or get("client_id") != CLIENT_ID or get("grant_type") != "client_credentials":
                write(w, 401, {"error": "invalid_client", "error_description": itest.CANARY})
                return
            scope = get("scope")
            if not scope.endswith("/.default"):
                self.errors.append(f"token scope {scope!r}")
            self.tokens += 1
            write(w, 200, {"token_type": "Bearer", "expires_in": 3599, "access_token": itest.CANARY + "-token-" + scope})

    def authed(self, r: Any) -> bool:
        return bool(r.header.get("Authorization").startswith("Bearer " + itest.CANARY + "-token-"))

    def graph(self, w: Any, r: Any) -> None:
        with self.mu:
            if not self.authed(r):
                arm_err(w, 401, "InvalidAuthenticationToken")
                return
            if self.status != 0:
                arm_err(w, self.status, "ServiceUnavailable")
                return
            if r.path != "/v1.0/users":
                self.errors.append(f"graph: no route for {r.path}")
                arm_err(w, 404, "Request_ResourceNotFound")
                return
            flt = r.q("$filter")
            value: list[dict[str, Any]] = []
            for u in self.users:
                for lit in ("mail eq '" + u.mail + "'", "userPrincipalName eq '" + u.upn + "'"):
                    if lit.lower() in flt.lower():
                        value.append({"id": u.oid, "mail": u.mail, "userPrincipalName": u.upn, "accountEnabled": u.enabled, "displayName": itest.CANARY})
                        break
            if "dup@example.com" in flt:
                value.append({"id": "aaaaaaaa-0000-0000-0000-0000000000d1", "mail": "dup@example.com", "accountEnabled": True})
                value.append({"id": "aaaaaaaa-0000-0000-0000-0000000000d2", "userPrincipalName": "DUP@example.com", "accountEnabled": True})
            write(w, 200, {"value": value})

    def principals_of(self, oid: str) -> set[str]:
        """The user's own id and the groups it belongs to: what assignedTo()
        expands to."""
        out = {oid.lower()}
        for u in self.users:
            if u.oid.lower() == oid.lower():
                out.update(g.lower() for g in u.groups)
        return out

    def arm(self, w: Any, r: Any) -> None:
        with self.mu:
            self._arm(w, r)

    def _arm(self, w: Any, r: Any) -> None:
        if not self.authed(r):
            arm_err(w, 401, "InvalidAuthenticationToken")
            return
        if self.status != 0:
            arm_err(w, self.status, "InternalServerError")
            return
        if r.q("api-version") != API_VERSION:
            self.errors.append(f"api-version {r.q('api-version')!r}")
        p = r.path
        marker = "/providers/Microsoft.Authorization/"
        i = p.rfind(marker)
        if i < 0:
            arm_err(w, 404, "InvalidResourceType")
            return
        scope, rest = p[:i], p[i + len(marker) :]
        if self.forbidden.get(scope.lower()):
            arm_err(w, 403, "AuthorizationFailed")
            return
        oid = ""
        fl = r.q("$filter")
        if fl != "":
            if not fl.startswith("assignedTo('") and not fl.startswith("type eq"):
                self.errors.append(f"filter {fl!r}")
            oid = fl.removeprefix("assignedTo('").removesuffix("')")
        if rest == "roleAssignments":
            if not scope.startswith("/subscriptions/" + SUB_ID) and not scope.startswith("/providers/Microsoft.Management/"):
                arm_err(w, 404, "SubscriptionNotFound")
                return
            members = self.principals_of(oid)
            items = []
            for a in self.assignments:
                if a.principal.lower() not in members:
                    continue
                props: dict[str, Any] = {
                    "scope": a.scope,
                    "roleDefinitionId": a.role,
                    "principalId": a.principal,
                    "principalType": a.ptype,
                    "description": itest.CANARY,
                }
                if a.condition != "":
                    props["condition"] = a.condition
                    props["conditionVersion"] = "2.0"
                items.append(
                    {
                        "id": a.scope + "/providers/Microsoft.Authorization/roleAssignments/" + a.id,
                        "name": a.id,
                        "type": "Microsoft.Authorization/roleAssignments",
                        "properties": props,
                    }
                )
            start = 0
            skip = r.q("$skipToken")
            if skip.startswith("s"):
                digits = ""
                for ch in skip[1:]:
                    if not ch.isdigit():
                        break
                    digits += ch
                start = int(digits) if digits else 0
            end = min(start + self.page_size, len(items))
            start = min(start, len(items))
            body: dict[str, Any] = {"value": items[start:end]}
            if end < len(items):
                # Azure's next link is opaque; here it carries the filter along.
                body["nextLink"] = (
                    "https://" + r.host + p + "?api-version=" + API_VERSION + "&$filter=" + urllib.parse.quote_plus(fl) + "&$skipToken=s" + str(end)
                )
            write(w, 200, body)
        elif rest == "denyAssignments":
            members = self.principals_of(oid)
            value = []
            for d in self.denies:
                if not any(pr == ALL_PRINCES or pr.lower() in members for pr in d.principals):
                    continue
                principals = [{"id": pr, "type": "SystemDefined" if pr == ALL_PRINCES else "Group"} for pr in d.principals]
                excludes = [{"id": pr, "type": "User" if pr.startswith("aaaaaaaa") else "Group"} for pr in d.excludes]
                perm = {"actions": d.actions, "notActions": d.not_acts, "dataActions": d.data_actions, "notDataActions": []}
                props = {
                    "denyAssignmentName": d.name,
                    "description": itest.CANARY,
                    "scope": d.scope,
                    "doNotApplyToChildScopes": d.exact,
                    "permissions": [perm],
                    "principals": principals,
                    "excludePrincipals": excludes,
                    "isSystemProtected": True,
                }
                if d.condition != "":
                    props["condition"] = d.condition
                    props["conditionVersion"] = "2.0"
                value.append(
                    {
                        "id": d.scope + "/providers/Microsoft.Authorization/denyAssignments/" + d.id,
                        "name": d.id,
                        "type": "Microsoft.Authorization/denyAssignments",
                        "properties": props,
                    }
                )
            write(w, 200, {"value": value})
        elif rest.startswith("roleDefinitions/"):
            guid = rest.removeprefix("roleDefinitions/")
            found: dict[str, Any] | None = None
            for rid, pr in self.roles.items():
                if rid.endswith("/" + guid):
                    found = pr
            if found is None:
                arm_err(w, 404, "RoleDefinitionDoesNotExist")
                return
            write(w, 200, {"id": p, "name": guid, "type": "Microsoft.Authorization/roleDefinitions", "properties": found})
        elif rest == "roleDefinitions":
            value = [{"id": rid, "properties": pr} for rid, pr in self.roles.items() if pr["type"] == "BuiltInRole"]
            write(w, 200, {"value": value})
        else:
            self.errors.append(f"arm: no route for {p}")
            arm_err(w, 404, "NotFound")


def write(w: Any, status: int, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write(json.dumps(v) + "\n")


def arm_err(w: Any, status: int, code: str) -> None:
    write(w, status, {"error": {"code": code, "message": itest.CANARY}})


def specs() -> Any:
    return any_spec(
        spec_from_env("azure-RoleAssignmentsCalls"),
        spec_from_env("azure-RoleDefinitionsCalls"),
        spec_from_env("azure-DenyAssignmentCalls"),
        spec_from_env("msgraph"),
    )


NewServer = Callable[[], "tuple[itest.Server, Fake]"]
Setup = Callable[[], "tuple[itest.Server, Fake, Connection]"]


@pytest.fixture
def new_server() -> Iterator[NewServer]:
    made: list[tuple[itest.Server, Fake]] = []

    def make() -> tuple[itest.Server, Fake]:
        srv = itest.Server()
        # api-version and the {scope} parameter are defined in a sibling file
        # the description references; $skipToken is declared on the generic
        # scope path only; the tenant-root role definition listing the probe
        # uses has no path in the description.
        srv.use_spec(
            specs(),
            SpecOptions(
                strip_prefix=[r"/v1\.0"],
                allow_query=["api-version", "$skipToken"],
                ignore_paths=[r"/oauth2/v2\.0/token$", r"^/providers/Microsoft\.Authorization/roleDefinitions$"],
            ),
        )
        f = Fake()
        srv.handle("POST", "/" + TENANT_ID + "/oauth2/v2.0/token", f.token)
        srv.handle("GET", "/v1.0/*", f.graph)
        srv.handle("GET", "/subscriptions/*", f.arm)
        srv.handle("GET", "/providers/*", f.arm)
        made.append((srv, f))
        return srv, f

    yield make
    errors: list[str] = []
    for srv, f in made:
        srv.close()
        errors.extend(srv.spec_errors)
        errors.extend(f.errors)
    assert not errors, "\n".join(errors)


@pytest.fixture
def setup(new_server: NewServer) -> Setup:
    def make() -> tuple[itest.Server, Fake, Connection]:
        srv, f = new_server()
        deps, _ = itest.deps(srv)
        s = itest.settings(
            "az",
            "azure",
            {"tenant_id": TENANT_ID, "client_id": CLIENT_ID, "url": srv.url, "graph_url": srv.url, "authority_url": srv.url},
            {"credential": literal(f.secret)},
        )
        c = Azure().new(background(), s, deps)
        return srv, f, c

    return make


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, Azure(), u, action, resource)


def expect(d: Decision, code: Code, text: str) -> None:
    itest.expect_code(d, code)
    assert text == "" or text in d.text, f"text {d.text!r} does not contain {text!r}"
    itest.assert_no_canary(d.text)


# --- the action table -------------------------------------------------------


def test_action_vm_read_allow(setup: Setup) -> None:
    _, _, c = setup()
    # Reader at the subscription, inherited by the VM.
    expect(check(c, dana, "vm.read", "resource:" + SCOPE_VM), Code.ALLOWED, 'role "Reader" assigned directly at ' + SCOPE_SUB)
    # Owner at a management group, inherited by everything in the subscription.
    expect(check(c, bob, "vm.read", "subscription:" + SUB_ID), Code.ALLOWED, "Owner")


def test_action_vm_read_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, none, "vm.read", "resource:" + SCOPE_VM), Code.DENIED, "no role assignment")


def test_action_vm_start_allow(setup: Setup) -> None:
    _, _, c = setup()
    # Custom role through group G1 at the resource group.
    expect(check(c, dana, "vm.start", "resource:" + SCOPE_VM), Code.ALLOWED, "through group " + GROUP_G1)


def test_action_vm_start_deny(setup: Setup) -> None:
    _, _, c = setup()
    # The group assignment is at prod; a VM in another group is not covered.
    expect(
        check(c, dana, "vm.start", "resource:" + SCOPE_OTHER + "/providers/Microsoft.Compute/virtualMachines/x"),
        Code.DENIED,
        "none of dana@example.com's 1 role assignment(s)",
    )


def test_action_vm_restart_allow(setup: Setup) -> None:
    _, _, c = setup()
    # The deny excludes dana directly.
    expect(check(c, dana, "vm.restart", "resource:" + SCOPE_VM), Code.ALLOWED, "VM Operator")


def test_action_vm_restart_deny(setup: Setup) -> None:
    _, _, c = setup()
    # Contributor grants it, the deny at prod blocks it.
    expect(check(c, lead, "vm.restart", "resource:" + SCOPE_VM), Code.DENIED, 'deny assignment "no-restart-except-dana"')


def test_action_vm_deallocate_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, lead, "vm.deallocate", "resource:" + SCOPE_VM), Code.ALLOWED, "Contributor")


def test_action_vm_deallocate_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "vm.deallocate", "resource:" + SCOPE_VM), Code.DENIED, "")
    # A conditional deny leaves the answer unknown.
    expect(
        check(c, lead, "vm.deallocate", "resource:" + SCOPE_OTHER + "/providers/Microsoft.Compute/virtualMachines/x"),
        Code.UNSUPPORTED,
        'deny assignment "cond-deny" may block',
    )


def test_action_vm_delete_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, lead, "vm.delete", "resource:" + SCOPE_OTHER + "/providers/Microsoft.Compute/virtualMachines/x"), Code.ALLOWED, "Contributor")


def test_action_vm_delete_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, lead, "vm.delete", "resource:" + SCOPE_VM), Code.DENIED, 'deny assignment "no-vm-delete-prod" at ' + SCOPE_PROD + " blocks")
    expect(check(c, dana, "vm.delete", "resource:" + SCOPE_VM), Code.DENIED, "")
    # The scope is compared as ARM spells it: parentheses are not escaped.
    expect(check(c, lead, "vm.delete", "resource:" + SCOPE_PAREN + "/providers/Microsoft.Compute/virtualMachines/x"), Code.DENIED, '"no-vm-delete-paren"')
    expect(check(c, lead, "vm.delete", "resourcegroup:" + SUB_ID + "/rg(1)"), Code.DENIED, '"no-vm-delete-paren"')
    expect(check(c, lead, "vm.start", "resourcegroup:" + SUB_ID + "/rg(1)"), Code.ALLOWED, "Contributor")


def test_denies_read_only_when_something_grants(setup: Setup) -> None:
    srv, _, c = setup()
    expect(check(c, none, "vm.read", "resource:" + SCOPE_VM), Code.DENIED, "")
    for call in srv.calls():
        assert not call.path.endswith("/denyAssignments"), "deny assignments listed although nothing grants"


def test_action_storage_listkeys_allow(setup: Setup) -> None:
    _, f, c = setup()
    with f.mu:
        f.denies = f.denies[:1]
    expect(check(c, lead, "storage.listkeys", "resource:" + SCOPE_STOR), Code.ALLOWED, "Contributor")


def test_action_storage_listkeys_deny(setup: Setup) -> None:
    _, _, c = setup()
    # The deny excludes group G2; whether lead is in it is not readable.
    expect(check(c, lead, "storage.listkeys", "resource:" + SCOPE_STOR), Code.UNSUPPORTED, '"no-listkeys" may block')
    expect(check(c, dana, "storage.listkeys", "resource:" + SCOPE_STOR), Code.DENIED, "")


def test_action_storage_blob_read_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "storage.blob.read", "resource:" + SCOPE_STOR), Code.ALLOWED, "Storage Blob Data Reader")


def test_action_storage_blob_read_deny(setup: Setup) -> None:
    _, _, c = setup()
    # Contributor has no data actions.
    expect(check(c, lead, "storage.blob.read", "resource:" + SCOPE_STOR), Code.DENIED, "grants Microsoft.Storage")


def test_action_storage_blob_write_allow(setup: Setup) -> None:
    _, f, c = setup()
    with f.mu:
        f.roles[ROLE_BLOB_READER.lower()]["permissions"] = _perm(
            [],
            [],
            ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"],
            ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"],
        )
    expect(check(c, dana, "storage.blob.write", "resource:" + SCOPE_STOR), Code.ALLOWED, "")
    expect(check(c, dana, "data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete", "resource:" + SCOPE_STOR), Code.DENIED, "")


def test_action_storage_blob_write_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "storage.blob.write", "resource:" + SCOPE_STOR), Code.DENIED, "")


def test_action_keyvault_secret_read_allow(setup: Setup) -> None:
    _, f, c = setup()
    kv = SCOPE_PROD + "/providers/Microsoft.KeyVault/vaults/prod-kv"
    with f.mu:
        f.roles["/providers/microsoft.authorization/roledefinitions/4633458b-17de-408a-b874-0445c86b69e6"] = {
            "roleName": "Key Vault Secrets User",
            "type": "BuiltInRole",
            "permissions": _perm([], [], ["Microsoft.KeyVault/vaults/secrets/getSecret/action", "Microsoft.KeyVault/vaults/secrets/readMetadata/action"], []),
        }
        f.assignments.append(
            Assignment("ra-kv", kv, "/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6", OID_NONE, "User")
        )
    expect(check(c, none, "keyvault.secret.read", "resource:" + kv), Code.ALLOWED, "Key Vault Secrets User")


def test_action_keyvault_secret_read_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, lead, "keyvault.secret.read", "resource:" + SCOPE_PROD + "/providers/Microsoft.KeyVault/vaults/prod-kv"), Code.DENIED, "")


def test_action_keyvault_secret_write_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, bob, "keyvault.secret.write", "resource:" + SCOPE_PROD + "/providers/Microsoft.KeyVault/vaults/prod-kv"), Code.DENIED, "")
    _, f, c = setup()
    with f.mu:
        f.roles[ROLE_OWNER.lower()]["permissions"] = _perm(["*"], [], ["*"], [])
    expect(check(c, bob, "keyvault.secret.write", "resource:" + SCOPE_PROD + "/providers/Microsoft.KeyVault/vaults/prod-kv"), Code.ALLOWED, "Owner")


def test_action_keyvault_secret_write_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "keyvault.secret.write", "resource:" + SCOPE_PROD + "/providers/Microsoft.KeyVault/vaults/prod-kv"), Code.DENIED, "")


def test_action_aks_admin_credentials_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, lead, "aks.admin_credentials", "resource:" + SCOPE_PROD + "/providers/Microsoft.ContainerService/managedClusters/k8s"), Code.ALLOWED, "")


def test_action_aks_admin_credentials_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "aks.admin_credentials", "resource:" + SCOPE_PROD + "/providers/Microsoft.ContainerService/managedClusters/k8s"), Code.DENIED, "")


def test_action_aks_user_credentials_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, bob, "aks.user_credentials", "resource:" + SCOPE_PROD + "/providers/Microsoft.ContainerService/managedClusters/k8s"), Code.ALLOWED, "")


def test_action_aks_user_credentials_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, none, "aks.user_credentials", "resource:" + SCOPE_PROD + "/providers/Microsoft.ContainerService/managedClusters/k8s"), Code.DENIED, "")


def test_action_rbac_write_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, bob, "rbac.write", "resourcegroup:" + SUB_ID + "/prod"), Code.ALLOWED, "Owner")


def test_action_rbac_write_deny(setup: Setup) -> None:
    _, _, c = setup()
    # Contributor's notActions subtract Microsoft.Authorization/*/Write.
    expect(check(c, lead, "rbac.write", "resourcegroup:" + SUB_ID + "/prod"), Code.DENIED, "none of lead@example.com's 1 role assignment(s)")


def test_action_resourcegroup_delete_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, lead, "resourcegroup.delete", "resourcegroup:" + SUB_ID + "/prod"), Code.ALLOWED, "")


def test_action_resourcegroup_delete_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "resourcegroup.delete", "resourcegroup:" + SUB_ID + "/prod"), Code.DENIED, "")


def test_action_deployment_write_allow(setup: Setup) -> None:
    _, _, c = setup()
    # The exact-scope deny at the subscription does not reach the group.
    expect(check(c, lead, "deployment.write", "resourcegroup:" + SUB_ID + "/prod"), Code.ALLOWED, "")


def test_action_deployment_write_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, lead, "deployment.write", "subscription:" + SUB_ID), Code.DENIED, '"no-deploy-sub-exact"')


def test_raw_actions(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "raw:Microsoft.Network/publicIPAddresses/read", "resourcegroup:" + SUB_ID + "/prod"), Code.ALLOWED, "Reader")
    expect(check(c, dana, "raw:Microsoft.Network/publicIPAddresses/delete", "resourcegroup:" + SUB_ID + "/prod"), Code.DENIED, "")
    expect(check(c, dana, "data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", "resource:" + SCOPE_STOR), Code.ALLOWED, "")
    # Reader's */read is a control-plane action, not a data action.
    expect(check(c, dana, "data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", "resourcegroup:" + SUB_ID + "/prod"), Code.DENIED, "")


def test_conditional_assignment(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "vm.delete", "resourcegroup:" + SUB_ID + "/cond"), Code.UNSUPPORTED, "ABAC condition")
    # An unconditional grant elsewhere still answers.
    expect(check(c, dana, "vm.read", "resourcegroup:" + SUB_ID + "/cond"), Code.ALLOWED, "Reader")


def test_management_groups(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, bob, "vm.delete", "managementgroup:corp"), Code.ALLOWED, "Owner")
    # Another management group: bob's Owner at corp may or may not be above it.
    expect(check(c, bob, "vm.delete", "managementgroup:other-mg"), Code.UNSUPPORTED, "management group")
    expect(check(c, dana, "vm.read", "managementgroup:corp"), Code.DENIED, "")


def test_assignments_below_do_not_apply(setup: Setup) -> None:
    _, _, c = setup()
    # bob's Contributor at other is below the subscription; only Owner at corp applies.
    expect(check(c, bob, "rbac.write", "subscription:" + SUB_ID), Code.ALLOWED, "Owner")
    _, f, c = setup()
    with f.mu:
        f.assignments = f.assignments[:4]
        f.assignments.append(Assignment("ra-6", SCOPE_OTHER, ROLE_CONTRIBUTOR, OID_BOB, "User"))
    expect(check(c, bob, "vm.read", "subscription:" + SUB_ID), Code.DENIED, "no role assignment at or above")
    expect(check(c, bob, "vm.read", "resourcegroup:" + SUB_ID + "/other"), Code.ALLOWED, "Contributor")


# --- identity ---------------------------------------------------------------


def test_identity(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, User(email="nobody@example.com"), "vm.read", "subscription:" + SUB_ID), Code.USER_NOT_FOUND, "no Entra user")
    expect(check(c, User(email="dup@example.com"), "vm.read", "subscription:" + SUB_ID), Code.USER_AMBIGUOUS, "2 Entra users")
    expect(check(c, User(email="off@example.com"), "vm.read", "subscription:" + SUB_ID), Code.DENIED, "disabled")
    expect(check(c, User(email="not an email"), "vm.read", "subscription:" + SUB_ID), Code.INVALID_REQUEST, "")
    # By UPN as well as mail.
    expect(check(c, User(email="dana@corp.example"), "vm.read", "subscription:" + SUB_ID), Code.ALLOWED, "")


def test_filter_quotes_email(setup: Setup) -> None:
    srv, _, c = setup()
    check(c, User(email="o'neil@example.com"), "vm.read", "subscription:" + SUB_ID)
    for call in srv.calls():
        if call.path == "/v1.0/users":
            assert "'o''neil@example.com'" in call.q("$filter"), f"filter {call.q('$filter')!r}"


class StubIdentity(Connection):
    """A microsoft365 connection that resolves one user."""

    def __init__(self, ident: Identity) -> None:
        self.ident = ident

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        return self.ident

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        raise NotImplementedError

    def probe(self, ctx: Context) -> ProbeResult:
        raise NotImplementedError


def test_microsoft365_connection(new_server: NewServer) -> None:
    srv, _ = new_server()
    deps, _ = itest.deps(srv)

    def connection(cid: str) -> Connection:
        if cid != "m365":
            raise LookupError("no such connection")
        return StubIdentity(Identity(id=OID_DANA, display="dana@example.com", attrs={"account_enabled": "true"}))

    deps.connection = connection
    s = itest.settings(
        "az",
        "azure",
        {"tenant_id": TENANT_ID, "client_id": CLIENT_ID, "url": srv.url, "authority_url": srv.url, "microsoft365_connection": "m365"},
        {"credential": literal(itest.CANARY + "secret")},
    )
    c = Azure().new(background(), s, deps)
    expect(check(c, dana, "vm.read", "subscription:" + SUB_ID), Code.ALLOWED, "Reader")
    for call in srv.calls():
        assert not call.path.startswith("/v1.0/"), f"Graph called although a microsoft365 connection resolves users: {call.path}"
    with pytest.raises(ValueError):
        Azure().new(
            background(),
            itest.settings("az", "azure", {"tenant_id": TENANT_ID, "client_id": CLIENT_ID, "microsoft365_connection": "nope"}, {"credential": literal("x")}),
            deps,
        )
    # An identity that does not say whether the account is enabled.
    deps.connection = lambda cid: StubIdentity(Identity(id=OID_DANA, display="dana@example.com", attrs={"account_enabled": "unknown"}))
    c2 = Azure().new(background(), s, deps)
    expect(check(c2, dana, "vm.read", "subscription:" + SUB_ID), Code.UNSUPPORTED, "not reported")
    # The token endpoint was used for ARM only.
    tokens = sum(1 for call in srv.calls() if call.path.endswith("/oauth2/v2.0/token"))
    assert tokens == 1, f"{tokens} token calls, want 1"


def test_caller_groups_ignored(setup: Setup) -> None:
    srv, _, c = setup()
    expect(check(c, User(email="none@example.com", groups=(GROUP_G1,)), "vm.start", "resource:" + SCOPE_VM), Code.DENIED, "")
    for call in srv.calls():
        assert GROUP_G1 not in call.q("$filter"), "caller group reached the filter"


# --- transport --------------------------------------------------------------


def test_paging_and_caching(setup: Setup) -> None:
    srv, f, c = setup()
    with f.mu:
        f.page_size = 1
    # No assignment grants this, so every page and every covering role
    # definition is read; the second check finds the definitions cached.
    expect(check(c, dana, "rbac.write", "resourcegroup:" + SUB_ID + "/prod"), Code.DENIED, "2 role assignment(s)")
    expect(check(c, dana, "rbac.write", "resourcegroup:" + SUB_ID + "/prod"), Code.DENIED, "")
    pages = defs = tokens = 0
    for call in srv.calls():
        if call.path.endswith("/roleAssignments"):
            pages += 1
        elif "/roleDefinitions/" in call.path:
            defs += 1
        elif call.path.endswith("/token"):
            tokens += 1
    # dana has four assignments: four pages per check.
    assert pages == 8, f"{pages} assignment pages, want 8"
    assert defs == 2, f"{defs} role definition reads, want 2 (Reader and VM Operator, cached)"
    assert tokens == 2, f"{tokens} token calls, want 2 (ARM and Graph, cached)"


def test_next_link_off_host_is_refused(setup: Setup) -> None:
    srv, _, c = setup()

    def h(w: Any, r: Any) -> None:
        if r.path.endswith("/denyAssignments"):
            write(w, 200, {"value": []})
            return
        write(
            w,
            200,
            {"value": [], "nextLink": "https://evil.example.com/subscriptions/x/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"},
        )

    srv.handle("GET", "/subscriptions/*", h)
    expect(check(c, dana, "vm.read", "subscription:" + SUB_ID), Code.UPSTREAM_ERROR, "outside the ARM endpoint")


def test_scope_not_visible(setup: Setup) -> None:
    _, f, c = setup()
    with f.mu:
        f.forbidden[SCOPE_OTHER.lower()] = True
    expect(check(c, dana, "vm.read", "resourcegroup:" + SUB_ID + "/other"), Code.RESOURCE_NOT_VISIBLE, "needs Reader")
    expect(check(c, dana, "vm.read", "subscription:44444444-4444-4444-4444-444444444444"), Code.RESOURCE_NOT_VISIBLE, "")


@pytest.mark.parametrize(
    ("action", "resource"),
    [
        ("vm.read", "subscription:not-a-guid"),
        ("vm.read", "resourcegroup:" + SUB_ID),
        ("vm.read", "resourcegroup:" + SUB_ID + "/bad."),
        ("vm.read", "resource:/subscriptions/" + SUB_ID + "/resourceGroups/prod"),
        ("vm.read", "resource:/subscriptions/" + SUB_ID + "/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines"),
        ("vm.read", "resource:/subscriptions/" + SUB_ID + "/resourceGroups/prod/providers/Compute/virtualMachines/x"),
        ("vm.read", "resource:/subscriptions/" + SUB_ID + "/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/a b"),
        ("vm.read", "subscription:" + SUB_ID + "?x=1"),
        ("vm.read", "vm:x"),
        ("vm.read", "managementgroup:a/b"),
        ("vm.read", "managementgroup:.."),
        ("vm.read", "managementgroup:..."),
        ("vm.read", "resource:/subscriptions/" + SUB_ID + "/resourceGroups/prod/providers/Microsoft.Compute/../.."),
        ("vm.read", "resource:/subscriptions/" + SUB_ID + "/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/."),
        ("vm.read", "resourcegroup:" + SUB_ID + "/.."),
    ],
)
def test_invalid_requests(setup: Setup, action: str, resource: str) -> None:
    _, _, c = setup()
    d = check(c, dana, action, resource)
    assert d.code == Code.INVALID_REQUEST, f"{action} {resource}: {d.code} {d.text}"


def test_raw_action_shapes() -> None:
    for bad in (
        "raw:virtualMachines/read",
        "raw:Microsoft.Compute/*/read",
        "raw:Microsoft.Compute",
        "data:Microsoft.Compute/virtualMachines/read/../x",
        "raw:",
        "data:Microsoft.Compute/vm read",
        "raw:Microsoft.Compute/vm?x",
    ):
        assert Azure().match_action(bad) is None, f"{bad!r} accepted"
    for good in (
        "raw:Microsoft.Compute/virtualMachines/read",
        "data:Microsoft.KeyVault/vaults/secrets/getSecret/action",
        "raw:microsoft.web/sites/restart/Action",
    ):
        assert Azure().match_action(good) is not None, f"{good!r} rejected"


@pytest.mark.parametrize(
    ("pattern", "op", "want"),
    [
        ("*", "Microsoft.Compute/virtualMachines/delete", True),
        ("*/read", "Microsoft.Compute/virtualMachines/read", True),
        ("*/read", "Microsoft.Compute/virtualMachines/delete", False),
        ("Microsoft.Compute/*", "microsoft.compute/virtualMachines/start/action", True),
        ("Microsoft.Compute/virtualMachines/*", "Microsoft.Compute/disks/read", False),
        ("Microsoft.Authorization/*/Write", "Microsoft.Authorization/roleAssignments/write", True),
        ("Microsoft.Authorization/*/Write", "Microsoft.Authorization/roleAssignments/read", False),
        ("Microsoft.Compute/virtualMachines/read", "Microsoft.Compute/virtualMachines/read", True),
        ("Microsoft.Compute/virtualMachines/read", "Microsoft.Compute/virtualMachines/readx", False),
        ("Microsoft.*/read", "Microsoft.Compute/virtualMachines/read", True),
    ],
)
def test_match_operation(pattern: str, op: str, want: bool) -> None:
    assert match_operation(pattern, op) == want, f"match({pattern!r}, {op!r}) = {match_operation(pattern, op)}"


def test_failures(setup: Setup) -> None:
    srv, _, c = setup()
    # Warm the tokens so the failure lands on ARM, not the token endpoint.
    check(c, dana, "vm.read", "subscription:" + SUB_ID)
    itest.failure_cases(srv, lambda: check(c, dana, "vm.read", "subscription:" + SUB_ID))


def test_bad_secret(new_server: NewServer) -> None:
    srv, _ = new_server()
    deps, _ = itest.deps(srv)
    s = itest.settings(
        "az",
        "azure",
        {"tenant_id": TENANT_ID, "client_id": CLIENT_ID, "url": srv.url, "graph_url": srv.url, "authority_url": srv.url},
        {"credential": literal("wrong")},
    )
    c = Azure().new(background(), s, deps)
    expect(check(c, dana, "vm.read", "subscription:" + SUB_ID), Code.CREDENTIAL_REJECTED, "")


@pytest.mark.parametrize(
    ("values", "with_secret"),
    [
        ({"tenant_id": TENANT_ID, "client_id": CLIENT_ID}, False),
        ({"tenant_id": "bad tenant", "client_id": CLIENT_ID}, True),
        ({"tenant_id": TENANT_ID, "client_id": "not-a-guid"}, True),
        ({"tenant_id": TENANT_ID, "client_id": CLIENT_ID, "url": "ftp://x"}, True),
    ],
)
def test_new_validation(srv: itest.Server, values: dict[str, str], with_secret: bool) -> None:
    deps, _ = itest.deps(srv)
    secrets = {"credential": literal("x")} if with_secret else {}
    with pytest.raises(ValueError):
        Azure().new(background(), itest.settings("az", "azure", values, secrets), deps)


def test_probe(setup: Setup) -> None:
    _, f, c = setup()
    res = c.probe(background())
    assert "4 built-in role definitions" in res.summary and "Graph user listing works" in res.summary, f"summary {res.summary!r}"
    itest.assert_no_canary(res.summary)
    with f.mu:
        f.secret = "rotated"
    # Cached tokens still work; a fresh connection fails.
    c.probe(background())


def test_no_secret_in_logs(new_server: NewServer) -> None:
    srv, f = new_server()
    deps, logs = itest.deps(srv)
    s = itest.settings(
        "az",
        "azure",
        {"tenant_id": TENANT_ID, "client_id": CLIENT_ID, "url": srv.url, "graph_url": srv.url, "authority_url": srv.url},
        {"credential": literal(f.secret)},
    )
    c = Azure().new(background(), s, deps)
    check(c, dana, "vm.read", "resource:" + SCOPE_VM)
    check(c, dana, "vm.read", "subscription:44444444-4444-4444-4444-444444444444")
    itest.assert_no_canary(logs.text())
