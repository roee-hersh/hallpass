"""Port of internal/integrations/salesforce/salesforce_test.go."""

from __future__ import annotations

import base64
import calendar
import json
import re
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from hallpass.authx.jwt import RS256, decode_jwt_claims, verify
from hallpass.core.catalog import Action, Resource
from hallpass.core.context import background
from hallpass.core.decision import Code, Decision, HallpassError, to_decision
from hallpass.core.integration import CheckRequest, Connection, User, find_action, validate_fields
from hallpass.core.secret import Secret
from hallpass.core.secret import literal as secret_literal
from hallpass.integrations.salesforce import Salesforce
from hallpass.integrations.salesforce.salesforce import (
    ATTR_ACTIVE,
    ATTR_FROZEN,
    FLOW_CLIENT_CREDENTIALS,
    FLOW_JWT_BEARER,
    FROZEN_TRUE,
    FROZEN_UNKNOWN,
    MATCH_EMAIL,
    MATCH_FEDERATION_ID,
    MATCH_USERNAME,
    SalesforceConnection,
    decode_api_error,
)
from hallpass.net import httpx
from tests import harness as itest

# -- test key ----------------------------------------------------------------------

_KEY_LOCK = threading.Lock()
_KEY: list[rsa.RSAPrivateKey] = []


def signing_key() -> rsa.RSAPrivateKey:
    with _KEY_LOCK:
        if not _KEY:
            _KEY.append(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        return _KEY[0]


def key_secret() -> Secret:
    """The private key PEM with a canary comment line in front, so a leaked
    credential is caught by the log check."""
    p = signing_key().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    return secret_literal("# " + itest.CANARY + "sf\n" + p.decode())


# -- fake Salesforce ---------------------------------------------------------------

TEST_CLIENT_ID = "3MVG9consumerKey"
TEST_USERNAME = "hallpass@acme.example"
TEST_AUDIENCE = "https://login.salesforce.com"
TEST_VERSION = "v66.0"

DANA_ID = "005000000000001AAA"
BOB_ID = "005000000000002AAA"
IAN_ID = "005000000000003AAA"
FRED_ID = "005000000000004AAA"
ONEIL_ID = "005000000000005AAA"
SHARED_A = "005000000000006AAA"
SHARED_B = "005000000000007AAA"
TWIN_A = "005000000000008AAA"
TWIN_B = "005000000000009AAA"
AMB_A = "00500000000000AAAA"
AMB_B = "00500000000000BAAA"
MANY_A = "00500000000000CAAA"
MANY_B = "00500000000000DAAA"
MANY_C = "00500000000000EAAA"
MANY_D = "00500000000000FAAA"
MANY_E = "00500000000000GAAA"
DUP_A = "00500000000000HAAA"
DUP_B = "00500000000000IAAA"
ACCT_ID = "001000000000001AAA"
HIDDEN_ID = "001000000000009AAA"
GROUP_ID = "0PG000000000001AAA"

dana = User(email="dana@example.com")
bob = User(email="bob@example.com")
ian = User(email="ian@example.com")
fred = User(email="fred@example.com")
oneil = User(email="o'neil@example.com")


@dataclass
class SfErr:
    status: int
    code: str


def user_row(id: str, active: bool, username: str, email: str, fed: str = "", typ: str = "", name: str = "") -> dict[str, Any]:
    """A User row as Go's userRow marshals."""
    return {"Id": id, "IsActive": active, "Username": username, "Email": email, "FederationIdentifier": fed, "UserType": typ, "Name": name}


def record_access(read: bool = False, edit: bool = False, delete: bool = False, transfer: bool = False, all: bool = False, level: str = "") -> dict[str, Any]:
    return {
        "RecordId": ACCT_ID,
        "HasReadAccess": read,
        "HasEditAccess": edit,
        "HasDeleteAccess": delete,
        "HasTransferAccess": transfer,
        "HasAllAccess": all,
        "MaxAccessLevel": level,
    }


def parent(name: str = "", profile: bool = False) -> dict[str, Any]:
    return {"IsOwnedByProfile": profile, "Name": name}


def object_perm(parent_ref: dict[str, Any], **cols: bool) -> dict[str, Any]:
    row: dict[str, Any] = {
        c: cols.get(c, False)
        for c in (
            "PermissionsRead",
            "PermissionsCreate",
            "PermissionsEdit",
            "PermissionsDelete",
            "PermissionsViewAllRecords",
            "PermissionsModifyAllRecords",
        )
    }
    row["Parent"] = parent_ref
    return row


def field_perm(parent_ref: dict[str, Any], read: bool = False, edit: bool = False) -> dict[str, Any]:
    return {"PermissionsRead": read, "PermissionsEdit": edit, "Parent": parent_ref}


FROM_RE = re.compile(r"FROM (\w+)", re.ASCII)
WHERE_RE = re.compile(r"WHERE (\w+) = '((?:[^'\\]|\\.)*)'", re.ASCII)
PERM_RE = re.compile(r"WHERE (Permissions\w+) = true", re.ASCII)
IN_RE = re.compile(r"IN \(('[^)]*')\)")
LIMIT_RE = re.compile(r" LIMIT (\d+)\Z", re.ASCII)
# The activation/expiry filter every assignment sub-select must carry
# (finding: session-based and expired assignments must not grant).
ASSIGN_FILTER = (
    r"\(SELECT PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId = '\w+' AND PermissionSet\.HasActivationRequired = false "
    r"AND \(ExpirationDate = null OR ExpirationDate > (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\)\)"
)
ASSIGN_FILTER_RE = re.compile(ASSIGN_FILTER, re.ASCII)
ASSIGN_LOOSE_RE = re.compile(r"\(SELECT PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId = '\w+'\)", re.ASCII)


def lit(q: str, field: str) -> str:
    """The escaped literal compared to field, unescaped."""
    m = re.search(re.escape(field) + r" = '((?:[^'\\]|\\.)*)'", q)
    if m is None:
        return ""
    return unescape(m.group(1))


def unescape(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            i += 1
            out.append({"n": "\n", "r": "\r", "t": "\t"}.get(s[i], s[i]))
        else:
            out.append(s[i])
        i += 1
    return "".join(out)


def write_sf_error(w: itest.ResponseWriter, status: int, code: str) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write(f'[{{"message":"{itest.CANARY}message for {code}","errorCode":"{code}"}}]')


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class FakeSF:
    def __init__(self, srv: itest.Server) -> None:
        self.srv = srv
        self.pub = signing_key().public_key()
        self.mu = threading.Lock()
        self.errs: list[str] = []  # Go: t.Errorf from a handler
        self.instance_url = srv.url + "/inst"  # token response instance_url; "" omits the field
        self.valid_tokens: set[str] = set()
        self.token_calls = 0
        self.queries: list[str] = []
        self.revoke_next = False  # the next API call answers 401 INVALID_SESSION_ID and forgets the token
        self.always_revoke = False
        self.lenient_jwt = False  # do not fail the test on a bad assertion
        self.users: list[dict[str, Any]] = [
            user_row("005000000000000AAA", True, TEST_USERNAME, TEST_USERNAME, "", "Standard", "hallpass"),
            user_row(DANA_ID, True, "dana@example.com", "dana@example.com", "dana", "Standard", "Dana"),
            user_row(BOB_ID, True, "bob@example.com", "bob@example.com", "bob", "Standard", "Bob"),
            user_row(IAN_ID, False, "ian@example.com", "ian@example.com", "", "Standard", "Ian"),
            user_row(FRED_ID, True, "fred@example.com", "fred@example.com", "", "Standard", "Fred"),
            user_row(ONEIL_ID, True, "oneil@example.com.acme", "o'neil@example.com", "", "Standard", "O'Neil"),
            # shared: two rows, the one whose Username is the email wins.
            user_row(SHARED_A, True, "shared@example.com.portal", "shared@example.com", "", "CspLitePortal", "Shared portal"),
            user_row(SHARED_B, True, "shared@example.com", "shared@example.com", "", "Standard", "Shared"),
            # twin: two rows, only one active Standard.
            user_row(TWIN_A, False, "twin@example.com.old", "twin@example.com", "", "Standard", "Twin old"),
            user_row(TWIN_B, True, "twin@example.com.new", "twin@example.com", "", "Standard", "Twin new"),
            # amb: two active Standard rows, neither username matches.
            user_row(AMB_A, True, "amb1@example.com", "amb@example.com", "", "Standard", "Amb 1"),
            user_row(AMB_B, True, "amb2@example.com", "amb@example.com", "", "Standard", "Amb 2"),
            # many: five rows share the email; only one is an active Standard
            # user, but the query limit is reached so nothing may be picked.
            user_row(MANY_A, True, "many1@example.com", "many@example.com", "", "Standard", "Many 1"),
            user_row(MANY_B, False, "many2@example.com", "many@example.com", "", "Standard", "Many 2"),
            user_row(MANY_C, True, "many3@example.com", "many@example.com", "", "CspLitePortal", "Many 3"),
            user_row(MANY_D, False, "many4@example.com", "many@example.com", "", "Standard", "Many 4"),
            user_row(MANY_E, True, "many5@example.com", "many@example.com", "", "Guest", "Many 5"),
            # dup: two rows with the same Username, which Salesforce should
            # never allow; the exact lookup must not pick one.
            user_row(DUP_A, True, "dup@example.com", "dup-a@example.com", "", "Standard", "Dup A"),
            user_row(DUP_B, True, "dup@example.com", "dup-b@example.com", "", "Standard", "Dup B"),
        ]
        self.frozen: dict[str, bool] = {FRED_ID: True}
        self.record_access: dict[str, dict[str, Any]] = {
            DANA_ID + "|" + ACCT_ID: record_access(True, True, True, True, True, "All"),
            BOB_ID + "|" + ACCT_ID: record_access(read=True, level="Read"),
        }
        all_cols = dict.fromkeys(
            (
                "PermissionsRead",
                "PermissionsCreate",
                "PermissionsEdit",
                "PermissionsDelete",
                "PermissionsViewAllRecords",
                "PermissionsModifyAllRecords",
            ),
            True,
        )
        self.object_perms: dict[str, list[dict[str, Any]]] = {
            DANA_ID + "|Account": [object_perm(parent("Sales", True), **all_cols)],
            BOB_ID + "|Account": [
                object_perm(parent("Minimum Access", True), PermissionsRead=True),
                object_perm(parent("Empty_Set")),
            ],
        }
        # Rows granted through session-based or expired assignments: a real
        # org returns them only when the assignment sub-select carries no
        # activation/expiry filter.
        self.session_object_perms: dict[str, list[dict[str, Any]]] = {
            # Bob's session-based set grants Edit only while activated, and an
            # expired assignment grants Delete: neither is in force.
            BOB_ID + "|Account": [
                object_perm(parent("Session_Editors"), PermissionsRead=True, PermissionsEdit=True),
                object_perm(parent("Expired_Deleters"), PermissionsRead=True, PermissionsDelete=True),
            ],
            BOB_ID + "|Invoice__c": [object_perm(parent("Session_Invoices"), PermissionsRead=True)],
        }
        # The sObjects whose describe answers 200.
        self.objects: dict[str, bool] = {"Account": True, "Invoice__c": True, "Contact": True}
        self.field_perms: dict[str, list[dict[str, Any]]] = {
            DANA_ID + "|Account.Rating": [field_perm(parent("Sales", True), read=True, edit=True)],
            BOB_ID + "|Account.Rating": [field_perm(parent("Readers"), read=True)],
            BOB_ID + "|Account.Secret__c": [field_perm(parent("Minimum Access", True))],
        }
        self.sys_perms: dict[str, dict[str, str]] = {
            DANA_ID: {"PermissionsApiEnabled": "Sales", "PermissionsViewSetup": "Sales"},
            BOB_ID: {"PermissionsApiEnabled": "Minimum Access"},
        }
        # Assigned permission sets as Name or ns__Name.
        self.perm_sets: dict[str, list[str]] = {DANA_ID: ["Sales_Ops", "acme__Billing"], BOB_ID: ["Billing"]}
        self.groups: dict[str, list[str]] = {}
        self.group_status: dict[str, str] = {GROUP_ID: "Updated"}
        self.describe_fields = ["Id", "Name", "IsOwnedByProfile", "PermissionsApiEnabled", "PermissionsViewSetup", "PermissionsModifyAllData"]
        self.errors: dict[str, SfErr] = {}
        # Makes any query whose assignment sub-select filters on
        # HasActivationRequired/ExpirationDate answer 400 INVALID_FIELD, like
        # an org whose API version lacks those fields.
        self.reject_assignment_filter = False
        self.remaining = 14000
        srv.handle("POST", "/services/oauth2/token", self.handle_token)
        srv.handle("GET", "/services/data/*", self.handle_api)
        srv.handle("GET", "/inst/services/data/*", self.handle_api)

    def error(self, msg: str) -> None:
        self.errs.append(msg)

    def verify_jwt(self, a: str) -> str | None:
        parts = a.split(".")
        if len(parts) != 3:
            return f"assertion has {len(parts)} parts"
        try:
            hdr = json.loads(_b64url_decode(parts[0]))
            if hdr.get("alg") != "RS256":
                return f"alg {hdr.get('alg')}"
            sig = _b64url_decode(parts[2])
            try:
                verify(self.pub, RS256, (parts[0] + "." + parts[1]).encode(), sig)
            except ValueError as e:
                return f"signature: {e}"
            claims = decode_jwt_claims(a)
        except ValueError as e:
            return str(e)
        if claims.get("iss") != TEST_CLIENT_ID or claims.get("sub") != TEST_USERNAME or claims.get("aud") != TEST_AUDIENCE:
            return f"claims iss={claims.get('iss')!r} sub={claims.get('sub')!r} aud={claims.get('aud')!r}"
        now = int(time.time())
        exp = claims.get("exp", 0)
        if exp <= now or exp > now + 180 + 5:
            return f"exp {exp} is not within 3 minutes of now {now}"
        return None

    def handle_token(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        form = r.form()
        with self.mu:
            self.token_calls += 1
            n = self.token_calls
            inst = self.instance_url

        def fail(code: str) -> None:
            w.header().set("Content-Type", "application/json")
            w.write_header(400)
            w.write(f'{{"error":"{code}","error_description":"{itest.CANARY}description"}}')

        def get(k: str) -> str:
            vs = form.get(k)
            return vs[0] if vs else ""

        if r.header.get("Content-Type") != "application/x-www-form-urlencoded":
            self.error(f"token request content type {r.header.get('Content-Type')!r}")
        grant = get("grant_type")
        if grant == "urn:ietf:params:oauth:grant-type:jwt-bearer":
            err = self.verify_jwt(get("assertion"))
            if err is not None:
                with self.mu:
                    lenient = self.lenient_jwt
                if not lenient:
                    self.error(f"assertion: {err}")
                fail("invalid_grant")
                return
        elif grant == "client_credentials":
            if get("client_id") != TEST_CLIENT_ID or get("client_secret") != itest.CANARY + "consumer":
                fail("invalid_client")
                return
        else:
            fail("unsupported_grant_type")
            return
        tok = itest.CANARY + "tok" + str(n)
        with self.mu:
            self.valid_tokens.add(tok)
        body: dict[str, Any] = {"access_token": tok, "id": "https://login.salesforce.com/id/00D/005", "token_type": "Bearer", "issued_at": "1700000000000", "scope": "api"}
        if inst != "":
            body["instance_url"] = inst
        w.header().set("Content-Type", "application/json")
        w.write(json.dumps(body) + "\n")

    def handle_api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        tok = r.header.get("Authorization").removeprefix("Bearer ")
        with self.mu:
            valid = tok in self.valid_tokens
            if valid and (self.revoke_next or self.always_revoke):
                self.valid_tokens.discard(tok)
                self.revoke_next = False
                valid = False
        if not valid:
            write_sf_error(w, 401, "INVALID_SESSION_ID")
            return
        path = r.path.removeprefix("/inst")
        rest = path.removeprefix("/services/data/" + TEST_VERSION)
        if rest == path:
            self.error(f"unexpected API version in {r.path}")
            write_sf_error(w, 404, "NOT_FOUND")
            return
        if rest == "/query":
            self.handle_query(w, r)
        elif rest == "/limits":
            with self.mu:
                rem = self.remaining
            w.header().set("Content-Type", "application/json")
            w.write(f'{{"DailyApiRequests":{{"Max":15000,"Remaining":{rem}}},"DailyBulkApiBatches":{{"Max":15000,"Remaining":15000}}}}')
        elif rest == "/sobjects/PermissionSet/describe":
            with self.mu:
                fields = list(self.describe_fields)
            out = [{"name": n, "type": "boolean"} for n in fields]
            w.header().set("Content-Type", "application/json")
            w.write(json.dumps({"name": "PermissionSet", "fields": out}) + "\n")
        elif rest.startswith("/sobjects/") and rest.endswith("/describe"):
            name = rest.removeprefix("/sobjects/").removesuffix("/describe")
            with self.mu:
                e = self.errors.get("describe:" + name)
                exists = self.objects.get(name, False)
            if e is not None:
                write_sf_error(w, e.status, e.code)
            elif exists:
                w.header().set("Content-Type", "application/json")
                w.write(json.dumps({"name": name, "queryable": True, "fields": []}) + "\n")
            else:
                write_sf_error(w, 404, "NOT_FOUND")
        else:
            write_sf_error(w, 404, "NOT_FOUND")

    def describe_calls(self, name: str) -> int:
        """The sObject describes of name."""
        return sum(1 for call in self.srv.calls() if call.path.endswith("/sobjects/" + name + "/describe"))

    def check_assignment_filter(self, w: itest.ResponseWriter, q: str) -> tuple[bool, bool]:
        """Enforce the finding on the assignment sub-select: the query
        carries the activation/expiry filter with a current timestamp, or
        (when the org is set to reject it) it is the loose form of a retry.
        Returns (loose, failed)."""
        if "(SELECT PermissionSetId FROM PermissionSetAssignment" not in q:
            return False, False
        m = ASSIGN_FILTER_RE.search(q)
        if m is not None:
            if self.reject_assignment_filter:
                write_sf_error(w, 400, "INVALID_FIELD")
                return False, True
            try:
                ts = calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ"))
            except ValueError:
                ts = None
            now = time.time()
            if ts is None or ts < now - 60 or ts > now + 60:
                self.error(f"assignment filter timestamp {m.group(1)!r} is not now: {q}")
            return False, False
        if ASSIGN_LOOSE_RE.search(q):
            if not self.reject_assignment_filter:
                self.error(f"assignment sub-select lacks the activation/expiry filter: {q}")
            return True, False
        self.error(f"unrecognised assignment sub-select: {q}")
        write_sf_error(w, 400, "MALFORMED_QUERY")
        return False, True

    def handle_query(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        q = r.q("q")
        with self.mu:
            self.queries.append(q)
            m = FROM_RE.search(q)
            if m is None:
                write_sf_error(w, 400, "MALFORMED_QUERY")
                return
            obj = m.group(1)
            e = self.errors.get(obj)
            if e is not None:
                write_sf_error(w, e.status, e.code)
                return
            records: list[Any] = []
            uid = lit(q, "AssigneeId")
            loose, failed = self.check_assignment_filter(w, q)
            if failed:
                return
            if obj == "User":
                wm = WHERE_RE.search(q)
                if wm is None:
                    write_sf_error(w, 400, "MALFORMED_QUERY")
                    return
                field, val = wm.group(1), unescape(wm.group(2))
                limit = len(self.users)
                lm = LIMIT_RE.search(q)
                if lm is not None:
                    limit = int(lm.group(1))
                elif q.startswith("SELECT Id, IsActive, Username, Email"):
                    self.error(f"identity query without LIMIT: {q}")
                for u in self.users:
                    if len(records) >= limit:
                        break
                    if field not in ("Email", "Username", "FederationIdentifier"):
                        write_sf_error(w, 400, "INVALID_FIELD")
                        return
                    if u[field] == val:
                        records.append(u)
            elif obj == "UserLogin":
                id = lit(q, "UserId")
                for u in self.users:
                    if u["Id"] == id:
                        records.append({"IsFrozen": self.frozen.get(id, False)})
            elif obj == "UserRecordAccess":
                row = self.record_access.get(lit(q, "UserId") + "|" + lit(q, "RecordId"))
                if row is not None:
                    records.append(row)
            elif obj == "ObjectPermissions":
                key = uid + "|" + lit(q, "SobjectType")
                records.extend(self.object_perms.get(key, []))
                if loose:
                    records.extend(self.session_object_perms.get(key, []))
            elif obj == "FieldPermissions":
                records.extend(self.field_perms.get(uid + "|" + lit(q, "Field"), []))
            elif obj == "PermissionSet":
                pm = PERM_RE.search(q)
                if pm is None:
                    write_sf_error(w, 400, "MALFORMED_QUERY")
                    return
                par = self.sys_perms.get(uid, {}).get(pm.group(1))
                if par is not None:
                    records.append({"Id": "0PS000000000001AAA", "Name": par, "IsOwnedByProfile": True})
            elif obj == "PermissionSetAssignment":
                if "PermissionSetGroupId != null" in q:
                    for g in self.groups.get(uid, []):
                        records.append({"PermissionSetGroupId": g})
                else:
                    name = lit(q, "PermissionSet.Name")
                    want = name
                    if q.endswith(" AND PermissionSet.NamespacePrefix = null"):
                        pass
                    elif lit(q, "PermissionSet.NamespacePrefix") != "":
                        want = lit(q, "PermissionSet.NamespacePrefix") + "__" + name
                    else:
                        self.error(f"permission set query without a NamespacePrefix condition: {q}")
                    for n in self.perm_sets.get(uid, []):
                        if n == want:
                            records.append({"Id": "0Pa000000000001AAA"})
            elif obj == "PermissionSetGroup":
                im = IN_RE.search(q)
                if im is None:
                    write_sf_error(w, 400, "MALFORMED_QUERY")
                    return
                for id in im.group(1).split(","):
                    id = id.strip("'")
                    st = self.group_status.get(id)
                    if st is not None:
                        records.append({"Id": id, "DeveloperName": "Group_" + id[-4:], "Status": st})
            else:
                write_sf_error(w, 400, "INVALID_TYPE")
                return
            w.header().set("Content-Type", "application/json")
            w.write(json.dumps({"totalSize": len(records), "done": True, "records": records}) + "\n")

    def queries_from(self, obj: str) -> list[str]:
        with self.mu:
            out = []
            for q in self.queries:
                m = FROM_RE.search(q)
                if m is not None and m.group(1) == obj:
                    out.append(q)
            return out

    def token_count(self) -> int:
        with self.mu:
            return self.token_calls


# -- connection helpers ------------------------------------------------------------


def base_values(srv_url: str) -> dict[str, str]:
    return {
        "url": srv_url,
        "client_id": TEST_CLIENT_ID,
        "auth_flow": FLOW_JWT_BEARER,
        "username": TEST_USERNAME,
        "audience": TEST_AUDIENCE,
        "api_version": TEST_VERSION,
        "match_field": MATCH_EMAIL,
        "token_ttl": "15m",
    }


class Env:
    """Makes fakes and connections; every server is closed and every fake's
    handler errors are checked when the test ends."""

    def __init__(self) -> None:
        self.fakes: list[FakeSF] = []

    def new_fake(self) -> FakeSF:
        f = FakeSF(itest.Server())
        self.fakes.append(f)
        return f

    def new_conn(self, f: FakeSF, values: dict[str, str] | None = None, cred: Secret | None = None) -> Connection:
        deps, _ = itest.deps(f.srv)
        v = base_values(f.srv.url)
        v.update(values or {})
        if cred is None or cred.is_zero():
            cred = key_secret()
        s = itest.settings("sf", "salesforce", v, {"credential": cred})
        return Salesforce().new(background(), s, deps)

    def setup(self) -> tuple[FakeSF, Connection]:
        f = self.new_fake()
        return f, self.new_conn(f)

    def close(self) -> None:
        for f in self.fakes:
            f.srv.close()
        for f in self.fakes:
            assert not f.errs, "\n".join(f.errs)
            assert not f.srv.spec_errors, "\n".join(f.srv.spec_errors)


@pytest.fixture
def env() -> Iterator[Env]:
    e = Env()
    yield e
    e.close()


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, Salesforce(), u, action, resource)


def expect_query(qs: list[str], want: str) -> None:
    """Compare one recorded query with want, in which "<assigned>" stands for
    the filtered assignment sub-select (its timestamp is now)."""
    pattern = ASSIGN_FILTER.join(re.escape(p) for p in want.split("<assigned>"))
    assert len(qs) == 1 and re.fullmatch(pattern, qs[0], re.ASCII), f"query {qs!r}\nwant  {want!r}"


def expect(d: Decision, code: Code, text_part: str) -> None:
    itest.expect_code(d, code)
    assert text_part == "" or text_part in d.text, f"decision text {d.text!r} does not mention {text_part!r}"
    assert itest.CANARY not in d.text, f"decision text leaks an upstream message: {d.text!r}"


def resolve_err(c: Connection, u: User) -> BaseException | None:
    try:
        c.resolve_identity(background(), u)
    except Exception as e:
        return e
    return None


def code_of(err: BaseException | None) -> Code | None:
    return None if err is None else to_decision(err).code


# -- auth ----------------------------------------------------------------------------


def test_jwt_bearer_flow(env: Env) -> None:
    f, c = env.setup()
    expect(check(c, dana, "record.read", "record:" + ACCT_ID), Code.ALLOWED, "HasReadAccess")
    expect(check(c, dana, "record.edit", "record:" + ACCT_ID), Code.ALLOWED, "")
    assert f.token_count() == 1, f"token minted {f.token_count()} times, want 1 (cached)"
    token_call = None
    for call in f.srv.calls():
        if call.path == "/services/oauth2/token":
            token_call = call
        elif "/services/data/" in call.path:
            assert call.path.startswith("/inst/services/data/" + TEST_VERSION + "/"), f"API call {call.path} did not use instance_url and the pinned version"
            if call.path.endswith("/query"):
                assert call.q("q") != "", f"query without q: {call.path}"
    assert token_call is not None
    body = token_call.body.decode()
    assert "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer" in body and "assertion=" in body, f"token form: {body}"
    assert "client_secret" not in body, "jwt_bearer sent a client_secret"


def test_client_credentials_flow(env: Env) -> None:
    f = env.new_fake()
    c = env.new_conn(f, {"auth_flow": FLOW_CLIENT_CREDENTIALS, "username": ""}, itest.literal("consumer"))
    expect(check(c, dana, "record.read", "record:" + ACCT_ID), Code.ALLOWED, "")
    body = f.srv.calls()[0].body.decode()
    assert "grant_type=client_credentials" in body and "client_id=" + TEST_CLIENT_ID in body and "client_secret=" in body, f"token form: {body}"
    bad = env.new_conn(f, {"auth_flow": FLOW_CLIENT_CREDENTIALS, "username": ""}, itest.literal("wrong"))
    expect(check(bad, dana, "record.read", "record:" + ACCT_ID), Code.CREDENTIAL_REJECTED, "")
    with pytest.raises(Exception) as ei:
        bad.probe(background())
    assert itest.CANARY not in str(ei.value), f"probe with a wrong secret: {ei.value}"


def test_instance_url_absent(env: Env) -> None:
    f = env.new_fake()
    f.instance_url = ""
    c = env.new_conn(f)
    expect(check(c, dana, "record.read", "record:" + ACCT_ID), Code.ALLOWED, "")
    for call in f.srv.calls():
        assert not call.path.startswith("/inst/"), f"used an instance prefix without instance_url: {call.path}"


def test_invalid_session_remint(env: Env) -> None:
    f, c = env.setup()
    expect(check(c, dana, "record.read", "record:" + ACCT_ID), Code.ALLOWED, "")
    with f.mu:
        f.revoke_next = True
    expect(check(c, dana, "record.read", "record:" + ACCT_ID), Code.ALLOWED, "")
    assert f.token_count() == 2, f"token minted {f.token_count()} times, want 2 (one re-mint)"
    with f.mu:
        f.always_revoke = True
    expect(check(c, dana, "record.read", "record:" + ACCT_ID), Code.CREDENTIAL_REJECTED, "")
    assert f.token_count() == 3, f"token minted {f.token_count()} times, want 3 (re-mint once, then give up)"


# -- identity ------------------------------------------------------------------------


def test_identity_escaping(env: Env) -> None:
    f, c = env.setup()
    id = c.resolve_identity(background(), oneil)
    assert id.id == ONEIL_ID, id
    qs = f.queries_from("User")
    assert (
        len(qs) == 2 and qs[0].endswith(r"WHERE Username = 'o\'neil@example.com' LIMIT 2") and qs[1].endswith(r"WHERE Email = 'o\'neil@example.com' LIMIT 4")
    ), f"user queries: {qs!r}"
    for q in qs:
        assert q.startswith("SELECT Id, IsActive, Username, Email, FederationIdentifier, UserType, Name FROM User WHERE"), f"user query columns: {q!r}"
    assert id.attr(ATTR_ACTIVE) == "true" and id.attr(ATTR_FROZEN) == "false" and id.display == "oneil@example.com.acme", f"identity {id}"
    for bad in ("x' OR 1=1--", "Dana <dana@example.com>", "dana@example.com\n", ""):
        assert code_of(resolve_err(c, User(email=bad))) == Code.INVALID_REQUEST, f"email {bad!r}"
    assert len(f.queries_from("User")) == 2, "an invalid email reached the query"


def test_identity_cases(env: Env) -> None:
    _, c = env.setup()
    ctx = background()
    assert code_of(resolve_err(c, User(email="nobody@example.com"))) == Code.USER_NOT_FOUND
    id = c.resolve_identity(ctx, User(email="shared@example.com"))
    assert id.id == SHARED_B, f"shared email should pick the Username match: {id}"
    id = c.resolve_identity(ctx, User(email="twin@example.com"))
    assert id.id == TWIN_B, f"twin email should pick the single active Standard user: {id}"
    err = resolve_err(c, User(email="amb@example.com"))
    assert err is not None
    d = to_decision(err)
    assert d.code == Code.USER_AMBIGUOUS and "FederationIdentifier" in d.text, f"ambiguous email: {err}"

    f2 = env.new_fake()
    by_username = env.new_conn(f2, {"match_field": MATCH_USERNAME})
    id = by_username.resolve_identity(ctx, User(email="twin@example.com.new"))
    assert id.id == TWIN_B, f"by username: {id}"
    qs = f2.queries_from("User")
    assert "WHERE Username = 'twin@example.com.new'" in qs[0], f"username query: {qs[0]!r}"
    f3 = env.new_fake()
    by_fed = env.new_conn(f3, {"match_field": MATCH_FEDERATION_ID})
    id = by_fed.resolve_identity(ctx, User(email="bob"))
    assert id.id == BOB_ID, f"by federation id: {id}"
    qs = f3.queries_from("User")
    assert "WHERE FederationIdentifier = 'bob'" in qs[0], f"federation query: {qs[0]!r}"
    assert code_of(resolve_err(by_fed, User(email="bob\x01"))) == Code.INVALID_REQUEST, "control character accepted"


def test_inactive_and_frozen(env: Env) -> None:
    f, c = env.setup()
    expect(check(c, ian, "record.read", "record:" + ACCT_ID), Code.DENIED, "inactive")
    expect(check(c, ian, "user.active", "user:ian@example.com"), Code.DENIED, "inactive")
    expect(check(c, fred, "object.read", "object:Account"), Code.DENIED, "frozen")
    qs = f.queries_from("UserLogin")
    assert len(qs) == 3 and "WHERE UserId = '" + FRED_ID + "'" in qs[2], f"UserLogin queries: {qs!r}"
    assert len(f.queries_from("UserRecordAccess")) == 0 and len(f.queries_from("ObjectPermissions")) == 0, (
        "an inactive or frozen user still reached the permission query"
    )


def test_frozen_check_skipped_when_user_login_missing(env: Env) -> None:
    f, c = env.setup()
    f.errors["UserLogin"] = SfErr(400, "INVALID_TYPE")
    # The user is still allowed, but the identity records that freezing was
    # not evaluated and user.active says so.
    id = c.resolve_identity(background(), fred)
    assert id.attr(ATTR_FROZEN) == FROZEN_UNKNOWN, f"identity with UserLogin missing: {id}"
    expect(check(c, fred, "user.active", "user:fred@example.com"), Code.ALLOWED, "frozen users are not detected")
    # The probe reports the gap by trying the query on the integration user.
    r = c.probe(background())
    assert any("frozen users are not detected: UserLogin not queryable" in w for w in r.warnings), f"probe warnings {r.warnings!r} lack the frozen warning"
    qs = f.queries_from("UserLogin")
    assert qs and "WHERE UserId = '005000000000000AAA'" in qs[-1], f"probe UserLogin queries: {qs!r}"
    f.errors["UserLogin"] = SfErr(403, "INSUFFICIENT_ACCESS")
    expect(check(c, fred, "user.active", "user:fred@example.com"), Code.CREDENTIAL_REJECTED, "UserLogin")
    with pytest.raises(Exception) as ei:
        c.probe(background())
    assert to_decision(ei.value).code == Code.CREDENTIAL_REJECTED, f"probe with UserLogin forbidden: {ei.value}"
    # With a frozen user the attribute is definite and the check denies.
    del f.errors["UserLogin"]
    id = c.resolve_identity(background(), fred)
    assert id.attr(ATTR_FROZEN) == FROZEN_TRUE, f"identity of a frozen user: {id}"
    # client_credentials has no username: UserLogin is probed unfiltered.
    f2 = env.new_fake()
    f2.errors["UserLogin"] = SfErr(400, "INVALID_FIELD")
    c2 = env.new_conn(f2, {"auth_flow": FLOW_CLIENT_CREDENTIALS, "username": ""}, itest.literal("consumer"))
    r = c2.probe(background())
    assert len(r.warnings) == 2 and "frozen users are not detected" in r.warnings[0], f"client_credentials probe: {r}"
    qs = f2.queries_from("UserLogin")
    assert qs == ["SELECT IsFrozen FROM UserLogin LIMIT 1"], f"unfiltered UserLogin probe: {qs!r}"


def test_session_and_expired_assignments_excluded(env: Env) -> None:
    """Finding: session-based permission sets and expired time-bound
    assignments must not grant, and when the org cannot filter them out an
    allow is unknown."""
    f, c = env.setup()
    # Bob's session-based set grants Edit and his expired assignment Delete;
    # the filtered sub-select hides both.
    expect(check(c, bob, "object.edit", "object:Account"), Code.DENIED, "PermissionsEdit")
    expect(check(c, bob, "object.delete", "object:Account"), Code.DENIED, "PermissionsDelete")
    expect(check(c, bob, "object.read", "object:Invoice__c"), Code.DENIED, "Invoice__c")
    n = len(f.queries_from("ObjectPermissions"))
    assert n == 3, f"{n} ObjectPermissions queries, want 3 (no retry)"
    # An org whose API version lacks the filter fields: the loose retry may
    # deny but never allow.
    with f.mu:
        f.reject_assignment_filter = True
    f.srv.reset()
    f.queries = []
    expect(check(c, bob, "object.edit", "object:Account"), Code.UNSUPPORTED, "could not exclude session-based or expired assignments")
    qs = f.queries_from("ObjectPermissions")
    assert len(qs) == 2 and ASSIGN_FILTER_RE.search(qs[0]) and ASSIGN_LOOSE_RE.search(qs[1]), f"fallback queries: {qs!r}"
    expect(check(c, bob, "object.create", "object:Account"), Code.DENIED, "PermissionsCreate")
    expect(check(c, bob, "object.read", "object:Contact"), Code.DENIED, "Contact")
    expect(check(c, dana, "field.read", "field:Account.Rating"), Code.UNSUPPORTED, "could not exclude")
    expect(check(c, bob, "field.edit", "field:Account.Rating"), Code.DENIED, "PermissionsEdit")
    expect(check(c, dana, "system.permission", "permission:PermissionsApiEnabled"), Code.UNSUPPORTED, "could not exclude")
    expect(check(c, bob, "system.permission", "permission:PermissionsViewSetup"), Code.DENIED, "PermissionsViewSetup")
    # An INVALID_FIELD that the loose retry also hits is reported as such.
    f.errors["ObjectPermissions"] = SfErr(400, "INVALID_FIELD")
    expect(check(c, bob, "object.read", "object:Account"), Code.UNSUPPORTED, "INVALID_FIELD")


def test_identity_exact_username_first(env: Env) -> None:
    """Finding: the identity lookup is an exact Username match first, then a
    bounded match_field query from which nothing is picked when the bound is
    reached."""
    f, c = env.setup()
    ctx = background()
    id = c.resolve_identity(ctx, dana)
    assert id.id == DANA_ID, id
    qs = f.queries_from("User")
    assert len(qs) == 1 and qs[0].endswith("WHERE Username = 'dana@example.com' LIMIT 2"), f"a Username match should need one query: {qs!r}"
    # Five rows share the email and exactly one is an active Standard user,
    # but the query limit is reached: the rows are a subset, so ambiguous.
    err = resolve_err(c, User(email="many@example.com"))
    assert err is not None
    d = to_decision(err)
    assert d.code == Code.USER_AMBIGUOUS and "at least 4" in d.text, f"limit reached: {err}"
    qs = f.queries_from("User")
    assert qs[-1].endswith("WHERE Email = 'many@example.com' LIMIT 4"), f"match_field query: {qs[-1]!r}"
    # Two rows with one Username: the exact lookup does not pick either.
    assert code_of(resolve_err(c, User(email="dup@example.com"))) == Code.USER_AMBIGUOUS, "duplicate Username"
    # match_field Username is one exact query, LIMIT 2.
    f2 = env.new_fake()
    by_username = env.new_conn(f2, {"match_field": MATCH_USERNAME})
    assert code_of(resolve_err(by_username, User(email="nobody@example.com"))) == Code.USER_NOT_FOUND, "unknown username"
    qs = f2.queries_from("User")
    assert len(qs) == 1 and qs[0].endswith("WHERE Username = 'nobody@example.com' LIMIT 2"), f"username queries: {qs!r}"
    assert code_of(resolve_err(by_username, User(email="dup@example.com"))) == Code.USER_AMBIGUOUS, "duplicate username by Username"
    # match_field FederationIdentifier never consults Username: a federation
    # id that happens to equal another user's Username must not resolve.
    f3 = env.new_fake()
    f3.users.append(user_row("00500000000000JAAA", True, "fed@example.com", "fed-other@example.com", "someone-else", "Standard"))
    by_fed = env.new_conn(f3, {"match_field": MATCH_FEDERATION_ID})
    assert code_of(resolve_err(by_fed, User(email="fed@example.com"))) == Code.USER_NOT_FOUND, "federation id equal to a Username"
    qs = f3.queries_from("User")
    assert len(qs) == 1 and "WHERE FederationIdentifier = 'fed@example.com' LIMIT 4" in qs[0], f"federation queries: {qs!r}"


def test_object_missing_is_unknown(env: Env) -> None:
    """Finding: zero ObjectPermissions rows for an object that does not
    exist is unknown, not deny; the describe that tells them apart is
    cached."""
    f, c = env.setup()
    expect(check(c, bob, "object.read", "object:Ghost__c"), Code.RESOURCE_NOT_VISIBLE, "does not exist or is not visible")
    expect(check(c, bob, "object.edit", "object:Ghost__c"), Code.RESOURCE_NOT_VISIBLE, "Ghost__c")
    assert f.describe_calls("Ghost__c") == 1, f"Ghost__c described {f.describe_calls('Ghost__c')} times, want 1 (cached)"
    # An object that exists with no rows is still a deny, and its describe is
    # cached too.
    expect(check(c, bob, "object.read", "object:Invoice__c"), Code.DENIED, "Invoice__c")
    expect(check(c, bob, "object.create", "object:Invoice__c"), Code.DENIED, "Invoice__c")
    assert f.describe_calls("Invoice__c") == 1, f"Invoice__c described {f.describe_calls('Invoice__c')} times, want 1 (cached)"
    # Rows present: no describe at all.
    expect(check(c, bob, "object.edit", "object:Account"), Code.DENIED, "")
    assert f.describe_calls("Account") == 0, f"Account described {f.describe_calls('Account')} times, want 0"
    # Describe failures other than 404 are errors, never deny.
    f.errors["describe:Nope__c"] = SfErr(403, "INSUFFICIENT_ACCESS")
    expect(check(c, bob, "object.read", "object:Nope__c"), Code.CREDENTIAL_REJECTED, "Nope__c")
    f.errors["describe:Nope__c"] = SfErr(500, "UNKNOWN_EXCEPTION")
    expect(check(c, bob, "object.read", "object:Nope__c"), Code.UPSTREAM_ERROR, "")
    # The describe path is the sObject's own.
    for call in f.srv.calls():
        if "/sobjects/Ghost__c" in call.path:
            assert call.path == "/inst/services/data/" + TEST_VERSION + "/sobjects/Ghost__c/describe", f"describe path {call.path}"


def test_perm_set_namespace(env: Env) -> None:
    """Finding: a managed package's permission set is permset:<ns>__<Name>
    and the namespace is part of the match."""
    f, c = env.setup()
    expect(check(c, dana, "permset.assigned", "permset:acme__Billing"), Code.ALLOWED, "acme__Billing")
    qs = f.queries_from("PermissionSetAssignment")
    assert qs == [
        "SELECT Id FROM PermissionSetAssignment WHERE AssigneeId = '" + DANA_ID + "' AND PermissionSet.Name = 'Billing' AND PermissionSet.NamespacePrefix = 'acme'"
    ], f"query {qs!r}"
    # The unprefixed name matches only sets without a namespace, and the
    # prefixed one only the package's set.
    expect(check(c, dana, "permset.assigned", "permset:Billing"), Code.DENIED, "Billing")
    expect(check(c, bob, "permset.assigned", "permset:Billing"), Code.ALLOWED, "Billing")
    expect(check(c, bob, "permset.assigned", "permset:acme__Billing"), Code.DENIED, "acme__Billing")
    expect(check(c, dana, "permset.assigned", "permset:other__Billing"), Code.DENIED, "other__Billing")
    before = len(f.queries_from("PermissionSetAssignment"))
    for bad in ("permset:acme__", "permset:__Billing", "permset:a__b__c", "permset:1ns__Billing", "permset:acme__Bill'ing", "permset:ac me__Billing"):
        expect(check(c, dana, "permset.assigned", bad), Code.INVALID_REQUEST, "")
    assert len(f.queries_from("PermissionSetAssignment")) == before, "a malformed permset resource reached the query"


def test_upstream_strings_sanitised(env: Env) -> None:
    """Finding: upstream error codes and MaxAccessLevel are validated before
    they reach a decision text or a log line."""
    f, c = env.setup()
    f.errors["UserRecordAccess"] = SfErr(400, "INVALID_TYPE " + itest.CANARY)
    expect(check(c, dana, "record.read", "record:" + ACCT_ID), Code.UPSTREAM_ERROR, "")
    f.errors["UserRecordAccess"] = SfErr(403, "insufficient-access " + itest.CANARY)
    expect(check(c, dana, "record.read", "record:" + ACCT_ID), Code.CREDENTIAL_REJECTED, "")
    f.errors["UserRecordAccess"] = SfErr(400, "MALFORMED_QUERY")
    d = check(c, dana, "record.read", "record:" + ACCT_ID)
    expect(d, Code.UNSUPPORTED, "MALFORMED_QUERY")
    del f.errors["UserRecordAccess"]
    f.record_access[BOB_ID + "|" + ACCT_ID] = record_access(read=True, level=itest.CANARY)
    expect(check(c, bob, "record.read", "record:" + ACCT_ID), Code.ALLOWED, "max access level unknown")
    f.record_access[BOB_ID + "|" + ACCT_ID] = record_access(level="None")
    expect(check(c, bob, "record.read", "record:" + ACCT_ID), Code.DENIED, "max access level None")
    # The ApiError's own string, which reaches logs, carries no raw code.
    e = decode_api_error(
        httpx.Response(status=400, header=httpx.Headers(), body=b'[{"errorCode":"BAD code","message":"m"},{"errorCode":"INVALID_FIELD"},{"errorCode":"x"}]')
    )
    assert str(e) == "salesforce: HTTP 400 unknown error,INVALID_FIELD", f"ApiError: {e!s}"


def test_instance_url_untrusted_host(env: Env) -> None:
    """Finding: instance_url from the token response is used only when its
    host is the configured url's or a Salesforce domain."""
    f = env.new_fake()
    f.instance_url = "https://evil.example.com/inst"
    deps, logs = itest.deps(f.srv)
    s = itest.settings("sf", "salesforce", base_values(f.srv.url), {"credential": key_secret()})
    c = Salesforce().new(background(), s, deps)
    expect(check(c, dana, "record.read", "record:" + ACCT_ID), Code.ALLOWED, "")
    for call in f.srv.calls():
        assert not call.path.startswith("/inst/"), f"used the untrusted instance_url: {call.path}"
    text = logs.text()
    assert "untrusted host" in text and "evil.example.com" in text, f"no debug log about the ignored instance_url:\n{text}"
    conn = SalesforceConnection(
        settings=s,
        url="https://acme.my.salesforce.com",
        client_id="",
        flow="",
        username="",
        audience="",
        version="",
        match_field="",
        logger=deps.logger,
        now=time.time,
    )
    for inst, want in (
        ("https://acme.my.salesforce.com", "https://acme.my.salesforce.com"),
        ("https://ACME.my.salesforce.com/", "https://ACME.my.salesforce.com"),
        ("https://na139.salesforce.com", "https://na139.salesforce.com"),
        ("https://acme--dev.sandbox.my.salesforce.com", "https://acme--dev.sandbox.my.salesforce.com"),
        ("https://acme.lightning.force.com", "https://acme.lightning.force.com"),
        ("https://acme.my.salesforce.mil", "https://acme.my.salesforce.mil"),
        ("https://salesforce.com", "https://acme.my.salesforce.com"),
        ("https://evilsalesforce.com", "https://acme.my.salesforce.com"),
        ("https://acme.my.salesforce.com.evil.example", "https://acme.my.salesforce.com"),
        ("https://user@acme.my.salesforce.com", "https://acme.my.salesforce.com"),
        ("http://acme.my.salesforce.com", "https://acme.my.salesforce.com"),
        ("https://acme.my.salesforce.com?x=1", "https://acme.my.salesforce.com"),
        ("", "https://acme.my.salesforce.com"),
    ):
        conn.set_instance_url(inst)
        assert conn.api_base() == want, f"instance_url {inst!r} -> base {conn.api_base()!r}, want {want!r}"


# -- checks ----------------------------------------------------------------------------


def test_record_query_shape_and_unknowns(env: Env) -> None:
    f, c = env.setup()
    expect(check(c, bob, "record.read", "record:" + ACCT_ID), Code.ALLOWED, "Read")
    qs = f.queries_from("UserRecordAccess")
    want = (
        "SELECT RecordId, HasReadAccess, HasEditAccess, HasDeleteAccess, HasTransferAccess, HasAllAccess, MaxAccessLevel FROM UserRecordAccess WHERE UserId = '"
        + BOB_ID
        + "' AND RecordId = '"
        + ACCT_ID
        + "'"
    )
    assert qs == [want], f"query {qs!r}\nwant  {want!r}"
    expect(check(c, dana, "record.read", "record:" + HIDDEN_ID), Code.RESOURCE_NOT_VISIBLE, "not visible")
    assert find_action(Salesforce(), "record.create") is None, "record.create must not be an action; records are created per object"


def test_record_create_hint(env: Env) -> None:
    _, c = env.setup()
    id = c.resolve_identity(background(), dana)
    with pytest.raises(HallpassError) as ei:
        c.check(background(), CheckRequest(user=dana, identity=id, action=Action(name=""), action_name="record.create", resource=Resource(raw="")))
    d = to_decision(ei.value)
    assert d.code == Code.INVALID_REQUEST and "object.create" in d.text, f"record.create: {ei.value}"


def test_object_query_shape_and_unknowns(env: Env) -> None:
    f, c = env.setup()
    expect(check(c, bob, "object.read", "object:Account"), Code.ALLOWED, "profile Minimum Access")
    expect_query(
        f.queries_from("ObjectPermissions"),
        "SELECT PermissionsRead, PermissionsCreate, PermissionsEdit, PermissionsDelete, PermissionsViewAllRecords, PermissionsModifyAllRecords, "
        "Parent.IsOwnedByProfile, Parent.Name FROM ObjectPermissions WHERE SobjectType = 'Account' AND ParentId IN <assigned>",
    )
    # Zero rows for an object that exists: nothing grants it, a deny.
    expect(check(c, bob, "object.read", "object:Invoice__c"), Code.DENIED, "Invoice__c")
    # The object does not exist: unknown.
    f.errors["ObjectPermissions"] = SfErr(400, "INVALID_TYPE")
    expect(check(c, bob, "object.read", "object:Nope__c"), Code.UNSUPPORTED, "Nope__c")
    del f.errors["ObjectPermissions"]
    f.errors["ObjectPermissions"] = SfErr(400, "INVALID_FIELD")
    expect(check(c, bob, "object.read", "object:Account"), Code.UNSUPPORTED, "INVALID_FIELD")


def test_field_query_shape_and_unknowns(env: Env) -> None:
    f, c = env.setup()
    expect(check(c, bob, "field.read", "field:Account.Rating"), Code.ALLOWED, "permission set Readers")
    expect_query(
        f.queries_from("FieldPermissions"),
        "SELECT PermissionsRead, PermissionsEdit, Parent.IsOwnedByProfile, Parent.Name FROM FieldPermissions "
        "WHERE SobjectType = 'Account' AND Field = 'Account.Rating' AND ParentId IN <assigned>",
    )
    expect(check(c, bob, "field.read", "field:Account.Name"), Code.UNSUPPORTED, "no FieldPermissions rows")


def test_system_permission_describe(env: Env) -> None:
    f, c = env.setup()
    expect(check(c, dana, "system.permission", "permission:PermissionsViewSetup"), Code.ALLOWED, "profile Sales")
    expect_query(f.queries_from("PermissionSet"), "SELECT Id, Name, IsOwnedByProfile FROM PermissionSet WHERE PermissionsViewSetup = true AND Id IN <assigned>")
    expect(check(c, dana, "system.permission", "permission:PermissionsNotAThing"), Code.INVALID_REQUEST, "PermissionsNotAThing")
    assert len(f.queries_from("PermissionSet")) == 1, "an unknown permission name reached the query"
    describes = sum(1 for call in f.srv.calls() if call.path.endswith("/sobjects/PermissionSet/describe"))
    assert describes == 1, f"describe fetched {describes} times, want 1 (cached)"
    # Shape violations never reach the describe either.
    before = len(f.srv.calls())
    expect(check(c, dana, "system.permission", "permission:ApiEnabled"), Code.INVALID_REQUEST, "")
    expect(check(c, dana, "system.permission", "permission:PermissionsApiEnabled = true OR Id != null"), Code.INVALID_REQUEST, "")
    for call in f.srv.calls()[before:]:
        assert not (call.path.endswith("/describe") or (call.path.endswith("/query") and "FROM PermissionSet " in call.q("q"))), (
            f"shape violation reached {call.path}"
        )


def test_permission_set_group_status(env: Env) -> None:
    f, c = env.setup()
    f.groups[DANA_ID] = [GROUP_ID]
    expect(check(c, dana, "object.read", "object:Account"), Code.ALLOWED, "")
    qs = f.queries_from("PermissionSetGroup")
    assert len(qs) == 1 and "WHERE Id IN ('" + GROUP_ID + "')" in qs[0], f"group query: {qs!r}"
    with f.mu:
        f.group_status[GROUP_ID] = "Outdated"
    expect(check(c, dana, "object.read", "object:Account"), Code.UNSUPPORTED, "not yet recalculated")
    expect(check(c, dana, "field.read", "field:Account.Rating"), Code.UNSUPPORTED, "Group_1AAA")
    expect(check(c, dana, "system.permission", "permission:PermissionsApiEnabled"), Code.UNSUPPORTED, "")
    # Assignments to groups, and the group object, may not exist in the org.
    f.errors["PermissionSetAssignment"] = SfErr(400, "INVALID_FIELD")
    expect(check(c, dana, "object.read", "object:Account"), Code.ALLOWED, "")


@pytest.mark.parametrize(
    ("err", "code"),
    [
        (SfErr(403, "REQUEST_LIMIT_EXCEEDED"), Code.UPSTREAM_RATE_LIMIT),
        (SfErr(403, "API_DISABLED_FOR_ORG"), Code.CREDENTIAL_REJECTED),
        (SfErr(403, "INSUFFICIENT_ACCESS"), Code.CREDENTIAL_REJECTED),
        (SfErr(404, "NOT_FOUND"), Code.RESOURCE_NOT_VISIBLE),
        (SfErr(400, "MALFORMED_QUERY"), Code.UNSUPPORTED),
        (SfErr(400, "INVALID_TYPE"), Code.UNSUPPORTED),
        (SfErr(400, "SOMETHING_ELSE"), Code.UPSTREAM_ERROR),
        (SfErr(429, "REQUEST_LIMIT_EXCEEDED"), Code.UPSTREAM_RATE_LIMIT),
    ],
)
def test_error_mapping(env: Env, err: SfErr, code: Code) -> None:
    f, c = env.setup()
    f.errors["UserRecordAccess"] = err
    d = check(c, dana, "record.read", "record:" + ACCT_ID)
    assert d.code == code, f"{err.status} {err.code} -> {d.code} ({d.text}), want {code}"
    assert itest.CANARY not in d.text, f"upstream message leaked: {d.text}"


def test_bad_resources(env: Env) -> None:
    f, c = env.setup()
    before = len(f.srv.calls())
    cases = [
        ("record.read", "object:Account"),
        ("record.read", "record:001"),
        ("record.read", "record:001000000000001AAA'"),
        ("record.read", "record:" + ACCT_ID + "?x=1"),
        ("object.read", "record:" + ACCT_ID),
        ("object.read", "object:Account'"),
        ("object.read", "object:Account Name"),
        ("object.read", "object:"),
        ("field.read", "field:Account"),
        ("field.read", "field:Account.Rating.Sub"),
        ("field.read", "field:Account.Rating'"),
        ("field.edit", "object:Account"),
        ("system.permission", "permission:ApiEnabled"),
        ("system.permission", "permset:X"),
        ("permset.assigned", "permset:Sales Ops"),
        ("permset.assigned", "permission:PermissionsApiEnabled"),
        ("user.active", "user:not-an-email"),
        ("user.active", "user:Dana <dana@example.com>"),
        ("user.active", "object:Account"),
        ("user.active", "record:" + ACCT_ID),
        ("user.active", "user:bob@example.com"),
    ]
    for action, resource in cases:
        d = check(c, dana, action, resource)
        assert d.code == Code.INVALID_REQUEST, f"{action} {resource} -> {d.code}: {d.text}"
    # Only identity lookups happened: no permission query was sent for any of them.
    for call in f.srv.calls()[before:]:
        q = call.q("q")
        assert q == "" or "FROM User " in q or "FROM UserLogin " in q, f"invalid resource reached a query: {q}"


def test_failures(env: Env) -> None:
    f, c = env.setup()
    expect(check(c, dana, "record.read", "record:" + ACCT_ID), Code.ALLOWED, "")
    itest.failure_cases(f.srv, lambda: check(c, dana, "record.read", "record:" + ACCT_ID))
    # Also with no token cached yet: the failure hits the token endpoint.
    f2 = env.new_fake()
    c2 = env.new_conn(f2)
    itest.failure_cases(f2.srv, lambda: check(c2, dana, "record.read", "record:" + ACCT_ID))


def test_probe(env: Env) -> None:
    f, c = env.setup()
    r = c.probe(background())
    assert "14000 of 15000" in r.summary and TEST_USERNAME in r.summary and TEST_VERSION in r.summary and "3 permission fields" in r.summary, (
        f"summary {r.summary!r}"
    )
    assert len(r.warnings) == 1 and "View All" in r.warnings[0], f"warnings {r.warnings!r}"
    qs = f.queries_from("User")
    assert qs == ["SELECT Id, Username, IsActive FROM User WHERE Username = '" + TEST_USERNAME + "'"], f"probe user query {qs!r}"
    qs = f.queries_from("UserLogin")
    assert qs == ["SELECT IsFrozen FROM UserLogin WHERE UserId = '005000000000000AAA'"], f"probe frozen query {qs!r}"
    with f.mu:
        f.remaining = 1200
    r = c.probe(background())
    assert len(r.warnings) == 2 and "10%" in r.warnings[0], f"low-limit warnings {r.warnings!r}"
    f3 = env.new_fake()
    f3.users = f3.users[1:]  # no row for the integration user
    c3 = env.new_conn(f3)
    r = c3.probe(background())
    assert len(r.warnings) == 2 and TEST_USERNAME in r.warnings[0], f"missing integration user: {r}"
    f3.srv.fail(itest.Failure.UNAUTHORIZED)
    with pytest.raises(Exception) as ei:
        c3.probe(background())
    assert to_decision(ei.value).code == Code.CREDENTIAL_REJECTED, f"probe with a rejected credential: {ei.value}"
    f3.srv.fail(itest.Failure.NONE)
    f4 = env.new_fake()
    f4.describe_fields = ["Id", "Name"]
    c4 = env.new_conn(f4)
    with pytest.raises(Exception):
        c4.probe(background())


def test_new_validation(env: Env) -> None:
    f = env.new_fake()
    deps, _ = itest.deps(f.srv)

    def attempt(values: dict[str, str] | None, cred: Secret | None) -> BaseException | None:
        v = base_values(f.srv.url)
        v.update(values or {})
        secrets = {}
        if cred is not None and not cred.is_zero():
            secrets["credential"] = cred
        try:
            Salesforce().new(background(), itest.settings("sf", "salesforce", v, secrets), deps)
        except Exception as e:
            return e
        return None

    assert attempt(None, key_secret()) is None, "valid settings"
    assert attempt(None, None) is not None, "missing credential accepted"
    for bad in (
        {"username": ""},
        {"client_id": ""},
        {"url": ""},
        {"api_version": ""},
        {"api_version": "66.0"},
        {"api_version": "v66"},
        {"api_version": "latest"},
        {"auth_flow": "password"},
        {"match_field": "Alias"},
        {"token_ttl": "soon"},
        {"token_ttl": "10s"},
    ):
        assert attempt(bad, key_secret()) is not None, f"settings {bad} accepted"
    assert attempt({"auth_flow": FLOW_CLIENT_CREDENTIALS, "username": ""}, itest.literal("consumer")) is None, "client_credentials without username"

    # Field validators agree with new.
    def ok(fn: Callable[[str], None], v: str) -> bool:
        try:
            fn(v)
        except ValueError:
            return False
        return True

    for fld in Salesforce().fields():
        if fld.validate is None:
            continue
        if fld.name == "api_version":
            assert ok(fld.validate, "v66.0") and not ok(fld.validate, "66"), "api_version validator"
        elif fld.name == "token_ttl":
            assert ok(fld.validate, "15m") and not ok(fld.validate, "x"), "token_ttl validator"
        elif fld.name == "username":
            assert ok(fld.validate, "a@b.c") and not ok(fld.validate, "a'b"), "username validator"
        elif fld.name == "audience":
            assert ok(fld.validate, "https://test.salesforce.com") and not ok(fld.validate, "http://evil"), "audience validator"
    validate_fields(Salesforce().fields())


def test_bad_key_and_no_leak(env: Env) -> None:
    f = env.new_fake()
    deps, logs = itest.deps(f.srv)
    s = itest.settings("sf", "salesforce", base_values(f.srv.url), {"credential": itest.literal("not-a-key")})
    c = Salesforce().new(background(), s, deps)
    d = check(c, dana, "record.read", "record:" + ACCT_ID)
    assert d.code == Code.CREDENTIAL_REJECTED and itest.CANARY not in d.text, f"bad key: {d.code} {d.text}"
    assert f.token_count() == 0, "a token request was sent without a signed assertion"
    # A rejected assertion: the error_description carries the canary.
    f2 = env.new_fake()
    f2.lenient_jwt = True  # the claim mismatch is the point
    c2 = env.new_conn(f2, {"username": "someone-else@acme.example"})
    d = check(c2, dana, "record.read", "record:" + ACCT_ID)
    assert d.code == Code.CREDENTIAL_REJECTED and itest.CANARY not in d.text, f"rejected assertion: {d.code} {d.text}"
    itest.assert_no_canary(logs.text())


def test_actions_listed() -> None:
    seen = set()
    for a in Salesforce().actions():
        assert not a.pattern and a.description != "", f"action {a}"
        seen.add(a.name)
    for want in (
        "record.read",
        "record.edit",
        "record.delete",
        "record.transfer",
        "record.share",
        "object.read",
        "object.create",
        "object.edit",
        "object.delete",
        "object.view_all",
        "object.modify_all",
        "field.read",
        "field.edit",
        "system.permission",
        "permset.assigned",
        "user.active",
    ):
        assert want in seen, f"action {want} missing"
    assert len(seen) == 16, f"{len(seen)} actions, want 16"


# -- allow/deny per action (coverage gate) ---------------------------------------------


def test_action_record_read_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "record.read", "record:" + ACCT_ID), Code.ALLOWED, "HasReadAccess")


def test_action_record_read_deny(env: Env) -> None:
    f, c = env.setup()
    f.record_access[BOB_ID + "|" + ACCT_ID] = record_access(level="None")
    expect(check(c, bob, "record.read", "record:" + ACCT_ID), Code.DENIED, "HasReadAccess")


def test_action_record_edit_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "record.edit", "record:" + ACCT_ID), Code.ALLOWED, "HasEditAccess")


def test_action_record_edit_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "record.edit", "record:" + ACCT_ID), Code.DENIED, "HasEditAccess")


def test_action_record_delete_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "record.delete", "record:" + ACCT_ID), Code.ALLOWED, "HasDeleteAccess")


def test_action_record_delete_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "record.delete", "record:" + ACCT_ID), Code.DENIED, "HasDeleteAccess")


def test_action_record_transfer_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "record.transfer", "record:" + ACCT_ID), Code.ALLOWED, "HasTransferAccess")


def test_action_record_transfer_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "record.transfer", "record:" + ACCT_ID), Code.DENIED, "HasTransferAccess")


def test_action_record_share_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "record.share", "record:" + ACCT_ID), Code.ALLOWED, "HasAllAccess")


def test_action_record_share_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "record.share", "record:" + ACCT_ID), Code.DENIED, "HasAllAccess")


def test_action_object_read_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "object.read", "object:Account"), Code.ALLOWED, "profile Sales")


def test_action_object_read_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "object.read", "object:Invoice__c"), Code.DENIED, "")


def test_action_object_create_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "object.create", "object:Account"), Code.ALLOWED, "PermissionsCreate")


def test_action_object_create_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "object.create", "object:Account"), Code.DENIED, "2 assigned")


def test_action_object_edit_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "object.edit", "object:Account"), Code.ALLOWED, "PermissionsEdit")


def test_action_object_edit_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "object.edit", "object:Account"), Code.DENIED, "PermissionsEdit")


def test_action_object_delete_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "object.delete", "object:Account"), Code.ALLOWED, "PermissionsDelete")


def test_action_object_delete_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "object.delete", "object:Account"), Code.DENIED, "PermissionsDelete")


def test_action_object_view_all_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "object.view_all", "object:Account"), Code.ALLOWED, "PermissionsViewAllRecords")


def test_action_object_view_all_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "object.view_all", "object:Account"), Code.DENIED, "PermissionsViewAllRecords")


def test_action_object_modify_all_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "object.modify_all", "object:Account"), Code.ALLOWED, "PermissionsModifyAllRecords")


def test_action_object_modify_all_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "object.modify_all", "object:Account"), Code.DENIED, "PermissionsModifyAllRecords")


def test_action_field_read_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "field.read", "field:Account.Rating"), Code.ALLOWED, "Account.Rating")


def test_action_field_read_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "field.read", "field:Account.Secret__c"), Code.DENIED, "Account.Secret__c")


def test_action_field_edit_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "field.edit", "field:Account.Rating"), Code.ALLOWED, "PermissionsEdit")


def test_action_field_edit_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "field.edit", "field:Account.Rating"), Code.DENIED, "PermissionsEdit")


def test_action_system_permission_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "system.permission", "permission:PermissionsApiEnabled"), Code.ALLOWED, "PermissionsApiEnabled")


def test_action_system_permission_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "system.permission", "permission:PermissionsViewSetup"), Code.DENIED, "PermissionsViewSetup")


def test_action_permset_assigned_allow(env: Env) -> None:
    f, c = env.setup()
    expect(check(c, dana, "permset.assigned", "permset:Sales_Ops"), Code.ALLOWED, "Sales_Ops")
    qs = f.queries_from("PermissionSetAssignment")
    assert qs == [
        "SELECT Id FROM PermissionSetAssignment WHERE AssigneeId = '" + DANA_ID + "' AND PermissionSet.Name = 'Sales_Ops' AND PermissionSet.NamespacePrefix = null"
    ], f"query {qs!r}"


def test_action_permset_assigned_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, bob, "permset.assigned", "permset:Sales_Ops"), Code.DENIED, "Sales_Ops")


def test_action_user_active_allow(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, dana, "user.active", "user:dana@example.com"), Code.ALLOWED, "active")
    expect(check(c, dana, "user.active", "user:Dana@Example.com"), Code.ALLOWED, "active")
    expect(check(c, dana, "user.active", "record:" + DANA_ID), Code.ALLOWED, "active")


def test_action_user_active_deny(env: Env) -> None:
    _, c = env.setup()
    expect(check(c, ian, "user.active", "user:ian@example.com"), Code.DENIED, "inactive")
    expect(check(c, fred, "user.active", "record:" + FRED_ID), Code.DENIED, "frozen")
