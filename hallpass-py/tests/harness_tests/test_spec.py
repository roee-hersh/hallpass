"""Port of internal/integration/itest/spec_test.go."""

from __future__ import annotations

import os
import urllib.request

import pytest

from tests import harness as itest
from tests.harness import spec as itspec
from tests.harness.spec import SpecError, SpecOptions, SpecRequest, any_spec, load_spec, server_path, spec_from_env, with_optional


def req(method: str, rawurl: str, ct: str) -> SpecRequest:
    return SpecRequest.from_url(method, rawurl, ct)


def validate(s: itspec.Spec, r: SpecRequest, body: bytes | None) -> SpecError | None:
    """Go's Validate: the error, or None."""
    try:
        s.validate(r, body or b"")
    except SpecError as e:
        return e
    return None


OAS3 = """{
 "openapi": "3.0.0",
 "servers": [{"url": "https://api.example.com/v4"}],
 "components": {"parameters": {"per": {"name": "per_page", "in": "query", "schema": {"type": "integer"}}},
   "schemas": {"Review": {"type": "object", "required": ["spec"], "properties": {"spec": {"type": "object"}}}}},
 "paths": {
  "/repos/{owner}/{repo}/collaborators/{username}/permission": {"get": {"parameters": [{"$ref": "#/components/parameters/per"}]}},
  "/repos/{owner}/{repo}": {"get": {}, "delete": {}},
  "/users": {"get": {"parameters": [{"name": "search", "in": "query", "required": true}]}},
  "/reviews": {"post": {"requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Review"}}}}}}
 }}"""


def test_open_api3() -> None:
    s = load_spec("t", OAS3.encode())
    ok = [
        req("GET", "https://x/repos/acme/api/collaborators/dana/permission?per_page=1", ""),
        req("GET", "https://x/v4/repos/acme/api", ""),
        req("DELETE", "https://x/repos/acme/a.b", ""),
        req("GET", "https://x/users?search=a", ""),
    ]
    for r in ok:
        assert validate(s, r, None) is None, f"{r.method} {r.raw_path}?{r.raw_query}"
    bad = {
        "unknown path": req("GET", "https://x/repos/acme", ""),
        "wrong method": req("POST", "https://x/repos/acme/api", ""),
        "missing required": req("GET", "https://x/users", ""),
        "undeclared query": req("GET", "https://x/repos/acme/api?foo=1", ""),
        "empty segment": req("GET", "https://x/repos//api", ""),
    }
    for name, r in bad.items():
        assert validate(s, r, None) is not None, f"{name} accepted"
    assert validate(s, req("POST", "https://x/reviews", "application/json"), b'{"spec":{}}') is None
    err = validate(s, req("POST", "https://x/reviews", "application/json"), b'{"kind":"x"}')
    assert err is not None and "spec" in str(err), f"missing required body property accepted: {err}"
    assert validate(s, req("POST", "https://x/reviews", "application/json"), None) is not None, "missing required body accepted"
    assert validate(s, req("POST", "https://x/reviews", "text/plain"), b"x") is not None, "wrong content type accepted"


OAS2 = """{"swagger": "2.0", "basePath": "/api", "paths": {
 "/users.lookupByEmail": {"get": {"parameters": [{"name": "email", "in": "query", "required": true}, {"name": "token", "in": "query"}]}},
 "/permissions/check": {"post": {"parameters": [{"name": "body", "in": "body", "required": true, "schema": {"required": ["accountId"]}}]}}
}}"""


def test_swagger2() -> None:
    s = load_spec("t", OAS2.encode())
    assert validate(s, req("GET", "https://x/api/users.lookupByEmail?email=a", ""), None) is None
    assert validate(s, req("GET", "https://x/users.lookupByEmail", ""), None) is not None, "missing email accepted"
    assert validate(s, req("POST", "https://x/permissions/check", "application/json"), b'{"accountId":"1"}') is None
    assert validate(s, req("POST", "https://x/permissions/check", "application/json"), b"{}") is not None, "missing accountId accepted"


YAML_SPEC = """
openapi: 3.0.1
paths:
  /projects/{id}/members/all/{user_id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
"""


def test_yaml_spec() -> None:
    s = load_spec("t", YAML_SPEC.encode())
    assert validate(s, req("GET", "https://x/projects/acme%2Fapi/members/all/7", ""), None) is None


DISC = """{"discoveryVersion": "v1", "servicePath": "drive/v3/", "parameters": {"fields": {"location": "query"}},
 "resources": {"files": {"methods": {"get": {"path": "files/{fileId}", "httpMethod": "GET",
   "parameters": {"fileId": {"location": "path", "required": true}, "supportsAllDrives": {"location": "query"}}}}},
  "users": {"resources": {"settings": {"methods": {"list": {"path": "admin/directory/v1/users", "httpMethod": "GET",
   "parameters": {"customer": {"location": "query", "required": true}}}}}}}}}"""


def test_discovery() -> None:
    s = load_spec("t", DISC.encode())
    assert validate(s, req("GET", "https://x/drive/v3/files/abc?supportsAllDrives=true&fields=capabilities", ""), None) is None
    assert validate(s, req("GET", "https://x/drive/v3/files/abc?nope=1", ""), None) is not None, "undeclared query accepted"
    assert validate(s, req("GET", "https://x/drive/v3/admin/directory/v1/users", ""), None) is not None, "missing customer accepted"
    assert validate(s, req("POST", "https://x/drive/v3/files/abc", ""), None) is not None, "wrong method accepted"


BOTO = """{"metadata": {"protocol": "query"}, "operations": {"AssumeRole": {"input": {"shape": "AssumeRoleRequest"}}},
 "shapes": {"AssumeRoleRequest": {"type": "structure", "required": ["RoleArn", "RoleSessionName"],
   "members": {"RoleArn": {}, "RoleSessionName": {}, "ExternalId": {}, "PolicyArns": {}}}}}"""

BOTO_JSON = """{"metadata": {"protocol": "json", "targetPrefix": "AWSIdentityStore"}, "operations": {"GetUserId": {"input": {"shape": "In"}}},
 "shapes": {"In": {"type": "structure", "required": ["IdentityStoreId", "AlternateIdentifier"],
   "members": {"IdentityStoreId": {}, "AlternateIdentifier": {}}}}}"""


def test_botocore() -> None:
    s = load_spec("t", BOTO.encode())
    post = req("POST", "https://sts/", "application/x-www-form-urlencoded")
    assert validate(s, post, b"Action=AssumeRole&Version=2011-06-15&RoleArn=a&RoleSessionName=s&PolicyArns.member.1=x") is None
    assert validate(s, post, b"Action=AssumeRole&RoleArn=a") is not None, "missing member accepted"
    assert validate(s, post, b"Action=Nope") is not None, "unknown action accepted"
    assert validate(s, post, b"Action=AssumeRole&RoleArn=a&RoleSessionName=s&Bogus=1") is not None, "unknown parameter accepted"
    j = load_spec("t", BOTO_JSON.encode())
    r = req("POST", "https://is/", "application/x-amz-json-1.1")
    r.header.set("X-Amz-Target", "AWSIdentityStore.GetUserId")
    assert validate(j, r, b'{"IdentityStoreId":"d","AlternateIdentifier":{}}') is None
    assert validate(j, r, b'{"IdentityStoreId":"d"}') is not None, "missing member accepted"
    r.header.set("X-Amz-Target", "Other.GetUserId")
    assert validate(j, r, b"{}") is not None, "wrong target prefix accepted"


def _client_get(url: str) -> None:
    urllib.request.urlopen(urllib.request.Request(url), context=itest.test_ca().client_context(), timeout=5).read()


def _client_post(url: str, content_type: str) -> None:
    rq = urllib.request.Request(url, data=b"", method="POST", headers={"Content-Type": content_type})
    urllib.request.urlopen(rq, context=itest.test_ca().client_context(), timeout=5).read()


def test_server_use_spec(srv: itest.Server) -> None:
    spec = load_spec("t", OAS3.encode())
    srv.use_spec(spec, SpecOptions(strip_prefix=[r"/ex/[a-z]+/[a-f0-9-]+"], ignore_paths=[r"^/token$"], allow_query=["team_id"]))
    srv.json("GET", "/ex/jira/abc-1/repos/acme/api", 200, "{}")
    srv.json("POST", "/token", 200, "{}")
    # Valid through a stripped prefix and an allowed extra query parameter.
    _client_get(srv.url + "/ex/jira/abc-1/repos/acme/api?team_id=T1")
    _client_post(srv.url + "/token", "application/x-www-form-urlencoded")
    assert srv.calls(), "no calls"
    assert srv.spec is not None, "spec not set"
    # Go: NewServer's t.Errorf fails the test on a violation; the srv
    # fixture checks spec_errors at teardown, checked here too.
    assert not srv.spec_errors, srv.spec_errors


def test_server_use_spec_reports_violations() -> None:
    # Python only: validate_request reports what Server.validate passes to
    # t.Errorf, honours optional_params and skips a missing spec.
    with itest.Server() as s:
        s.use_spec(None, SpecOptions())
        _client_get_ignore(s.url + "/users")
        assert s.spec_errors == []
        s.use_spec(load_spec("t", OAS3.encode()), SpecOptions(allow_query=["team_id"]))
        _client_get_ignore(s.url + "/users?team_id=1")
        _client_get_ignore(s.url + "/repos/acme/api?foo=1")
        assert len(s.spec_errors) == 2, s.spec_errors
        assert s.spec_errors[0] == "request does not match the t API description: t: GET /users lacks required query parameters [search]"
        assert 'sends undeclared query parameter "foo"' in s.spec_errors[1]
        s.spec_errors.clear()
        s.use_spec(load_spec("t", OAS3.encode()), SpecOptions(optional_params=["search"]))
        _client_get_ignore(s.url + "/users")
        assert s.spec_errors == []


def _client_get_ignore(url: str) -> None:
    try:
        _client_get(url)
    except urllib.error.HTTPError:
        pass


def test_optional_params() -> None:
    s = load_spec("t", OAS2.encode())
    r = req("GET", "https://x/api/users.lookupByEmail", "")
    assert validate(s, r, None) is not None, "required email accepted"
    assert validate(s, with_optional(r, ["email"]), None) is None
    assert any_spec(None, s) is None and any_spec(None) is None, "AnySpec must skip validation when a description is missing"
    a = any_spec(s, s)
    assert a is not None, "AnySpec with every description present"
    assert validate(a, req("GET", "https://x/nope", ""), None) is not None, "AnySpec accepted unknown path"


def test_server_path_with_variables() -> None:
    """A server URL whose host carries a template variable still yields its
    path prefix, so paths relative to it validate."""
    doc = """{"openapi":"3.0.1","servers":[{"url":"https://{your-domain}.atlassian.net/wiki/api/v2","variables":{"your-domain":{"default":"your-domain"}}}],
 "paths":{"/spaces":{"get":{"responses":{"200":{"description":"ok"}}}}}}"""
    s = load_spec("c", doc.encode())
    err = validate(s, req("GET", "https://x/wiki/api/v2/spaces", ""), None)
    assert err is None, f"prefixed path rejected: {err}"
    err = validate(s, req("GET", "https://x/spaces", ""), None)
    assert err is None, f"bare path rejected: {err}"
    for inp, want in {
        "https://{h}/wiki/api/v2/": "/wiki/api/v2",
        "{scheme}://{h}/a": "/a",
        "https://h": "",
        "https://h/": "",
        "/rest/api": "/rest/api",
    }.items():
        got = server_path({"url": inp})
        assert got == want, f"serverPath({inp!r}) = {got!r}, want {want!r}"


def test_leading_variable_spans_segments() -> None:
    arm = """{"swagger": "2.0", "paths": {
  "/{scope}/providers/Microsoft.Authorization/roleAssignments": {"get": {"parameters": [{"name": "$filter", "in": "query", "type": "string"}]}},
  "/{roleId}": {"get": {}},
  "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments": {"get": {}}
 }}"""
    s = load_spec("arm", arm.encode())
    for u in [
        "https://x/subscriptions/1/resourceGroups/rg/providers/Microsoft.Authorization/roleAssignments?$filter=atScope()",
        "https://x/subscriptions/1/providers/Microsoft.Authorization/roleAssignments",
        "https://x/providers/Microsoft.Management/managementGroups/mg/providers/Microsoft.Authorization/roleAssignments",
    ]:
        err = validate(s, req("GET", u, ""), None)
        assert err is None, f"{u}: {err}"
    assert validate(s, req("GET", "https://x/subscriptions/1/providers/Microsoft.Authorization/roleAssignments?bogus=1", ""), None) is not None, (
        "undeclared query accepted"
    )
    # A bare /{roleId} template matches one segment only, so a typo in a
    # literal path is still caught.
    assert validate(s, req("GET", "https://x/subscriptions/1/providers/Microsoft.Authorization/roleAssignmentz", ""), None) is not None, (
        "misspelled path accepted through /{roleId}"
    )
    err = validate(s, req("GET", "https://x/abc", ""), None)
    assert err is None, f"/{{roleId}}: {err}"
    assert validate(s, req("GET", "https://x//providers/Microsoft.Authorization/roleAssignments", ""), None) is not None, "empty spanned segment accepted"


def test_spec_from_env(tmp_path: object, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # Python only: SpecFromEnv has no Go test. Absent directory or file:
    # None and one note per name; a present file loads and is cached.
    monkeypatch.setattr(itspec, "_spec_noted", set())
    monkeypatch.delenv("HALLPASS_SPECS_DIR", raising=False)
    assert spec_from_env("t-absent") is None
    assert spec_from_env("t-absent") is None
    assert capsys.readouterr().err.count("HALLPASS_SPECS_DIR not set") == 1
    d = str(tmp_path)
    monkeypatch.setenv("HALLPASS_SPECS_DIR", d)
    assert spec_from_env("t-missing") is None
    assert "no " + os.path.join(d, "t-missing.spec") in capsys.readouterr().err
    with open(os.path.join(d, "t-oas2.spec"), "w") as f:
        f.write(OAS2)
    s = spec_from_env("t-oas2")
    assert s is not None and s.name() == "t-oas2"
    assert spec_from_env("t-oas2") is s
