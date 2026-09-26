# Writing an integration

An *integration* is one product (github, jira). A *connection* is one configured system of that
product. This page is the contract every integration package follows. Paths are under
`hallpass-py/`. `src/hallpass/integrations/fake.py` and `src/hallpass/integrations/pagerduty/` are
the reference implementations.

## Package layout

```
src/hallpass/integrations/<name>/__init__.py    exports INTEGRATION
src/hallpass/integrations/<name>/<name>.py      the Integration and Connection classes
src/hallpass/integrations/<name>/actions.py     action table, resource parsing
tests/integrations/<name>/test_<name>.py        tests against a fake upstream
tests/integrations/<name>/test_fuzz.py          property tests of the resource parser
docs/integrations/<name>.md
```

The package name equals the integration name (`googleworkspace`, `microsoft365`). The package
exposes one instance as `INTEGRATION`, and registration is one line: its name in `NAMES` in
`src/hallpass/integrations/__init__.py`. Integrations use only the standard library and hallpass's
own modules; signing with a private key goes through `hallpass.authx`, which imports
`cryptography` (the `crypto` extra) only when it is needed.

## The classes (`hallpass.core.integration`)

```python
class Integration(ABC):
    def name(self) -> str: ...                  # lowercase, the "integration:" config value
    def fields(self) -> list[Field]: ...        # config keys beyond ca_file/tls_server_name/proxy_url/timeout
    def actions(self) -> list[Action]: ...      # fixed actions; Action(..., pattern=True) documents a shape
    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection: ...
    def match_action(self, name: str) -> Action | None: ...   # optional, for pattern actions

class Connection(ABC):
    def resolve_identity(self, ctx: Context, u: User) -> Identity: ...
    def check(self, ctx: Context, r: CheckRequest) -> Decision: ...
    def probe(self, ctx: Context) -> ProbeResult: ...
```

- `new` must not touch the network. Build the transport with `d.http_client(s)` and wrap it in
  `httpx.Client(http=..., base=..., auth=..., logger=d.logger)`. Read secrets at call time, in the
  `auth` function, through `s.secret("credential").get_string()`, never in `new` (files rotate).
  Raise `ValueError` from `new` for a setting that cannot work; `hallpass validate` reports it.
- `fields`: use `url_field`, `credential_field` and `connection_ref_field`; set `default`, `enum`
  and `validate` on a `Field` where sensible. Secret fields are `secret=True` and arrive as `env:`
  or `file:` references (`Settings.secret(name)`); the rest are strings (`Settings.get`,
  `Settings.bool`). Never declare `url`, `credential` and the like through both a helper and a
  literal. A `*_connection` field names another connection, which `d.connection(id)` returns.
- Pattern actions (`raw:<verb>:<resource>`) are listed with `pattern=True` and matched by
  `match_action`.

A minimal integration, for a made-up API:

```python
import re

from hallpass.core import jsonx
from hallpass.core.catalog import Action
from hallpass.core.decision import Code, allowed, denied, errorf, unknown_decision, user_ambiguous, user_not_found, wrap_error
from hallpass.core.integration import Connection, Identity, Integration, ProbeResult, credential_field, url_field
from hallpass.core.secret import SecretError
from hallpass.net import httpx

_PROJECT_KEY = re.compile(r"[A-Z][A-Z0-9]{1,9}")


class Acme(Integration):
    def name(self):
        return "acme"

    def fields(self):
        return [url_field(True, "the account URL"), credential_field(True, "a read-only API token")]

    def actions(self):
        return [Action("project.write", "change a project's settings")]

    def new(self, ctx, s, d):
        cred = s.secret("credential")

        def auth(ctx, r):
            try:
                token = cred.get_string()
            except SecretError as e:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the API token could not be read") from e
            r.headers.set("Authorization", "Bearer " + token)

        return AcmeConnection(httpx.Client(http=d.http_client(s), base=s.get("url").rstrip("/"), auth=auth, logger=d.logger))


class AcmeConnection(Connection):
    def __init__(self, api):
        self.api = api

    def resolve_identity(self, ctx, u):
        try:
            _, body = self.api.get_json(ctx, "/api/users", {"email": u.email})
            users = [jsonx.obj(x) for x in jsonx.arr(jsonx.obj(body), "users")]
        except Exception as e:
            raise httpx.classify(e) from e
        if not users:
            raise user_not_found(f"no Acme user has email {u.email}")
        if len(users) > 1:
            raise user_ambiguous(f"{len(users)} Acme users have email {u.email}")
        return Identity(id=jsonx.s(users[0], "id"), display=u.email)

    def check(self, ctx, r):
        if r.resource.type != "project" or not _PROJECT_KEY.fullmatch(r.resource.id):
            raise errorf(Code.INVALID_REQUEST, "resource must be project:<KEY>")
        path = f"/api/projects/{httpx.path_escape(r.resource.id)}/members/{httpx.path_escape(r.identity.id)}"
        try:
            _, body = self.api.get_json(ctx, path)
        except Exception as e:
            if httpx.status(e) == 404:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"project {r.resource.id} does not exist or hallpass cannot see it")
            raise httpx.classify(e) from e
        role = jsonx.s(jsonx.obj(body), "role")
        if role in ("admin", "maintainer"):
            return allowed(f"{r.identity.display} is a {role} of project {r.resource.id}")
        return denied(f"{r.identity.display} is a {role or 'non-member'} of project {r.resource.id}, not a maintainer")

    def probe(self, ctx):
        try:
            _, body = self.api.get_json(ctx, "/api/me")
        except Exception as e:
            raise httpx.classify(e) from e
        return ProbeResult(summary="authenticated as " + jsonx.s(jsonx.obj(body), "name"))


INTEGRATION = Acme()  # in the package's __init__.py
```

The real integrations are fully typed (`mypy --strict` runs on `src/hallpass`); the types are left
out here for space.

## Decisions

`deny` only when the third-party system positively says no. Everything hallpass could not evaluate
is `unknown` with a code from `hallpass.core.decision.Code`:

| Situation | Return or raise |
|---|---|
| allowed | `return allowed("...")` |
| positively refused | `return denied("...")` |
| no account for the email | `raise user_not_found(...)` from `resolve_identity` |
| several accounts | `raise user_ambiguous(...)` |
| hallpass's credential rejected (401, or 403 where it means "hallpass lacks the right") | `raise wrap_error(Code.CREDENTIAL_REJECTED, err, "...")` |
| resource not visible / not found (404 that may mean "no access") | `return unknown_decision(Code.RESOURCE_NOT_VISIBLE, ...)` |
| a policy construct hallpass does not model | `return unsupported(...)` |
| bad resource shape for this integration | `raise errorf(Code.INVALID_REQUEST, ...)` |
| transport, 5xx, 429, timeout | `raise httpx.classify(err) from err` |

Any other exception that escapes `resolve_identity` or `check` becomes `unknown` with
`upstream_error` (or `upstream_timeout`), so a bug fails closed; but classify what you expect, so
that a 401 says `credential_rejected`. Decision text must never contain a secret or an upstream
body. Keep it one sentence.

## Upstream JSON

Read decoded bodies with `hallpass.core.jsonx`: `jsonx.obj(v)`, and `jsonx.s`, `i`, `b`, `arr`,
`o` and `strs` for a key. A missing key or `null` is the zero value; a value of the wrong type
raises `jsonx.DecodeError`, so a malformed answer is `upstream_error`, never a silently wrong
decision. Do not index decoded JSON directly.

## Resources

`type:id`, parsed by `hallpass.core.catalog.parse_resource` into `r.resource.type` and
`r.resource.id` (and query parameters, for forms such as `namespace:payments?name=api`). The
integration validates the type and id with strict regular expressions (`fullmatch`) before putting
either into a URL path (`httpx.path_escape`), a query, a GraphQL variable, a JQL or SOQL string, or
anything else. Git hosts use `catalog.split_branch` for `@branch`.

## HTTP

`httpx.Client` handles TLS, retries (idempotent calls only), 429 with `Retry-After`, the body cap
and redaction. Use `get_json`, `post_json`, `do`, `paginate` and `next_link` (which refuses a next
page on another host, so the credential never travels there). Bodies are never logged. Use
`httpx.status(err)` to branch on 403 and 404, and `httpx.classify(err)` for everything else. Every
call takes the `ctx` hallpass passed in: it carries the connection's timeout and cancellation.

Every response the client completes during `resolve_identity` and `check` is recorded as evidence on
the decision (method, path, status, and the `ETag` or the body's SHA-256) and written to the
decision log by the engine; an integration does nothing for this. Calls made from the client's
`auth` function or by an `authx` token source are not recorded. A lookup an integration caches in a
`hallpass.core.cache.TTL` (role definitions, policies) is replayed, marked `cached`, on every check
the entry serves, and is looked up again for a check with `"fresh": true`
(`hallpass.core.evidence.fresh(ctx)`). Keep such lookups in a `TTL` rather than a hand-rolled dict
so both hold. A map read from a local file (`role_map_file`, `user_map_file`) is configuration, not
upstream state, and keeps its own re-read schedule.

## Auth (`hallpass.authx`)

`authx.token.TokenSource` caches a token and refreshes it 5 minutes before expiry.
`authx.jwt.sign_jwt` signs RS256 and PS256 with `kid` and `x5t#S256` headers.
`authx.oauth2.client_credentials`, `client_assertion` and `jwt_bearer` are token-endpoint fetchers,
and `authx.oauth2.classify_token_error` maps their failures. `authx.sigv4` signs AWS requests and
`authx.google` reads Google service-account keys and the metadata server.

## Tests

Use the harness in `tests/harness` (`from tests import harness as itest`):

- The `srv` fixture is an `itest.Server`: a TLS fake upstream with `handle`, `json`, `calls`,
  `last_call` and `fail(mode)` injection. Handlers take `(w, r)`.
- `itest.deps(srv)` returns `Deps` trusting the server, and the logs. After every test, the
  conftest fails it if `itest.CANARY` appears in any log line. Every test secret is
  `itest.literal("...")`, which carries the canary. Put the canary in fake upstream bodies too.
- `itest.settings(id, integration, values, secrets)` builds `Settings` with a short timeout.
- `itest.check(conn, integ, user, action, resource)` runs the check like the engine;
  `itest.expect_code(d, code)` asserts the code.
- `itest.failure_cases(srv, lambda: ...)` asserts the `unknown` codes for 500, 429, 401 and a
  timeout.
- `srv.use_spec(spec_from_env("<name>"), SpecOptions(...))` (from `tests.harness.spec`) validates
  every request against the vendor's published API description (OpenAPI, Google discovery,
  botocore or GraphQL SDL) when `HALLPASS_SPECS_DIR` holds `<name>.spec`; `test/specs/fetch.sh`
  downloads them. A wrong path, method, missing required parameter or body field fails the test.
  Use `strip_prefix` for gateway prefixes, `ignore_paths` for endpoints the description lacks (say
  why in a comment), and `allow_query` and `optional_params` for parameters newer or older than the
  description.

```python
from hallpass.core.context import background
from hallpass.core.decision import Code
from hallpass.core.integration import User
from hallpass.integrations.acme import Acme
from tests import harness as itest
from tests.harness.spec import SpecOptions, spec_from_env


def setup(srv):
    srv.use_spec(spec_from_env("acme"), SpecOptions())
    srv.json("GET", "/api/users", 200, {"users": [{"id": "u1", "email": "dana@example.com"}]})
    srv.json("GET", "/api/projects/PAY/members/u1", 200, {"role": "maintainer"})
    deps, _ = itest.deps(srv)
    s = itest.settings("acme-main", "acme", {"url": srv.url}, {"credential": itest.literal("token")})
    return Acme().new(background(), s, deps)


def test_action_project_write_allow(srv):
    d = itest.check(setup(srv), Acme(), User(email="dana@example.com"), "project.write", "project:PAY")
    itest.expect_code(d, Code.ALLOWED)


def test_action_project_write_deny(srv):
    c = setup(srv)
    srv.json("GET", "/api/projects/PAY/members/u1", 200, {"role": "viewer"})
    itest.expect_code(itest.check(c, Acme(), User(email="dana@example.com"), "project.write", "project:PAY"), Code.DENIED)


def test_failures(srv):
    c = setup(srv)
    itest.failure_cases(srv, lambda: itest.check(c, Acme(), User(email="dana@example.com"), "project.write", "project:PAY"))
```

The coverage gate, `tests/integrations/test_registry.py`, requires for every non-pattern action of
every registered integration a `test_action_<name>_allow` and a `test_action_<name>_deny` among the
integration's tests, with every character outside `[A-Za-z0-9]` in the name replaced by `_`
(`repo.push` -> `test_action_repo_push_allow`; case does not matter). It also requires the module
name to equal the integration name.

Every resource parser has property tests in `test_fuzz.py` (Hypothesis) asserting that an accepted
resource is made only of validated pieces before it reaches a URL or query.

## Docs

`docs/integrations/<name>.md` has, in this order: how it checks (one paragraph), the credential to
create and the minimum permissions, the connection keys, resources, actions, decisions table, what it
cannot see, an **Unverified** section listing every behaviour marked `# UNVERIFIED:` in the code, and
how to test. Add the integration to the table in `docs/integrations/README.md`.

## Words

Integration, connection. Not instance, adapter, target, caller, cluster/server/site as a config key.
The endpoint is `/check`.
