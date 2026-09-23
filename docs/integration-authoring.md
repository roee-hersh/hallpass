# Writing an integration

An *integration* is one product (github, jira). A *connection* is one configured system of that
product. This page is the contract every integration package follows. `internal/integrations/fake`
and `internal/integrations/kubernetes` are the reference implementations.

## Package layout

```
internal/integrations/<name>/<name>.go     Integration + Connection
internal/integrations/<name>/actions.go    action table, resource parsing
internal/integrations/<name>/<name>_test.go
internal/integrations/<name>/testdata/     recorded fixtures, if any
docs/integrations/<name>.md
```

The package directory name equals the integration name (`googleworkspace`, `microsoft365`).
Registration happens in `internal/integrations/all/all.go`, one line per integration.

## The interfaces (`internal/integration`)

```go
type Integration interface {
    Name() string                       // lowercase, the "integration:" config value
    Fields() []Field                    // config keys beyond ca_file/tls_server_name/proxy_url/timeout
    Actions() []catalog.Action          // fixed actions; Pattern: true entries document shapes
    New(ctx, *Settings, Deps) (Connection, error)
}
type Connection interface {
    ResolveIdentity(ctx, User) (Identity, error)
    Check(ctx, CheckRequest) (Decision, error)
    Probe(ctx) (ProbeResult, error)
}
```

- `New` must not touch the network. Build the HTTP client with `Deps.HTTPClient(settings)`, wrap it
  in `httpx.Client` with `Base`, `Logger: deps.Logger` and an `Auth` func. Read secrets at call time
  through `settings.Secret("credential").GetString()`, never at build time (files rotate).
- `Fields`: use `integration.URLField`, `integration.CredentialField`,
  `integration.ConnectionRefField`; set `Default`, `Enum`, `Validate` where sensible. Secrets are
  `Secret: true` and arrive as `env:`/`file:` references. Never declare `url`, `credential` etc.
  through both a constructor and a literal.
- Pattern actions (`raw:<verb>:<resource>`) implement `integration.ActionMatcher`.

## Decisions

`deny` only when the third-party system positively says no. Everything hallpass could not evaluate
is `unknown` with a code from `internal/integration/decision.go`:

| Situation | Return |
|---|---|
| allowed | `integration.Allowed("...")` |
| positively refused | `integration.Denied("...")` |
| no account for the email | `integration.UserNotFound(...)` error from `ResolveIdentity` |
| several accounts | `integration.UserAmbiguous(...)` error |
| hallpass's credential rejected (401, or 403 where it means "hallpass lacks the right") | `integration.Wrap(integration.CodeCredentialRejected, err, "...")` |
| resource not visible / not found (404 that may mean "no access") | `integration.UnknownDecision(integration.CodeResourceNotVisible, ...)` |
| a policy construct hallpass does not model | `integration.Unsupported(...)` |
| bad resource shape for this integration | `integration.Errorf(integration.CodeInvalidRequest, ...)` |
| transport/5xx/429/timeout | return the error from `httpx` (`httpx.Classify` picks the code) |

Decision text must never contain a secret or an upstream body. Keep it one sentence.

## Resources

`type:id`, parsed by `catalog.ParseResource`. The integration validates `Type` and `Id` with strict
regexes before putting either into a URL path (`httpx.PathEscape`), a query, a GraphQL variable, a
JQL/SOQL string, or anything else. Git hosts use `catalog.SplitBranch` for `@branch`.

## HTTP

`httpx.Client` handles TLS, retries (idempotent calls only), 429 with Retry-After, the body cap and
redaction. Use `GetJSON`, `PostJSON`, `Do`, `Paginate` and `NextLink` (which refuses a next page on
another host, so the credential never travels there). Bodies are never logged. Use
`httpx.Status(err)` to branch on 403/404, and `httpx.Classify(err)` for everything else.

Every response `httpx` completes during `ResolveIdentity` and `Check` is recorded as evidence on the
decision (method, path, status, and the `ETag` or the body's SHA-256) and written to the decision log
by the engine; an integration does nothing for this. Calls made from the client's `Auth` func (a
token exchange) are not recorded. A lookup an integration caches itself is evidence only for the
check that made it.

## Auth (`internal/authx`)

`authx.TokenSource` caches a token and refreshes it 5 minutes before expiry. `authx.SignJWT` signs
RS256/PS256 with `kid`/`x5t#S256` headers. `authx.ClientCredentials`, `authx.ClientAssertion` and
`authx.JWTBearer` are token-endpoint fetchers. `authx.ClassifyTokenError` maps failures.

## Tests

Use `internal/integration/itest`:

- `itest.NewServer(t)` is a TLS fake upstream with `Handle`, `JSON`, `Calls`, `LastCall` and
  `Fail(mode)` injection.
- `itest.Deps(t, srv)` returns Deps trusting the server and a log buffer; the cleanup fails the
  test if `itest.Canary` appears in any log line. Every test secret is `itest.Literal("...")`, which
  carries the canary. Put the canary in fake upstream bodies too.
- `itest.Check(t, conn, integ, user, action, resource)` runs the check like the engine.
- `itest.FailureCases(t, srv, func() Decision)` asserts the unknown codes for 500, 429, 401 and a
  timeout.
- `srv.UseSpec(itest.SpecFromEnv(t, "<name>"), opts)` validates every request against the vendor's
  published API description (OpenAPI, Google discovery or botocore) when `HALLPASS_SPECS_DIR` holds
  `<name>.spec`; `test/specs/fetch.sh` downloads them and CI runs the suite with them. A wrong path,
  method, missing required parameter or body field fails the test. Use `StripPrefix` for gateway
  prefixes, `IgnorePaths` for endpoints the description lacks (say why in a comment), `AllowQuery`
  and `OptionalParams` for parameters newer or older than the description.

The coverage gate in `internal/integrations/all` requires, for every non-pattern action, a
`TestAction_<name>_allow` and `TestAction_<name>_deny` in the integration package, with every
character outside `[A-Za-z0-9]` in the name replaced by `_` (`repo.push` -> `TestAction_repo_push_allow`).

## Docs

`docs/integrations/<name>.md` has, in this order: how it checks (one paragraph), the credential to
create and the minimum permissions, the connection keys, resources, actions, decisions table, what it
cannot see, an **Unverified** section listing every behaviour marked `// UNVERIFIED:` in the code, and
how to test.

## Words

Integration, connection. Not instance, adapter, target, caller, cluster/server/site as a config key.
The endpoint is `/check`.
