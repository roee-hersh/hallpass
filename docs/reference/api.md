# HTTP API reference

The toolpass server (`toolpass serve`) has two routes. Clients: `Toolpass.remote` in the
[`toolpass` package](client.md), [`toolpass-client`](client.md#toolpass-client-node) for Node, or any
HTTP client. The in-process engine answers with the same decisions and codes, without HTTP.

## POST /check

Send the configured `api_key` as a bearer token and a JSON body of at most 64 KiB. Unknown fields
are rejected, and so is a field given twice; names match regardless of ASCII case. The body is framed
by one `Content-Length` or by `Transfer-Encoding: chunked`, never both or twice. `user` is an email
of at most 320 bytes, with no whitespace or control characters (C1 and Unicode separators included)
and none of the letters that case-fold to ASCII ones (`İ`, `ı`, `ſ`, the Kelvin sign). `groups` holds
at most 200 entries of at most 256 bytes each.

```json
{
  "user": "dana@example.com",
  "groups": ["platform-team"],
  "connection": "k8s-prod-eu",
  "action": "deployment.create",
  "resource": "namespace:payments"
}
```

```json
{ "decision": "allow" | "deny" | "unknown", "reason": "<code>: <text>" }
```

| Case | HTTP | decision | code |
|---|---|---|---|
| Evaluated | 200 | allow / deny | `allowed` / `denied` |
| User has no account in that system | 200 | deny | `user_not_found` |
| Several accounts match the email | 200 | unknown | `user_ambiguous` |
| Upstream timeout, error or rate limit | 200 | unknown | `upstream_timeout`, `upstream_error`, `upstream_rate_limited` |
| toolpass's own credential was rejected | 200 | unknown | `credential_rejected` |
| Resource not visible to toolpass | 200 | unknown | `resource_not_visible` |
| Policy construct toolpass does not understand | 200 | unknown | `unsupported` |
| Bad request, unknown connection or action | 400 | unknown | `invalid_request`, `unknown_connection`, `unknown_action` |
| Bad or missing API key | 401 | unknown | `unauthorized` |
| A method other than `POST` | 405 | unknown | `invalid_request` |
| A body over 64 KiB | 413 | unknown | `invalid_request` |

`deny` means the third-party system positively said no. Anything toolpass could not evaluate is
`unknown`. Callers should treat `unknown` as deny.

## Fresh checks

The request also accepts `"fresh": true`. A fresh check skips every cache for that one request,
the decision cache, the identity cache and the lookups an integration caches itself (role
definitions, policies), and asks the upstream system now; what it learns replaces the cached
entries, so reads keep using the cache. Use it for destructive actions (delete, merge, scale),
where a 30-second-old answer is not good enough, and not for reads: a fresh check costs every
upstream call an uncached check makes (for Argo CD, the policy config maps and the project list;
for Vault, the policies involved; for Snowflake, the grants of every role in the hierarchy).
Lookups that are not permission state are reused for as long as any check reuses them: GitHub's
organization-wide SAML identity listing (the permission read after it is live anyway), AWS
Identity Center's role inventory and permission set names, Salesforce's object and field
describes, and toolpass's own principal name in Databricks. Fresh checks share
a lookup one of them has in flight (an identity, a role's permissions, a policy) and one read
less than a second ago; a fresh answer is one from reads in flight when the caller asked or begun
no more than a second before. Maps toolpass reads from a local file
(`role_map_file`, `user_map_file`) are re-read on their own schedule, not per fresh check. A fresh
check narrows the window between the check and the action to the time between the two; it does
not close it. Closing it needs a conditional write in the upstream system (for example `If-Match`
with an ETag), which only some APIs support. A toolpass built before `fresh` existed rejects a
request that carries it (`invalid_request: unknown field "fresh"`, which the clients report as
`unknown`), so upgrade the server before turning it on in agents.

## GET /healthz

Returns `{"status":"ok"}` with status 200, without authentication. It says the process is up, not
that every connection works; `toolpass probe` checks connections.
