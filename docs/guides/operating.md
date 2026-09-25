# Operating hallpass

Running hallpass day to day: what it logs, how to watch it, and what each `unknown` means. To set
it up, see [Deploy](deploy.md). For the file format, see the
[configuration reference](../reference/configuration.md).

## Health and connections

- `GET /healthz` answers `{"status":"ok"}` while the process runs. Use it for liveness and readiness.
- At startup `serve` probes every connection and logs a warning for each one that fails. A broken
  connection never stops the service from starting; its checks answer `unknown`.
- `hallpass probe -config FILE [-connection ID]` repeats that probe on demand, for example after
  rotating a credential.

## Decision log

Every answered check is one JSON line in `decision_log` (a path, `stderr`, `stdout` or `none`):

```json
{"time":"2026-09-23T10:00:00Z","connection":"github-acme","user":"dana@example.com",
 "action":"repo.create","resource":"org:acme","decision":"allow","code":"allowed",
 "reason":"dana is a member of organization acme, whose members may create repositories",
 "cached":false,"duration_ms":212,"status":200,"remote":"10.0.3.7",
 "evidence":{"upstream":[
   {"method":"GET","path":"/users/dana","status":200,"etag":"W/\"a1b2c3\"","cached":true},
   {"method":"GET","path":"/orgs/acme/memberships/dana","status":200,"etag":"W/\"d4e5f6\""},
   {"method":"GET","path":"/orgs/acme","status":200,"sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}]}}
```

`reason` says what the decision was based on; `evidence` ties it to the exact upstream state. Each
entry under `upstream` is one call the decision was computed from: the method and path (never the
query string, which may carry user data), the host only when the call went to a host other than the
connection's own base URL or to an instance the vendor named at login (some vendors spread an API
over several hosts), the HTTP status, and the
response's `ETag` when the upstream sent one, else the SHA-256 of the response body.
Response bodies, other headers and credentials are never logged; the token exchange an integration
makes to authenticate is not evidence and is left out. A call marked `cached` was not made for this
check: its result was served from a stored cache entry (the identity cache, or a lookup the
integration keeps such as a role definition or a policy), and the entry shows the evidence recorded
when the call was made. A call marked `shared` was made by a concurrent check whose lookup this one
joined: live during this check, but not asked for by it. A decision served from the decision cache
has `cached: true` and carries the evidence of the check that produced it, every call marked
`cached`. `fresh: true` marks a check that skipped the caches on the caller's
request. The list is capped at 100 calls; past it the oldest calls are dropped, replayed ones
first, so the calls that decided the check are kept, and `truncated: true` says some were dropped.

## When the answer is unknown

Every `unknown` carries a code. What each one usually means and what to do:

| Code | Usually | Do |
|---|---|---|
| `upstream_timeout` | The system took longer than the connection's `timeout` | Check the system's status; raise `timeout` if it is routinely slow |
| `upstream_rate_limited` | The system returned 429 | Keep the decision cache on and ask the vendor for a higher limit |
| `upstream_error` | The system returned 5xx or an unexpected body | Check the system's status; the decision log shows the call and its status |
| `credential_rejected` | hallpass's own credential was refused | Rotate or re-grant it as the integration page describes; `hallpass probe` confirms |
| `resource_not_visible` | hallpass's credential cannot see that resource | Grant the read permission the integration page lists for it |
| `user_ambiguous` | Several accounts match the email | Fix the directory, or use the integration's mapping file |
| `unsupported` | A policy construct hallpass does not evaluate, such as an IAM condition | Expected; the integration page lists these |
| `unauthorized` (HTTP 401) | The caller's API key is wrong or missing | Check the agent's `HALLPASS_API_KEY` |
| `unknown_connection`, `unknown_action`, `invalid_request` (HTTP 400) | A mistake in the request | `hallpass catalog <integration>` lists the actions |

`deny` with `user_not_found` is not an error: the person has no account in that system.

## Rotating secrets

- A `file:` credential is re-read on every use, so replacing the file, or the Kubernetes Secret
  behind it, is enough.
- An `env:` credential is read at startup. Restart to pick up a new value.
- To rotate the API key without downtime, run a second hallpass with the new key, move the agents
  across, then stop the old one.
