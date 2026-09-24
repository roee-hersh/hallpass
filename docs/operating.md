# Operating hallpass

Everything about running the service: the configuration file, the commands, containers and
Kubernetes, the decision log, and the design decisions behind them. The [README](../README.md) has
the API and the integrations.

## Configuration

One YAML file, one flat list of connections. An *integration* is the product (kubernetes, jira).
A *connection* is one configured system of that product. Callers name the connection by `id`.

```yaml
api_key: env:HALLPASS_API_KEY

connections:
  - id: k8s-prod-eu
    integration: kubernetes
    url: https://10.20.0.5:6443
    ca_file: /etc/hallpass/ca/prod-eu.pem
    credential: file:/secrets/k8s-prod-eu-token

  - id: jira-main
    integration: jira
    url: https://acme.atlassian.net
    username: hallpass-bot@acme.com
    credential: env:JIRA_TOKEN
```

Secrets are never written into the file. Every credential is `env:NAME` or `file:/path`; files are
re-read on every use so rotating tokens keep working. Unknown keys, repeated keys, inline secrets
and dangling references are rejected with file and line.

Every connection also accepts `ca_file`, `tls_server_name`, `proxy_url` and `timeout`. There is no
option to skip TLS verification. `timeout` (default `8s`, up to `5m`) is the budget for one upstream
call, including the wait for its response headers; connecting and the TLS handshake are each capped
at the smaller of 5 s and the timeout. URLs must be `https://`; plain `http://` is accepted only for
`localhost` or a loopback IP address.

Top-level keys: `api_key`, `listen` (default `:8080`), `decision_log` (path, `stderr`, `stdout` or
`none`), `decision_cache_seconds` (default 30, 0 disables), `identity_cache_seconds` (default 900; a
resolved identity is reused per connection, user and set of groups).

`hallpass catalog <integration>` prints the keys and actions of an integration. `examples/hallpass.yaml`
carries a commented example for every integration.

## Commands

| Command | What it does |
|---|---|
| `hallpass serve -config FILE` | Run the service |
| `hallpass validate -config FILE` | Check the file, credential references and certificates. No network |
| `hallpass probe -config FILE [-connection ID]` | Call each system with its credential and report |
| `hallpass check -config FILE -connection ID -user EMAIL -action NAME -resource RES [-group G]... [-json]` | Answer one question from the command line |
| `hallpass check -server URL [-api-key REF] [-ca-file PEM] [-timeout D] [-fresh] ...` | Ask a running hallpass the same question; `-fresh` skips its caches |
| `hallpass catalog [INTEGRATION]` | List integrations, config keys and actions |

At startup `serve` probes every connection and logs warnings. A broken connection never stops the
service from starting.

`check` runs the same code path as `POST /check` in-process, so it needs the config file and the
connection's credential but no running server and no API key. It prints the decision and reason
(`-json` prints the HTTP response body) and exits 0 for `allow`, 1 for `deny`, 3 for `unknown` and
2 when no decision was reached (bad flags, a config that does not load, an interrupted run), so
`if hallpass check ...` treats `unknown` as deny. Only the connection asked about is built, so a
sibling whose credential is missing on this machine does not get in the way.

```sh
$ hallpass check -config hallpass.yaml -connection jira-main \
    -user dana@example.com -action DELETE_ISSUES -resource issue:PAY-123
deny
  denied: Dana Levi does not hold DELETE_ISSUES on issue PAY-123
```

With `-server URL` the same question goes to a running hallpass over `POST /check`, so it can be
asked from a machine that holds the API key but none of the upstream credentials. `-api-key` is an
`env:NAME` or `file:/path` reference (default `env:HALLPASS_API_KEY`); a key value on the command
line is rejected. The URL must be `https://` unless it is `localhost` or a loopback address.
Output and exit codes are the same; a reply that is not a decision (wrong host, proxy error page)
or none within `-timeout` (default `1m`) exits 2.

```sh
hallpass check -server https://hallpass.internal -connection jira-main \
    -user dana@example.com -action DELETE_ISSUES -resource issue:PAY-123
```

## Running in a container

```sh
docker build -t hallpass .
docker run -p 8080:8080 -e HALLPASS_API_KEY=change-me \
  -v $PWD/examples/hallpass.yaml:/etc/hallpass/hallpass.yaml:ro hallpass
```

## Running on Kubernetes

A Helm chart lives in [`deploy/helm/hallpass`](../deploy/helm/hallpass). It runs the
`ghcr.io/roee-hersh/hallpass` image as a non-root Deployment with liveness and readiness probes
on `GET /healthz`, the config file in a ConfigMap and the API key in a Secret.

```sh
git clone https://github.com/roee-hersh/hallpass && cd hallpass
helm install hallpass deploy/helm/hallpass --namespace hallpass --create-namespace \
  --set apiKey.value=change-me
helm test hallpass -n hallpass
```

Real connections go under `config.connections` in your values file, exactly as in `hallpass.yaml`.
Credentials stay references: an `env:NAME` maps to a Secret through `extraEnv`, a `file:/path` to a
Secret mounted with `extraVolumes` and `extraVolumeMounts`, and the API key comes from a Secret you
own with `apiKey.existingSecret`. To let hallpass answer questions about the cluster it runs in, set
`rbac.subjectAccessReview.create=true`, which grants its ServiceAccount the one permission it needs.
The chart's [README](../deploy/helm/hallpass/README.md) lists every value.

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

## Design notes

- Every integration is called with plain HTTP from the standard library. No vendor SDKs.
- hallpass's credential should be read-only wherever the product allows it. The per-integration
  docs say exactly what to grant and where a product forces a broader grant.
- Request and response bodies of upstream calls are never logged. Secrets print as `[REDACTED]`.
- The decision log is JSON lines, one per answered check, each with the evidence (path, status,
  ETag or body hash) of the upstream calls the decision was computed from.
- Allow and deny answers are cached for 30 seconds by default; unknown answers are never cached.
  Both caches key on the connection, the user and the exact list of groups the caller sent. A
  request with `"fresh": true` bypasses every cache for itself and refreshes their entries.
