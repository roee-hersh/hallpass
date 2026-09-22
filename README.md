# hallpass

hallpass is a small self-hosted service that answers one question:

> May user X do action Y on resource Z in system C?

Other apps and AI agents act in third-party systems (Jira, GitHub, Kubernetes, ...) with their own
bot credentials, which can usually do more than the person who asked. Before acting, the app asks
hallpass. hallpass asks the third-party system live, with its own read-only credential, and answers
`allow`, `deny` or `unknown`. It only checks. It never performs the action.

## Try it

```sh
export HALLPASS_API_KEY=change-me
go run ./cmd/hallpass validate -config examples/hallpass.yaml
go run ./cmd/hallpass serve    -config examples/hallpass.yaml
```

```sh
curl -X POST localhost:8080/check \
  -H "Authorization: Bearer $HALLPASS_API_KEY" -H 'Content-Type: application/json' \
  -d '{"user":"dana@example.com","connection":"demo","action":"thing.write","resource":"thing:1"}'
```

```json
{"decision":"deny","reason":"denied: dana@example.com is not an admin"}
```

## API

`POST /check` with a bearer token.

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
| hallpass's own credential was rejected | 200 | unknown | `credential_rejected` |
| Resource not visible to hallpass | 200 | unknown | `resource_not_visible` |
| Policy construct hallpass does not understand | 200 | unknown | `unsupported` |
| Bad request, unknown connection or action | 400 | unknown | `invalid_request`, `unknown_connection`, `unknown_action` |
| Bad or missing API key | 401 | unknown | `unauthorized` |

`deny` means the third-party system positively said no. Anything hallpass could not evaluate is
`unknown`. Callers should treat `unknown` as deny.

`GET /healthz` returns `{"status":"ok"}` without authentication.

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
re-read on every use so rotating tokens keep working. Unknown keys, inline secrets and dangling
references are rejected with file and line.

Every connection also accepts `ca_file`, `tls_server_name`, `proxy_url` and `timeout`. There is no
option to skip TLS verification.

Top-level keys: `api_key`, `listen` (default `:8080`), `decision_log` (path, `stderr`, `stdout` or
`none`), `decision_cache_seconds` (default 30, 0 disables), `identity_cache_seconds` (default 900).

`hallpass catalog <integration>` prints the keys and actions of an integration.

## Commands

| Command | What it does |
|---|---|
| `hallpass serve -config FILE` | Run the service |
| `hallpass validate -config FILE` | Check the file, credential references and certificates. No network |
| `hallpass probe -config FILE [-connection ID]` | Call each system with its credential and report |
| `hallpass catalog [INTEGRATION]` | List integrations, config keys and actions |

At startup `serve` probes every connection and logs warnings. A broken connection never stops the
service from starting.

## Integrations

| Integration | Status |
|---|---|
| kubernetes | ready |
| argocd | ready |
| gitlab | ready |
| github | ready |
| jira (Cloud) | ready |
| confluence (Cloud) | ready |
| slack | ready |
| aws | planned |
| googleworkspace | planned |
| microsoft365 | planned |
| salesforce | planned |
| fake | for smoke tests |

Each integration is documented in `docs/integrations/<name>.md`: the credential to create, the
minimum permissions it needs, the actions and resources, and what it cannot see.

## Running in a container

```sh
docker build -t hallpass .
docker run -p 8080:8080 -e HALLPASS_API_KEY=change-me \
  -v $PWD/examples/hallpass.yaml:/etc/hallpass/hallpass.yaml:ro hallpass
```

## Testing

```sh
go test -race ./...                                   # unit tests against fake upstreams
test/kind/run.sh                                      # kubernetes end to end on a kind cluster
go test -tags differential ./test/differential/      # Argo CD evaluator vs the argocd CLI
HALLPASS_LIVE_CASES=$PWD/cases.yaml go test -tags live ./test/live/   # real systems, opt-in
```

Every integration's tests run against a fake of its API with injected failures (500, 429, 401,
timeout) and assert that no secret ever reaches a log line. The live test takes a cases file
(see `examples/live-cases.yaml`) that names a config file and the answers you expect from your own
systems; run it once after setting up each connection.

## Design notes

- Every integration is called with plain HTTP from the standard library. No vendor SDKs.
- hallpass's credential should be read-only wherever the product allows it. The per-integration
  docs say exactly what to grant and where a product forces a broader grant.
- Request and response bodies of upstream calls are never logged. Secrets print as `[REDACTED]`.
- The decision log is JSON lines, one per answered check.
- Allow and deny answers are cached for 30 seconds by default; unknown answers are never cached.

## License

Apache-2.0.
