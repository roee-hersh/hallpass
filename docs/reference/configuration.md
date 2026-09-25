# Configuration reference

hallpass reads one YAML file, `/etc/hallpass/hallpass.yaml` by default (`-config` changes it).
[`examples/hallpass.yaml`](../../examples/hallpass.yaml) has a commented example for every
integration, and `hallpass catalog <integration>` prints an integration's keys and actions.

The file holds one flat list of connections. An *integration* is the product (kubernetes, jira).
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

## Top-level keys

| Key | Default | Meaning |
|---|---|---|
| `api_key` | required | The bearer key callers send, as `env:NAME` or `file:/path` |
| `listen` | `:8080` | Address `serve` listens on. `-listen` overrides it |
| `decision_log` | `stderr` | A path, `stderr`, `stdout` or `none`. See [Decision log](../guides/operating.md#decision-log) |
| `decision_cache_seconds` | `30` | How long `allow` and `deny` answers are reused. `0` disables |
| `identity_cache_seconds` | `900` | How long an email-to-account lookup is reused, per connection, user and groups |
| `connections` | required | The list of connections |

## Keys every connection accepts

| Key | Default | Meaning |
|---|---|---|
| `id` | required | The name callers use in `connection` |
| `integration` | required | One of the [integrations](../integrations/README.md) |
| `ca_file` | system roots | PEM bundle for a private CA |
| `tls_server_name` | from the URL | Name checked against the server certificate |
| `proxy_url` | none | HTTP proxy for this connection's calls |
| `timeout` | `8s` | Budget for one upstream call, up to `5m` |

Every other key belongs to the integration and is listed on its page under
[integrations](../integrations/README.md).

## Checking a file

```sh
hallpass validate -config hallpass.yaml   # syntax, references, certificates; no network
hallpass probe    -config hallpass.yaml   # calls each system with its credential and reports
```
