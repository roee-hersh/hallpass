# Deploy toolpass

toolpass is one Python package. The engine runs inside your agent's process, or as one stateless
server process (a container or a `pip install`) with one config file and the credentials it
references. This page covers where to run it, how to reach it safely, and each way to install it.
The [quickstart](../quickstart.md) runs it locally in five minutes. The
[configuration reference](../reference/configuration.md) documents the file.

## Pick a topology

| | In-process | Sidecar | Shared service |
|---|---|---|---|
| **Shape** | `pip install toolpass` in the agent; `Toolpass.from_config(...)` | One toolpass container next to each agent, in the same pod or on the same host | One toolpass deployment that every agent calls |
| **Agent uses** | the engine directly | `Toolpass.remote("http://localhost:8080", key)` | `Toolpass.remote("https://toolpass.example.internal", key)` |
| **TLS** | Not needed: no network hop | Not needed: traffic never leaves the pod | Needed in front of toolpass (see below) |
| **Upstream credentials** | In the agent's process | In every agent's pod, mounted only into the toolpass container | In one place |
| **Cache** | Per agent process | Per agent | Shared by every agent that hits the same replica |
| **Languages** | Python | any (Python, the Node client, HTTP) | any |
| **Choose it when** | Development, or an agent that may hold the lookup credentials | One or two agents, or you want the API key never to cross the network | Several agents or teams, or you want the upstream credentials held in one place |

In-process is the simplest: nothing to deploy and no API key. It also puts toolpass's lookup
credentials in the agent's process, where agent code (or a model with a shell) could read them.
Those credentials answer for every user, and in Jira they need Administer Jira
([trust boundaries](../concepts/architecture.md#trust-boundaries)). When that matters, run a server
and change one line in the agent: `Toolpass.from_config(...)` becomes `Toolpass.remote(...)`.

## In-process

```sh
pip install "toolpass[crypto]"   # crypto only for the integrations that sign with a private key
```

```python
from toolpass import Toolpass

tp = Toolpass.from_config("/etc/toolpass/toolpass.yaml")
```

The file's caches and `decision_log` apply; `listen` and `api_key` are for the server and are not
needed. `Toolpass(connections=[...])` takes the same connections in code (see the
[configuration reference](../reference/configuration.md#connections-in-code)); there the decision log
is off unless you pass `decision_log=`. Build one `Toolpass` per process and share it: each one
keeps its own caches.

## TLS and reaching toolpass

The toolpass server serves plain HTTP. `Toolpass.remote` and the Node client accept `http://` only
for `localhost` or a loopback address, because the API key travels in a header. So:

- **Sidecar**: point the agent at `http://localhost:8080`. Nothing else to do.
- **Shared service**: put TLS in front and give agents an `https://` URL. Use an Ingress or Gateway
  with a certificate (cert-manager, your cloud load balancer), or a TLS-terminating proxy on the
  host. A private CA works: point Python at it with `SSL_CERT_FILE` and Node with
  `NODE_EXTRA_CA_CERTS`.

Keep toolpass off the public internet either way. Only your agents' tool layers need to reach it.

## Docker

```sh
docker run -d --name toolpass -p 127.0.0.1:8080:8080 \
  -e TOOLPASS_API_KEY="$(openssl rand -hex 32)" \
  -e JIRA_TOKEN \
  -v "$PWD/toolpass.yaml:/etc/toolpass/toolpass.yaml:ro" \
  ghcr.io/roee-hersh/toolpass:0.6.0
```

The image is `python:3.13-slim` with `toolpass[crypto]` installed and compiled, runs as the
non-root user 65532 (it works with a read-only root filesystem), and starts `toolpass serve -config
/etc/toolpass/toolpass.yaml`. It is built for `linux/amd64` and `linux/arm64`. Pass each `env:`
credential with `-e` and mount each `file:` credential read-only. Pin a version tag rather than
`latest`.

## pip

The server is the `toolpass` command of the same package. Install it into its own virtual
environment and run it under your service manager:

```sh
python3 -m venv /opt/toolpass
/opt/toolpass/bin/pip install "toolpass[crypto]"   # pin it: "toolpass[crypto]==<version>"
```

A systemd unit:

```ini
[Unit]
Description=toolpass
After=network-online.target

[Service]
ExecStart=/opt/toolpass/bin/toolpass serve -config /etc/toolpass/toolpass.yaml
# TOOLPASS_API_KEY=... and each env: credential, one per line
EnvironmentFile=/etc/toolpass/env
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Kubernetes with Helm

The chart runs toolpass as a non-root Deployment with a read-only root filesystem, probes on
`/healthz`, the config in a ConfigMap and the API key in a Secret. Every release from 0.4.1 on
publishes it to GitHub's container registry:

```sh
kubectl create namespace toolpass
kubectl -n toolpass create secret generic toolpass-api-key \
  --from-literal=TOOLPASS_API_KEY="$(openssl rand -hex 32)"

helm install toolpass oci://ghcr.io/roee-hersh/charts/toolpass -n toolpass \
  --set apiKey.existingSecret=toolpass-api-key
helm test toolpass -n toolpass
```

Add `--version` to pin a chart version; each chart version deploys the toolpass image of the same
version. From a clone of the repository, the chart is `deploy/helm/toolpass`.

Your connections go in a values file under `config`, exactly as in `toolpass.yaml`. Credentials stay
references: an `env:NAME` maps to a Secret through `extraEnv`, and a `file:/path` to a Secret
mounted with `extraVolumes` and `extraVolumeMounts`. To answer questions about the cluster it runs
in, set `rbac.subjectAccessReview.create=true`. The [chart README](../../deploy/helm/toolpass/README.md)
has a full values file and every value.

The chart creates a ClusterIP Service only. For a shared service, add your own Ingress or Gateway
route with TLS, for example:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: toolpass
  namespace: toolpass
  annotations:
    cert-manager.io/cluster-issuer: internal-ca
spec:
  ingressClassName: internal
  tls:
    - hosts: [toolpass.example.internal]
      secretName: toolpass-tls
  rules:
    - host: toolpass.example.internal
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: toolpass
                port:
                  number: 8080
```

For a sidecar, add the toolpass image as a second container in the agent's own pod, with the same
config ConfigMap and Secrets, and point the agent at `http://localhost:8080`
(`Toolpass.remote("http://localhost:8080", key)`). Mount the Secrets
only into the toolpass container, never into the agent's: they answer for every user, and in Jira
they need Administer Jira, so the agent should not be able to read them
([trust boundaries](../concepts/architecture.md#trust-boundaries)).

## Scaling and availability

- The server keeps no state, so run as many replicas as you need behind the Service. Two is a good
  default for a shared service.
- Each replica keeps its own caches. More replicas mean more upstream calls after a restart, never
  a different answer.
- Upstream rate limits usually bind before toolpass does. Keep `decision_cache_seconds` above zero,
  and use `"fresh": true` only for destructive actions.
- A connection that is down does not stop the others; its checks answer `unknown`.

## Upgrading

Releases follow semantic versioning. The `toolpass` package, the Docker image, the Helm chart and
`toolpass-client` on npm all carry the same version. With a server, upgrade it before
the agents when a release adds a request field (such as `fresh`): an older toolpass rejects fields
it does not know, and the clients report that as `unknown`, so nothing fails open.

## Production checklist

- [ ] You chose in-process or a server knowing where the lookup credentials end up.
- [ ] With a server: the API key is random (`openssl rand -hex 32`), stored in a secret manager,
      and given only to the agents' tool layers, and agents reach toolpass on `localhost` or over
      TLS.
- [ ] Every upstream credential is read-only and scoped as its [integration page](../integrations/README.md)
      describes.
- [ ] `toolpass probe` passes for every connection.
- [ ] The decision log goes to your log pipeline (`decision_log: stdout` in containers).
- [ ] You alert on a rise in `unknown` decisions; [Operating](operating.md#when-the-answer-is-unknown)
      lists the codes.
- [ ] The image, chart or package is pinned to a version.
- [ ] You ran the [live test](../development/testing.md#against-your-own-systems), with cases like
      [`examples/live-cases.yaml`](../../examples/live-cases.yaml), against your own systems for
      each integration you rely on.
