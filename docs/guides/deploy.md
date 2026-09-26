# Deploy hallpass

hallpass is one Python package. The engine runs inside your agent's process, or as one stateless
server process (a container or a `pip install`) with one config file and the credentials it
references. This page covers where to run it, how to reach it safely, and each way to install it.
The [quickstart](../quickstart.md) runs it locally in five minutes. The
[configuration reference](../reference/configuration.md) documents the file.

## Pick a topology

| | In-process | Sidecar | Shared service |
|---|---|---|---|
| **Shape** | `pip install hallpass` in the agent; `Hallpass.from_config(...)` | One hallpass container next to each agent, in the same pod or on the same host | One hallpass deployment that every agent calls |
| **Agent uses** | the engine directly | `Hallpass.remote("http://localhost:8080", key)` | `Hallpass.remote("https://hallpass.example.internal", key)` |
| **TLS** | Not needed: no network hop | Not needed: traffic never leaves the pod | Needed in front of hallpass (see below) |
| **Upstream credentials** | In the agent's process | In every agent's pod, mounted only into the hallpass container | In one place |
| **Cache** | Per agent process | Per agent | Shared by every agent that hits the same replica |
| **Languages** | Python | any (Python, the Node client, HTTP) | any |
| **Choose it when** | Development, or an agent that may hold the lookup credentials | One or two agents, or you want the API key never to cross the network | Several agents or teams, or you want the upstream credentials held in one place |

In-process is the simplest: nothing to deploy and no API key. It also puts hallpass's lookup
credentials in the agent's process, where agent code (or a model with a shell) could read them.
Those credentials answer for every user, and in Jira they need Administer Jira
([trust boundaries](../concepts/architecture.md#trust-boundaries)). When that matters, run a server
and change one line in the agent: `Hallpass.from_config(...)` becomes `Hallpass.remote(...)`.

## In-process

```sh
pip install "hallpass[crypto]"   # crypto only for the integrations that sign with a private key
```

```python
from hallpass import Hallpass

hp = Hallpass.from_config("/etc/hallpass/hallpass.yaml")
```

The file's caches and `decision_log` apply; `listen` and `api_key` are for the server and are not
needed. `Hallpass(connections=[...])` takes the same connections in code (see the
[configuration reference](../reference/configuration.md#connections-in-code)); there the decision log
is off unless you pass `decision_log=`. Build one `Hallpass` per process and share it: each one
keeps its own caches.

## TLS and reaching hallpass

The hallpass server serves plain HTTP. `Hallpass.remote` and the Node client accept `http://` only
for `localhost` or a loopback address, because the API key travels in a header. So:

- **Sidecar**: point the agent at `http://localhost:8080`. Nothing else to do.
- **Shared service**: put TLS in front and give agents an `https://` URL. Use an Ingress or Gateway
  with a certificate (cert-manager, your cloud load balancer), or a TLS-terminating proxy on the
  host. A private CA works: point Python at it with `SSL_CERT_FILE` and Node with
  `NODE_EXTRA_CA_CERTS`.

Keep hallpass off the public internet either way. Only your agents' tool layers need to reach it.

## Docker

```sh
docker run -d --name hallpass -p 127.0.0.1:8080:8080 \
  -e HALLPASS_API_KEY="$(openssl rand -hex 32)" \
  -e JIRA_TOKEN \
  -v "$PWD/hallpass.yaml:/etc/hallpass/hallpass.yaml:ro" \
  ghcr.io/roee-hersh/hallpass:0.4.0
```

The image is `python:3.13-slim` with `hallpass[crypto]` installed and compiled, runs as the
non-root user 65532 (it works with a read-only root filesystem), and starts `hallpass serve -config
/etc/hallpass/hallpass.yaml`. It is built for `linux/amd64` and `linux/arm64`. Pass each `env:`
credential with `-e` and mount each `file:` credential read-only. Pin a version tag rather than
`latest`.

## pip

The server is the `hallpass` command of the same package. Install it into its own virtual
environment and run it under your service manager:

```sh
python3 -m venv /opt/hallpass
/opt/hallpass/bin/pip install "hallpass[crypto]"   # pin it: "hallpass[crypto]==<version>"
```

A systemd unit:

```ini
[Unit]
Description=hallpass
After=network-online.target

[Service]
ExecStart=/opt/hallpass/bin/hallpass serve -config /etc/hallpass/hallpass.yaml
# HALLPASS_API_KEY=... and each env: credential, one per line
EnvironmentFile=/etc/hallpass/env
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Kubernetes with Helm

The chart runs hallpass as a non-root Deployment with a read-only root filesystem, probes on
`/healthz`, the config in a ConfigMap and the API key in a Secret. Every release from 0.4.1 on
publishes it to GitHub's container registry:

```sh
kubectl create namespace hallpass
kubectl -n hallpass create secret generic hallpass-api-key \
  --from-literal=HALLPASS_API_KEY="$(openssl rand -hex 32)"

helm install hallpass oci://ghcr.io/roee-hersh/charts/hallpass -n hallpass \
  --set apiKey.existingSecret=hallpass-api-key
helm test hallpass -n hallpass
```

Add `--version` to pin a chart version; each chart version deploys the hallpass image of the same
version. From a clone of the repository, the chart is `deploy/helm/hallpass`.

Your connections go in a values file under `config`, exactly as in `hallpass.yaml`. Credentials stay
references: an `env:NAME` maps to a Secret through `extraEnv`, and a `file:/path` to a Secret
mounted with `extraVolumes` and `extraVolumeMounts`. To answer questions about the cluster it runs
in, set `rbac.subjectAccessReview.create=true`. The [chart README](../../deploy/helm/hallpass/README.md)
has a full values file and every value.

The chart creates a ClusterIP Service only. For a shared service, add your own Ingress or Gateway
route with TLS, for example:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: hallpass
  namespace: hallpass
  annotations:
    cert-manager.io/cluster-issuer: internal-ca
spec:
  ingressClassName: internal
  tls:
    - hosts: [hallpass.example.internal]
      secretName: hallpass-tls
  rules:
    - host: hallpass.example.internal
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: hallpass
                port:
                  number: 8080
```

For a sidecar, add the hallpass image as a second container in the agent's own pod, with the same
config ConfigMap and Secrets, and point the agent at `http://localhost:8080`
(`Hallpass.remote("http://localhost:8080", key)`). Mount the Secrets
only into the hallpass container, never into the agent's: they answer for every user, and in Jira
they need Administer Jira, so the agent should not be able to read them
([trust boundaries](../concepts/architecture.md#trust-boundaries)).

## Scaling and availability

- The server keeps no state, so run as many replicas as you need behind the Service. Two is a good
  default for a shared service.
- Each replica keeps its own caches. More replicas mean more upstream calls after a restart, never
  a different answer.
- Upstream rate limits usually bind before hallpass does. Keep `decision_cache_seconds` above zero,
  and use `"fresh": true` only for destructive actions.
- A connection that is down does not stop the others; its checks answer `unknown`.

## Upgrading

Releases follow semantic versioning. The `hallpass` package, the Docker image, the Helm chart,
`hallpass-client` on PyPI and on npm all carry the same version. With a server, upgrade it before
the agents when a release adds a request field (such as `fresh`): an older hallpass rejects fields
it does not know, and the clients report that as `unknown`, so nothing fails open.

## Production checklist

- [ ] You chose in-process or a server knowing where the lookup credentials end up.
- [ ] With a server: the API key is random (`openssl rand -hex 32`), stored in a secret manager,
      and given only to the agents' tool layers, and agents reach hallpass on `localhost` or over
      TLS.
- [ ] Every upstream credential is read-only and scoped as its [integration page](../integrations/README.md)
      describes.
- [ ] `hallpass probe` passes for every connection.
- [ ] The decision log goes to your log pipeline (`decision_log: stdout` in containers).
- [ ] You alert on a rise in `unknown` decisions; [Operating](operating.md#when-the-answer-is-unknown)
      lists the codes.
- [ ] The image, chart or package is pinned to a version.
- [ ] You ran the [live test](../development/testing.md#against-your-own-systems), with cases like
      [`examples/live-cases.yaml`](../../examples/live-cases.yaml), against your own systems for
      each integration you rely on.
