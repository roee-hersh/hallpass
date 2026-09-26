# Deploy hallpass

hallpass is one stateless process: a binary or a container, one config file, and the credentials
it references. This page covers where to run it, how to reach it safely, and each way to install
it. The [quickstart](../quickstart.md) runs it locally in two minutes. The
[configuration reference](../reference/configuration.md) documents the file.

## Pick a topology

| | Sidecar | Shared service |
|---|---|---|
| **Shape** | One hallpass container next to each agent, in the same pod or on the same host | One hallpass deployment that every agent calls |
| **Agent URL** | `http://localhost:8080` | `https://hallpass.example.internal` |
| **TLS** | Not needed: traffic never leaves the pod | Needed in front of hallpass (see below) |
| **Upstream credentials** | In every agent's pod, mounted only into the hallpass container | In one place |
| **Cache** | Per agent | Shared by every agent that hits the same replica |
| **Choose it when** | One or two agents, or you want the API key never to cross the network | Several agents or teams, or you want the upstream credentials held in one place |

## TLS and reaching hallpass

hallpass serves plain HTTP. The [client libraries](../../sdk) accept `http://` only for
`localhost` or a loopback address, because the API key travels in a header. So:

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

The image is distroless, runs as a non-root user, and starts `hallpass serve -config
/etc/hallpass/hallpass.yaml`. Pass each `env:` credential with `-e` and mount each `file:`
credential read-only. Pin a version tag rather than `latest`.

## Binary

Download the archive for your platform from [Releases](https://github.com/roee-hersh/hallpass/releases),
check it against `checksums.txt`, and run it under your service manager. A systemd unit:

```ini
[Unit]
Description=hallpass
After=network-online.target

[Service]
ExecStart=/usr/local/bin/hallpass serve -config /etc/hallpass/hallpass.yaml
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
config ConfigMap and Secrets, and point the agent at `http://localhost:8080`. Mount the Secrets
only into the hallpass container, never into the agent's: they answer for every user, and in Jira
they need Administer Jira, so the agent should not be able to read them
([trust boundaries](../concepts/architecture.md#trust-boundaries)).

## Scaling and availability

- hallpass keeps no state, so run as many replicas as you need behind the Service. Two is a good
  default for a shared service.
- Each replica keeps its own caches. More replicas mean more upstream calls after a restart, never
  a different answer.
- Upstream rate limits usually bind before hallpass does. Keep `decision_cache_seconds` above zero,
  and use `"fresh": true` only for destructive actions.
- A connection that is down does not stop the others; its checks answer `unknown`.

## Upgrading

Releases follow semantic versioning, and the client libraries share the service's version. Upgrade
the service before the clients when a release adds a request field (such as `fresh`): an older
hallpass rejects fields it does not know, and the clients report that as `unknown`, so nothing
fails open.

## Production checklist

- [ ] The API key is random (`openssl rand -hex 32`), stored in a secret manager, and given only to
      the agents' tool layers.
- [ ] Agents reach hallpass on `localhost` or over TLS.
- [ ] Every upstream credential is read-only and scoped as its [integration page](../integrations/README.md)
      describes.
- [ ] `hallpass probe` passes for every connection.
- [ ] The decision log goes to your log pipeline (`decision_log: stdout` in containers).
- [ ] You alert on a rise in `unknown` decisions; [Operating](operating.md#when-the-answer-is-unknown)
      lists the codes.
- [ ] The image or binary is pinned to a version.
- [ ] You ran [`examples/live-cases.yaml`](../../examples/live-cases.yaml) against your own systems
      for each integration you rely on.
