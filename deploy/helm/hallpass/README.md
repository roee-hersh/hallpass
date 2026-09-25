# hallpass Helm chart

Runs [hallpass](https://github.com/roee-hersh/hallpass) on Kubernetes: one Deployment of the
`ghcr.io/roee-hersh/hallpass` image behind a ClusterIP Service, the config file from a ConfigMap,
the API key from a Secret, liveness and readiness probes on `GET /healthz`, and a non-root,
read-only-root-filesystem security context.

## Try it

Each release publishes the chart to GitHub's container registry, with the chart version equal to
the hallpass version. From a clone of the repository, use `deploy/helm/hallpass` instead of the
`oci://` reference.

```sh
helm install hallpass oci://ghcr.io/roee-hersh/charts/hallpass --namespace hallpass --create-namespace \
  --set apiKey.value=change-me
helm test hallpass -n hallpass
kubectl -n hallpass port-forward svc/hallpass 8080:8080 &
curl -X POST localhost:8080/check \
  -H 'Authorization: Bearer change-me' -H 'Content-Type: application/json' \
  -d '{"user":"dana@example.com","connection":"demo","action":"thing.write","resource":"thing:1"}'
```

The default config carries only the `demo` connection, which talks to nothing.

## Configure

Put your connections in a values file. `config` is rendered verbatim into `hallpass.yaml`, so
everything [the configuration reference](../../../docs/reference/configuration.md) documents works here, except `listen`, which the
chart sets from `containerPort`.

Secrets never go into the config. Every credential is an `env:NAME` or `file:/path` reference, and the
chart gives you a place for each:

```yaml
apiKey:
  existingSecret: hallpass-api-key       # key HALLPASS_API_KEY

config:
  api_key: env:HALLPASS_API_KEY
  connections:
    - id: jira-main
      integration: jira
      url: https://acme.atlassian.net
      username: hallpass-bot@acme.com
      credential: env:JIRA_TOKEN         # -> extraEnv
    - id: k8s-prod-eu
      integration: kubernetes
      url: https://10.20.0.5:6443
      ca_file: /secrets/k8s-prod-eu/ca.pem
      tls_server_name: kubernetes
      credential: file:/secrets/k8s-prod-eu/token   # -> extraVolumes

extraEnv:
  - name: JIRA_TOKEN
    valueFrom:
      secretKeyRef:
        name: hallpass-jira
        key: token

extraVolumes:
  - name: k8s-prod-eu
    secret:
      secretName: hallpass-k8s-prod-eu   # keys ca.pem and token
extraVolumeMounts:
  - name: k8s-prod-eu
    mountPath: /secrets/k8s-prod-eu
    readOnly: true
```

```sh
kubectl -n hallpass create secret generic hallpass-api-key --from-literal=HALLPASS_API_KEY="$(openssl rand -hex 32)"
helm upgrade --install hallpass oci://ghcr.io/roee-hersh/charts/hallpass -n hallpass -f values.yaml
```

Files mounted from Secrets are re-read on every use, so rotating a token in the Secret is enough.
A config change rolls the pods (the pod template carries a checksum of the ConfigMap).

### The cluster hallpass runs in

To answer questions about its own cluster, hallpass needs a ServiceAccount token that may create
`SubjectAccessReview`s. The chart can grant exactly that and nothing else:

```yaml
serviceAccount:
  automountToken: true
rbac:
  subjectAccessReview:
    create: true
config:
  connections:
    - id: k8s-local
      integration: kubernetes
      url: https://kubernetes.default.svc
      ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      credential: file:/var/run/secrets/kubernetes.io/serviceaccount/token
      username_template: "{email}"      # match your API server's OIDC settings
```

See [docs/integrations/kubernetes.md](../../../docs/integrations/kubernetes.md) for
`username_template` and `group_prefix`.

## Values

| Value | Default | Meaning |
|---|---|---|
| `image.repository` | `ghcr.io/roee-hersh/hallpass` | Image |
| `image.tag` | chart `appVersion` | Image tag |
| `image.digest` | `""` | Pin by digest (`sha256:...`) instead of tag |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `replicaCount` | `1` | hallpass keeps no state, so more is fine |
| `apiKey.existingSecret` | `""` | Secret holding the API key. Set this or `apiKey.value` |
| `apiKey.key` | `HALLPASS_API_KEY` | Key inside that Secret |
| `apiKey.value` | `""` | Inline key; the chart writes it into a Secret it owns. For try-outs |
| `config` | demo connection | Rendered into `hallpass.yaml` |
| `existingConfigMap` | `""` | Use your own ConfigMap (key `hallpass.yaml`) instead of `config` |
| `extraEnv` | `[]` | Extra `EnvVar`s, for `env:` references |
| `extraEnvFrom` | `[]` | Extra `envFrom` sources |
| `extraVolumes`, `extraVolumeMounts` | `[]` | For `file:` references and `ca_file` bundles |
| `extraArgs` | `[]` | Appended to `hallpass serve`, e.g. `["-log-level", "debug"]` |
| `containerPort` | `8080` | Listen port; probes and the Service target it |
| `service.type`, `service.port`, `service.annotations` | `ClusterIP`, `8080`, `{}` | |
| `serviceAccount.create`, `.name`, `.annotations` | `true`, `""`, `{}` | |
| `serviceAccount.automountToken` | `false` | Needed only for an in-cluster `kubernetes` connection |
| `rbac.subjectAccessReview.create` | `false` | ClusterRole + binding allowing only `create subjectaccessreviews`. Requires `automountToken: true` and a named ServiceAccount |
| `podSecurityContext`, `securityContext` | non-root 65532, read-only root, no capabilities | |
| `livenessProbe`, `readinessProbe` | `GET /healthz` | |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints`, `priorityClassName` | unset | |
| `podAnnotations`, `podLabels` | `{}` | |

## Test

`helm test <release>` runs a pod that asks the Service for `GET /healthz`. `test/kind/helm.sh` in the
repository installs the chart on a kind cluster with an in-cluster `kubernetes` connection and asserts
a few RBAC answers; CI runs it.
