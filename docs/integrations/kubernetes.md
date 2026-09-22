# kubernetes

hallpass asks the API server with a `SubjectAccessReview`: "may user U with groups G do verb V on
resource R in namespace N?". The API server answers from RBAC and every other authorizer it has
(webhooks, ABAC, Node). Nothing is persisted.

## Credential

A ServiceAccount whose only permission is creating SubjectAccessReviews. That is one ClusterRole rule:

```yaml
rules:
  - apiGroups: ["authorization.k8s.io"]
    resources: ["subjectaccessreviews"]
    verbs: ["create"]
```

`test/kind/hallpass-rbac.yaml` has the full ServiceAccount, ClusterRole and ClusterRoleBinding. This
is tighter than the built-in `system:auth-delegator`, which also allows TokenReviews.

A projected token (`kubectl create token hallpass -n hallpass`, or a projected volume in a pod) expires;
reference it with `credential: file:/path` and hallpass re-reads it on every use.

## Connection

```yaml
  - id: k8s-prod-eu
    integration: kubernetes
    url: https://10.20.0.5:6443
    ca_file: /etc/hallpass/ca/prod-eu.pem     # the cluster CA
    tls_server_name: kubernetes                # when the URL is an IP
    credential: file:/secrets/k8s-prod-eu-token
    username_template: "oidc:{email}"          # optional, default {email}
    group_prefix: "oidc:"                      # optional
    add_authenticated_group: "true"            # optional, default true
```

| Key | Meaning |
|---|---|
| `url` | API server URL |
| `credential` | ServiceAccount token, `env:` or `file:` |
| `username_template` | How the API server names your users. Placeholders `{email}`, `{local}`, `{domain}`. Must contain `{email}` or `{local}` |
| `group_prefix` | Prefix the API server puts on groups from your identity provider |
| `add_authenticated_group` | Also send `system:authenticated`, as the API server would for any logged-in user |

hallpass has no user directory to consult. The Kubernetes username is a pure transform of the email, so
the template must match the API server's `--oidc-username-prefix` / `--oidc-username-claim` flags or its
structured authentication config. A wrong template silently denies everyone. Run one check for a user
you know is allowed after configuring.

Groups come from the caller's `groups` field. hallpass cannot look them up.

## Resources

| Resource | Meaning |
|---|---|
| `namespace:<ns>` | a namespaced resource; add `?resource=<plural>[.<group>]&name=<n>` |
| `cluster` | a cluster-scoped resource; add `?resource=nodes&name=<n>` |
| `nonresource:<path>` | a non-resource URL such as `/metrics` or `/version` |

Examples: `namespace:payments`, `namespace:payments?resource=deployments.apps&name=api`,
`cluster?resource=nodes`, `nonresource:/metrics`.

## Actions

| Action | Kubernetes verb and resource |
|---|---|
| `raw:<verb>:<resource>[.<group>][/<subresource>]` | exactly that, e.g. `raw:create:deployments.apps`, `raw:get:pods/log`, `raw:use:podsecuritypolicies.policy` |
| `raw:<verb>` | the verb on a `nonresource:` path |
| `pods.exec` | create pods/exec |
| `pods.logs` | get pods/log |
| `pods.portforward` | create pods/portforward |
| `pods.attach` | create pods/attach |
| `scale` | update `<resource from request>/scale` |
| `secrets.read` / `secrets.list` | get / list secrets |
| `impersonate` | impersonate users (or `?resource=groups`, `serviceaccounts`) |
| `deployment.create/update/delete/restart` | create/update/delete/patch deployments.apps |
| `namespace.create/delete` | create/delete namespaces |
| `rbac.bind` | create rolebindings.rbac.authorization.k8s.io |

When both the action and the request name a resource they must agree.

## Decisions

| API server says | hallpass answers |
|---|---|
| `allowed: true` | allow |
| `allowed: false`, no `evaluationError` | deny |
| `evaluationError` set | unknown (`unsupported`) |
| 401 | unknown (`credential_rejected`): the token is invalid |
| 403 | unknown (`credential_rejected`): the ServiceAccount may not create SubjectAccessReviews |

## Probe

`hallpass probe` posts a SubjectAccessReview for a throwaway subject to prove the token may create
them, then a SelfSubjectRulesReview (any authenticated subject may) and warns when the token can do
anything beyond that one rule, listing the extra verbs and resources.

## What it cannot see

- Admission: ValidatingAdmissionPolicy, admission webhooks, Pod Security admission and resource quotas
  run after authorization and can still reject a request hallpass allowed.
- A wrong `username_template` denies everyone silently.
- Groups are whatever the caller sends.

## Managed clusters (UNVERIFIED)

- **EKS**: with IAM authentication the username is the mapped IAM identity (`{{SessionName}}` style);
  whether EKS access policies show up in a SubjectAccessReview is unverified. Prefer checking via groups.
- **GKE**: the username is the Google email; groups are Google Group emails (with Google Groups for RBAC).
  Whether IAM-granted access appears in a review is unverified.
- **AKS** with Entra: the username is the UPN and groups are group object-id GUIDs, so callers must pass
  GUIDs. Azure RBAC for Kubernetes is unverified.

## Test

Unit tests run against a fake API server. `test/kind/run.sh` creates a kind cluster, applies
`test/kind/hallpass-rbac.yaml` and `test/kind/fixtures.yaml`, and runs `test/e2e` against it.
