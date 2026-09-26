# argocd

Argo CD has no API that asks "may user X do Y" for another user (`account/can-i` is only for the
caller). hallpass therefore reads the RBAC policy from the cluster and evaluates it locally with the
same rules as the Argo CD API server. The evaluator is a port of `argo-cd/util/rbac` and
`argo-cd/server/rbacpolicy` (v3), verified against upstream master in September 2026, and its tests
are ported from Argo CD's own.

## Credential

None of its own. An argocd connection names a kubernetes connection, whose ServiceAccount needs, in
the Argo CD namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: hallpass-argocd-reader
  namespace: argocd
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["argocd-rbac-cm", "argocd-cm"]
    verbs: ["get"]
  - apiGroups: ["argoproj.io"]
    resources: ["appprojects"]
    verbs: ["get", "list"]
```

`test/kind/argocd-rbac.yaml` has the Role and RoleBinding. All reads; nothing in Argo CD is touched.

## Connection

```yaml
  - id: argocd-prod
    integration: argocd
    kubernetes_connection: k8s-prod-eu
    namespace: argocd              # default
    rbac_configmap: argocd-rbac-cm # default
    user_subject: none             # default; or email
```

| Key | Meaning |
|---|---|
| `kubernetes_connection` | id of the kubernetes connection for the cluster Argo CD runs in |
| `namespace` | Argo CD's namespace |
| `rbac_configmap` | name of the RBAC config map |
| `user_subject` | what Argo CD sees as the user's subject. `none`: hallpass evaluates only the default role and the caller's groups. `email`: the email is also the subject, as when your identity provider's `sub` claim is the email |

The policy (config maps and AppProjects) is cached for 30 seconds.

## How the evaluation works

Exactly as in Argo CD:

1. Policy = built-in policy (role:readonly, role:admin, admin) + `policy.csv` + every `policy.*.csv`
   key in sorted order + the AppProject's roles when the request is project scoped.
2. Matching is a glob with no separators (`*` crosses `/`) or, with `policy.matchMode: regex`, an
   unanchored RE2 regular expression, as Argo CD's Go code evaluates it. An invalid pattern never
   matches.
3. Effect: some matching `allow` and no matching `deny`.
4. Order: `policy.default` role first, then the subject, then each group that appears as the first
   element of some `g` line.
5. Group values are the caller's `groups`. When `scopes` in `argocd-rbac-cm` includes `email`, the
   email is a group value too.
6. `server.rbac.disableApplicationFineGrainedRBACInheritance` in `argocd-cm` (default true since v3):
   when true `app.update` does not imply `app.update/<resource>`; when false the top-level verb is
   checked first.
7. `server.rbac.rollback.enforce.enable` in `argocd-cm` (default false): `app.rollback` checks `sync`
   unless it is true, then it checks `rollback`.

## Resources

| Resource | Argo CD object |
|---|---|
| `applications:<project>/<name>` or `applications:<project>/<namespace>/<name>` | application |
| `applicationsets:<project>/<name>` | ApplicationSet |
| `logs:<project>/<app>`, `exec:<project>/<app>` | logs and exec (an `applications:` resource is accepted too) |
| `projects:<name>` | project |
| `clusters:<url>` or `clusters:<project>/<url>` | cluster |
| `repositories:<url>`, `write_repositories:<url>` | repository |
| `certificates:<id>`, `accounts:<name>`, `gpgkeys:<id>`, `extensions:<name>` | as named |

## Actions

`app.get/create/update/delete/sync/rollback/override`, `app.action/<group>/<kind>/<action>`,
`app.update/<group>/<kind>/<namespace>/<name>`, `app.delete/<group>/<kind>/<namespace>/<name>`,
`logs.get`, `exec.create`, `appset.get/create/update/delete`, `project.get/create/update/delete`,
`cluster.get/create/update/delete`, `repo.get/create/update/delete`,
`writerepo.get/create/update/delete`, `certificate.get/create/update/delete`,
`account.get/update`, `gpgkey.get/create/delete`, `extension.invoke`.

## Decisions

| Situation | Answer |
|---|---|
| A rule allows and none denies | allow |
| No rule allows, or a rule denies | deny |
| `user_subject: none` and the policy has user-level rules hallpass cannot reach through groups | unknown (`unsupported`) rather than deny |
| The policy is invalid (Argo CD would refuse it too) | unknown (`unsupported`) |
| An AppProject's role policy is invalid | evaluated without it, as Argo CD does |
| The ServiceAccount may not read the config maps or projects | unknown (`credential_rejected`) |

## What it cannot see

- Policies bound to opaque identity provider subjects (Dex `sub`, `federated_claims.user_id`).
  Use `user_subject: email` only when the subject really is the email.
- Local Argo CD accounts, project JWT tokens.
- Sync windows, project source/destination restrictions, and anything else enforced outside RBAC.
- Applications in other namespaces are addressed as `<project>/<namespace>/<name>`; hallpass does not
  look the application up to find its project.

## Test

Unit tests run against a fake API server. `hallpass-py/tests/integrations/argocd/rbac` contains the
ported Argo CD tests. `hallpass-py/tests/differential/test_argocd.py` compares the evaluator with
`argocd admin settings rbac can` when the `argocd` binary is on the PATH.
