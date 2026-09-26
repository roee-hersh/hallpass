# googlecloud

hallpass authenticates as a service account and asks the Policy Troubleshooter API
(`POST https://policytroubleshooter.googleapis.com/v3/iam:troubleshoot`) whether a principal holds an
IAM permission on a full resource name. Google evaluates the allow policies and the deny policies of
the resource and every ancestor (project, folder, organization), expanding group membership, and
answers `CAN_ACCESS`, `CANNOT_ACCESS`, `UNKNOWN_CONDITIONAL` or `UNKNOWN_INFO`. One check is one
call. Nothing is written and no user credential is ever used.

## Credential

1. Create a service account in a project where the **Policy Troubleshooter API** is enabled.
2. Grant it `roles/iam.securityReviewer` on the organization, folder or project you want to answer
   for (`scope`). The role is read-only: `*.getIamPolicy` on every resource type plus the deny
   policy reads. The troubleshooter can only explain policies the caller can read, so a role granted
   too low in the hierarchy makes every check `UNKNOWN_INFO` (unknown).
3. Either create a key for the service account and store the JSON in a file (`auth_mode: key`), or
   run hallpass on GCE/GKE as that service account and use `auth_mode: keyless`: hallpass then takes
   the runtime identity's token from the metadata server and no key exists.
4. If the credential's own project cannot be billed for the API (the API is disabled there, or the
   service account belongs to another organization), set `quota_project` to a project where the
   API is enabled; hallpass sends it as `X-Goog-User-Project`, and the service account needs
   `serviceusage.services.use` on that project.

`hallpass probe` warns when the role is missing under `scope` and always reminds that the
troubleshooter discloses which permissions other principals hold: that is what hallpass is for, but
the service account should be held by hallpass alone.

Signing with a service-account key (`auth_mode: key`) needs `cryptography`: install `hallpass[crypto]` (the Docker image has it).

## Connection

```yaml
  - id: gcp-acme
    integration: googlecloud
    scope: organization:123456789012             # or folder:<number>, project:<id>
    credential: file:/secrets/gcp-hallpass.json   # service-account key JSON (auth_mode key)
    auth_mode: key                                # or keyless
    quota_project: acme-hallpass                  # optional
    googleworkspace_connection: gws-acme          # optional, see Identity
```

| Key | Meaning |
|---|---|
| `scope` | `organization:<number>`, `folder:<number>` or `project:<id>`: where the service account holds `roles/iam.securityReviewer`. The probe asks the troubleshooter about this resource. Checks are not restricted to it |
| `credential` | service-account key JSON (`file:`); `client_email`, `private_key` and `private_key_id` are read from it (the token endpoint is `token_url`). Required in `auth_mode: key` |
| `auth_mode` | `key` (default) signs a JWT with the key; `keyless` uses the GCE/GKE runtime identity |
| `quota_project` | sent as `X-Goog-User-Project` on every call |
| `googleworkspace_connection` | id of a `googleworkspace` connection used to resolve the user first |
| `token_url` | default `https://oauth2.googleapis.com/token` |
| `api_url` | default `https://policytroubleshooter.googleapis.com` |
| `metadata_url` | default `http://metadata.google.internal`, `keyless` only |

Production leaves the three URLs at their defaults; they exist so tests can point at a fake.

In `key` mode the token is a JWT bearer exchange: RS256 with `kid` = `private_key_id`, `iss` =
`client_email`, `scope` = `https://www.googleapis.com/auth/cloud-platform`, `aud` = `token_url`, no
`sub`, one hour lifetime; the token is cached and refreshed five minutes before it expires. In
`keyless` mode the metadata server's token is used as is. A 401 from the API invalidates the token
and retries the call once.

### Identity

The principal is an email address. Without `googleworkspace_connection` the caller's email,
lowercased, is sent as is: the troubleshooter answers for that address whether or not a Google
Account exists, so an unknown user is `deny` ("no allow policy grants ..."), never `user_not_found`.

With `googleworkspace_connection` the Workspace Directory is consulted first, as that connection
does: an alias becomes the primary address (which is the principal sent to Google), an email with no
account is `user_not_found`, and a suspended or archived account is denied every action without
asking Google. Groups sent by the caller are ignored: the troubleshooter expands Google Groups
itself.

## Resources

| Resource | Full resource name |
|---|---|
| `project:<id or number>` | `//cloudresourcemanager.googleapis.com/projects/<id>` |
| `folder:<number>` | `//cloudresourcemanager.googleapis.com/folders/<number>` |
| `organization:<number>` | `//cloudresourcemanager.googleapis.com/organizations/<number>` |
| `bucket:<name>` | `//storage.googleapis.com/projects/_/buckets/<name>` |
| `object:<bucket>/<object name>` | `//storage.googleapis.com/projects/_/buckets/<bucket>/objects/<object name>` |
| `dataset:<project>/<dataset>` | `//bigquery.googleapis.com/projects/<p>/datasets/<d>` |
| `table:<project>/<dataset>/<table>` | `//bigquery.googleapis.com/projects/<p>/datasets/<d>/tables/<t>` |
| `secret:<project>/<name>` | `//secretmanager.googleapis.com/projects/<p>/secrets/<name>` |
| `serviceaccount:<name>@<project>.iam.gserviceaccount.com` | `//iam.googleapis.com/projects/<project>/serviceAccounts/<email>` |
| `instance:<project>/<zone>/<name>` | `//compute.googleapis.com/projects/<p>/zones/<z>/instances/<name>` |
| `service:<project>/<region>/<name>` | `//run.googleapis.com/projects/<p>/locations/<r>/services/<name>` (Cloud Run) |
| `cluster:<project>/<location>/<name>` | `//container.googleapis.com/projects/<p>/locations/<l>/clusters/<name>` (GKE) |
| `name:<full resource name>` | verbatim; must start with `//<service>.googleapis.com/` |

Every piece is validated against a strict shape (project ids or numbers, bucket names, numbers,
resource names) before it is placed in the request; anything else is `invalid_request`. An object
name may contain any character but control characters, since it only travels inside the JSON body,
except `.` or `..` segments. `<project>` is a project id or a project number everywhere.
Google-managed service accounts (`...@developer.gserviceaccount.com`) are addressed through `name:`.

## Actions

| Action | IAM permission | Resources |
|---|---|---|
| `raw:<permission>` | exactly that, in the v1 (`storage.objects.delete`) or v2 (`iam.googleapis.com/roles.create`) format | any |
| `project.view` | `resourcemanager.projects.get` | project |
| `iam.set` | `<type>.setIamPolicy` of the resource type | project, folder, organization, bucket, secret, serviceaccount, table |
| `storage.read` / `storage.write` / `storage.delete` | `storage.objects.get` / `create` / `delete` | bucket, object |
| `storage.list` | `storage.objects.list` | bucket |
| `bucket.delete` | `storage.buckets.delete` | bucket |
| `bigquery.read` / `bigquery.write` / `bigquery.delete` | `bigquery.tables.getData` / `updateData` / `delete` | dataset, table |
| `secret.read` | `secretmanager.versions.access` | secret |
| `serviceaccount.actas` | `iam.serviceAccounts.actAs` | serviceaccount |
| `compute.start` / `compute.stop` / `compute.delete` | `compute.instances.start` / `stop` / `delete` | instance |
| `run.deploy` | `run.services.update` | service |
| `gke.access` | `container.clusters.get` | cluster |

Every action also accepts a `project:`, `folder:`, `organization:` or `name:` resource, since a
permission is meaningful at any level of the hierarchy: `storage.delete` on `project:acme-prod` asks
whether the user may delete objects anywhere in the project's buckets (as far as IAM is concerned).
`iam.set` needs a typed resource to pick the permission; on `name:` use
`raw:<service>.<type>.setIamPolicy`.

## Decisions

| Troubleshooter says | hallpass answers |
|---|---|
| `overallAccessState: CAN_ACCESS` | allow |
| `CANNOT_ACCESS` with `denyPolicyExplanation.denyAccessState: DENY_ACCESS_STATE_DENIED` | deny ("a deny policy denies ...") |
| `CANNOT_ACCESS` otherwise | deny ("no allow policy grants ...") |
| `UNKNOWN_CONDITIONAL` (a binding or deny rule has a condition Google could not evaluate without a request context) | unknown (`unsupported`) |
| `UNKNOWN_INFO` (hallpass cannot read one of the policies, or the resource does not exist) | unknown (`resource_not_visible`) |
| any other or missing state, unreadable body | unknown (`upstream_error`) |
| suspended / archived account (with `googleworkspace_connection`) | deny |
| no Workspace account (with `googleworkspace_connection`) | deny (`user_not_found`) |
| Workspace record without `suspended` or `archived` | unknown (`unsupported`) |
| HTTP 400 (bad permission name, bad resource name, principal is not a Google Account or service account) | unknown (`invalid_request`) |
| HTTP 403 with a rate-limit reason (`RATE_LIMIT_EXCEEDED`, `quotaExceeded`, status `RESOURCE_EXHAUSTED`), HTTP 429 | unknown (`upstream_rate_limited`) |
| HTTP 403 otherwise (API disabled, role missing, quota project refused), HTTP 401 after one retry, token endpoint `invalid_grant` | unknown (`credential_rejected`) |
| HTTP 404 | unknown (`resource_not_visible`) |
| 5xx, timeout | unknown (`upstream_error` / `upstream_timeout`) |

Error bodies are read whole so the reason is found even after a long message; only the status and reason tokens are used. Google error messages and the explained policies are never copied into a decision text.

## Probe

`hallpass probe` mints a token, then asks the troubleshooter whether the service account itself may
`resourcemanager.<type>.get` the `scope` resource. `CAN_ACCESS` or `CANNOT_ACCESS` proves the API
is enabled and the policies under `scope` are readable; `UNKNOWN_INFO` warns that
`roles/iam.securityReviewer` is missing there. Without `googleworkspace_connection` it warns that an
unknown email is answered as deny rather than `user_not_found`.

## What it cannot see

The troubleshooter evaluates IAM allow and deny policies of the resource and its ancestors. It does
not evaluate:

- IAM Conditions: a conditional binding answers `UNKNOWN_CONDITIONAL` (unknown), never allow;
- Cloud Storage legacy ACLs on buckets without uniform bucket-level access, BigQuery dataset access
  entries that are not IAM bindings, and other product-specific grants outside IAM;
- VPC Service Controls perimeters, organization policy constraints, principal access boundary
  policies, and Access Context Manager levels;
- principals that are not a Google Account or a service account: Workforce Identity Federation
  users, Workload Identity Federation identities, `allUsers` and `allAuthenticatedUsers`;
- whether the user can actually sign in (a suspended account is only caught with
  `googleworkspace_connection`);
- resources that do not exist: the answer is `UNKNOWN_INFO`, not deny.

## Unverified

Marked `# UNVERIFIED:` in the code:

- Whether `roles/iam.securityReviewer` is enough for the troubleshooter to read every allow and deny
  policy under `scope`, or whether a `policytroubleshooter.*` permission is needed as well; the probe
  reports `UNKNOWN_INFO` if the role is not enough.
- Group expansion: the troubleshooter expands Google Groups only when the caller can see the
  membership; for groups it cannot read the state is `UNKNOWN_INFO`, which hallpass reports as
  `resource_not_visible` like an unreadable policy.
- A principal that is not a Google Account or a service account: assumed to answer `CANNOT_ACCESS`
  or HTTP 400 rather than some other state.

## Test

Unit tests run against one fake server that serves the token endpoint, the metadata server and
`/v3/iam:troubleshoot`, verifying the JWT assertion, the bearer, the quota header and every request
against the API's discovery document (`google-policytroubleshooter` in `test/specs/fetch.sh`). There is
no live test; after configuring, run `hallpass probe` and one check for a user you know is allowed.
