# datadog

One connection is one Datadog organization. hallpass authenticates with an API key and a scoped
application key, finds the user by email, reads the permissions carried by the user's roles, and for
a monitor, dashboard, SLO or notebook reads the asset's restriction policy and its legacy
`restricted_roles` and author fields. A user may change such an asset only when a role carries the
write permission **and** the asset's restrictions, if any, name the user, one of the user's roles or
teams, or the whole org. Nothing is written.

## Credential

1. An **API key** of the organization (`api_key`).
2. An **application key** (`credential`) created for a dedicated service account or user and
   **scoped** to `user_access_read`, `teams_read` and the read scope of each asset type asked about:
   `monitors_read`, `dashboards_read`, `slos_read`, `notebooks_read`. Reading a restriction policy
   needs no named scope. An unscoped application key carries every permission of its creator, which
   is far more than hallpass needs.

`hallpass probe` validates the API key, lists one user (which proves `user_access_read`) and reminds
you of the other scopes.

## Connection

```yaml
  - id: datadog-acme
    integration: datadog
    api_key: env:DATADOG_API_KEY
    credential: env:DATADOG_APP_KEY
    # url: https://api.datadoghq.eu     # default https://api.datadoghq.com; US3 api.us3.datadoghq.com, US5 api.us5.datadoghq.com, AP1 api.ap1.datadoghq.com
```

| Key | Meaning |
|---|---|
| `url` | the site's API URL |
| `api_key` | sent as `DD-API-KEY`, `env:` or `file:` |
| `credential` | the application key, sent as `DD-APPLICATION-KEY`, `env:` or `file:` |

### Identity

`GET /api/v2/users?filter=<email>&filter[status]=Active,Pending,Disabled`, every page. The filter is
a substring match on name, handle and email, so only the record whose `email` equals the address
(ignoring case) is the user; none is `user_not_found`, two are `user_ambiguous`. A `disabled` user is
denied every action. The identity carries the user's handle and the ids of the user's roles; each
role's permissions come from `GET /api/v2/roles/{id}/permissions`, cached for five minutes. Groups
sent by the caller are ignored.

## Resources

| Resource | Meaning |
|---|---|
| `monitor:<id>` | a monitor |
| `dashboard:<id>` | a dashboard (`abc-def-ghi`) |
| `slo:<id>` | a service level objective |
| `notebook:<id>` | a notebook |
| `org` | the organization, for permissions that are not about one asset |

## Actions

| Action | Permission | Restriction relation | Resource |
|---|---|---|---|
| `monitor.edit` | `monitors_write` | editor | monitor |
| `monitor.mute` | `monitors_downtime` | editor (muting counts as editing a restricted monitor) | monitor |
| `monitor.read` | `monitors_read` | viewer | monitor |
| `dashboard.edit` | `dashboards_write` | editor | dashboard |
| `dashboard.read` | `dashboards_read` | viewer | dashboard |
| `slo.edit` | `slos_write` | editor | slo |
| `notebook.edit` | `notebooks_write` | editor | notebook |
| `logs.read` | `logs_read_data` | | org |
| `users.manage` | `user_access_manage` | | org |
| `apikeys.manage` | `api_keys_write` | | org |
| `raw:<permission>` | that permission | on an asset: editor when it is the type's write permission, viewer otherwise | any |

### Evaluation

1. The permission: one of the user's roles must list it. On the `org` resource that is the answer.
2. The asset is read (`GET /api/v1/monitor/{id}`, `/api/v1/dashboard/{id}`, `/api/v1/slo/{id}`,
   `/api/v1/notebooks/{id}`); a 404 is `resource_not_visible` whatever the permission.
3. The restriction policy: `GET /api/v2/restriction_policy/{type}:{id}`. When it has bindings, the
   user must appear in a binding whose relation is the one needed or higher (`viewer` < `editor`;
   type-specific relations above editor count as editor) as `user:<id>`, `role:<one of the user's
   roles>`, `team:<a team the user is a member of>` (`GET /api/v2/team/{id}/memberships`, every
   page) or `org:<any>`.
4. Without a policy, the legacy fields: a monitor's or dashboard's `restricted_roles` must include
   one of the user's roles for an edit, except that a dashboard's author (`author_handle`) may always
   edit. Reads are not restricted by `restricted_roles`.

## Decisions

| Situation | hallpass answers |
|---|---|
| a role carries the permission and the asset has no restriction | allow |
| a role carries the permission and a binding at the relation names the user, a role, a team the user is on, or the org | allow, naming the principal kind |
| a role carries the permission and `restricted_roles` includes a role of the user, or the user authored the dashboard | allow |
| no role carries the permission | deny |
| the asset's restriction policy or `restricted_roles` name none of the user's principals | deny |
| disabled user | deny |
| no user with the email | deny (`user_not_found`) |
| several users | unknown (`user_ambiguous`) |
| user record without `disabled` | unknown (`unsupported`) |
| the asset, a role of the user, or a team named by the policy answers 404 | unknown (`resource_not_visible`) |
| 401, 403 (the application key lacks the scope) | unknown (`credential_rejected`) |
| 429, 5xx, timeout | unknown (`upstream_rate_limited` / `upstream_error` / `upstream_timeout`) |

Error bodies are never copied into a decision text.

## What it cannot see

- Self-elevation: a user with `user_access_manage` can add themselves to any restriction policy.
  hallpass answers for the policy as it stands, so such a user is denied until they do.
- Assets other than monitors, dashboards, SLOs and notebooks (synthetics tests, security rules,
  workflows, ...), which have restriction policies of their own but no action here yet; use
  `raw:<permission>` on `org` for their permissions alone.
- Log restriction queries, index-level log permissions, and RBAC on APM services.
- Team membership through team-links or provisioning that the memberships endpoint does not list.

## Unverified

Marked `// UNVERIFIED:` in the code:

- Whether a monitor's creator keeps edit rights under `restricted_roles` the way a dashboard's
  author does. Datadog documents roles only for monitors, so the creator is not exempted.

Assumed from Datadog's documentation rather than tested live: that the write permission is still
required when a restriction policy grants `editor` ("the limitations are applied both in the UI and
API"), and that `GET /api/v2/restriction_policy/{id}` answers `200` with empty bindings, not 404,
for an asset without a policy (a 404 is treated the same).

## Test

Unit tests run against a fake that serves users (paged), role permissions, monitors, dashboards,
SLOs, notebooks, restriction policies and team memberships (paged), validating every request against
Datadog's v1 and v2 OpenAPI descriptions (`datadog-v1` and `datadog-v2` in `test/specs/fetch.sh`).
There is no live test; after configuring, run `hallpass probe` and one check for a user you know is
allowed.
