# pagerduty

One connection is one PagerDuty account. hallpass authenticates with a read-only REST API key, finds
the user by email, reads the user's base role and, when the object asked about belongs to teams, the
user's role on each of those teams. Base roles set account-wide access; a team role adds access to the
team's incidents, services, escalation policies and schedules. Nothing is written.

## Credential

A **General Access REST API key** created with "Read-only API Key" checked (Integrations, API Access
Keys). General access keys see every object in the account, so no team membership is needed for
hallpass itself. A personal user key would be limited to that user's own visibility; do not use one.

`hallpass probe` lists the account's abilities and warns when `teams` or advanced permissions are
missing, and always reminds that it cannot tell a read-only key from a full one.

## Connection

```yaml
  - id: pagerduty-acme
    integration: pagerduty
    credential: env:PAGERDUTY_API_KEY
    # url: https://api.eu.pagerduty.com    # EU service region; default https://api.pagerduty.com
```

| Key | Meaning |
|---|---|
| `url` | API URL, default `https://api.pagerduty.com` |
| `credential` | the REST API key, `env:` or `file:`; sent as `Authorization: Token token=...` |

Every call carries `Accept: application/vnd.pagerduty+json;version=2`.

### Identity

`GET /users?query=<email>&include[]=teams`, every page. The query matches names as well as
addresses, so only the record whose `email` equals the address (ignoring case) is the user; none is
`user_not_found`, two are `user_ambiguous`. The identity carries the base `role` and the ids of the
user's teams. Groups sent by the caller are ignored.

## Resources

| Resource | Meaning |
|---|---|
| `incident:<id>` | an incident, by id (`PABC123`) or incident number |
| `service:<id>` | a service |
| `escalation_policy:<id>` | an escalation policy |
| `schedule:<id>` | a schedule |
| `team:<id>` | a team |
| `account` | the account |

Ids are upper-cased and must be alphanumeric.

## Actions

| Action | What it asks | Resource |
|---|---|---|
| `incident.acknowledge` / `incident.resolve` / `incident.reassign` | act on the incident | incident |
| `schedule.override` | create an override | schedule |
| `service.edit` / `escalation_policy.edit` / `schedule.edit` | change or delete the object's configuration | service, escalation_policy, schedule |
| `service.maintenance` | create a maintenance window for the service | service |
| `team.manage` | change the team, its members and their roles | team |
| `team.member` | is a member of the team | team |
| `account.admin` | is an account owner or global admin | account |

### Evaluation

The base role is read from the user record (API names, web UI names in brackets):

| Base role | Incident actions and overrides | Configuration changes |
|---|---|---|
| `owner` (Account Owner), `admin` (Global Admin) | everywhere | everywhere |
| `user` (Manager) | everywhere | everywhere |
| `limited_user` (Responder) | everywhere | only through a team role |
| `observer`, `restricted_access` | only through a team role | only through a team role |
| `read_only_user`, `read_only_limited_user` (Stakeholders) | never | never |

The object is always read first, so a deleted or invisible id is `unknown` whatever the role. When
the base role does not settle it, the object's teams (`teams[]` of the service, escalation policy or
schedule; for an incident its own `teams[]` and its service's, with `include[]=services`, or a
separate service read when it comes back as a reference) are intersected with the teams on the
user's record, and the user's role on each of those is read from `GET /teams/{id}/members`, every
page, stopping at the first manager role.
A team `responder` or `manager` may act on the team's incidents, create overrides and set
maintenance windows; a team `manager` may also change the team's configuration; a team `observer`
may not act. An object with no team, or one whose teams give the user no role, is denied.

`account.admin` and `team.member` are answered from the user record alone (after checking the team
exists).

## Decisions

| Situation | hallpass answers |
|---|---|
| the base role grants the action account-wide | allow, naming the role |
| a responder or manager team role (incident actions, overrides, maintenance) or a manager team role (configuration) on one of the object's teams | allow, naming the team role |
| a stakeholder role | deny |
| no team role, a team observer role, or an object without teams | deny |
| `limited_user` asking `service.maintenance` without a responder or manager team role on the service's teams | unknown (`unsupported`): whether a base Responder may set maintenance windows account-wide is not documented |
| a base role hallpass does not know | unknown (`unsupported`) |
| no user with the email | deny (`user_not_found`) |
| several users | unknown (`user_ambiguous`) |
| the object, or one of its teams, answers 404 (error 2100) | unknown (`resource_not_visible`) |
| 401, 403 (error 2010) | unknown (`credential_rejected`) |
| 402 (the account lacks an ability) | unknown (`unsupported`) |
| 429, 5xx, timeout | unknown (`upstream_rate_limited` / `upstream_error` / `upstream_timeout`) |

Only the numeric error code is read from an error body; messages are never copied into a decision.

## What it cannot see

- Object-level roles ("Additional Permissions" on a single service, escalation policy or schedule):
  the REST API exposes none, so a user who may act on one object only through an object role is
  denied.
- A team role that lowers a Manager's access on that team's objects: the base role is taken as the
  floor.
- Whether advanced permissions (team roles) are in effect on the account's plan; the probe warns when
  no such ability is reported.
- Incident state: hallpass says whether the user may act, not whether the incident can still be
  acknowledged.

## Unverified

Not marked in code; the rules come from PagerDuty's role documentation rather than a permission
API, so they are documented here:

- The user search (`GET /users?query=`) is documented as matching names; that it also matches email
  addresses is assumed, and results are compared exactly either way.
- Whether a base Responder may create maintenance windows account-wide (answered `unknown`), and
  whether a team responder may act on every incident of the team's services or only on incidents
  assigned to them (hallpass takes the former, per the Advanced Permissions page).
- The ability names `advanced_permissions` / `permissions_teams` the probe looks for.

## Test

Unit tests run against a fake that serves users, team members (paged), incidents with expanded
services, services, escalation policies, schedules, teams and abilities, validating every request
against PagerDuty's OpenAPI description (`pagerduty` in `test/specs/fetch.sh`). There is no live
test; after configuring, run `hallpass probe` and one check for a user you know is allowed.
