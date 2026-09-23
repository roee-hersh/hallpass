# linear

One connection is one Linear workspace. hallpass authenticates with a personal API key or an OAuth
token, finds the user by email through the GraphQL API and reads the workspace role (owner, admin,
member, guest, app), whether the account is active, and the teams the user belongs to and owns.
Team, issue and project questions read the object and apply Linear's visibility rules: members see
every public team, guests only the teams they joined, private teams only their members. Nothing is
written.

## Credential

Either of:

1. A **personal API key** (`auth_mode: api_key`, the default) created under Settings > Security &
   access > Personal API keys, sent bare in the `Authorization` header. It acts with the full
   permissions of its user, so create it for a dedicated workspace administrator and keep it tightly
   held.
2. An **OAuth access token** (`auth_mode: oauth`) with the `read` scope, sent as `Bearer`.

Use an administrator's credential: a member credential cannot read private teams it has not
joined, and their issues and projects then answer `resource_not_visible`.

`hallpass probe` reads `viewer` and `organization` and reports the credential's user and workspace.

## Connection

```yaml
  - id: linear-acme
    integration: linear
    credential: env:LINEAR_API_KEY
    # auth_mode: oauth                  # credential is then an OAuth access token
    # url: https://api.linear.app/graphql
```

| Key | Meaning |
|---|---|
| `url` | the GraphQL endpoint, default `https://api.linear.app/graphql` |
| `auth_mode` | `api_key` (default) or `oauth` |
| `credential` | the API key or access token, `env:` or `file:` |

### Identity

`users(filter: { email: { eqIgnoreCase: $email } }, includeDisabled: true)`, compared exactly
(ignoring case) against each result's `email`; none is `user_not_found`, two are `user_ambiguous`.
An inactive user (`active: false`, with `disableReason` such as admin suspension or pending invite)
is denied every action. The identity carries `admin`, `owner`, `guest` and `app`; its groups are the
ids of the teams from `user.teamMemberships`, and `owned_teams` the ids of teams whose membership
has `owner: true`. Groups sent by the caller are ignored. Every value travels as a GraphQL variable,
never inside the query text.

## Resources

| Resource | Meaning |
|---|---|
| `team:<KEY>` or `team:<id>` | a team by key (`ENG`) or Linear id |
| `issue:<KEY-n>` or `issue:<id>` | an issue by identifier (`ENG-123`) or Linear id |
| `project:<slug>` or `project:<id>` | a project by slug id or Linear id |
| `workspace` | the workspace |

Keys and identifiers are upper-cased before lookup.

## Actions

| Action | Resource | Decided by |
|---|---|---|
| `team.view` | `team:` | team access (below) |
| `team.member` | `team:` | a team membership exists |
| `team.admin` | `team:` | workspace owner or admin, or the membership's `owner: true`; a plain member answers `unsupported` |
| `issue.view` | `issue:` | team access to the issue's team |
| `issue.edit` | `issue:` | team access to the issue's team: members and guests edit and comment on every issue they can see |
| `project.view` | `project:` | team access to any of the project's teams |
| `workspace.member` | `workspace` | active, not a guest, not an app |
| `workspace.admin` | `workspace` | `admin` or `owner` (on Free plans every member is an admin) |
| `workspace.owner` | `workspace` | `owner` |

### Team access

| Team `visibility` | Visible when |
|---|---|
| `public` | the user is a member, or a non-guest workspace member |
| `private` | the user is a member; a non-member administrator answers `unsupported` |
| `restricted` | the user is a member; anyone else answers `unsupported` (the private boundary is not read) |
| archived team | `unsupported` |

App users answer `unsupported` for every team, issue and project question.

## Decisions

| Code | When |
|---|---|
| `allowed` / `denied` | the rules above decide |
| `unsupported` | an app user; an archived team; a restricted team or a private team for a non-member administrator; a trashed issue or project; a project with no team; a member's right to manage team settings |
| `resource_not_visible` | Linear answers an entity-not-found error for the team, issue or project |
| `user_not_found` / `user_ambiguous` | the email search |
| `credential_rejected` | HTTP 401 or 403, or a GraphQL error of type `authentication error`, `forbidden` or `feature not accessible` |
| `upstream_rate_limited` | HTTP 429, or HTTP 400 with `RATELIMITED` / type `ratelimited` or `usage limit exceeded` |
| `invalid_request` | an id that is not a key, identifier, slug or uuid; a query on the resource |
| `upstream_*` | 5xx, timeouts, other GraphQL errors |

## What it cannot see

- **Team settings.** Whether plain members may manage a team's settings, labels and templates is a
  per-team setting the API does not expose; `team.admin` answers `unsupported` for them.
- **Private boundaries.** Which members of a parent private team may see a `restricted` team.
- **Issue-level rules.** Linear has no per-issue permissions; deleting issues and archiving teams
  are not modelled.
- **SLAs, initiatives, customers** and other plan features.

## Unverified

Written from Linear's public GraphQL schema and help-center snippets; not run against a live
workspace. Marked `UNVERIFIED` in the code:

- Whether `issue(id:)` and `project(id:)` accept the human identifier and slug id as well as the
  uuid (the getting-started examples do).
- The exact shape of Linear's entity-not-found error; any error whose message contains "not found"
  answers `resource_not_visible`.
- Whether workspace administrators see the content of private teams they have not joined.
- Who sees `restricted` teams.

## Test

`go test ./internal/integrations/linear/` runs a fake GraphQL endpoint validated against Linear's
schema when `HALLPASS_SPECS_DIR` holds `linear.spec` (`test/specs/fetch.sh`): every field, argument
and variable of each query is checked against the SDL. The fake has an owner, an administrator, a
team owner, members with and without teams, a guest, an app user and suspended and invited users
over public, private, restricted and archived teams. `FuzzParseTarget` checks that only keys,
identifiers, slugs and uuids reach the API.
