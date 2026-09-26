# jira

hallpass resolves the caller's email to an Atlassian `accountId` with `GET /rest/api/3/user/search`,
then asks `POST /rest/api/3/permissions/check` whether that account holds the permission on the
project, the issue or globally. Jira evaluates permission schemes, project roles, groups and
issue-level grants (Reporter, Assignee, issue security) itself; hallpass only reads the answer.
Nothing in Jira is changed. Jira Cloud only; Data Center is out of scope.

## Credential

**This is not a read-only role.** `permissions/check` for another user needs **Administer Jira**
(global) on hallpass's account, plus **Browse users and groups** for the email lookup and **Browse
Projects** on every project you ask about (the project and issue lookups return 404 otherwise). An
account without Administer Jira gets HTTP 403 and every check answers unknown (`credential_rejected`).

Mitigate the blast radius with a dedicated service account and a **scoped API token** limited to the
read scopes `read:jira-work` and `read:jira-user` (`auth_mode: scoped_token`). The account still
holds Administer Jira, but the token hallpass carries can only read.

Three auth modes:

| `auth_mode` | Credential | Requests go to |
|---|---|---|
| `basic` (default) | `username` (the account's email) + API token | `{url}/rest/api/3/...` with HTTP basic auth |
| `scoped_token` | scoped API token | `https://api.atlassian.com/ex/jira/{cloudId}/rest/api/3/...` with `Authorization: Bearer` |
| `oauth_client` | OAuth 2.0 `client_id` + client secret | client credentials at `https://auth.atlassian.com/oauth/token`, then the same gateway as `scoped_token` |

The cloud id is discovered once per connection from `GET {url}/_edge/tenant_info` and cached. OAuth
tokens are cached and refreshed five minutes before expiry.

## Connection

```yaml
  - id: jira-acme
    integration: jira
    url: https://acme.atlassian.net
    auth_mode: basic                     # basic | scoped_token | oauth_client
    username: hallpass@acme.com          # basic only
    credential: env:JIRA_TOKEN           # API token, or client secret for oauth_client
    client_id: "abc123"                  # oauth_client only
```

| Key | Meaning |
|---|---|
| `url` | site URL |
| `auth_mode` | `basic`, `scoped_token` or `oauth_client` |
| `username` | email of the bot account; required for `basic` |
| `credential` | API token (`basic`, `scoped_token`) or OAuth client secret (`oauth_client`); `env:` or `file:` |
| `client_id` | OAuth 2.0 client id; required for `oauth_client` |

The key `strict_email_match` no longer exists. It let a connection accept a single candidate whose
profile hides its email, but `user/search?query=` matches the display name as well as the email, so
an account *named* `cfo@corp.com` with a hidden email was resolved as the CFO. The loader rejects
unknown keys (`integration jira does not accept key "strict_email_match"`): remove the line from any
existing connection.

Identity: `GET /rest/api/3/user/search?query=<email>` is read in pages of 50 (`startAt`), up to
five pages. The results are filtered to `accountType: atlassian` and `active: true`, and a candidate
counts only when its `emailAddress` equals the request email case-insensitively; a display name is
never a match. Exactly one match is the identity; several are `user_ambiguous`; none is
`user_not_found`, except that when candidates remain whose email the profile hides the answer is
unknown (`unsupported`, "email hidden by profile visibility": make the email visible to the site or
use a scoped token that can read it), and when five full pages hold no match it is unknown
(`unsupported`, "too many candidates"), since the account may sit on a page hallpass did not read.
An empty email is `invalid_request`.

## Resources

| Resource | Meaning |
|---|---|
| `project:<KEY>` | a project, key matching `^[A-Z][A-Z0-9_]{1,9}$` |
| `issue:<KEY-N>` | one issue, e.g. `issue:OPS-123` |
| `global` | the site, for global permissions |

The project or issue is looked up first (`GET /rest/api/3/project/{key}`,
`GET /rest/api/3/issue/{key}?fields=project`) because the bulk permission endpoint silently ignores
ids it does not know, which would read as deny.

## Actions

Action names are Jira's own permission keys.

Project permissions, on `project:` or `issue:` resources: `BROWSE_PROJECTS`, `CREATE_ISSUES`,
`EDIT_ISSUES`, `DELETE_ISSUES`, `ASSIGN_ISSUES`, `ASSIGNABLE_USER`, `TRANSITION_ISSUES`,
`RESOLVE_ISSUES`, `CLOSE_ISSUES`, `MOVE_ISSUES`, `LINK_ISSUES`, `ADD_COMMENTS`, `EDIT_ALL_COMMENTS`,
`DELETE_ALL_COMMENTS`, `CREATE_ATTACHMENTS`, `WORK_ON_ISSUES`, `MANAGE_WATCHERS`,
`VIEW_VOTERS_AND_WATCHERS`, `SCHEDULE_ISSUES`, `SET_ISSUE_SECURITY`, `MANAGE_SPRINTS_PERMISSION`,
`ADMINISTER_PROJECTS`.

Global permissions, on `global` only: `ADMINISTER`, `SYSTEM_ADMIN`, `USER_PICKER`,
`CREATE_SHARED_OBJECTS`, `MANAGE_GROUP_FILTER_SUBSCRIPTIONS`, `BULK_CHANGE`.

A project permission on `global`, or a global permission on a project or issue, is `invalid_request`.

## Decisions

| Jira says | hallpass answers |
|---|---|
| the project / issue id appears under the permission in the response, or the key appears in `globalPermissions` | allow |
| the permission is echoed in `projectPermissions` without the id, or the key is missing from `globalPermissions` | deny |
| 200 whose `projectPermissions` does not echo the requested permission key at all | unknown (`unsupported`): Jira did not evaluate the key |
| no active account with the email, or only candidates whose email is hidden, or five full search pages without a match | deny (`user_not_found`), unknown (`unsupported`), unknown (`unsupported`) |
| 404 on the project or issue lookup | unknown (`resource_not_visible`): missing, archived, or not browsable by hallpass's account |
| 403 on the project or issue lookup | unknown (`credential_rejected`): hallpass's account lacks Browse Projects |
| 403 on `permissions/check` | unknown (`credential_rejected`): hallpass's account lacks Administer Jira |
| 403 on the user search | unknown (`credential_rejected`): hallpass's account lacks Browse users and groups |
| 400 on `permissions/check` | unknown (`unsupported`): the permission key does not exist on this site |
| 401 | unknown (`credential_rejected`) |
| 429, 5xx, timeout | unknown (`upstream_rate_limited`, `upstream_error`, `upstream_timeout`) |

Rate limits are a points-based quota; Jira answers 429 with `Retry-After`, which `httpx` honours for
the idempotent calls.

## Probe

`GET /rest/api/3/myself` proves the credential, `GET /rest/api/3/mypermissions?permissions=ADMINISTER`
warns when Administer Jira is missing (every check for another user will answer unknown), and
`GET /rest/api/3/permissions` warns for any action key the site does not list.

## What it cannot see

- A `project:` answer over-approximates issue-level roles: a permission granted to Reporter or
  Assignee makes the user hold it "on the project" while they hold it only on some issues. Use
  `issue:` resources when that matters.
- Issue security levels beyond what `permissions/check` on an `issue:` already applies, workflow
  conditions and validators, Jira Service Management request types and customer portals, and
  archived projects (404, so `resource_not_visible`).
- Whatever a Forge or Connect app enforces on top of Jira's permissions.

## Unverified

- The `oauth_client` grant: implemented as a JSON body
  `{grant_type: client_credentials, client_id, client_secret, audience: api.atlassian.com}` posted to
  `https://auth.atlassian.com/oauth/token`, then `Authorization: Bearer` against the
  `api.atlassian.com/ex/jira/{cloudId}` gateway. Not exercised against a live token endpoint.
- Whether `user/search?query=<email>` returns accounts whose profile hides the email. If it does not,
  such users are `user_not_found` rather than the hidden-email `unsupported` answer.
- Whether `permissions/check` answers 400 for an unknown permission key. A project permission that
  Jira silently drops instead is caught by the echo check (no `projectPermissions` entry for the
  key, so `unsupported`); a dropped *global* permission has no echo to check and would read as deny.
  The probe's key validation is the safeguard for both.
- The page size and the five-page cap of the user search assume Jira honours `startAt` and
  `maxResults: 50` on `user/search` as the API description says; a smaller server-side cap would
  make the "too many candidates" answer appear sooner than documented.

## Test

Unit tests run against a fake Jira Cloud site (`hallpass-py/tests/integrations/jira/test_jira.py`) covering
the three auth modes, identity edge cases (display-name spoofing, hidden emails, paging and the
too-many-candidates cap, empty email), project/issue/global checks, a check whose response does not
echo the permission key, every action, the injected failure modes and the probe. With
`HALLPASS_SPECS_DIR` set, every request is validated against the Jira Cloud API description. No
live-site test exists yet.
