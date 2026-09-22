# confluence

For pages and blog posts hallpass asks Confluence directly:
`POST /wiki/rest/api/content/{id}/permission/check` with the user's `accountId` and the operation
(`read`, `update`, `delete`), which weighs site access, space permissions and content restrictions.
Confluence has no such call for space-level operations, so for `space:` resources hallpass reads the
space's permission list (`GET /wiki/api/v2/spaces/{id}/permissions`) and, when a group holds the
permission, the user's groups (`GET /wiki/rest/api/user/memberof`), and matches them itself.
Confluence's user search has no email field, so the email is resolved through a **jira** connection
on the same Atlassian site. Nothing in Confluence is changed. Cloud only; Data Center is out of scope.

## Credential

Checking another user's permissions needs **Confluence Administrator** on hallpass's account (a plain
user gets HTTP 403 on the permission check, answered as `credential_rejected`). The space permission
and group reads need view access to the space and Browse users. As with jira, prefer a dedicated
service account with a scoped API token (`auth_mode: scoped_token`) limited to read scopes such as
`read:confluence-content.all`, `read:confluence-space.summary`, `read:confluence-user` and
`read:confluence-groups`.

The auth modes are the jira integration's: `basic` (`username` + API token against `{url}/wiki/...`),
`scoped_token` (Bearer against `https://api.atlassian.com/ex/confluence/{cloudId}/wiki/...`) and
`oauth_client` (client credentials, then the same gateway). The cloud id is discovered once from
`GET {url}/_edge/tenant_info`.

## Connection

```yaml
  - id: confluence-acme
    integration: confluence
    url: https://acme.atlassian.net
    auth_mode: basic
    username: hallpass@acme.com
    credential: env:CONFLUENCE_TOKEN
    identity_connection: jira-acme        # jira connection on the same site
```

| Key | Meaning |
|---|---|
| `url` | site URL (without `/wiki`) |
| `auth_mode` | `basic`, `scoped_token` or `oauth_client` |
| `username` | email of the bot account; required for `basic` |
| `credential` | API token or OAuth client secret; `env:` or `file:` |
| `client_id` | OAuth 2.0 client id; required for `oauth_client` |
| `strict_email_match` | accepted for parity with jira; the lookup runs in the jira connection, so that connection's own setting governs it |
| `identity_connection` | id of a jira connection on the same Atlassian site, used for the email lookup. Without it every check answers unknown (`unsupported`, "Confluence cannot look up users by email") |

## Resources

| Resource | Meaning |
|---|---|
| `page:<id>` | a page by numeric content id |
| `blogpost:<id>` | a blog post by numeric content id |
| `space:<KEY>` | a space by key (`^[A-Za-z0-9~_-]{1,255}$`) |

## Actions

Native, through the content permission check:

| Action | Resource | Operation |
|---|---|---|
| `page.read`, `page.update`, `page.delete` | `page:` | `read`, `update`, `delete` |
| `blogpost.read`, `blogpost.update`, `blogpost.delete` | `blogpost:` | `read`, `update`, `delete` |

Evaluated from the space permission list, on `space:`:

| Action | Space permission (operation key / target type) |
|---|---|
| `space.read` | `read` / `space` |
| `page.create` | `create` / `page` |
| `blogpost.create` | `create` / `blogpost` |
| `comment.create` | `create` / `comment` |
| `attachment.create` | `create` / `attachment` |
| `space.export` | `export` / `space` |
| `page.restrict` | `restrict_content` / `space` |
| `space.admin` | `administer` / `space` |

An action on the wrong resource type is `invalid_request`.

## Decisions

| Situation | Answer |
|---|---|
| `hasPermission: true` | allow |
| `hasPermission: false` | deny |
| a `user` principal with the user's accountId, or a `group` principal whose id is among the user's groups, holds the operation and target type | allow |
| no principal holds it, or only groups the user is not in | deny |
| no match, and the permission is held by a principal type hallpass does not model (for example `role`) | unknown (`unsupported`, "role-based space permissions not evaluated") |
| 404 on the content check, or no space with the key | unknown (`resource_not_visible`) |
| 403 | unknown (`credential_rejected`): hallpass's account is not a Confluence Administrator, or cannot read the space or groups |
| no `identity_connection` | unknown (`unsupported`) |
| 401, 429, 5xx, timeout | unknown (`credential_rejected`, `upstream_rate_limited`, `upstream_error`, `upstream_timeout`) |

## Probe

`GET /wiki/rest/api/user/current` proves the credential. The probe warns when `identity_connection`
is unset and always reminds that checking other users needs Confluence Administrator, which hallpass
cannot verify without a resource.

## What it cannot see

- Creating under a restricted parent: `page.create` is a space-level answer; a parent page whose
  restrictions exclude the user still blocks the create.
- Guests and anonymous access, and the product-access ("use Confluence") permission that gates
  everything else: a user without a Confluence licence may still show up as holding a space
  permission through a group.
- Space permissions held by roles or other principal types (answered unknown, never deny).
- Archived spaces and anything an app enforces on top of Confluence's permissions.

## Unverified

- The operation keys and target types the v2 space permissions API uses for `space.export`
  (`export`/`space`), `page.restrict` (`restrict_content`/`space`) and `space.admin`
  (`administer`/`space`). A different key would make those actions deny for everyone; compare
  against a live site's `GET /wiki/api/v2/spaces/{id}/permissions` before relying on them.
- The shape of `_links.next` in the two paginated calls. hallpass accepts a v1 link relative to
  `{url}/wiki`, a v2 link relative to the site and an absolute URL, and normalises all three to the
  connection's base.
- The auth-mode behaviours listed as unverified in the jira integration apply here as well.

## Test

Unit tests run against one fake Atlassian site that serves both Jira's user search and Confluence's
content, space and group APIs (`internal/integrations/confluence/confluence_test.go`). They wire a real
jira connection as `identity_connection`, and cover content checks, space evaluation through user and
group principals with pagination, unknown principal types, the missing-identity case, every action,
the injected failure modes and the probe. No live-site test exists yet.
