# bitbucket

One connection is one Bitbucket Cloud workspace (`edition: cloud`, the default) or one Bitbucket Data
Center instance (`edition: datacenter`). Both answer the same actions.

**Cloud**: hallpass finds the user among the workspace's members by email, reads the user's effective
repository permission (the highest of direct, group and project grants, as Bitbucket computes it),
the user's explicit project permission, whether the user is a workspace owner, and for `@branch`
questions the repository's branch restrictions. **Data Center**: hallpass finds the user by email,
lists the groups the user belongs to, and combines the direct, group, project, project-default,
public and global grants into the effective level itself, then the ref restrictions for `@branch`
questions. Every call is a read with hallpass's own token; nothing is written.

## Credential

### Cloud

A **workspace access token** (Premium) with the read `repository`, `project` and `account`
(workspace) scopes, sent as a bearer. Reading repository permissions and branch restrictions needs
admin on the repository (`repository:admin`), and reading explicit project permissions needs
`project:admin`; a workspace access token holds those for the whole workspace. Alternatively an
**Atlassian API token** of a workspace administrator with `auth_mode: basic` and `username` set to
the account's email. App passwords no longer work.

Filtering members by email, which is how the user is found, is allowed only for a workspace
administrator, an integration or a workspace access token.

### Data Center

An **HTTP access token** of a user with the global `ADMIN` permission, sent as a bearer. Listing
repository and project permissions needs `REPO_ADMIN` or `PROJECT_ADMIN` on each object, listing
global permissions needs `ADMIN`, and listing a user's groups needs `LICENSED_USER`; a global
administrator has them all. With a lesser token, objects and grants hallpass cannot read answer
`unknown`, never `deny`.

`hallpass probe` checks the token: on Cloud that it can look members up by email, on Data Center
that it authenticates and whether it can read global permissions.

## Connection

```yaml
  - id: bitbucket-acme
    integration: bitbucket
    workspace: acme                          # Cloud: every resource is in this workspace
    credential: env:BITBUCKET_TOKEN          # workspace access token
    # auth_mode: basic                       # Atlassian API token instead: username + credential
    # username: bot@acme.com

  - id: bitbucket-dc
    integration: bitbucket
    edition: datacenter
    url: https://bitbucket.acme.internal
    credential: env:BITBUCKET_DC_TOKEN       # HTTP access token of an administrator
```

| Key | Meaning |
|---|---|
| `edition` | `cloud` (default) or `datacenter` |
| `url` | Data Center base URL, required there; Cloud default `https://api.bitbucket.org` |
| `workspace` | Cloud only, required: the workspace slug |
| `auth_mode` | `bearer` (default): `Authorization: Bearer`; `basic`: HTTP Basic with `username` and the token |
| `username` | `auth_mode: basic`: the Atlassian account email the API token belongs to |
| `credential` | the token, `env:` or `file:` |

### Identity

Cloud: `GET /2.0/workspaces/{workspace}/members?q=user.email IN ("<email>")` with
`fields=values.user.email,values.user.account_id,...`. The address is lowercased and must be a plain
email (no quotes, so the filter cannot be broken out of); the member whose `email` equals it is the
user and the Atlassian `account_id` is the identity. No member is `user_not_found`, two are
`user_ambiguous`. A person with a Bitbucket account who is not in the workspace is `user_not_found`.

Data Center: `GET /rest/api/latest/users?filter=<email>`, every page; the filter is a substring match
on name and email, so only the record whose `emailAddress` equals the address counts. The user name
is the identity; `active: false` is denied every action. The user's groups come from
`GET /rest/api/latest/admin/users/more-members?context=<name>`; when that answers 403 the identity
still resolves, and any group grant that would change the answer makes it `unknown`.

Groups sent by the caller are ignored.

## Resources

| Resource | Cloud | Data Center |
|---|---|---|
| `repo:<slug>[@branch]` | a repository of the workspace | not accepted |
| `repo:<PROJECT>/<slug>[@branch]` | not accepted | a repository; `~user` keys are personal projects |
| `project:<key>` | a project of the workspace | a project |
| `workspace` | the workspace | the instance |

Slugs and keys are `[A-Za-z0-9][A-Za-z0-9._-]*` (or a Cloud `{uuid}`); a branch name follows git's
rules (no `..`, no leading `-`, no `?*[\^~:` or spaces). Everything is path-escaped before it
reaches a URL.

## Actions

| Action | Needs | Resource |
|---|---|---|
| `repo.read` | read | repo |
| `repo.push` | write; on `@branch`, no `push` restriction (Cloud) or `read-only` / `pull-request-only` restriction (Data Center) that stops the user | repo |
| `pr.merge` | write; on `@branch`, no `restrict_merges` restriction (Cloud) or `read-only` restriction (Data Center) that stops the user | repo |
| `repo.admin` | admin | repo |
| `project.read` / `project.write` / `project.admin` | read / write / admin on the project | project |
| `repo.create` | Cloud: `create-repo` (or admin); Data Center: project admin, see Unverified | project |
| `workspace.member` | Cloud: member of the workspace; Data Center: an active user | workspace |
| `workspace.admin` | Cloud: workspace owner; Data Center: global `ADMIN` or `SYS_ADMIN` | workspace |

### Cloud evaluation

- Repository: `GET /2.0/repositories/{ws}/{slug}` (404 is `resource_not_visible`), then
  `GET /2.0/workspaces/{ws}/permissions/repositories/{slug}?q=user.account_id="<id>"`, whose entries
  are effective permissions. A Bitbucket that rejects the filter (400) is read whole. No entry: a
  workspace owner has admin, a public repository grants read, otherwise none.
- Branch: `GET /2.0/repositories/{ws}/{slug}/branch-restrictions?kind=push|restrict_merges`. A
  restriction whose glob `pattern` matches the branch stops the user unless the user is in its
  `users`; a matching restriction that exempts `groups` is `unknown`, since Cloud exposes no group
  membership. `branching_model` restrictions and patterns with `[]{}` are `unknown`.
- Project: `GET .../projects/{key}/permissions-config/users/{account_id}` is the explicit
  permission. When it does not suffice, a public project grants read and a workspace owner is
  allowed; otherwise the project's group permissions are read and a group that would suffice makes
  the answer `unknown`.
- Workspace: `GET .../members/{account_id}` (404 is not a member); owners from
  `GET .../permissions?q=permission="owner"`.

### Data Center evaluation

- The level is the highest of: the user's direct grant and the grants of the user's groups on the
  repository (`.../repos/{slug}/permissions/users?filter=<name>` exact-matched, and
  `/permissions/groups`), the same on the project, the project's default permission
  (`.../permissions/PROJECT_READ|WRITE|ADMIN/all`), `public` on the repository or project (read),
  and the global permissions (`/rest/api/latest/admin/permissions/users|groups`, where `ADMIN` and
  `SYS_ADMIN` carry admin everywhere). Project levels carry to repositories.
- Branch: `GET /rest/branch-permissions/2.0/projects/{key}/repos/{slug}/restrictions` and the
  project's own `.../projects/{key}/restrictions`, which every repository inherits. `read-only`
  stops pushes and merges, `pull-request-only` stops direct pushes; `ANY_REF` matchers match every
  branch, `BRANCH` matchers compare the name, `PATTERN` matchers are globs; the listed `users` and
  `groups` are exempt. Branching-model matchers are `unknown`.

Globs are Ant-style: `*` and `?` stay within one path segment, `**` crosses segments, and
`refs/heads/` is stripped from a pattern. Bitbucket Cloud does not document whether its `*` crosses
`/`, and neither edition documents whether a pattern without `/` matches a branch of that name inside
a folder (`main` against `release/main`), so a pattern whose readings disagree for the branch asked
about answers `unknown` rather than guessing. Character classes and alternations are `unknown` on
both editions.

## Decisions

| Situation | hallpass answers |
|---|---|
| level held, and for `@branch` no restriction stops the user | allow, naming the source (direct, group, project, default, public, owner, global) |
| level not held | deny ("has read, needs write") |
| a restriction matches and the user is not exempt | deny, naming the restriction |
| a matching restriction exempts a group hallpass cannot resolve (Cloud always; Data Center without `LICENSED_USER`) | unknown (`unsupported`) |
| a `branching_model` restriction, a pattern with character classes, or on Cloud a pattern whose glob semantics are ambiguous for the branch, could apply | unknown (`unsupported`) |
| Cloud project: explicit permission insufficient, not an owner, a group grant would suffice | unknown (`unsupported`) |
| Data Center: level insufficient and a group or global grant hallpass could not read would matter | unknown (`unsupported`) |
| deactivated user (Data Center) | deny |
| no member / user with the email | deny (`user_not_found`) |
| repository or project answers 404 | unknown (`resource_not_visible`) |
| 401, 403 (the token lacks the permission the read needs; Data Center `workspace.admin` without `ADMIN`) | unknown (`credential_rejected`) |
| a next page outside the API base | unknown (`upstream_error`) |
| 429, 5xx, timeout | unknown (`upstream_rate_limited` / `upstream_error` / `upstream_timeout`) |

Error bodies are never copied into a decision text.

## What it cannot see

- Cloud group membership: the 2.0 API exposes none, so grants that come only through a group answer
  `unknown` (repository permissions are the exception: Bitbucket folds groups into the effective
  permission itself).
- Cloud project-level grants folded into a repository answer are trusted as Bitbucket reports them;
  hallpass does not recompute them.
- Branching-model branch types, merge checks other than who may merge (approvals, builds, tasks), and
  Data Center access keys as exemptions.
- Data Center: the `permission` filters of `/rest/api/latest/users`, personal repository visibility
  rules beyond `public`, and repository-level default permissions.

## Unverified

Marked `# UNVERIFIED:` in the code:

- Cloud: the filter grammar `q=user.account_id="..."` on the repository permissions list; the spec
  says the list "may be filtered by user" and documents only `permission>"read"`. A 400 falls back to
  reading the list whole, so a wrong grammar costs calls, not correctness.
- Cloud: whether `*` in a branch restriction pattern matches across `/`; both editions: whether a
  pattern without `/` matches inside folders. hallpass answers `unknown` whenever the readings differ
  for the branch asked about.
- Data Center: repository creation in a project is taken to need `PROJECT_ADMIN`. If Bitbucket lets
  `PROJECT_WRITE` create repositories, users with write are denied `repo.create` although they could.

## Test

Unit tests run against fakes of both editions: the Cloud fake validates every request against the
official description (`bitbucket-cloud` in `test/specs/fetch.sh`, with the undeclared `q`, `fields`
and paging parameters allowed) and serves members, permissions, branch restrictions and projects;
the Data Center fake serves users, groups, grant listings with substring filters, defaults, public
flags, restrictions and start/limit paging. There is no live test; after configuring, run
`hallpass probe` and one check for a user you know is allowed.
