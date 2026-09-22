# gitlab

hallpass resolves the email to a GitLab account, reads the account's effective membership of the
project or group (`GET /projects/:id/members/all/:user_id`, which includes inherited and invited-group
members) and maps the access level to the asked action with an exact set of levels per action. For
`repo.push` and `mr.merge` on a named branch (`project:acme/webapp@main`) it also reads the project's
protected-branch rules and evaluates the "allowed to push/merge" entries. Non-members are evaluated
against the project's visibility. Every call is a read with hallpass's own token; nothing is written.

## Credential

A personal access token with the `read_api` scope, sent in the `PRIVATE-TOKEN` header.

- **Self-managed**: an administrator's token. Only administrators can search users by private email
  (`identity_mode: admin_search`) and see `is_admin`, which the "Admins" protected-branch entry needs.
- **GitLab.com**: an Owner of the top-level group, for the enterprise-user (`enterprise_users`) and SAML
  identity (`saml`) APIs. The token's user must be able to see the projects being asked about.

Prefer a dedicated account. `hallpass probe` warns when the token is not an administrator's in
`admin_search` mode, when it carries scopes broader than `read_api` (`api`, `write_repository`,
`sudo`, ...) and when it expires within 14 days.

Rate limits: GitLab.com allows 2,000 authenticated requests per minute and 300 requests per 10 minutes
to `/users/:id`. A 429 is retried (up to twice, honouring a short `Retry-After`) and otherwise
answers `upstream_rate_limited`. One check costs one identity call, one membership call and, for a
non-member or a branch check, one or two more.

## Connection

```yaml
  - id: gitlab-com
    integration: gitlab
    url: https://gitlab.com              # default; the API is used at {url}/api/v4
    credential: env:GITLAB_TOKEN
    identity_mode: enterprise_users      # admin_search (default), enterprise_users, saml, template
    group: acme                          # top-level group; required for enterprise_users and saml
    username_template: "{local}"         # template mode only; default {local}
```

| Key | Meaning |
|---|---|
| `url` | GitLab URL. Default `https://gitlab.com` |
| `credential` | personal access token, `env:` or `file:` |
| `identity_mode` | how the email becomes an account, see below |
| `group` | top-level group path for the group-scoped identity modes |
| `username_template` | for `template` mode: placeholders `{email}`, `{local}`, `{domain}`; must contain `{email}` or `{local}` |

### Identity modes

| Mode | Lookup | Needs |
|---|---|---|
| `admin_search` | `GET /users?search=<email>`; the `email` field (or `public_email` when the token cannot see private emails) must equal the email, ignoring case | an administrator's token; with a non-admin token results carry no email and every lookup answers `unsupported` |
| `enterprise_users` | `GET /groups/:group/enterprise_users?search=<email>`, same exact match | GitLab.com, 17.7+, token of a group Owner |
| `saml` | `GET /groups/:group/saml/identities` (all pages), `extern_uid` must equal the email ignoring case, then `GET /users/:id` | GitLab.com group SAML with the email as NameID |
| `template` | `GET /users?username=<username_template applied>` | nothing; a wrong template answers `user_not_found` for everyone |

Several matches answer `user_ambiguous`; none answer `user_not_found`. A resolved account that is not
`active` (blocked, deactivated, ldap_blocked, banned) or is a bot is denied every action.

## Resources

| Resource | Meaning |
|---|---|
| `project:<path-or-id>` | a project by full path (`acme/webapp`) or numeric id |
| `project:<path-or-id>@<branch>` | the same project, with a branch for `repo.push` and `mr.merge`; ignored by other actions |
| `group:<path-or-id>` | a group by full path or numeric id |

Paths must match `[A-Za-z0-9_.][A-Za-z0-9_.-]*` per segment with no `.`/`..` segments; branch names
may not contain spaces, control characters, `..`, `@{`, `~ ^ : ? * [ \`, or start with `-`.

## Actions

Access levels: 0 none, 5 Minimal, 10 Guest, 15 Planner, 20 Reporter, 25 Security Manager, 30
Developer, 40 Maintainer, 50 Owner. Planner and Security Manager are not cumulative, so each action
lists the exact set of levels that grants it.

| Action | Resource | Levels that allow | Non-members |
|---|---|---|---|
| `project.read` | project | 10, 15, 20, 25, 30, 40, 50 | allowed on public and internal projects |
| `issue.create` | project | 10, 15, 20, 25, 30, 40, 50 | allowed on internal projects |
| `issue.edit` | project | 15, 20, 25, 30, 40, 50 | |
| `mr.create` | project | 30, 40, 50 | |
| `mr.approve` | project | 30, 40, 50; 15 and 20 answer unknown (approval rules decide) | |
| `repo.push` | project[@branch] | 30, 40, 50 on unprotected branches; protected-branch rules otherwise | |
| `mr.merge` | project[@branch] | 30, 40, 50 on unprotected branches; protected-branch rules otherwise | |
| `branch.protect` | project | 40, 50 | |
| `project.admin` | project | 40, 50 | |
| `member.manage` | project | 40, 50 | |
| `project.delete` | project | 50 | |
| `pipeline.run` | project | 30, 40, 50 | |
| `variable.manage` | project | 40, 50 | |
| `runner.manage` | project | 40, 50 | |
| `group.member` | group | 10, 15, 20, 25, 30, 40, 50 | |
| `group.admin` | group | 50 | |
| `group.project.create` | group | 30, 40, 50 | |

### Protected branches

With `@branch`, `repo.push` and `mr.merge` read `GET /projects/:id/protected_branches` and match the
branch against every rule's `name`, where `*` matches any sequence of characters. If no rule matches,
the unprotected rule above applies. Otherwise the `push_access_levels` (or `merge_access_levels`)
entries of every matching rule are evaluated and the most permissive one wins:

| Entry | Allows the user when |
|---|---|
| `user_id` | it is the user |
| `group_id` | `GET /groups/:group_id/members/all/:user_id` answers 200 (404 means not through this entry; anything else leaves the entry unresolved and the answer unknown) |
| `member_role_id` | the user's membership has that custom role; otherwise the entry is unresolved |
| `access_level` 30 or 40 | the user's level is at least that (Developer or above) |
| `access_level` 60 (Admins) | the account is known to be an administrator; unknown administrator status answers unknown |
| `access_level` 0 (No one) | never; if every entry is "No one" the answer is deny for everyone |

## Decisions

| Situation | Answer |
|---|---|
| level in the action's set | allow |
| level not in the set, plain role | deny |
| level not in the set, membership has a custom role (`member_role`) | unknown (`unsupported`): custom roles add abilities hallpass cannot see |
| Planner or Reporter asking `mr.approve` | unknown (`unsupported`) |
| account not `active`, or a bot | deny |
| membership `state` not `active` (for example awaiting) | deny |
| not a member; project visibility grants the action to signed-in users | allow |
| not a member otherwise | deny |
| project or group answers 404 to the token | unknown (`resource_not_visible`) |
| no account for the email | deny (`user_not_found`) |
| several accounts | unknown (`user_ambiguous`) |
| `admin_search` with a token that cannot see emails | unknown (`unsupported`) |
| 401 | unknown (`credential_rejected`) |
| 403 on members, projects, groups, identity or protected-branch reads | unknown (`credential_rejected`): the token lacks the right |
| protected branch entries unresolved (group or custom-role entry, unknown admin status) | unknown (`unsupported`) |

## What it cannot see

- Abilities added by custom roles beyond their base level; a custom role answers unknown whenever the
  base level says no.
- Merge request approval rules, merge checks (pipeline must succeed, discussions resolved), push
  rules, CODEOWNERS approvals and locked files.
- Group IP allow-lists, SSO enforcement and 2FA requirements that block a member at request time.
- Per-feature access levels (`issues_access_level`, `merge_requests_access_level`, repository
  disabled): a Developer on a project whose repository feature is disabled still answers allow for
  `repo.push`.
- Instance administrators acting outside their memberships (admin mode); administrator status only
  matters for the "Admins" protected-branch entry.
- Deploy keys and deploy tokens, project access tokens (bots are denied), and external users.
- `group.project.create` does not read the group's "allowed to create projects" setting.

## Unverified

Marked `// UNVERIFIED:` in the code:

- `issue.edit` for Security Manager (25) is assumed allowed like Reporter.
- `group.project.create` assumes the default group setting (Developers and above may create projects).
- The minimum role required to list protected branches; a 403 answers `credential_rejected`.
- How GitLab combines several protected-branch rules that match one branch; hallpass pools every
  matching rule's entries and lets the most permissive win.
- A protected-branch entry with `member_role_id` is taken to match a member holding exactly that
  custom role; any other member leaves the entry unresolved (unknown).
- The probe's token check uses `GET /personal_access_tokens/self`; a 403 or 404 there becomes a
  "could not verify scopes" warning rather than an error.

## Test

Unit tests run against a fake GitLab API (`gitlab_test.go`) that models users, enterprise users, SAML
identities, projects, groups, memberships and protected branches, and answers only to the canary
token. No live fixtures. To try a real connection, configure it and run `hallpass probe`, then one
check for a user known to be a Developer on some project.
