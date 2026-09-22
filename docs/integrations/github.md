# github

hallpass authenticates as a GitHub App installed in one organization, maps the user's email to a
GitHub login (through the organization's SAML identities, a login template or a mapping file), and
asks the REST API for that login's effective permission: the collaborator permission endpoint for
repositories (the highest of direct, team, organization and enterprise grants, as GitHub computes
it), the membership endpoints for organizations and teams. For `@branch` questions it also reads the
branch's rules. Nothing is written and no user token is ever used.

## Credential

Create a GitHub App (organization settings, Developer settings, GitHub Apps), install it in the
organization, and give it these permissions, all **read**:

| Permission | Why |
|---|---|
| Repository: Metadata (read) | collaborator permission, repository settings, rules |
| Organization: Members (read) | organization and team memberships, SAML external identities |
| Repository: Administration (read), optional | branch rules on repositories with rulesets that hide their rules from read-only apps |

Generate a private key for the App and store the PEM in a file or environment variable. The App's
client id (`Iv1...` / `Iv23...`) is the preferred `app_id`; the numeric App id also works. The
installation id is discovered from `GET /orgs/{org}/installation` unless you set it.

The App's JWT is signed RS256 with `iat` 60 s in the past and `exp` 9 minutes ahead; the
installation token it buys lasts one hour and is cached and refreshed five minutes before expiry. A
401 from the API drops the token and retries the call once with a fresh one.

## Connection

```yaml
  - id: github-acme
    integration: github
    organization: acme
    app_id: Iv1.0123456789abcdef
    credential: file:/secrets/github-app.pem
    # url: https://github.example.com     # GitHub Enterprise Server only
    # installation_id: "12345678"         # optional, discovered when omitted
    # identity_mode: saml                 # saml (default), template or map_file
    # login_template: "{local}"           # template mode
    # user_map_file: /etc/hallpass/github-users.txt   # map_file mode
```

| Key | Meaning |
|---|---|
| `url` | GitHub Enterprise Server base URL; REST is then `{url}/api/v3` and GraphQL `{url}/api/graphql`. Omit for github.com |
| `organization` | the organization the App is installed in. Every resource must belong to it: the installation is per organization |
| `app_id` | the App's client id (preferred) or numeric App id; the JWT issuer |
| `installation_id` | numeric installation id; discovered when omitted |
| `credential` | the App private key PEM (PKCS#1 or PKCS#8), `env:` or `file:` |
| `identity_mode` | `saml`: look the email up in the organization's SAML external identities. `template`: render `login_template` and verify the login exists. `map_file`: look the email up in `user_map_file` |
| `login_template` | placeholders `{email}`, `{local}`, `{domain}`; must contain `{email}` or `{local}` |
| `user_map_file` | lines of `email login` or `email=login`, `#` comments; must exist at startup; re-read at most every 60 s (a broken rewrite keeps the previous map) |

### Identity

- **saml**: one GraphQL query filters `externalIdentities` by `userName`. A hit with a linked
  GitHub user is the login. If nothing matches by `userName` (some identity providers only send the
  address as the SAML `nameId`), hallpass lists every external identity (100 per page, at most 50
  pages or 5,000 identities), builds an address-to-login map from `samlIdentity.nameId`,
  `samlIdentity.username` and `scimIdentity.username`, caches it for 10 minutes and looks the email
  up case-insensitively. An identity whose user is null (the person has not linked their SAML
  identity to a GitHub account) is unknown (`unsupported`), not a deny. An organization without a
  SAML identity provider is unknown (`unsupported`) with a message pointing at the other modes.
  `/search/users` is never used.
- **template**: `GET /users/{login}` confirms the rendered login exists and is a user, not an
  organization.
- **map_file**: no upstream call for the identity.

## Resources

| Resource | Meaning |
|---|---|
| `repo:<owner>/<name>[@branch]` | a repository; `@branch` adds the branch's rules to `repo.push` and `pr.merge` |
| `org:<login>` | the organization |
| `team:<org>/<slug>` | a team, by slug |

The owner or organization must equal `organization` (case-insensitive); anything else is
`invalid_request`. Owner and login names must match GitHub's rules (alphanumerics and single
hyphens, at most 39 characters), repository names may also contain `.` and `_`, team slugs are
lowercase. Branch names may not contain `..`, spaces, control characters, `\ ~ ^ : ? * [ @`, or start
with `-`. Everything is path-escaped before it goes into a URL.

## Actions

| Action | What GitHub is asked |
|---|---|
| `repo.read` | permissions include `pull` |
| `repo.triage` | `triage` |
| `repo.push` | `push`; with `@branch`, the branch's rules are read (see below) |
| `repo.maintain` | `maintain` |
| `repo.admin` | `admin` |
| `issue.create` | `pull` and the repository's `has_issues` is true |
| `pr.create` | `pull`. Without `push` the allow says "via fork; pushing a branch to the repository itself needs push" |
| `pr.merge` | `push`; with `@branch`, the branch's rules are appended to the reason |
| `org.member` | organization membership with state `active` |
| `org.admin` | membership role `admin` (owner) |
| `org.repo.create` | owner; or member when the organization's `members_can_create_repositories` is true |
| `team.member` | team membership with state `active` |
| `team.maintainer` | team membership role `maintainer` |

Permissions come from `user.permissions` (`pull`, `triage`, `push`, `maintain`, `admin`) of
`GET /repos/{owner}/{repo}/collaborators/{login}/permission`; `role_name` (a custom role's name where
one applies) is quoted in the reason. When the response carries only the top-level `permission`
string it is expanded (`admin` > `maintain` > `write` > `triage` > `read`).

### Branch rules

For `repo.push` and `pr.merge` on `repo:<owner>/<name>@<branch>`, after an allow hallpass reads
`GET /repos/{owner}/{repo}/rules/branches/{branch}` and appends "branch b has N rules (types ...): a
direct push may still be rejected". If a `pull_request` rule applies and the action is `repo.push`,
the allow becomes unknown (`unsupported`, "branch requires pull requests; direct push not allowed by
rules"). A 403 or 404 on the rules endpoint keeps the allow and says the rules could not be read. A
deny never reads rules.

## Decisions

| Situation | Answer |
|---|---|
| the login's permissions include the level, membership matches | allow |
| permissions do not include the level (including role `none`) | deny |
| `issue.create` and issues are disabled | deny |
| organization membership 404, or state `pending` | deny |
| team membership 404 and the team exists | deny |
| team 404 as well | unknown (`resource_not_visible`) |
| collaborator permission 404 | unknown (`resource_not_visible`): the repository is not visible to the App, or the login is not a collaborator on a private repository |
| `members_can_create_repositories` absent | unknown (`unsupported`) |
| `has_issues` absent | unknown (`unsupported`) |
| SAML identity unlinked, or no SAML provider | unknown (`unsupported`) |
| no SAML identity, no `/users/{login}`, no map entry | deny (`user_not_found`) |
| 401, or 403 without an exhausted rate limit; GraphQL `FORBIDDEN` / `INSUFFICIENT_SCOPES`; App not installed | unknown (`credential_rejected`) |
| 403 with `X-RateLimit-Remaining: 0` or `Retry-After`, 429, GraphQL `RATE_LIMITED` | unknown (`upstream_rate_limited`) |
| other GraphQL errors, 5xx, transport | unknown (`upstream_error`); timeouts `upstream_timeout` |

Rate limit: 5,000 requests per hour per installation. A check costs one to three calls after the
token is cached (identity, permission, and rules or repository metadata where needed).

## Probe

`GET /app` and `GET /orgs/{org}/installation` with the App JWT. The summary is
"app <slug> installed in <org>". Warnings: `metadata` or `members` missing from the installation's
permissions; any permission with value `write` or `admin` (over-privileged); `installation_id` not
matching what GitHub reports; in `saml` mode, an organization without a SAML identity provider.

## What it cannot see

- Ruleset bypass actors, branch protection rules (the classic kind, not rulesets), required
  reviewers, CODEOWNERS and status checks: an allowed push or merge may still be rejected.
- Enterprise-level SAML and Enterprise Managed Users: their external identities are not reachable
  with an organization installation token (see Unverified).
- Repository-level custom roles are reported by name in `role_name`; hallpass only evaluates the
  five permission booleans behind them.
- Outside collaborators are collaborators: `repo.*` answers for them, `org.member` denies.
- Whether a login may create a repository of a particular visibility: the allow lists the
  visibilities the organization permits when GitHub reports them.

## Unverified

Each item is marked `// UNVERIFIED:` in the code.

- Whether an installation token sees `members_can_create_repositories` and the per-visibility
  fields on `GET /orgs/{org}`; when they are absent `org.repo.create` for a non-owner is unknown.
- Whether a non-collaborator on a public repository gets `pull: true` from the collaborator
  permission endpoint; if GitHub answers 404 instead, `repo.read` on public repositories is unknown
  (`resource_not_visible`) for outsiders.
- Which of 403/404 GitHub returns from the rules endpoint when the App lacks Administration: read;
  both are treated as "could not be read".
- Ruleset bypass actors: a `pull_request` rule downgrades `repo.push` to unknown even for a login the
  ruleset lets bypass it.
- Enterprise-level SAML / Enterprise Managed Users: `organization.samlIdentityProvider` is expected to
  be null there, so `identity_mode: saml` reports "no SAML identity provider"; use `template` or
  `map_file`.
- Branch names containing `/` are sent path-escaped (`feature%2Fx`) to the rules endpoint.

## Test

`go test ./internal/integrations/github/` runs against a fake GitHub (REST and GraphQL) that
verifies the App JWT signature and claims with the test key, hands out installation tokens, and
serves the permission, membership, rules and SAML identity endpoints. Against a real organization:
install the App, configure a connection, run `hallpass probe` and one check for a user you know has
`push` on some repository.
