# github

hallpass authenticates as a GitHub App installed in one organization, maps the user's email to a
GitHub login (through the organization's SAML identities, a login template or a mapping file), and
asks the REST API for that login's effective permission: the collaborator permission endpoint for
repositories (the highest of direct, team, organization and enterprise grants, as GitHub computes
it), the membership endpoints for organizations and teams. For `@branch` questions it also reads the
branch's ruleset rules and its classic branch protection. Nothing is written and no user token is
ever used.

## Credential

Create a GitHub App (organization settings, Developer settings, GitHub Apps), install it in the
organization, and give it these permissions, all **read**:

| Permission | Why |
|---|---|
| Repository: Metadata (read) | collaborator permission, repository settings, rules |
| Organization: Members (read) | organization and team memberships, SAML external identities |
| Repository: Administration (read) | `@branch` questions: branch rules and classic branch protection; without it they are unknown |

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
    # email_domains: acme.com,acme.io     # template mode, required
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
| `email_domains` | template mode, required: comma-separated domains the template applies to (each lowercase `[a-z0-9.-]`). An email from any other domain is unknown (`unsupported`), so `root@attacker.example` never renders to the login `root` |
| `user_map_file` | lines of `email login` or `email=login`, `#` comments; must exist at startup; re-read at most every 60 s (a broken rewrite keeps the previous map) |

### Identity

- **saml**: one GraphQL query filters `externalIdentities` by `userName`. GitHub's filter is not
  trusted: only returned identities whose `samlIdentity.nameId`, `samlIdentity.username` or
  `scimIdentity.username` equals the email (case-insensitively) count. One such identity with a
  linked GitHub user is the login; several linked to different accounts is `user_ambiguous`. If no
  returned identity carries the email (some identity providers only send the address as the SAML
  `nameId`), hallpass lists every external identity (100 per page, at most 50 pages or 5,000
  identities), builds an address-to-login map from the three fields above, caches it for 10 minutes
  and looks the email up case-insensitively. An address that appears on identities linked to
  different accounts is recorded as a conflict and answers `user_ambiguous`. When the listing
  stopped at a cap, the map is partial: a miss is then unknown (`unsupported`, "identity list
  truncated"), not `user_not_found`. An identity whose user is null (the person has not linked their
  SAML identity to a GitHub account) is unknown (`unsupported`), not a deny. An organization without
  a SAML identity provider is unknown (`unsupported`) with a message pointing at the other modes.
  `/search/users` is never used.
- **template**: the email's domain must be listed in `email_domains`, otherwise the answer is
  unknown (`unsupported`) and nothing is looked up. `GET /users/{login}` then confirms the rendered
  login exists and is a user, not an organization.
- **map_file**: no upstream call for the identity.

## Resources

| Resource | Meaning |
|---|---|
| `repo:<owner>/<name>[@branch]` | a repository; `@branch` adds the branch's rules and protection to `repo.push` and `pr.merge` |
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
| `repo.push` | `push`; with `@branch`, the branch's rules and protection are read (see below) |
| `repo.maintain` | `maintain` |
| `repo.admin` | `admin` |
| `issue.create` | `pull` and the repository's `has_issues` is true |
| `pr.create` | `pull`. With `push` the branch can live in the repository. Without `push` the pull request must come from a fork, so the repository's `allow_forking` is read: `false` is a deny ("forking disabled; pull request needs push access"), absent is unknown, `true` allows "via fork" and quotes the repository's `visibility` |
| `pr.merge` | `push`; with `@branch`, the branch's rules and protection are read (see below) |
| `org.member` | organization membership with state `active` |
| `org.admin` | membership role `admin` (owner) |
| `org.repo.create` | owner; or member when the organization's `members_can_create_repositories` is true |
| `team.member` | team membership with state `active` |
| `team.maintainer` | team membership role `maintainer` |

Permissions come from `user.permissions` (`pull`, `triage`, `push`, `maintain`, `admin`) of
`GET /repos/{owner}/{repo}/collaborators/{login}/permission`; `role_name` is quoted in the reason.
When the response carries only the top-level `permission` string it is expanded (`admin` >
`maintain` > `write` > `triage` > `read`). A `role_name` that is not one of `read`, `triage`,
`write`, `maintain`, `admin` (or `none`) is a custom repository role: when the booleans grant the
level the answer is allow as usual; when they do not, the answer is unknown (`unsupported`, "custom
repository role; extra abilities not modeled") rather than a deny, since a custom role may carry
abilities the five booleans do not show. A lossy record whose `permission` string is not a base
role is unknown too.

### Branch rules and protection

For `repo.push` and `pr.merge` on `repo:<owner>/<name>@<branch>`, after the permission allows,
hallpass reads two records and never reads either for a deny:

1. `GET /repos/{owner}/{repo}/rules/branches/{branch}`, the ruleset rules that apply. The endpoint
   answers `200 []` for a branch without rules, so a 404 means the repository or branch is not
   visible: unknown (`resource_not_visible`). A 403 means the App lacks Repository Administration:
   read: unknown (`unsupported`, "branch rules not readable; grant Repository Administration: read").
2. `GET /repos/{owner}/{repo}/branches/{branch}/protection`, the classic branch protection. 404 is
   "not protected"; 403 is unknown (`unsupported`) as above.

Then, in this order:

- **Push restrictions** (classic `restrictions`, "Restrict who can push to matching branches"): the
  login must appear in `restrictions.users[].login` or be an `active` member of a team in
  `restrictions.teams[].slug` (`GET /orgs/{org}/teams/{slug}/memberships/{login}`; child-team
  members are included by GitHub). Apps are skipped. Not listed is a **deny** for `repo.push`
  ("branch restricts pushes to listed users, teams and apps") and unknown for `pr.merge` (see
  Unverified). A team that cannot be checked (403, an unparseable slug, a membership without a
  state) is unknown, never a deny. Repository admins are exempt unless `enforce_admins.enabled` is
  true; for an admin on a protected branch without an `enforce_admins` object the answer is unknown.
- **Rules that route changes through pull requests**: for `repo.push`, a `pull_request`, `update`
  or `merge_queue` rule turns the allow into unknown (`unsupported`, "direct push not allowed by
  rules"), because only bypass actors may push directly and bypass lists are not evaluated.
  `creation` and `deletion` rules do not affect a push to an existing branch. `pr.merge` is not
  affected.
- **Required reviews** (classic `required_pull_request_reviews`): for `repo.push`, unknown
  (`unsupported`, "requires pull request reviews"), unless the login is an exempt admin. `pr.merge`
  is not affected.
- Otherwise the allow stands and the reason lists the rule types ("branch b has N rules (types ...):
  a direct push may still be rejected") and whether classic protection applies.

## Decisions

| Situation | Answer |
|---|---|
| the login's permissions include the level, membership matches | allow |
| permissions do not include the level (including role `none`) | deny |
| permissions do not include the level and `role_name` is a custom role | unknown (`unsupported`) |
| `issue.create` and issues are disabled | deny |
| `pr.create` without `push` and `allow_forking` is false | deny |
| `pr.create` without `push` and `allow_forking` is absent | unknown (`unsupported`) |
| `@branch` push restrictions exclude the login (`repo.push`) | deny |
| `@branch` rule `pull_request`/`update`/`merge_queue`, or required reviews (`repo.push`) | unknown (`unsupported`) |
| rules or protection endpoint 403 | unknown (`unsupported`) |
| rules endpoint 404 | unknown (`resource_not_visible`) |
| organization membership 404, or state `pending` | deny |
| organization or team membership without a `state` | unknown (`unsupported`) |
| team membership 404 and the team exists | deny |
| team 404 as well | unknown (`resource_not_visible`) |
| collaborator permission 404 | unknown (`resource_not_visible`): the repository is not visible to the App, or the login is not a collaborator on a private repository |
| `members_can_create_repositories` absent | unknown (`unsupported`) |
| `has_issues` absent | unknown (`unsupported`) |
| SAML identity unlinked, or no SAML provider | unknown (`unsupported`) |
| SAML address on identities linked to different accounts | deny (`user_ambiguous`) |
| no SAML identity in a truncated listing | unknown (`unsupported`) |
| template mode, email domain not in `email_domains` | unknown (`unsupported`) |
| no SAML identity in a complete listing, no `/users/{login}`, no map entry | deny (`user_not_found`) |
| 401, or 403 without an exhausted rate limit; GraphQL `FORBIDDEN` / `INSUFFICIENT_SCOPES`; App not installed | unknown (`credential_rejected`) |
| 403 with `X-RateLimit-Remaining: 0` or `Retry-After`, 429, GraphQL `RATE_LIMITED` | unknown (`upstream_rate_limited`) |
| other GraphQL errors, 5xx, transport | unknown (`upstream_error`); timeouts `upstream_timeout` |

Rate limit: 5,000 requests per hour per installation. A check costs one to four calls after the
token is cached (identity, permission, repository metadata where needed, and for `@branch` the rules
and protection records plus one team membership call per restricted team).

## Probe

`GET /app` and `GET /orgs/{org}/installation` with the App JWT. The summary is
"app <slug> installed in <org>". Warnings: `metadata` or `members` missing from the installation's
permissions; any permission with value `write` or `admin` (over-privileged); `installation_id` not
matching what GitHub reports; in `saml` mode, an organization without a SAML identity provider.

## What it cannot see

- Ruleset bypass actors, who may review, CODEOWNERS, status checks, signatures and the other
  classic protection settings: an allowed push or merge may still be rejected. Of classic
  protection only push restrictions, required reviews and `enforce_admins` are evaluated.
- Enterprise-level SAML and Enterprise Managed Users: their external identities are not reachable
  with an organization installation token (see Unverified).
- The abilities of a custom repository role beyond the five permission booleans: a custom role that
  lacks the level is unknown rather than denied.
- Whether a private or internal repository may be forked by this particular login when
  `allow_forking` is true: `allow_forking` is taken as the effective answer.
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
- Ruleset bypass actors: a `pull_request`, `update` or `merge_queue` rule downgrades `repo.push` to
  unknown even for a login the ruleset lets bypass it.
- Classic protection field shapes: `restrictions.users[].login`, `restrictions.teams[].slug`,
  `required_pull_request_reviews` (present means required) and `enforce_admins.enabled` are read
  as GitHub's OpenAPI description declares them; the tests use that description but no live
  response was captured.
- Classic push restrictions are assumed not to apply to repository admins unless
  `enforce_admins.enabled` is true ("Do not allow bypassing the above settings"); an admin on a
  protected branch whose record lacks `enforce_admins` is unknown.
- Whether a classic push restriction also blocks merging a pull request into the branch:
  `pr.merge` for a login outside the restriction is unknown, not a deny.
- `allow_forking` on a private or internal repository is assumed to reflect the organization's
  "members can fork private repositories" policy.
- Enterprise-level SAML / Enterprise Managed Users: `organization.samlIdentityProvider` is expected to
  be null there, so `identity_mode: saml` reports "no SAML identity provider"; use `template` or
  `map_file`.
- Branch names containing `/` are sent path-escaped (`feature%2Fx`) to the rules and protection
  endpoints.

## Test

`go test ./internal/integrations/github/` runs against a fake GitHub (REST and GraphQL) that
verifies the App JWT signature and claims with the test key, hands out installation tokens, and
serves the repository, permission, membership, rules, branch protection and SAML identity endpoints.
With `HALLPASS_SPECS_DIR` set (see `test/specs/fetch.sh`) every REST request is validated against
GitHub's OpenAPI description. Against a real organization: install the App, configure a connection,
run `hallpass probe` and one check for a user you know has `push` on some repository, then one for
`repo.push` on `repo:<org>/<name>@<protected branch>` to confirm the protection record shapes.
