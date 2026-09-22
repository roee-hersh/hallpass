# slack

hallpass reads the Slack Web API with a bot token and answers from what it finds: the user object
(`users.lookupByEmail`: deactivated, bot, guest, admin, owner), the channel object
(`conversations.info`: private, archived, general, posting restriction), the user's channel
membership (`users.conversations`, falling back to `conversations.members` for users in very many
channels), who may post in `#general` (`team.preferences.list`) and user group membership
(`usergroups.list`). Slack has no "can user X do Y" method, so hallpass applies Slack's documented
rules to those facts. Every call is a read; nothing is posted, joined or changed.

## Credential

Create an internal Slack app (api.slack.com/apps, "from scratch"), add the bot token scopes below,
install it to the workspace and use the **Bot User OAuth Token** (`xoxb-...`). hallpass refuses any
token that does not start with `xoxb-` (user tokens would run checks as a person).

| Scope | Needed for |
|---|---|
| `users:read` | `auth.test`, user objects |
| `users:read.email` | `users.lookupByEmail` (every check) |
| `channels:read` | public channel info and membership |
| `groups:read` | private channel info and membership |
| `team.preferences:read` | optional: `message.post` in `#general` |
| `usergroups:read` | optional: `usergroup.member` |

No write scope. `hallpass probe` warns if the token carries one.

The bot sees a private channel only when it is a member of it. Invite the bot (`/invite @hallpass`)
to the private channels you want to check; until then those channels answer unknown.

Rate limits are per method and tier (roughly 20, 50 or 100+ calls per minute for the tiers used
here). On HTTP 429 or `ratelimited` hallpass retries once after `Retry-After` and then answers
unknown (`upstream_rate_limited`).

## Connection

```yaml
  - id: slack-acme
    integration: slack
    credential: env:SLACK_BOT_TOKEN          # xoxb-...
    url: https://slack.com/api               # default
    team_id: T0123456789                     # only for Enterprise Grid org-level installs
    assume_default_prefs: "false"            # default
```

| Key | Meaning |
|---|---|
| `credential` | bot token, `env:` or `file:` |
| `url` | Web API base URL; change only for a proxy |
| `team_id` | workspace to address when the app is installed at the Enterprise Grid org level; sent as `team_id` on every call |
| `assume_default_prefs` | `true`: a workspace preference the bot cannot read (`who_can_post_general` without the scope or field, and "who can create / invite / archive / rename" which no bot token can read) is taken to be Slack's default, "everyone". `false`: those cases answer unknown |

## Resources

| Resource | Meaning |
|---|---|
| `workspace` | the workspace itself (no id) |
| `channel:<id>` | a channel by id, `C...` (public, or private created recently) or `G...` (older private channel) |
| `usergroup:<id>` | a user group by id, `S...` |

Ids only, never names: `channel:C0123456789`.

## Actions

| Action | Resource | Answer |
|---|---|---|
| `user.active` | `workspace` | allow unless deactivated, a bot, or invited and not yet joined |
| `workspace.admin` | `workspace` | allow for `is_admin` / `is_owner` / `is_primary_owner` |
| `org.admin` | `workspace` | allow for `enterprise_user.is_admin` / `is_owner`; unknown outside Enterprise Grid |
| `channel.read` | `channel` | public: allow for full members, guests only when a member; private: allow iff member; archived channels stay readable |
| `channel.join` | `channel` | public and not archived: allow for full members, guests only when already a member; private: allow only when already a member; archived: deny |
| `message.post` | `channel` | deny when archived or not a member; in `#general` apply `who_can_post_general`; apply `posting_restricted_to` unless the user is an admin; else allow |
| `message.post_thread` | `channel` | as `message.post`, but `posting_restricted_to` does not block replies (allow with a caveat in the text) |
| `file.upload` | `channel` | as `message.post` |
| `usergroup.member` | `usergroup` | allow iff the user id is in the group's `users` |
| `channel.invite` | `channel` | deny for guests, allow for admins and owners, unknown for full members (see below); deny when archived |
| `channel.create` | `workspace` | deny for guests, allow for admins and owners, unknown for full members |
| `channel.archive` | `channel` | as above; deny when already archived or the channel is `#general` |
| `channel.rename` | `channel` | as above; deny when archived |

Deactivated, bot and invited-but-not-joined accounts are denied every action.

## Decisions

| Slack says | hallpass answers |
|---|---|
| `users_not_found` | deny (`user_not_found`) |
| user `deleted`, `is_bot` (or `USLACKBOT`), `is_invited_user` | deny |
| user `is_stranger` (Slack Connect external) on a channel action | unknown (`unsupported`) |
| `channel_not_found` | unknown (`resource_not_visible`): no such channel, or a private channel the bot is not in; invite the bot |
| `not_in_channel` | unknown (`resource_not_visible`): invite the bot |
| user group id not listed | unknown (`resource_not_visible`): unknown or disabled group |
| `invalid_auth`, `not_authed`, `account_inactive`, `token_revoked`, `token_expired`, HTTP 401 | unknown (`credential_rejected`) |
| `missing_scope` | unknown (`credential_rejected`), naming the scope from `needed` |
| token does not start with `xoxb-` | unknown (`credential_rejected`), no call is made |
| `ratelimited` or HTTP 429 after one retry | unknown (`upstream_rate_limited`) |
| any other `ok: false` error, 5xx, timeout | unknown (`upstream_error` / `upstream_timeout`) |
| workspace preference not readable by a bot token (`channel.create/invite/archive/rename` for a full member) | unknown (`unsupported`), or allow with `assume_default_prefs: true` |
| `who_can_post_general` absent or in an unrecognised shape | unknown (`unsupported`), or allow with `assume_default_prefs: true` when absent |
| user in more channels than 5 pages of `users.conversations` | membership read from `conversations.members` instead (up to 50 pages, then `unsupported`) |

Membership checks are skipped when they cannot change the answer (a full member reading or joining a
public channel).

## What it cannot see

- The workspace preferences "who can create channels", "who can invite", "who can archive", "who can
  rename" and "who can use @channel / @here". No bot token reads them; full members answer unknown
  for those actions unless `assume_default_prefs` is set.
- Private channels the bot is not in. They look identical to non-existent channels
  (`channel_not_found`) and answer `resource_not_visible`.
- Slack Connect: external users (`is_stranger`) and what a shared channel's other workspace allows.
- Enterprise Grid: only the org-level `enterprise_user.is_admin` / `is_owner` is read. The
  per-workspace `is_admin` on a Grid user object is the value for the workspace addressed by
  `team_id`, which is not verified.
- Huddles, canvases, lists, DMs and group DMs (`D...` ids are rejected), message editing and deletion,
  channel-level "who can post" set through Slack's admin tools other than `posting_restricted_to`.
- Guest expiry dates, channel-specific guest restrictions beyond membership.

## Unverified

Marked `// UNVERIFIED:` in the code; behaviour is implemented as described and should be confirmed
against a real workspace.

- `enterprise_user.is_admin` and `enterprise_user.is_owner` are the field names for org roles on
  Enterprise Grid user objects.
- The shape of `who_can_post_general` in `team.preferences.list`. Read as `{"type":["admin"|"owner"],
  "user":["U..."]}`; a string form is accepted too, with `everyone`, `regular` and `ra` meaning
  everyone, `admin` meaning admins and owners, `owner` meaning owners, and anything else unknown.
- Whether `conversations.info` exposes `properties.posting_restricted_to` to a bot token. When it is
  absent the channel is treated as unrestricted and the decision text says "no posting restriction
  is visible to the bot".
- `posting_restricted_to` limits top-level posts only: `message.post_thread` allows with a caveat when
  the user is not among the posters.
- Slack's default for the "who can create / invite / archive / rename channels" preferences is
  "everyone", which is what `assume_default_prefs: true` assumes.
- Whether Slack sends an `X-OAuth-Scopes` header on Web API responses. The probe reads it when present
  and says nothing when absent.

## Test

Unit tests run against a fake Web API in `internal/integrations/slack/slack_test.go` with fixture
users (full member, admin, owner, two guest kinds, deactivated, bot, invited, external, two Grid
users) and channels (public, `#general` with a posting rule, a channel with `posting_restricted_to`,
archived, private with the bot, private without the bot). Against a real workspace:

```sh
hallpass probe -config hallpass.yaml -connection slack-acme
curl -X POST localhost:8080/check -H "Authorization: Bearer $HALLPASS_API_KEY" -H 'Content-Type: application/json' \
  -d '{"user":"you@acme.com","connection":"slack-acme","action":"message.post","resource":"channel:C0123456789"}'
```

The probe reports the bot user and workspace from `auth.test`, confirms `users:read.email` with a
lookup that cannot match, and warns about missing optional scopes and any write scope.
