# googleworkspace

hallpass authenticates as a service account with domain-wide delegation. Directory calls impersonate
one admin (`admin_email`) with read-only scopes to find the user and to answer group membership.
Drive, Calendar and Gmail calls impersonate **the user being asked about**, so Google itself
evaluates that user's access: a file's `capabilities`, a calendar's `accessRole`, the user's send-as
addresses. One access token is minted per (impersonated user, scope) and cached. hallpass never
performs an action and nothing is persisted.

## Credential

1. Create a service account and enable domain-wide delegation for it. **Domain-wide delegation is
   a broad grant**: the key can impersonate any user in the domain within the allowlisted scopes.
   Keep the key file tightly held, or use `auth_mode: keyless` on GCE/GKE so no key exists.
2. In the Admin console, allowlist the service account's client id with exactly these scopes:

   ```
   https://www.googleapis.com/auth/admin.directory.user.readonly
   https://www.googleapis.com/auth/admin.directory.group.member.readonly
   https://www.googleapis.com/auth/drive.metadata.readonly
   https://www.googleapis.com/auth/calendar.calendarlist.readonly
   ```

   and, only when `enable_gmail_settings: "true"`:

   ```
   https://www.googleapis.com/auth/gmail.settings.basic
   ```

   `gmail.settings.basic` has **no read-only variant**: it can also change users' basic Gmail
   settings. Leave `enable_gmail_settings` off unless `mail.send_as` or `mail.delegate_access` are
   needed; with it off both actions are unknown, for the user's own mailbox too.
3. Make `admin_email` an admin whose custom role has only **Users > Read** and **Groups > Read**.
   A super admin works but is far more than hallpass needs.
4. Enable the Admin SDK, Drive, Calendar and (optionally) Gmail APIs in the service account's
   project.

## Connection

```yaml
  - id: gws-example
    integration: googleworkspace
    credential: file:/secrets/gws-sa.json       # service-account key JSON (auth_mode key)
    admin_email: hallpass-admin@example.com
    customer_id: my_customer                   # optional
    auth_mode: key                             # or keyless
    service_account_email: hallpass@proj.iam.gserviceaccount.com   # keyless only
    enable_gmail_settings: "false"             # optional
```

| Key | Meaning |
|---|---|
| `credential` | service-account key JSON (`file:`); `client_email`, `private_key`, `private_key_id` and `token_uri` are read from it. Required in `auth_mode: key` |
| `admin_email` | the admin impersonated for Directory calls |
| `customer_id` | Workspace customer id, default `my_customer` |
| `auth_mode` | `key` (default) signs the assertion with the key; `keyless` signs with the IAM Credentials API using the GCE/GKE identity |
| `service_account_email` | the service account to sign as, `keyless` only |
| `enable_gmail_settings` | `true` enables the Gmail settings calls (write-capable scope) |
| `token_url` | default `https://oauth2.googleapis.com/token` |
| `api_url` | default `https://www.googleapis.com` |
| `metadata_url` | default `http://metadata.google.internal`, `keyless` only |
| `iamcredentials_url` | default `https://iamcredentials.googleapis.com`, `keyless` only |

Production leaves the four URLs at their defaults; they exist so tests can point at a fake. The
Directory API is addressed as `{api_url}/admin/directory/v1/...`; its canonical host is
`https://admin.googleapis.com` and whether `www.googleapis.com` also serves it is unverified (see
below). There is no separate key for the Admin SDK host.

In `key` mode every token is a JWT bearer exchange: RS256 with `kid` = `private_key_id`, `iss` =
`client_email`, one `scope`, `aud` = `token_url`, `sub` = the impersonated user, one hour lifetime.
In `keyless` mode hallpass reads the runtime identity's token from the metadata server and asks
`iamcredentials.googleapis.com` to `signJwt` the same claims; the runtime identity needs
`roles/iam.serviceAccountTokenCreator` on the service account. A 401 from an API invalidates that
token and retries once.

## Resources

| Resource | Meaning |
|---|---|
| `user:<email>` | the caller's own account |
| `file:<id>` | a Drive file or folder id |
| `calendar:<id>` | a calendar id (an email, a `...@group.calendar.google.com` id, or `primary`) |
| `mailbox:<email>` | a Gmail mailbox |
| `group:<email>` | a Google group |

The user is `GET admin/directory/v1/users/{email}` as the admin; aliases resolve to the primary
email, which becomes the identity and the `sub` for user-scoped calls. A suspended or archived
account is a deny for every action; a user record that lacks the `suspended` or `archived` field is
unknown (`unsupported`) for every action, never taken as active (the identity attribute reads
`unknown`). Consumer and external accounts cannot be impersonated and are `user_not_found`.

## Actions

| Action | Resource | How |
|---|---|---|
| `user.active` | `user:` | `suspended` and `archived` both present and false |
| `drive.file.read` | `file:` | `GET drive/v3/files/{id}` as the user answers 200 |
| `drive.file.download` / `edit` / `comment` / `share` / `trash` / `delete` / `rename` / `copy` | `file:` | `capabilities.canDownload` / `canEdit` / `canComment` / `canShare` / `canTrash` / `canDelete` / `canRename` / `canCopy` |
| `drive.folder.add_child` / `drive.folder.list` | `file:` | `capabilities.canAddChildren` / `canListChildren` |
| `calendar.read` | `calendar:` | calendarList `accessRole` at least `reader` |
| `calendar.event.write` | `calendar:` | at least `writerWithoutPrivateAccess` |
| `calendar.share` | `calendar:` | `owner` |
| `mail.send_as` | `mailbox:` | Gmail `settings/sendAs` **as the user** (needs `enable_gmail_settings`): the entry for the address has `verificationStatus: accepted`, or is the mailbox's own `isPrimary` entry |
| `mail.delegate_access` | `mailbox:` | Gmail `settings/delegates` read **as the mailbox owner** (needs `enable_gmail_settings`): the user's entry is `accepted`; for the user's own mailbox a 200 from the call made as the user is the allow |
| `group.member` | `group:` | `GET admin/directory/v1/groups/{group}/hasMember/{user}` as the admin (nested groups included) |

`calendar:primary` and the user's own email are `owner` without a call. The Gmail actions always
call Gmail as the account, so a user without a Gmail mailbox is never a false allow for their own
address.

## Decisions

| Situation | hallpass answers |
|---|---|
| capability true, role sufficient, member | allow |
| send-as entry `verificationStatus: accepted`, or the mailbox's own `isPrimary` entry; delegate `accepted` | allow |
| capability false, role too low, not a member | deny |
| send-as address missing from the list, or `pending` (awaiting verification by the owner) | deny |
| delegate missing, `pending`, `rejected` or `expired` | deny |
| send-as or delegate entry with `verificationStatusUnspecified` or no status (`treatAsAlias` and a shared domain do not count) | unknown (`unsupported`) |
| the user's own primary address missing from their send-as list | unknown (`unsupported`) |
| Drive answers 404 with reason `notFound` | deny: "no access, or the file does not exist: Drive does not distinguish" |
| Drive answers 404 with any other reason or none | unknown (`resource_not_visible`) |
| suspended / archived account | deny |
| user record without `suspended` or `archived` | unknown (`unsupported`) |
| no Workspace account for the email | deny (`user_not_found`) |
| a capability field is missing from the response | unknown (`unsupported`) |
| `hasMember` body without `isMember` | unknown (`unsupported`) |
| calendar not in the user's list | unknown (`unsupported`): an ACL may still grant access |
| `hasMember` answers 400 or 404 | unknown (`unsupported`): unknown or cross-domain group |
| Gmail feature off, for any mailbox including the user's own | unknown (`unsupported`) |
| Gmail answers 404, 400 `failedPrecondition`, or 403 other than `insufficientPermissions` / `accessNotConfigured` / a rate limit, as the account | unknown (`unsupported`): no Gmail mailbox or licence, or a policy |
| `invalid_grant` minting a token for the **user** | unknown (`unsupported`): could not act as the user |
| `invalid_grant` minting a token for the **admin** | unknown (`credential_rejected`): delegation is missing the scope or `admin_email` is invalid |
| Directory or Drive 403 `insufficientFilePermissions` / `domainPolicy` / `appNotAuthorizedToFile` / `cannotDownloadAbusiveFile` / shared-drive membership reasons / `failedPrecondition` / `storageQuotaExceeded` | unknown (`unsupported`): a policy blocked the metadata call for this user |
| 403 `forbidden` / `insufficientPermissions` / `accessNotConfigured`, 403 with any other or no reason, 401 after one retry | unknown (`credential_rejected`) |
| 403 `rateLimitExceeded` / `userRateLimitExceeded` / `quotaExceeded` / `dailyLimitExceeded` / `sharingRateLimitExceeded`, 429 | unknown (`upstream_rate_limited`) |
| 5xx, timeout | unknown (`upstream_error` / `upstream_timeout`) |

Google error messages are never copied into a decision text; only `errors[].reason` is used.

## Probe

`hallpass probe` mints the admin Directory token (which proves delegation for that scope), lists
one user with `customer={customer_id}`, then mints a token per remaining scope as `admin_email` and
warns, naming the scope, for each one the token endpoint refuses. It warns that
`enable_gmail_settings` grants a write-capable scope when on, and always reminds that domain-wide
delegation is a broad grant. The summary names the service account and the admin.

## What it cannot see

- **DLP and IRM** rules, **context-aware access** and **Drive trust rules** can block an action
  Drive's capabilities allowed.
- **Service enablement per organisational unit or licence**: a user without Drive or Gmail still
  resolves; their calls fail with an unknown rather than a deny.
- **External and consumer accounts** cannot be impersonated, so nothing can be checked for them.
- **Per-app restrictions** (API access controls that block the service account's client) surface as
  `credential_rejected`.
- **Calendar ACLs** for calendars the user has not added to their list.
- **Send-as aliases without a verification status** (Workspace domain aliases, `treatAsAlias`
  entries): Gmail does not say whether they are usable, so they are unknown.
- **Why Drive answered 404**: with reason `notFound` Drive does not distinguish "no access" from
  "does not exist", and hallpass answers deny for both.

## Unverified

Each item is marked `// UNVERIFIED:` in the code.

- The IAM Credentials `signJwt` request `{"payload": "<claims JSON>"}` and response
  `{"keyId", "signedJwt"}` shapes for `auth_mode: keyless`.
- Whether `writerWithoutPrivateAccess` allows creating and changing events; assumed yes for
  `calendar.event.write`.
- The Directory is assumed to send `suspended` and `archived` explicitly (false included) in the
  basic projection; if it omitted a false value every check would be unknown.
- The primary entry of `settings/sendAs` is assumed to come without a `verificationStatus` (the
  API says the field "only applies to custom from aliases"), which is why `isPrimary` is consulted
  for the user's own address.
- An account without a Gmail licence is assumed to answer `400 failedPrecondition` ("Mail service
  not enabled") to Gmail settings calls.
- A Gmail `403 forbidden`, or a 403 without a reason, on a call made as the user ("Delegation
  denied for <user>") is assumed to be about that account and is unknown (`unsupported`); only
  `insufficientPermissions` and `accessNotConfigured` are taken as hallpass's credential.
- Whether `www.googleapis.com` serves the Directory API at `/admin/directory/v1`; the canonical host
  is `admin.googleapis.com`. Production leaves `api_url` at its default.

## Test

Unit tests run against a fake token endpoint that verifies every assertion (RS256, `kid`, `iss`,
single scope, `aud`, `sub`, one-hour lifetime) and issues distinct tokens per (user, scope), plus
fakes of the Directory, Drive, Calendar and Gmail endpoints and of the metadata server and
`signJwt` for keyless mode. They cover token caching per pair, the 401 retry, `invalid_grant` for
users and for the admin, every action allow and deny, calendar roles, missing capabilities, a user
record without `suspended`/`archived`, a Drive 404 whose reason is not `notFound`, the 403 reason
split, every send-as and delegate verification status including an absent one, Gmail refusals for
the user's own mailbox, a `hasMember` body without `isMember`, the Gmail feature on and off, the
probe warnings and the injected failure modes. The test key JSON's `private_key_id` carries the
canary and the key pair is generated in the test.
