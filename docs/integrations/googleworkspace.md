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
   settings. Leave `enable_gmail_settings` off unless `mail.send_as` for other addresses or
   `mail.delegate_access` are needed.
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
account is a deny for every action. Consumer and external accounts cannot be impersonated and are
`user_not_found`.

## Actions

| Action | Resource | How |
|---|---|---|
| `user.active` | `user:` | not suspended, not archived |
| `drive.file.read` | `file:` | `GET drive/v3/files/{id}` as the user answers 200 |
| `drive.file.download` / `edit` / `comment` / `share` / `trash` / `delete` / `rename` / `copy` | `file:` | `capabilities.canDownload` / `canEdit` / `canComment` / `canShare` / `canTrash` / `canDelete` / `canRename` / `canCopy` |
| `drive.folder.add_child` / `drive.folder.list` | `file:` | `capabilities.canAddChildren` / `canListChildren` |
| `calendar.read` | `calendar:` | calendarList `accessRole` at least `reader` |
| `calendar.event.write` | `calendar:` | at least `writerWithoutPrivateAccess` |
| `calendar.share` | `calendar:` | `owner` |
| `mail.send_as` | `mailbox:` | own mailbox: allow; another address: Gmail `settings/sendAs` as the user, `verificationStatus: accepted` (needs `enable_gmail_settings`) |
| `mail.delegate_access` | `mailbox:` | Gmail `settings/delegates` read **as the mailbox owner**, delegate accepted (needs `enable_gmail_settings`) |
| `group.member` | `group:` | `GET admin/directory/v1/groups/{group}/hasMember/{user}` as the admin (nested groups included) |

`calendar:primary` and the user's own email are `owner` without a call.

## Decisions

| Situation | hallpass answers |
|---|---|
| capability true, role sufficient, member, verified address | allow |
| capability false, role too low, not a member, address missing or unverified | deny |
| Drive answers 404 | deny: "no access, or the file does not exist: Drive does not distinguish" |
| suspended / archived account | deny |
| no Workspace account for the email | deny (`user_not_found`) |
| a capability field is missing from the response | unknown (`unsupported`) |
| calendar not in the user's list | unknown (`unsupported`): an ACL may still grant access |
| `hasMember` answers 400 or 404 | unknown (`unsupported`): unknown or cross-domain group |
| Gmail feature off | unknown (`unsupported`) |
| `invalid_grant` minting a token for the **user** | unknown (`unsupported`): could not act as the user |
| `invalid_grant` minting a token for the **admin** | unknown (`credential_rejected`): delegation is missing the scope or `admin_email` is invalid |
| 403 `forbidden` / `insufficientPermissions` / `accessNotConfigured`, 401 after one retry | unknown (`credential_rejected`) |
| 403 `rateLimitExceeded` / `userRateLimitExceeded`, 429 | unknown (`upstream_rate_limited`) |
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
- Whether a mailbox is set up (`isMailboxSetup`) is not checked for `mail.send_as` on the own
  mailbox.

## Unverified

Each item is marked `// UNVERIFIED:` in the code.

- The IAM Credentials `signJwt` request `{"payload": "<claims JSON>"}` and response
  `{"keyId", "signedJwt"}` shapes for `auth_mode: keyless`.
- Whether `writerWithoutPrivateAccess` allows creating and changing events; assumed yes for
  `calendar.event.write`.
- `mail.send_as` on the own mailbox does not consult `isMailboxSetup`; an active account without a
  Gmail licence would be a false allow.
- Whether `www.googleapis.com` serves the Directory API at `/admin/directory/v1`; the canonical host
  is `admin.googleapis.com`. Production leaves `api_url` at its default.

## Test

Unit tests run against a fake token endpoint that verifies every assertion (RS256, `kid`, `iss`,
single scope, `aud`, `sub`, one-hour lifetime) and issues distinct tokens per (user, scope), plus
fakes of the Directory, Drive, Calendar and Gmail endpoints and of the metadata server and
`signJwt` for keyless mode. They cover token caching per pair, the 401 retry, `invalid_grant` for
users and for the admin, every action allow and deny, calendar roles, missing capabilities, the
Gmail feature on and off, the probe warnings and the injected failure modes. The test key JSON's
`private_key_id` carries the canary and the key pair is generated in the test.
