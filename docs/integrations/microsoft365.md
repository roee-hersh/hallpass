# microsoft365

hallpass asks Microsoft Graph as an app registration with read-only application permissions. It
resolves the caller's email to an Entra user (by UPN, then `mail`, then proxy address), then reads
the facts the action needs: transitive group membership (`checkMemberGroups`), directory roles,
team and channel membership, and the effective permissions on a drive item. Exchange delegation
(Send As, Send on Behalf, Full Access, calendar sharing) has no Graph API and is always unknown.
hallpass never performs an action and nothing is persisted.

## Credential

An app registration with a client secret or a certificate, and **application** permissions with
admin consent. All of them are read-only:

| Permission | Needed for | Note |
|---|---|---|
| `User.Read.All` | identity lookup, `user.active`, `mail.send_as_self` | |
| `GroupMember.Read.All` | `group.member`, group grants on files | |
| `Member.Read.Hidden` (optional) | hidden-membership groups | without it those groups are silently omitted from `checkMemberGroups`: `group.member` answers unknown for a hidden-membership group unless membership is proven, but group grants on files are still omitted, a **possible false deny** there |
| `TeamMember.Read.All` | `team.*`, standard channels | |
| `ChannelMember.Read.All` | private and shared channels | |
| `Files.Read.All` | `file.*` | **broad**: this credential can read every file in every OneDrive and SharePoint site of the tenant. There is no narrower application permission that returns item permissions. Keep the secret tightly held, or omit this permission and accept `file.*` answering `credential_rejected`. |
| `RoleManagement.Read.Directory` (optional) | `role.member` | without it `role.member` is unknown (`credential_rejected`) |

Prefer a certificate: put the public certificate PEM in `certificate_file` and the private key PEM
in `credential`. hallpass then signs a PS256 client assertion with the `x5t#S256` thumbprint. With a
client secret, `credential` is the secret itself.

A certificate credential signs with `cryptography`: install `hallpass[crypto]` (the Docker image has it).

## Connection

```yaml
  - id: m365-contoso
    integration: microsoft365
    tenant_id: contoso.onmicrosoft.com          # or the tenant GUID
    client_id: 22222222-2222-2222-2222-222222222222
    credential: file:/secrets/m365-key.pem      # private key PEM, or the client secret
    certificate_file: /etc/hallpass/m365-cert.pem   # optional; present = certificate auth
    authority_url: https://login.microsoftonline.com  # optional
    url: https://graph.microsoft.com                  # optional
```

| Key | Meaning |
|---|---|
| `tenant_id` | Entra tenant, GUID or verified domain |
| `client_id` | application (client) id |
| `credential` | client secret, or the PEM private key when `certificate_file` is set (`env:`/`file:`) |
| `certificate_file` | path to the public certificate PEM; when set hallpass authenticates with a certificate assertion |
| `authority_url` | token authority, default `https://login.microsoftonline.com` |
| `url` | Graph endpoint, default `https://graph.microsoft.com` |

The token is fetched from `{authority_url}/{tenant_id}/oauth2/v2.0/token` with `scope={url}/.default`
and cached until shortly before expiry. A 401 from Graph invalidates it and the call is retried once.

National clouds are the same two keys (unverified, see below): GCC High / DoD use
`authority_url: https://login.microsoftonline.us` with `url: https://graph.microsoft.us` or
`https://dod-graph.microsoft.us`; China uses `https://login.chinacloudapi.cn` and
`https://microsoftgraph.chinacloudapi.cn`.

## Resources

| Resource | Meaning |
|---|---|
| `user:<email or object id>` | the caller's own account |
| `group:<guid>` | an Entra group (security or Microsoft 365) |
| `role:<guid>` | a directory role **template** id, e.g. `62e90394-69f5-4237-9190-012177145e10` for Global Administrator |
| `team:<guid>` | a team (its group id) |
| `team:<guid>/channel/<channel id>` | a channel; ids look like `19:...@thread.tacv2` |
| `drive:<drive id>/item/<item id>` | a OneDrive or SharePoint item |
| `mailbox:<email>` | an Exchange mailbox |

The user is found by `GET /users/{email}` (guest UPNs with `#EXT#` are path-escaped), then
`$filter=mail eq '...'`, then `$filter=proxyAddresses/any(p:p eq 'smtp:...')`. Several matches are
`user_ambiguous`. A disabled account (`accountEnabled: false`) is a deny for every action; an account
whose `accountEnabled` Graph does not report at all (`account_enabled=unknown` in the identity) is
unknown for every action, never assumed enabled. Guests are allowed but flagged (`guest=true` in the
identity and "(guest account)" in reasons); they are not credited with organization-wide sharing
links, which guest accounts cannot redeem.

## Actions

| Action | Resource | Graph call |
|---|---|---|
| `user.active` | `user:` or `mailbox:` | the resolved user's `accountEnabled`; unknown when Graph does not report it |
| `group.member` | `group:` | `GET /groups/{id}?$select=id,visibility` (404 = not visible, `HiddenMembership` = unknown unless membership is proven), then `POST /users/{id}/checkMemberGroups` (transitive) |
| `role.member` | `role:` | `GET /users/{id}/transitiveMemberOf/microsoft.graph.directoryRole` |
| `team.member` / `team.owner` | `team:` | `GET /teams/{id}/members?$filter=...userId eq '{id}'`, roles; only records whose `userId` is the caller's count, the filter result is never trusted on its own |
| `channel.read` | `team:.../channel/...` | channel `membershipType`; `standard` = team membership, `private` = `/channels/{c}/members`, `shared` = `/channels/{c}/allMembers`; a missing or other value is unknown |
| `channel.owner` | same | as above, roles contain `owner` |
| `channel.message.post` | same | membership; unknown when `moderationSettings.userNewMessageRestriction` is set to anything but `everyone` |
| `file.read` / `file.edit` / `file.delete` / `file.share` | `drive:.../item/...` | `GET /drives/{d}/items/{i}/permissions` plus `GET /drives/{d}?$select=owner` (a 404 there skips only the owner rule); group grants expanded with `checkMemberGroups` in batches of 20 |
| `mail.send_as_self` | `mailbox:` | allow only for the user's own mailbox with `mail` set; an empty `mail` is unknown, not deny |
| `mail.send_as`, `mail.send_on_behalf`, `mailbox.full_access`, `calendar.read`, `calendar.write` | `mailbox:` | **always unknown**: Exchange delegation has no Graph API |

File rules, in order:

1. a permission granted to the user's id with a sufficient role (read: `read`/`write`/`owner`;
   edit and delete: `write`/`owner`; share: `owner`) is an allow;
2. the drive owner (`owner.user.id`) is allowed everything; when the drive lookup answers 404 this
   rule is skipped and the rest still run;
3. permissions granted to Entra groups are expanded with `checkMemberGroups`;
4. a sharing link with `scope: organization` allows with the caveat "via an organization-wide
   sharing link", except for guest accounts, which cannot redeem such links;
5. a grant that reaches the caller (directly, through a group they are in, or through a usable
   organization link) with a role string other than `read`/`write`/`owner` (a custom SharePoint
   permission level such as `sp.full control`) is unknown when it did not already allow: the custom
   level may grant more than hallpass can see;
6. a sharing link whose `scope` is not `organization`, `anonymous` or `users` is unknown;
7. `file.share` with only read/write access is unknown ("sharing rights depend on site settings");
8. permissions granted to SharePoint `siteGroup` principals cannot be expanded through Graph: if
   nothing else allowed, unknown; likewise an anonymous link;
9. otherwise deny.

## Decisions

| Situation | hallpass answers |
|---|---|
| membership / role / permission found | allow |
| user is not a member, has no role, no grant matches and no siteGroup, anonymous link, custom role or unmodelled link scope exists | deny |
| a guest whose only route to a file is an organization-wide sharing link | deny |
| `accountEnabled: false` | deny ("account disabled") |
| `accountEnabled` not reported by Graph | unknown (`unsupported`), for every action |
| no user by UPN, mail or proxy address | deny (`user_not_found`) |
| several users match | unknown (`user_ambiguous`) |
| 404 on a group, team, channel, drive item or its permissions | unknown (`resource_not_visible`) |
| 404 on the drive-owner lookup only | ignored; the group and link rules decide |
| 403 (`Authorization_RequestDenied` or other) | unknown (`credential_rejected`): a permission is missing |
| token endpoint rejects the client | unknown (`credential_rejected`) |
| `group.member` on a `HiddenMembership` group the user is not seen in | unknown (`unsupported`) |
| channel with no `membershipType`, or one other than standard/private/shared | unknown (`unsupported`) |
| `mail.send_as_self` with an empty `mail` attribute | unknown (`unsupported`) |
| custom role strings on a grant reaching the caller, sharing links with an unmodelled scope | unknown (`unsupported`) |
| siteGroup-only grants, anonymous links, moderated channels, Exchange delegation, non-owner sharing | unknown (`unsupported`) |
| 429, 5xx, timeout | unknown (`upstream_rate_limited` / `upstream_error` / `upstream_timeout`) |

Graph error messages are never copied into a decision text; only the error code is used.

## Probe

`hallpass probe` fetches a token, reads `GET /organization` and reports the tenant, then reads the
app's own service principal and `appRoleAssignments` to list granted application permissions. It
warns for any permission that allows writes (`.ReadWrite.`, `Mail.Send`, ...), for required
permissions that are missing, for the breadth of `Files.Read.All`, and when `Member.Read.Hidden` is
absent. If it cannot read its own assignments it warns "could not verify permissions".

## What it cannot see

- **Site collection administrators** and SharePoint site-level roles are not in item permissions.
- **Custom SharePoint permission levels** collapse to read/write/owner; an unrecognised role string
  on a grant that reaches the caller makes the answer unknown rather than deny, because the level
  may include the right in question.
- **Sensitivity labels**, **Conditional Access**, **information barriers** and **Data Loss
  Prevention** can block an action hallpass allowed.
- **Team and channel moderation settings** are only detected, not evaluated; a member of a
  moderated channel is unknown for `channel.message.post`.
- **Exchange delegation** (Send As, Send on Behalf, Full Access, calendar folder permissions) has
  no application-permission Graph API: those actions are always unknown.
- **Hidden-membership groups** are omitted from `checkMemberGroups` without `Member.Read.Hidden`.
  `group.member` reads the group's `visibility` first and answers unknown for such a group unless
  membership is proven; group grants on files do not get that lookup (possible false deny there).
- **Organization-wide sharing links** are not credited to guest accounts; a guest with no other
  grant is denied.
- **PIM eligible** role assignments that are not activated do not appear in `transitiveMemberOf`.

## Unverified

Each item is marked `# UNVERIFIED:` in the code.

- Whether Entra still accepts RS256 with the legacy `x5t` header for certificate assertions; only
  PS256 with `x5t#S256` is implemented.
- The `proxyAddresses/any(p:p eq 'smtp:...')` advanced query with `ConsistencyLevel: eventual` and
  `$count=true`, and whether the `smtp:` prefix match is case-sensitive.
- The OData cast path `transitiveMemberOf/microsoft.graph.directoryRole?$select=roleTemplateId`.
- `/teams/{t}/channels/{c}/allMembers` for shared channels, and whether the `userId` filter applies
  there.
- `GET /drives/{id}?$select=owner` returning `owner.user.id`; SharePoint document libraries are
  expected to report the site's group instead, so the drive-owner rule mostly helps OneDrive.
- `file.delete` requiring only the `write` role; SharePoint "contribute without delete" levels are
  not distinguishable.
- `GET /groups/{id}?$select=id,visibility` being readable with `GroupMember.Read.All` alone, and
  `visibility` being null for security groups and `HiddenMembership` only for Microsoft 365 groups
  created that way.
- That `checkMemberGroups` omits hidden-membership groups (rather than failing) when
  `Member.Read.Hidden` is not granted; `group.member` treats a miss on such a group as unknown.
- That "people in your organization" sharing links cannot be redeemed by guest (B2B) accounts, as
  Microsoft's sharing documentation states; such links are not credited to guests.
- Whether an app can read its own service principal and `appRoleAssignments` with the permissions
  above; the probe warns instead of failing when it cannot.
- National cloud endpoints (`login.microsoftonline.us`, `graph.microsoft.us`,
  `dod-graph.microsoft.us`, `login.chinacloudapi.cn`, `microsoftgraph.chinacloudapi.cn`) are
  configured through `authority_url` and `url` but were not exercised.

## Test

Unit tests run against a fake token endpoint and a fake Graph (`tests/integrations/microsoft365/test_microsoft365.py`). They cover
both credential types (the certificate path decodes the assertion, checks PS256 and the `x5t#S256`
thumbprint and verifies the signature), token caching and the 401 retry, every identity fallback
(including `#`, `%` and `/` in the address being path-escaped), an unreported `accountEnabled`,
every action allow and deny, `checkMemberGroups` batching, missing and hidden-membership groups, a
members collection that ignores the `userId` filter, a channel without a `membershipType`, the
file permission rules (guest and organization links, custom role strings, unmodelled link scopes,
a 404 on the drive-owner lookup), private and shared channels, the probe warnings and the injected
failure modes.
