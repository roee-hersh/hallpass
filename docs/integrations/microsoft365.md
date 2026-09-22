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
| `Member.Read.Hidden` (optional) | hidden-membership groups | without it those groups are silently omitted from `checkMemberGroups`: a **possible false deny** |
| `TeamMember.Read.All` | `team.*`, standard channels | |
| `ChannelMember.Read.All` | private and shared channels | |
| `Files.Read.All` | `file.*` | **broad**: this credential can read every file in every OneDrive and SharePoint site of the tenant. There is no narrower application permission that returns item permissions. Keep the secret tightly held, or omit this permission and accept `file.*` answering `credential_rejected`. |
| `RoleManagement.Read.Directory` (optional) | `role.member` | without it `role.member` is unknown (`credential_rejected`) |

Prefer a certificate: put the public certificate PEM in `certificate_file` and the private key PEM
in `credential`. hallpass then signs a PS256 client assertion with the `x5t#S256` thumbprint. With a
client secret, `credential` is the secret itself.

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
`user_ambiguous`. A disabled account (`accountEnabled: false`) is a deny for every action. Guests are
allowed but flagged (`guest=true` in the identity and "(guest account)" in reasons).

## Actions

| Action | Resource | Graph call |
|---|---|---|
| `user.active` | `user:` or `mailbox:` | the resolved user's `accountEnabled` |
| `group.member` | `group:` | `POST /users/{id}/checkMemberGroups` (transitive) |
| `role.member` | `role:` | `GET /users/{id}/transitiveMemberOf/microsoft.graph.directoryRole` |
| `team.member` / `team.owner` | `team:` | `GET /teams/{id}/members?$filter=...userId eq '{id}'`, roles |
| `channel.read` | `team:.../channel/...` | channel `membershipType`; standard = team membership, private = `/channels/{c}/members`, shared = `/channels/{c}/allMembers` |
| `channel.owner` | same | as above, roles contain `owner` |
| `channel.message.post` | same | membership; unknown when `moderationSettings.userNewMessageRestriction` is set to anything but `everyone` |
| `file.read` / `file.edit` / `file.delete` / `file.share` | `drive:.../item/...` | `GET /drives/{d}/items/{i}/permissions` plus `GET /drives/{d}?$select=owner`; group grants expanded with `checkMemberGroups` in batches of 20 |
| `mail.send_as_self` | `mailbox:` | allow only for the user's own mailbox with `mail` set |
| `mail.send_as`, `mail.send_on_behalf`, `mailbox.full_access`, `calendar.read`, `calendar.write` | `mailbox:` | **always unknown**: Exchange delegation has no Graph API |

File rules, in order:

1. a permission granted to the user's id with a sufficient role (read: `read`/`write`/`owner`;
   edit and delete: `write`/`owner`; share: `owner`) is an allow;
2. the drive owner (`owner.user.id`) is allowed everything;
3. permissions granted to Entra groups are expanded with `checkMemberGroups`;
4. a sharing link with `scope: organization` allows with the caveat "via an organization-wide
   sharing link";
5. `file.share` with only read/write access is unknown ("sharing rights depend on site settings");
6. permissions granted to SharePoint `siteGroup` principals cannot be expanded through Graph: if
   nothing else allowed, unknown; likewise an anonymous link;
7. otherwise deny.

## Decisions

| Situation | hallpass answers |
|---|---|
| membership / role / permission found | allow |
| user is not a member, has no role, no grant matches and no siteGroup or anonymous link exists | deny |
| `accountEnabled: false` | deny ("account disabled") |
| no user by UPN, mail or proxy address | deny (`user_not_found`) |
| several users match | unknown (`user_ambiguous`) |
| 404 on a team, channel, drive or item | unknown (`resource_not_visible`) |
| 403 (`Authorization_RequestDenied` or other) | unknown (`credential_rejected`): a permission is missing |
| token endpoint rejects the client | unknown (`credential_rejected`) |
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
- **Custom SharePoint permission levels** collapse to read/write/owner; unrecognised role strings
  count as no access.
- **Sensitivity labels**, **Conditional Access**, **information barriers** and **Data Loss
  Prevention** can block an action hallpass allowed.
- **Team and channel moderation settings** are only detected, not evaluated; a member of a
  moderated channel is unknown for `channel.message.post`.
- **Exchange delegation** (Send As, Send on Behalf, Full Access, calendar folder permissions) has
  no application-permission Graph API: those actions are always unknown.
- **Hidden-membership groups** are omitted without `Member.Read.Hidden` (possible false deny).
- **PIM eligible** role assignments that are not activated do not appear in `transitiveMemberOf`.

## Unverified

Each item is marked `// UNVERIFIED:` in the code.

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
- Whether an app can read its own service principal and `appRoleAssignments` with the permissions
  above; the probe warns instead of failing when it cannot.
- National cloud endpoints (`login.microsoftonline.us`, `graph.microsoft.us`,
  `dod-graph.microsoft.us`, `login.chinacloudapi.cn`, `microsoftgraph.chinacloudapi.cn`) are
  configured through `authority_url` and `url` but were not exercised.

## Test

Unit tests run against a fake token endpoint and a fake Graph (`microsoft365_test.go`). They cover
both credential types (the certificate path decodes the assertion, checks PS256 and the `x5t#S256`
thumbprint and verifies the signature), token caching and the 401 retry, every identity fallback,
every action allow and deny, `checkMemberGroups` batching, the file permission rules, private and
shared channels, the probe warnings and the injected failure modes.
