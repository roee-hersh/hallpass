# salesforce

> **Warning: this integration was designed from secondary sources and has not been run against a
> real org.** Every Salesforce behaviour it relies on is listed under [Unverified](#unverified) and
> marked `// UNVERIFIED:` in the code. Confirm it in a Developer Edition org (setup, probe, one
> allow and one deny per action family) before using its answers for anything.

hallpass authenticates as an External Client App acting as a read-only integration user, maps the
caller's email to a `User` row, and asks Salesforce's own permission objects with SOQL: `UserRecordAccess`
for one record, `ObjectPermissions` and `FieldPermissions` across the user's profile and permission
sets (ORed, the way Salesforce combines them), `PermissionSet` for system permissions and
`PermissionSetAssignment` for permission set membership. Every question is a `GET
/services/data/{version}/query`; nothing is written and no user credential is ever used.

## Credential

Since Spring '26 new connected apps cannot be created; use an **External Client App** (Setup,
External Client App Manager):

1. Create the app with OAuth enabled and the **JWT bearer flow** on. Upload the certificate whose
   private key hallpass will sign with (`openssl req -x509 -newkey rsa:2048 -nodes -keyout
   hallpass.key -out hallpass.crt -days 365`), set the OAuth scope to **`api`** (Manage user data via
   APIs), and set the policy to **Admin approved users are pre-authorized**.
2. Create the integration user on the free **Salesforce Integration** licence with the **Minimum
   Access – API Only Integrations** profile. Give it a permission set with **API Enabled**, **View
   Setup and Configuration** and **View All Users**, and add that permission set (or its profile) to
   the app's pre-authorized list.
3. Store the private key PEM (PKCS#1 or PKCS#8, unencrypted) in a file or environment variable. The
   app's **consumer key** is `client_id`.

For `auth_flow: client_credentials` enable the client credentials flow instead, set the app's
**Run As** user to the integration user and store the **consumer secret** as `credential`.

**Read-only caveat.** `UserRecordAccess` reportedly answers only for records the *running* user
(the integration user) can see, and `ObjectPermissions`/`FieldPermissions` rows are visible only for
objects the running user knows. For `record.*` answers on records the integration user does not own
or share, it may need **View All** on each object it is asked about, or **View All Data** (read-only
but org-wide). Confirm what is needed before relying on record checks; the probe repeats this
warning.

The JWT is signed RS256 with `iss` = consumer key, `sub` = `username`, `aud` = `audience`, `exp` =
now + 3 minutes. The access token it buys carries no expiry, so it is reused for `token_ttl` and
minted again 5 minutes before that. A 401 from the API drops the token and retries the call once with
a fresh one.

## Connection

```yaml
  - id: salesforce-acme
    integration: salesforce
    url: https://acme.my.salesforce.com
    client_id: 3MVG9...                       # the app's consumer key
    username: hallpass@acme.com               # the integration user (JWT subject)
    credential: file:/secrets/salesforce-hallpass.pem
    api_version: v66.0
    # auth_flow: jwt_bearer                   # or client_credentials (consumer secret in credential)
    # audience: https://login.salesforce.com  # https://test.salesforce.com for sandboxes
    # match_field: Email                      # Username or FederationIdentifier
    # token_ttl: 15m
```

| Key | Meaning |
|---|---|
| `url` | the org's My Domain URL. The token endpoint is `{url}/services/oauth2/token`; API calls go to the `instance_url` the token response names when its host is `url`'s host or under `.salesforce.com`, `.force.com` or `.salesforce.mil`, otherwise (or when it names none) to `url` |
| `client_id` | consumer key of the External Client App; the JWT issuer |
| `auth_flow` | `jwt_bearer` (default): RS256 JWT bearer grant with `credential` as the private key. `client_credentials`: consumer secret, acting as the app's Run As user |
| `username` | the integration user's `Username`; the JWT `sub`. Required for `jwt_bearer` |
| `credential` | PEM RSA private key or consumer secret, `env:` or `file:`; read at every mint |
| `audience` | the JWT `aud`: `https://login.salesforce.com` (default) or `https://test.salesforce.com` |
| `api_version` | REST API version, pinned, `v66.0` style. Never discovered: a version bump is a config change |
| `match_field` | the `User` field the caller's email is compared to: `Email` (default), `Username` or `FederationIdentifier` |
| `token_ttl` | how long a minted token is reused (1m to 24h, default 15m) |

### Identity

Under `match_field: Email` (the default) and `Username`, the first query is exact: `SELECT Id,
IsActive, Username, Email, FederationIdentifier, UserType, Name FROM User WHERE Username =
'<escaped email>' LIMIT 2`. `Username` is unique, so one row is the user and two rows are
`user_ambiguous`. Under `Username` no row is `user_not_found`; under `Email` no row leads to the
second query, `... WHERE Email = '<escaped email>' LIMIT 4` (under `FederationIdentifier` only this
query runs, against that field). Email is not unique in Salesforce: among two or three rows a single
active `UserType = 'Standard'` row wins; four rows mean the limit was hit and the rows are only a
subset of the matches, so nothing is picked; anything else is `user_ambiguous`, advising
`match_field: FederationIdentifier`. No row is `user_not_found`. A further query, `SELECT IsFrozen
FROM UserLogin WHERE UserId = '<Id>'`, detects frozen users; where `UserLogin` cannot be queried
(`INVALID_TYPE`/`INVALID_FIELD`) the identity records `frozen=unknown`, the user is still allowed
(`user.active` says "frozen users are not detected") and the probe warns. An inactive or frozen user
is denied for every action.

### SOQL safety

Nothing from the caller is ever interpolated raw. Record Ids must match
`^[a-zA-Z0-9]{15}([a-zA-Z0-9]{3})?$`, object and field API names `^[A-Za-z][A-Za-z0-9_]{0,79}$`,
permission names `^Permissions[A-Za-z0-9]+$` *and* must appear in the cached
`PermissionSet` describe (`GET /sobjects/PermissionSet/describe`, cached one hour; an unknown
name is `invalid_request` and never reaches a query). Emails must parse with `net/mail` as a bare
address (no display name, no control characters) and are then escaped for a single-quoted literal:
`\` first, then `'`, plus newline, carriage return and tab. Everything goes through
`GET /query?q=<url-encoded>`.

## Resources

| Resource | Meaning |
|---|---|
| `record:<Id>` | one record by 15- or 18-character Id |
| `object:<ApiName>` | an sObject, e.g. `object:Account`, `object:Invoice__c` |
| `field:<Object>.<Field>` | one field, e.g. `field:Account.Rating`, `field:Invoice__c.Amount__c` |
| `permission:<PermissionsXxx>` | a system or app permission by `PermissionSet` field name, e.g. `permission:PermissionsModifyAllData` |
| `permset:<ApiName>` | a permission set without a namespace (`PermissionSet.Name`, `NamespacePrefix = null`) |
| `permset:<ns>__<ApiName>` | a managed package's permission set (`Name` and `NamespacePrefix`); both parts must be API names and the name may not contain another `__` |
| `user:<email>` | the requesting user (for `user.active`); `record:<UserId>` is also accepted |

Resources take no `?query` parameters.

## Actions

| Action | Resource | What Salesforce is asked |
|---|---|---|
| `record.read` | `record:` | `UserRecordAccess.HasReadAccess` |
| `record.edit` | `record:` | `UserRecordAccess.HasEditAccess` |
| `record.delete` | `record:` | `UserRecordAccess.HasDeleteAccess` |
| `record.transfer` | `record:` | `UserRecordAccess.HasTransferAccess` |
| `record.share` | `record:` | `UserRecordAccess.HasAllAccess` |
| `object.read` | `object:` | any assigned profile or permission set has `PermissionsRead` |
| `object.create` | `object:` | `PermissionsCreate` |
| `object.edit` | `object:` | `PermissionsEdit` |
| `object.delete` | `object:` | `PermissionsDelete` |
| `object.view_all` | `object:` | `PermissionsViewAllRecords` |
| `object.modify_all` | `object:` | `PermissionsModifyAllRecords` |
| `field.read` | `field:` | any assigned profile or permission set has `FieldPermissions.PermissionsRead` |
| `field.edit` | `field:` | `FieldPermissions.PermissionsEdit` |
| `system.permission` | `permission:` | any assigned permission set (profiles included) has `<PermissionsXxx> = true` |
| `permset.assigned` | `permset:` | a `PermissionSetAssignment` for the user with that `PermissionSet.Name` and `NamespacePrefix` |
| `user.active` | `user:` or `record:` | the user is active and not frozen |

There is no `record.create`: records are created per object, so ask `object.create` with
`object:<ApiName>` (the error says so).

The queries, with `<uid>` the resolved user Id and every other placeholder validated as above:

- record: `SELECT RecordId, HasReadAccess, HasEditAccess, HasDeleteAccess, HasTransferAccess,
  HasAllAccess, MaxAccessLevel FROM UserRecordAccess WHERE UserId = '<uid>' AND RecordId = '<Id>'`
- object: `SELECT PermissionsRead, ..., Parent.IsOwnedByProfile, Parent.Name FROM ObjectPermissions
  WHERE SobjectType = '<obj>' AND ParentId IN (SELECT PermissionSetId FROM PermissionSetAssignment
  WHERE AssigneeId = '<uid>' AND PermissionSet.HasActivationRequired = false AND (ExpirationDate =
  null OR ExpirationDate > <now, YYYY-MM-DDThh:mm:ssZ>))`. The sub-select keeps only assignments in
  force: session-based permission sets (in force only during an activated session) and expired
  time-bound assignments are excluded. When zero rows come back, `GET
  /sobjects/<obj>/describe` (cached one hour) tells a non-existent or invisible object (unknown)
  from one nothing grants (deny).
- field: the same over `FieldPermissions` with `Field = '<obj>.<field>'`
- system: `SELECT Id, Name, IsOwnedByProfile FROM PermissionSet WHERE <PermissionsXxx> = true AND
  Id IN (<the same sub-select>)`
- permset: `SELECT Id FROM PermissionSetAssignment WHERE AssigneeId = '<uid>' AND
  PermissionSet.Name = '<name>' AND PermissionSet.NamespacePrefix = '<ns>'` (or `= null` for an
  unprefixed name)

If the org answers `INVALID_FIELD` to the filtered sub-select (an API version without
`ExpirationDate`), the object, field and system queries run once more with the unfiltered
`(SELECT PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId = '<uid>')`. That superset may
still produce a deny, but a grant found through it is `unsupported` ("could not exclude
session-based or expired assignments"), never allow.

Before an object, field or system answer, hallpass reads the user's permission set group
assignments (`SELECT PermissionSetGroupId FROM PermissionSetAssignment WHERE AssigneeId = '<uid>' AND
PermissionSetGroupId != null`) and, when there are any, `SELECT Id, DeveloperName, Status FROM
PermissionSetGroup WHERE Id IN (...)`. A group whose `Status` is not `Updated` makes the answer
unknown until it is recalculated.

## Decisions

| Situation | Answer |
|---|---|
| the boolean asked about is true (record row, any object/field row through an assignment in force, any permission set row, an assignment exists) | allow, naming the profile or permission set where known (`MaxAccessLevel` is rendered only when it is one of None, Read, Edit, Delete, Transfer, All; otherwise "unknown") |
| the boolean is false on every row; no `ObjectPermissions` row at all for an object whose describe answers 200; no permission set has the permission; no assignment (name and namespace) | deny |
| user inactive (`IsActive = false`) or frozen (`UserLogin.IsFrozen`) | deny, for every action |
| `UserLogin` not queryable (`INVALID_TYPE`/`INVALID_FIELD`) | freezing is not evaluated: identity attribute `frozen=unknown`, the user is allowed, the probe warns |
| no `UserRecordAccess` row | unknown (`resource_not_visible`): the record is not visible to the integration user, or the object has no sharing settings |
| no `ObjectPermissions` row and the object's describe is 404 | unknown (`resource_not_visible`): the object does not exist or is not visible to the integration user |
| no `FieldPermissions` row | unknown (`unsupported`): required and system fields carry no rows |
| a permission set group not yet recalculated | unknown (`unsupported`) |
| a grant found only through the unfiltered assignment sub-select (the org rejected the activation/expiry filter) | unknown (`unsupported`): could not exclude session-based or expired assignments |
| `permission:` name not in the `PermissionSet` describe; malformed resource (including a `permset:` with a bad namespace); `record.create` | unknown (`invalid_request`) |
| two users share the `Username`; two or three users share the email with no single active Standard one; four users share the email (query limit) | deny (`user_ambiguous`); none | deny (`user_not_found`) |
| 400 `INVALID_TYPE` / `INVALID_FIELD` / `MALFORMED_QUERY` | unknown (`unsupported`), naming the object or field |
| 401 (after one re-mint), 403 `API_DISABLED_FOR_ORG`, `INSUFFICIENT_ACCESS` or any other 403, token endpoint `invalid_grant`/`invalid_client` | unknown (`credential_rejected`) |
| 403 `REQUEST_LIMIT_EXCEEDED`, 429 | unknown (`upstream_rate_limited`) |
| 404 | unknown (`resource_not_visible`) |
| other 4xx, 5xx, transport | unknown (`upstream_error`); timeouts `upstream_timeout` |

Salesforce error bodies (`[{"message": ..., "errorCode": ...}]`) contribute only their `errorCode`
to a decision, and only when it matches `^[A-Z_]{1,64}$`; anything else is rendered as "unknown
error" and the message is never copied.

## Limits

Every query counts against the org's daily API request allocation (a Developer Edition org has
about 15,000 per day, unverified). After the token is cached a check costs two to six requests:
the identity lookup (one or two queries), the frozen check, the permission set group check where
relevant, the question itself, and for an object with no permission rows its describe (cached one
hour). hallpass's decision cache is the mitigation; the probe reports the remaining
allocation and warns under 10%.

## Probe

Mints a token, reads `GET /services/data/{version}/limits` (`DailyApiRequests` into the summary,
a warning under 10% remaining), confirms the integration user with `SELECT Id, Username, IsActive
FROM User WHERE Username = '<username>'` (a warning when missing or inactive), tries the frozen
check on the integration user itself (`SELECT IsFrozen FROM UserLogin WHERE UserId = '<its Id>'`, or
`SELECT IsFrozen FROM UserLogin LIMIT 1` under `client_credentials`) and warns "frozen users are not
detected: UserLogin not queryable" when the org rejects it, and fetches the `PermissionSet`
describe, which also proves the permission-name validation can work. It always warns about the View
All Data caveat.

## What it cannot see

- Validation rules, Apex triggers, flows, approval-process locks, record types and their picklist
  restrictions: an allowed edit may still be rejected.
- Restriction rules and scoping rules, which hide records after sharing is computed.
- Login hours, login IP ranges, session settings and MFA: an active user may still be unable to log in.
- Field-level security is not folded into record answers: `record.edit` says nothing about which
  fields the user may edit; ask `field.edit` separately.
- Everything depends on the integration user's own visibility: a record it cannot see, or an object
  it has no permission on, is unknown, not deny.
- Sharing sets, portal and community sharing, territory management and manual shares are only
  reflected to the extent `UserRecordAccess` includes them.

## Unverified

Each item is marked `// UNVERIFIED:` in the code and must be confirmed in a Developer Edition org.

- The JWT bearer assertion must expire within 3 minutes; hallpass sets `exp` = now + 3 minutes with
  no `iat` or `jti`.
- The client credentials flow requires a Run As user on the External Client App and the token then
  acts as that user.
- The token response's `instance_url` names the REST host; hallpass uses it (https only, no query or
  userinfo) as the API base and falls back to `url`. That every org's REST host is `url`'s host or
  under `.salesforce.com`, `.force.com` or `.salesforce.mil` (any other host is ignored, logged at
  debug, and `url` is used) is unverified, as is that the token response carries no `expires_in`
  (hence `token_ttl`).
- An expired or revoked session is a 401 with `errorCode: INVALID_SESSION_ID`; hallpass re-mints on
  any 401, once.
- `nextRecordsUrl` is a `/services/data/...` path on the same instance; hallpass follows at most
  five pages.
- The `PermissionSet` describe lists one boolean `PermissionsXxx` field per system and app
  permission, and those same names are the queryable filter fields.
- `UserType = 'Standard'` identifies full-licence users for the email disambiguation rule.
- `UserLogin.IsFrozen` is queryable by the integration user; a `400 INVALID_TYPE/INVALID_FIELD`
  is the only failure that turns the frozen state unknown (a 403 on `UserLogin` fails the identity
  lookup and the probe as `credential_rejected`; if `UserLogin` turns out to need Manage Users, this
  must change). That `SELECT IsFrozen FROM UserLogin LIMIT 1` (the probe's unfiltered form under
  `client_credentials`) is accepted is also unverified.
- `UserRecordAccess.MaxAccessLevel` takes only the values None, Read, Edit, Delete, Transfer and
  All; any other value is rendered as "unknown".
- `PermissionSet.HasActivationRequired` and `PermissionSetAssignment.ExpirationDate` are filterable
  inside the `PermissionSetAssignment` sub-select, `ExpirationDate = null` matches assignments
  without an expiry, and an org whose API version lacks `ExpirationDate` answers `INVALID_FIELD`
  (which triggers the unfiltered retry described under Actions).
- `GET /sobjects/<name>/describe` answers 404 `NOT_FOUND` for an object that does not exist, and
  also for one the integration user cannot see at all; hallpass treats both as unknown. Whether an
  object the integration user has no permission on describes as 200 is unverified.
- `PermissionSet.NamespacePrefix` is null for local permission sets and filterable through the
  `PermissionSet` relationship of `PermissionSetAssignment`; a developer name never contains two
  consecutive underscores, so the first `__` in `permset:<ns>__<Name>` is the separator.
- `Username` is unique per org, so the exact lookup returning two rows is an anomaly reported as
  `user_ambiguous`.
- `UserRecordAccess` returns no row (rather than a row of false) for records the running user cannot
  see and for objects without sharing settings, and needs the exact `UserId = ... AND RecordId = ...`
  filter (this filter rule is confirmed; the empty-result behaviour is not).
- Profile object and field permissions appear as `ObjectPermissions`/`FieldPermissions` rows whose
  `Parent.IsOwnedByProfile` is true, and permission set group grants appear through the group's
  aggregate permission set with muting already applied.
- Required, system and some standard fields have no `FieldPermissions` rows, so zero rows is
  unknown, not deny.
- `PermissionSetAssignment.PermissionSetGroupId` is set for group assignments and
  `PermissionSetGroup.Status` reads `Updated` once recalculated; a `400` on that query skips the
  check.
- `GET /limits` reports `DailyApiRequests` with `Max` and `Remaining`; the Developer Edition
  allocation of about 15,000 per day.
- Setup details: the External Client App JWT flow settings, pre-authorization by permission set, the
  `api` scope, the Salesforce Integration licence, the Minimum Access – API Only Integrations
  profile, and which of View All / View All Data the integration user needs for record answers.

Confirmed: new connected apps cannot be created since Spring '26 (External Client Apps only), and
`UserRecordAccess` must be filtered by one `UserId` and one `RecordId`.

## Test

`go test ./internal/integrations/salesforce/` runs against a fake Salesforce that verifies the JWT
bearer assertion (RS256 signature, `iss`/`sub`/`aud`, `exp` within 3 minutes) and the client
credentials form, hands out tokens with an `instance_url`, revokes them on demand, and answers
`/query` by parsing the SOQL `FROM` object and its literals (so a test address `o'neil@example.com`
must arrive as `o\'neil@example.com`), `/limits`, the `PermissionSet` describe and per-object describes (404 for unknown objects). The fake
insists that every assignment sub-select carries the activation/expiry filter with a current
timestamp, hides session-based and expired grants behind it, honours `LIMIT`, and matches permission
sets on name and namespace. Against a real org: complete the setup above in a Developer Edition org, configure a connection, run `hallpass
probe`, then one allow and one deny for each of `record.read`, `object.read`, `field.read`,
`system.permission`, `permset.assigned` and `user.active`, and compare with what the user actually
sees in the UI. Work through the Unverified list while doing so.
