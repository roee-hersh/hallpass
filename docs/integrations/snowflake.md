# snowflake

One connection is one Snowflake account. hallpass authenticates as a service user with a key pair
through the SQL REST API, finds the user with `SHOW USERS`, lists the roles granted to the user with
`SHOW GRANTS TO USER`, walks the role hierarchy with `SHOW GRANTS TO ROLE` (database roles
included), and looks for the privilege the question needs on the object, with `OWNERSHIP` counting
for everything, plus `USAGE` on the object's database and schema. Only `SHOW` commands run, which
need no warehouse. Nothing is written.

## Credential

A **service user** with an RSA key pair: the public key registered on the user
(`ALTER USER HALLPASS SET RSA_PUBLIC_KEY = '...'`), the unencrypted private key as `credential`.
hallpass signs a key-pair JWT (`iss` `<ACCOUNT>.<USER>.SHA256:<fingerprint>`, `sub`
`<ACCOUNT>.<USER>`, 50-minute lifetime) the way the official drivers do.

The user's `role` must be able to run `SHOW GRANTS TO USER` and `SHOW GRANTS TO ROLE` for **other**
users and roles, which takes the **MANAGE GRANTS** privilege: `SECURITYADMIN`, or a custom role:

```sql
CREATE ROLE HALLPASS_READER;
GRANT MANAGE GRANTS ON ACCOUNT TO ROLE HALLPASS_READER;
GRANT ROLE HALLPASS_READER TO USER HALLPASS;
```

`MANAGE GRANTS` also lets its holder grant and revoke; there is no read-only equivalent for live
grants. The `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS` and `GRANTS_TO_ROLES` views are read-only but
lag up to two hours and need a warehouse; a `source: account_usage` mode reading them is not
implemented here.

`hallpass probe` lists hallpass's own roles and warns when none holds `MANAGE GRANTS`.

## Connection

```yaml
  - id: snowflake-prod
    integration: snowflake
    account: myorg-myaccount
    user: HALLPASS
    role: SECURITYADMIN
    credential: file:/secrets/snowflake-hallpass.p8
    # url: https://myorg-myaccount.snowflakecomputing.com
```

| Key | Meaning |
|---|---|
| `account` | the account identifier (`myorg-myaccount`, or a legacy locator `xy12345.us-east-1`) |
| `user` | the service user |
| `role` | the role statements run as |
| `credential` | the RSA private key (PEM, PKCS#1 or PKCS#8, unencrypted), `env:` or `file:` |
| `url` | the account URL; default `https://<account>.snowflakecomputing.com` |

### Identity

`SHOW USERS LIKE '<email>'` first (SCIM-provisioned users are named by their address; the `LIKE`
wildcards are escaped), then a page-by-page `SHOW USERS LIMIT 10000 [FROM '<name>']` scan matching
`name`, `login_name` or `email` exactly (ignoring case); none is `user_not_found`, two are
`user_ambiguous`. A disabled user is denied every action. The identity's groups are the roles
`SHOW GRANTS TO USER` lists (both the classic `role` column and the 2025 shape with `granted_on
ROLE` are read). Groups sent by the caller are ignored.

### Roles

The answer is the union of every role granted to the user, directly or through other roles and
database roles: a user can activate any of them, and with `DEFAULT_SECONDARY_ROLES = ('ALL')` a
session holds all of them at once. `SHOW GRANTS TO ROLE <r>` rows with `granted_on ROLE` (or
`DATABASE_ROLE`) and privilege `USAGE` are followed; the walk stops at 500 roles and is cached for
two minutes per role.

## Resources

| Resource | Name |
|---|---|
| `table:<db>.<schema>.<name>` | a table, view, materialized view, dynamic, external, event, Iceberg or hybrid table |
| `schema:<db>.<schema>` | a schema |
| `database:<db>` | a database |
| `warehouse:<name>` | a warehouse |
| `role:<name>` | a role |
| `account` | the account |

Identifiers follow Snowflake's rules: unquoted parts resolve to upper case, `"quoted"` parts keep
their case and may hold any character but control characters (`""` for a quote). Every part is
validated and re-quoted before it appears in a statement, and the caller's name never reaches a
statement at all: it is compared against `SHOW GRANTS` output.

## Actions

| Action | Resource | Privilege |
|---|---|---|
| `table.select` / `insert` / `update` / `delete` / `truncate` | `table:` | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE` |
| `schema.usage` / `schema.create_table` / `schema.create_view` | `schema:` | `USAGE`, `CREATE TABLE`, `CREATE VIEW` |
| `database.usage` / `database.create_schema` | `database:` | `USAGE`, `CREATE SCHEMA` |
| `warehouse.usage` / `operate` / `modify` | `warehouse:` | `USAGE`, `OPERATE`, `MODIFY` |
| `role.use` | `role:` | the role is granted, directly or through other roles |
| `account.create_database` / `account.manage_grants` | `account` | `CREATE DATABASE`, `MANAGE GRANTS` |
| `raw:<PRIVILEGE>` | any typed resource | the privilege, spelled with underscores (`raw:CREATE_STAGE`) |

`OWNERSHIP` of the object answers every question on it. An object in a schema also needs `USAGE`
(or `OWNERSHIP`) on its database and schema, which hallpass checks; a grant on the object without
them answers `denied` and says which `USAGE` is missing.

## Decisions

| Code | When |
|---|---|
| `allowed` | a reachable role holds the privilege (or `OWNERSHIP`) on the object, and `USAGE` on its parents |
| `denied` | no reachable role holds it (or the object does not exist: `SHOW GRANTS` says nothing about existence); `USAGE` on a parent is missing; the user has no role; the user is disabled |
| `unsupported` | `SHOW USERS` did not report `disabled`; more than 500 roles |
| `resource_not_visible` | a granted role's grants cannot be read by hallpass's role (Snowflake error 002003) |
| `user_not_found` / `user_ambiguous` | the user search |
| `credential_rejected` | the key-pair token is rejected (401, error 390144), the private key does not parse, or hallpass's role lacks the privilege for a `SHOW` (error 003001) |
| `invalid_request` | a malformed identifier, the wrong number of name parts, a resource type the action does not take |
| `upstream_*` | 5xx, 429, a statement that does not finish, other Snowflake errors (reported by code only; the message may echo identifiers) |

## What it cannot see

- **Future grants** before an object exists, **masking and row access policies**, **secure
  views'** underlying access, **network policies**, **session policies** and **authentication
  policies**: a `SELECT` grant may still return masked or filtered data.
- **Which role a session activates**: the answer is the union over all granted roles.
- **Object existence**: `SHOW GRANTS` does not say whether the object exists.
- **Grants through `PUBLIC`** are seen only when `PUBLIC` appears in the role walk (every user
  holds it; hallpass follows it only when `SHOW GRANTS TO USER` lists it).
- **Application roles, share grants and the `ACCOUNT_USAGE` views**.

## Unverified

Written from the SQL API specification, the official drivers' key-pair code and the documentation
of `SHOW GRANTS`, `SHOW USERS` and access control; not run against a live account. Marked
`UNVERIFIED` in the code where it matters:

- `USAGE` on the database and schema being required to reach an object in them (standard behaviour,
  not quoted from the docs).
- The `name` column's spelling of database roles (`<database>.<role>`) in `SHOW GRANTS TO ROLE`.
- The exact `SHOW GRANTS TO USER` columns after the 2025_01 change bundle; both shapes are read.

## Test

`go test ./internal/integrations/snowflake/` runs a fake SQL API validated against the
specification when `HALLPASS_SPECS_DIR` holds `snowflake-sqlapi.spec` (`test/specs/fetch.sh`). The
fake verifies the key-pair JWT's signature and claims with the test key, answers `SHOW USERS` (with
`LIKE`, `LIMIT` and `FROM` paging), `SHOW GRANTS TO USER` in both shapes, `SHOW GRANTS TO ROLE` and
`SHOW GRANTS TO DATABASE ROLE`, and can answer asynchronously (202 and polling) and in partitions.
`FuzzParseTarget` and `FuzzIdentifier` check that only well-formed, safely quoted identifiers are
accepted.
