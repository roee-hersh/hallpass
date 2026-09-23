# databricks

One connection is one Databricks workspace. hallpass authenticates as a service principal (OAuth
M2M) or with a personal access token, finds the user through the workspace SCIM API (email, active
flag, groups), and asks the workspace itself. Unity Catalog securables (catalogs, schemas, tables,
volumes, functions, models) are answered from the effective-permissions endpoint, which folds in
privileges inherited down the hierarchy; grants to the user and to any of the user's groups count,
and the securable's owner holds every privilege. Workspace objects (clusters, jobs, warehouses,
notebooks, ...) are answered from the Permissions API ACL, whose entries include inherited ones;
workspace admins hold `CAN_MANAGE` on every object. Nothing is written.

## Credential

1. Create a service principal in the account console, add it to the workspace, and generate an
   OAuth secret for it (`client_id` is its application id, `credential` the secret). A personal access
   token of a dedicated user works too (`auth_mode: token`).
2. Decide what it may read. Databricks has **no read-only admin role**:
   - the Permissions API returns an object's ACL only to a principal with `CAN_MANAGE` on that object
     (or a workspace admin);
   - Unity Catalog returns another principal's grants only to a metastore admin, the securable's
     owner, the owner of its catalog or schema, or a principal with `MANAGE` on it.

   Making the service principal a **workspace admin** answers every workspace-object question, and
   granting it `MANAGE` (or `BROWSE` plus ownership through a group) on the catalogs it should answer
   for covers Unity Catalog. A workspace admin can also change the workspace, so keep the secret
   tightly held. Whatever hallpass cannot read answers `unknown`, never `deny`.

`hallpass probe` reads the credential's own SCIM record and says whether it is a workspace admin.

## Connection

```yaml
  - id: databricks-prod
    integration: databricks
    url: https://adb-1234567890123456.7.azuredatabricks.net
    client_id: a1b2c3d4-e5f6-7890-abcd-ef1234567890   # service principal application id
    credential: env:DATABRICKS_OAUTH_SECRET            # its OAuth secret
    # auth_mode: token                                 # then credential is a personal access token
    # admins_manage_all: "true"                        # workspace admins pass every workspace-object check
```

| Key | Meaning |
|---|---|
| `url` | the workspace URL |
| `auth_mode` | `oauth` (default): client credentials with `client_id` and the secret; `token`: a personal access token |
| `client_id` | the service principal's application id, `oauth` only |
| `credential` | the OAuth secret or the personal access token, `env:` or `file:` |
| `token_url` | default `{url}/oidc/v1/token` |
| `admins_manage_all` | `true` (default): a member of the workspace `admins` group is allowed every workspace-object action, as Databricks grants admins `CAN_MANAGE` on every object; `false`: judge admins by the ACL alone |

OAuth: `POST {token_url}` with `grant_type=client_credentials&scope=all-apis` and the client id and
secret in an HTTP Basic header, as Databricks documents. The token is cached and refreshed five
minutes before it expires; a 401 from the workspace drops it and retries the call once. Every API
call carries `Authorization: Bearer`.

### Identity

`GET /api/2.0/preview/scim/v2/Users?filter=userName eq "<email>"&attributes=id,userName,active,groups`.
The email is lowercased and must be a plain address (no quotes or backslashes, so the SCIM filter
cannot be broken out of); the record whose `userName` equals it case-insensitively is the user. No
record is `user_not_found`, two are `user_ambiguous`. A user with `active: false` is denied every
action; a record without `active` is unknown. The user's groups are the `groups[].display` names of
the record; membership of `admins` marks a workspace admin. Groups sent by the caller are ignored.

## Resources

| Resource | Meaning |
|---|---|
| `catalog:<catalog>` | a Unity Catalog catalog |
| `schema:<catalog>.<schema>` | a schema |
| `table:<catalog>.<schema>.<table>` | a table or view |
| `volume:<catalog>.<schema>.<volume>` | a volume |
| `function:<catalog>.<schema>.<function>` | a function |
| `model:<catalog>.<schema>.<model>` | a registered model in Unity Catalog |
| `cluster:<id>` | an all-purpose cluster (Permissions API `clusters`) |
| `policy:<id>` | a cluster policy (`cluster-policies`) |
| `pool:<id>` | an instance pool (`instance-pools`) |
| `job:<id>` | a job (`jobs`) |
| `pipeline:<id>` | a pipeline (`pipelines`) |
| `warehouse:<id>` | a SQL warehouse (`warehouses`) |
| `notebook:<object id>`, `directory:<object id>`, `repo:<id>` | workspace files (`notebooks`, `directories`, `repos`); the numeric object id, not the path |
| `endpoint:<name>` | a model serving endpoint (`serving-endpoints`) |
| `experiment:<id>`, `registered_model:<id>` | MLflow experiments and workspace model registry models |

Each part of a Unity Catalog name must be a plain identifier (`[A-Za-z0-9_-]`, up to 255 characters);
names that need backtick quoting in SQL are not accepted. A workspace object id is
`[A-Za-z0-9][A-Za-z0-9_.-]*`. Both are path-escaped before they reach a URL.

## Actions

| Action | Requires | Resources |
|---|---|---|
| `raw:<PRIVILEGE>` | that one Unity Catalog privilege (`raw:SELECT`, `raw:CREATE_VOLUME`) | any Unity Catalog resource |
| `raw:<LEVEL>` | that permission level or one that implies it (`raw:CAN_RESTART`, `raw:IS_OWNER`); a level the object type does not have is `invalid_request` | any workspace object |
| `table.read` | `SELECT` + `USE_SCHEMA` + `USE_CATALOG` | table |
| `table.write` | `MODIFY` + `USE_SCHEMA` + `USE_CATALOG` | table |
| `table.create` | `CREATE_TABLE` + `USE_SCHEMA` + `USE_CATALOG` | schema |
| `schema.create` | `CREATE_SCHEMA` + `USE_CATALOG` | catalog |
| `catalog.use` | `USE_CATALOG` | catalog |
| `volume.read` / `volume.write` | `READ_VOLUME` / `WRITE_VOLUME` + `USE_SCHEMA` + `USE_CATALOG` | volume |
| `function.execute` | `EXECUTE` + `USE_SCHEMA` + `USE_CATALOG` | function |
| `uc.manage` | `MANAGE`, or ownership | any Unity Catalog resource |
| `cluster.attach` / `cluster.restart` / `cluster.manage` | `CAN_ATTACH_TO` / `CAN_RESTART` / `CAN_MANAGE` | cluster |
| `job.view` / `job.run` / `job.manage` | `CAN_VIEW` / `CAN_MANAGE_RUN` / `CAN_MANAGE` | job |
| `warehouse.use` / `warehouse.manage` | `CAN_USE` / `CAN_MANAGE` | warehouse |
| `notebook.read` / `notebook.run` / `notebook.edit` | `CAN_READ` / `CAN_RUN` / `CAN_EDIT` | notebook, directory, repo |
| `pipeline.run` | `CAN_RUN` | pipeline |
| `endpoint.query` | `CAN_QUERY` | endpoint |

Unity Catalog: `ALL_PRIVILEGES` covers every privilege, and the legacy `USAGE` counts as both
`USE_CATALOG` and `USE_SCHEMA`. Privileges are read from
`GET /api/2.1/unity-catalog/effective-permissions/{type}/{name}?max_results=0`, every page, and
unioned over the user and the user's groups. When they do not cover the action, the securable's
`owner` is read (`GET /api/2.1/unity-catalog/{tables,schemas,...}/{name}`). Ownership, directly or
through a group, stands for every privilege on the securable itself, but not for `USE_CATALOG` or
`USE_SCHEMA` on its parents: a table owner without `USE_SCHEMA` is denied `table.read`, as Databricks
would refuse the query.

Unity Catalog shows a principal without `MANAGE`, ownership or metastore admin only its own grants,
with a 200 rather than a 403. A listing in which no principal but hallpass itself appears is
therefore not a deny: it is answered `resource_not_visible` ("either nobody else holds any, or
hallpass may only see its own"). hallpass learns its own principal name from `GET
/api/2.0/preview/scim/v2/Me`, once every ten minutes.

Workspace objects: the ACL is `GET /api/2.0/permissions/{type}/{id}`. A level implies the weaker ones
of its chain (`CAN_ATTACH_TO` < `CAN_RESTART` < `CAN_MANAGE`; `CAN_VIEW` < `CAN_MANAGE_RUN` <
`IS_OWNER` < `CAN_MANAGE`; `CAN_READ` < `CAN_RUN` < `CAN_EDIT` < `CAN_MANAGE`; `CAN_VIEW` <
`CAN_QUERY` < `CAN_MANAGE`; warehouses `CAN_VIEW` < `CAN_MONITOR` and `CAN_VIEW` < `CAN_USE`, both
under `CAN_MANAGE`), and `CAN_MANAGE` and `IS_OWNER` imply everything. `CAN_MONITOR` does not imply
`CAN_USE`. Entries for service principals never match a user.

## Decisions

| Situation | hallpass answers |
|---|---|
| the needed privileges are all held (directly, through a group, or inherited from a parent securable), or `ALL_PRIVILEGES` | allow, saying where they come from |
| privileges missing but the user (or a group of theirs) owns the securable | allow ("owns ...") |
| privileges missing, the owner, but `USE_CATALOG` / `USE_SCHEMA` on a parent missing | deny ("owns ... but lacks ... on its parents") |
| privileges missing, not the owner, and the listing names a principal other than hallpass | deny, naming the missing privileges |
| privileges missing, not the owner, and the listing names nobody but hallpass | unknown (`resource_not_visible`) |
| a held level equals or implies the needed one | allow |
| no matching level, user is a workspace admin, `admins_manage_all: true` | allow ("workspace admin") |
| no matching level otherwise | deny, naming the levels held |
| deactivated user (`active: false`) | deny |
| no SCIM record for the email | deny (`user_not_found`) |
| several records | unknown (`user_ambiguous`) |
| record without `active` | unknown (`unsupported`) |
| securable or object answers 404 | unknown (`resource_not_visible`) |
| 403 `PERMISSION_DENIED` (hallpass lacks `CAN_MANAGE`, `MANAGE` or ownership) | unknown (`credential_rejected`) |
| 401 after one retry with a fresh token, token endpoint refuses the client | unknown (`credential_rejected`) |
| the SCIM search endpoint itself answers 404 (wrong `url`, an account console URL) | unknown (`upstream_error`) |
| 400 `INVALID_PARAMETER_VALUE` | unknown (`invalid_request`) |
| 429, 5xx, timeout, too many pages of grants | unknown (`upstream_rate_limited` / `upstream_error` / `upstream_timeout`) |

Only `error_code` is read from an error body; messages are never copied into a decision text.

## Probe

`hallpass probe` calls `GET /api/2.0/preview/scim/v2/Me`, names the principal and whether it is a
workspace admin, and warns either way: a non-admin cannot read most ACLs, an admin can change the
workspace.

## What it cannot see

- Metastore admins: their implicit privileges are not in SCIM or in the effective-permissions list,
  so a metastore admin without grants is denied Unity Catalog actions.
- Ownership of a parent (a catalog owner acting on a table) is not modelled; only the securable's
  own owner is, and only for privileges on that securable.
- Account-level groups the workspace SCIM record does not list, row filters and column masks,
  Lakehouse Federation credentials, table ACLs on the legacy Hive metastore, and the entitlements
  (`workspace-access`, `databricks-sql-access`, `allow-cluster-create`) that gate features rather than
  objects.
- Whether a cluster's access mode lets the user attach at all, and cluster policies' effect on
  what a job may run.

## Unverified

Marked `// UNVERIFIED:` in the code:

- Whether the effective-permissions endpoint already lists the owner's implicit privileges. The owner
  is looked up separately so an owner is never denied; if the API does list them the extra call is
  merely redundant.

Not marked in code, but assumed from Databricks' documentation rather than tested live: that a
`principal=`-less effective-permissions listing includes group principals by their display name, so
unioning over the user's SCIM groups is what "effective" means; that the workspace `admins` group
carries `CAN_MANAGE` on every Permissions API object even when the ACL does not show an entry for it;
and that `IS_OWNER` on jobs, pipelines and warehouses implies `CAN_MANAGE`.

## Test

Unit tests run against one fake server that serves the token endpoint (checking the Basic header and
the form), SCIM, effective permissions (paginated), securable metadata and the Permissions API.
Databricks publishes no OpenAPI description to validate requests against, so the fake checks paths
and parameters itself. There is no live test; after configuring, run `hallpass probe` and one check
for a user you know is allowed.
