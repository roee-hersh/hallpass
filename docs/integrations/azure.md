# azure

One connection is one Entra tenant's Azure Resource Manager. hallpass authenticates as an app
registration, resolves the user to an Entra object id, lists the role assignments and deny
assignments that apply to that user at a scope (inherited from parent scopes and through group
membership, which Azure's `assignedTo()` filter expands), reads the role definitions and evaluates
`actions` minus `notActions` (or `dataActions` minus `notDataActions`) the way Azure Resource
Manager does. A deny assignment wins over any grant. Nothing is written.

## Credential

An **app registration** with a **client secret** (`credential`). Grant it:

- the built-in **Reader** role (`*/read`, which includes `Microsoft.Authorization/roleAssignments/read`,
  `roleDefinitions/read` and `denyAssignments/read`) at the root management group, or at every
  subscription hallpass is asked about. Assignments at a scope the app cannot read answer
  `resource_not_visible`.
- for identity, either a `microsoft365_connection` (the microsoft365 integration's app resolves the
  user; nothing else is needed on this app), or the Graph application permission `User.Read.All`
  on this app so hallpass can look the user up itself.

`hallpass probe` fetches an ARM token, lists the built-in role definitions and, without a
`microsoft365_connection`, lists one Graph user.

## Connection

```yaml
  - id: azure-corp
    integration: azure
    tenant_id: 11111111-2222-3333-4444-555555555555
    client_id: 66666666-7777-8888-9999-000000000000
    credential: env:AZURE_CLIENT_SECRET
    # microsoft365_connection: m365-corp
    # url: https://management.azure.com            # https://management.usgovcloudapi.net for Azure Government
    # graph_url: https://graph.microsoft.com
    # authority_url: https://login.microsoftonline.com
```

| Key | Meaning |
|---|---|
| `tenant_id` | the tenant id or domain |
| `client_id` | the app registration's application id |
| `credential` | the client secret, `env:` or `file:` |
| `microsoft365_connection` | optional: resolve users through that connection |
| `url`, `graph_url`, `authority_url` | the ARM, Graph and token endpoints (sovereign clouds) |

### Identity

With a `microsoft365_connection`, that connection's identity (object id, `account_enabled`) is
used. Otherwise `GET /v1.0/users?$filter=mail eq '<email>' or userPrincipalName eq '<email>'`,
compared exactly; none is `user_not_found`, two are `user_ambiguous`. A disabled account is denied
every action. Groups sent by the caller are ignored: Azure expands the user's transitive group
memberships itself through `$filter=assignedTo('{objectId}')`.

## Resources

| Resource | Scope |
|---|---|
| `managementgroup:<name>` | `/providers/Microsoft.Management/managementGroups/<name>` |
| `subscription:<guid>` | `/subscriptions/<guid>` |
| `resourcegroup:<guid>/<name>` | `/subscriptions/<guid>/resourceGroups/<name>` |
| `resource:/subscriptions/.../providers/<ns>/<type>/<name>[/<type>/<name>]` | the full ARM id |

Every segment is validated and path-escaped before it reaches the URL.

## Actions

| Action | Operation | Plane |
|---|---|---|
| `vm.read` | `Microsoft.Compute/virtualMachines/read` | control |
| `vm.start` / `vm.restart` / `vm.deallocate` | `Microsoft.Compute/virtualMachines/{start,restart,deallocate}/action` | control |
| `vm.delete` | `Microsoft.Compute/virtualMachines/delete` | control |
| `storage.listkeys` | `Microsoft.Storage/storageAccounts/listkeys/action` | control |
| `storage.blob.read` / `storage.blob.write` | `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/{read,write}` | data |
| `keyvault.secret.read` / `keyvault.secret.write` | `Microsoft.KeyVault/vaults/secrets/{getSecret,setSecret}/action` | data (RBAC permission model) |
| `aks.admin_credentials` / `aks.user_credentials` | `Microsoft.ContainerService/managedClusters/listCluster{Admin,User}Credential/action` | control |
| `rbac.write` | `Microsoft.Authorization/roleAssignments/write` | control |
| `resourcegroup.delete` | `Microsoft.Resources/subscriptions/resourceGroups/delete` | control |
| `deployment.write` | `Microsoft.Resources/deployments/write` | control |
| `raw:<operation>` | any control-plane operation | control |
| `data:<operation>` | any data-plane operation | data |

Wildcards are not accepted in `raw:` or `data:`; role definitions carry them.

### Evaluation

1. `GET {scope}/providers/Microsoft.Authorization/denyAssignments?$filter=assignedTo('{oid}')`.
   Each deny whose scope is the target or an ancestor (honouring `doNotApplyToChildScopes`) and
   whose `actions` minus `notActions` (or data equivalents) match the operation **denies**, unless
   `excludePrincipals` names the user. A deny with a `condition`, one excluding a **group** (hallpass
   does not read group membership), or one at a management group whose relation to a management-group
   target is unknown, makes the answer `unsupported` if a role would otherwise grant.
2. `GET {scope}/providers/Microsoft.Authorization/roleAssignments?$filter=assignedTo('{oid}')`. Each
   assignment whose scope is the target or an ancestor is read (`GET {roleDefinitionId}`, cached five
   minutes); the first whose permissions grant the operation **allows**, naming the role, whether it
   was assigned directly or through a group, and the scope. An assignment with an ABAC `condition`
   counts only as a conditional grant: if nothing else grants, `unsupported`.
3. Assignments below the target scope do not apply. Management-group and tenant-root assignments
   are ancestors of every subscription; for a management-group target, an assignment at a different
   management group is `unsupported` since the hierarchy is not read.

## Decisions

| Code | When |
|---|---|
| `allowed` | an unconditional assignment at or above the scope grants the operation and no deny blocks it |
| `denied` | a deny assignment blocks it; no assignment at or above the scope grants it; the account is disabled |
| `unsupported` | only conditional grants; an uncertain deny (condition, excluded group, management-group scope); a management-group assignment whose place in the hierarchy is unknown |
| `resource_not_visible` | ARM answers 404, or 403 `AuthorizationFailed` (no Reader at the scope) |
| `user_not_found` / `user_ambiguous` | the Graph lookup |
| `credential_rejected` | the token endpoint rejects the client; 401; 403 other than `AuthorizationFailed` |
| `invalid_request` | a malformed scope or operation; a resource type or action the integration does not take |
| `upstream_*` | 5xx, 429, timeouts, a `nextLink` off the ARM endpoint, a role definition that cannot be read |

## What it cannot see

- **ABAC conditions** on role or deny assignments are not evaluated.
- **Group membership** for `excludePrincipals` on deny assignments.
- **The management-group hierarchy**: which management group holds a subscription.
- **Classic administrators**, **Azure Lighthouse** delegations (not returned by the listing),
  **Elevate access** for Global Administrators, and resource-provider-specific checks (Key Vault
  access policies when the vault is not in the RBAC permission model, storage account keys).
- **Service principals and managed identities** as the subject: identity is resolved from a user
  email.

## Unverified

Written from the authorization REST specification (2022-04-01), the Azure RBAC documentation source
and the Graph documentation; not run against a live tenant. Marked `UNVERIFIED` in the code where
it matters:

- Operation matching is case-insensitive and `*` spans slashes, as the documentation's examples
  imply.
- Whether `assignedTo()` on deny assignments already applies `excludePrincipals` (hallpass applies
  them again, which is safe).
- The tenant-root listing `GET /providers/Microsoft.Authorization/roleDefinitions` used by the probe
  is not in the specification file, though `az role definition list` uses it.

## Test

`go test ./internal/integrations/azure/` runs a fake token endpoint, Graph and ARM validated
against `authorization-RoleAssignmentsCalls`, `authorization-RoleDefinitionsCalls`,
`authorization-DenyAssignmentCalls` and the Graph description when `HALLPASS_SPECS_DIR` holds them
(`test/specs/fetch.sh`). The fake has Reader, Contributor, Owner, a data-plane role and a custom
role, assignments direct and through a group at management-group, subscription, resource-group and
resource scopes, a conditional assignment, and deny assignments with exclusions, conditions and
`doNotApplyToChildScopes`. `FuzzParseTarget` checks that only well-formed scopes and operations
reach the API.
