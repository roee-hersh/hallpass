# vault

One connection is one HashiCorp Vault (one namespace). hallpass authenticates with a token or an
AppRole, finds the identity entity whose alias on the configured auth mount is the user's email,
collects the ACL policies attached to the entity, its groups (direct and inherited) and the auth
role (declared in the connection), reads each policy and evaluates the requested path and
capability with Vault's own rules. Nothing is written.

## Credential

Either of:

1. A **token** (`auth_mode: token`, the default), for instance a periodic service token.
2. An **AppRole** (`auth_mode: approle`): `role_id` and the `secret_id` as `credential`; hallpass
   logs in at `auth/<approle_mount>/login` and renews the token by logging in again when it
   expires or is revoked.

Attach a policy with exactly these capabilities:

```hcl
path "identity/lookup/entity"     { capabilities = ["update"] }
path "identity/entity/id/*"       { capabilities = ["read"] }
path "identity/group/id/*"        { capabilities = ["read"] }
path "sys/policies/acl/*"         { capabilities = ["read"] }
path "sys/auth"                   { capabilities = ["read"] }
path "sys/mounts"                 { capabilities = ["read"] }
path "auth/token/lookup-self"     { capabilities = ["read"] }
```

`sys/auth` resolves the alias mount's accessor, `sys/mounts` the KV version of a mount. Nothing
under the secrets engines themselves is read.

`hallpass probe` looks the token up and resolves the alias mount's accessor.

## Connection

```yaml
  - id: vault-prod
    integration: vault
    url: https://vault.example.com:8200
    alias_mount: oidc/
    credential: env:VAULT_TOKEN
    # auth_mode: approle
    # role_id: 7f1c...
    # approle_mount: approle
    # token_policies: developers, oncall   # policies the oidc role attaches at login
    # namespace: admin/                    # Vault Enterprise, sent as X-Vault-Namespace
```

| Key | Meaning |
|---|---|
| `url` | the Vault address |
| `alias_mount` | the auth mount whose aliases carry the users' emails (`oidc/`, `ldap/`, `okta/`) |
| `credential` | the token or the AppRole `secret_id`, `env:` or `file:` |
| `auth_mode`, `role_id`, `approle_mount` | AppRole login |
| `token_policies` | policies every login through the alias mount receives (see below) |
| `namespace` | the Enterprise namespace |

### Identity

`POST identity/lookup/entity` with `alias_name` = the email and `alias_mount_accessor` = the
alias mount's accessor; no entity is `user_not_found`. Then `GET identity/entity/id/<id>` for the
entity's policies, `disabled` flag, metadata, aliases and group ids, and `GET identity/group/id/<id>`
for each direct and inherited group's name and policies. A disabled entity is denied every action.
The identity's groups are the group ids; its attributes carry the entity name, metadata, aliases and
group names so that policy templates can be resolved. Groups sent by the caller are ignored.

### Which policies

Vault attaches policies to a token from three places. hallpass sees two of them and takes the third
from configuration:

| Source | Read by hallpass |
|---|---|
| the entity's `policies` | yes |
| the policies of the entity's groups, direct and inherited (external groups included) | yes |
| the auth method role's `token_policies` (the OIDC role, the LDAP group mapping) | **no**: declare them in `token_policies` |
| `default` | assumed attached (UNVERIFIED for auth methods that exclude it) |

A policy named `root` allows everything. A policy a token names but Vault does not have contributes
nothing, as in Vault.

## Resources

| Resource | Meaning |
|---|---|
| `kv:<mount>/<key>` | a secret in a KV engine; the KV version comes from `sys/mounts` and the API path is derived (`<mount>/data/<key>`, `metadata`, `destroy` on v2; the logical path on v1) |
| `path:<api path>` | any API path, checked as written (`sys/seal`, `pki/issue/web`, `secret/data/x`) |

Paths are plain segments (letters, digits, `_ . - @ : ~ =`); wildcards and dot-only segments are
rejected. `LIST` questions are matched with a trailing slash, the way Vault sanitizes list requests.

## Actions

| Action | Capability | KV v2 path |
|---|---|---|
| `secret.read` | `read` | `<mount>/data/<key>` |
| `secret.write` | `create` and `update` (see below) | `<mount>/data/<key>` |
| `secret.delete` | `delete` | `<mount>/data/<key>` |
| `secret.list` | `list` (prefix) | `<mount>/metadata/<key>/` |
| `secret.metadata` | `read` | `<mount>/metadata/<key>` (v2 only) |
| `secret.destroy` | `update` | `<mount>/destroy/<key>` (v2 only) |
| `raw:<capability>` | `read`, `create`, `update`, `patch`, `delete`, `list`, `sudo`, `subscribe`, `recover` on a `path:` |

A **write** is `create` for a new secret and `update` for an existing one. When the policies grant
both the answer is `allowed`, neither `denied`, one of the two `unsupported` (the write succeeds
only if the secret does or does not exist yet).

### Evaluation

Vault's documented rules, applied to the union of the policies' stanzas:

1. Stanzas whose path matches the request path are candidates: an exact path, `+` for any
   characters within one segment, a trailing `*` for any suffix. `*` elsewhere is literal.
2. The highest-priority pattern wins: the one whose first wildcard comes latest, then one without a
   trailing glob, then fewer `+`, then longer, then lexicographically greater. The same pattern in
   several policies takes the union of its capabilities.
3. `deny` in the winning stanza denies. Otherwise the needed capability must be present.
4. `{{identity.entity.id}}`, `.name`, `.metadata.<k>`, `.aliases.<accessor>.id|name|metadata.<k>`,
   `{{identity.groups.ids.<id>.name}}` and `{{identity.groups.names.<name>.id}}` are resolved for
   the user. A template that cannot be resolved makes the stanza match one segment there and, if it
   wins or outranks the winner, the answer is `unsupported`.
5. `allowed_parameters`, `denied_parameters` and `required_parameters` on a write, and
   `min_wrapping_ttl` / `max_wrapping_ttl`, answer `unsupported`: hallpass does not see the request
   body.

Policies in HCL (including the deprecated `policy = "read|write|sudo|deny"` attribute and
`path = { ... }` maps) and in JSON (object and list forms) are parsed. Heredocs and other syntax
answer `unsupported`.

## Decisions

| Code | When |
|---|---|
| `allowed` | the winning stanza grants the capability, or the entity holds `root` |
| `denied` | no stanza matches; the winning stanza denies or lacks the capability; the entity is disabled |
| `unsupported` | a parameter or wrapping constraint; an unresolvable template; a policy hallpass cannot parse; a KV v2 question on a v1 mount; a non-KV mount asked with `kv:`; a mixed create/update write |
| `resource_not_visible` | `kv:` names a mount `sys/mounts` does not list |
| `user_not_found` | no entity has the alias |
| `credential_rejected` | 403 permission denied on a read hallpass needs; the AppRole login fails |
| `invalid_request` | a malformed path or resource; `alias_mount` is not an enabled auth method |
| `upstream_*` | 5xx, 429, 412, timeouts, a sealed Vault |

## What it cannot see

- **Token policies from auth roles**, unless declared in `token_policies`.
- **Sentinel** (EGP and RGP) policies, **control groups**, **MFA** enforcement.
- **Request parameters**: `allowed_parameters` and friends.
- **Namespaces above the connection's**: policies granted in a parent namespace on child paths.
- **Token-specific state**: TTLs, uses, bound CIDRs, `sudo` paths' `x-vault-sudo` requirement is
  not checked unless asked with `raw:sudo`.
- **Path aliases** resolved by engines (e.g. `secret/foo` on KV v2 rewritten by the CLI): hallpass
  checks the API path, so use `kv:` for KV engines.

## Unverified

Written from Vault's documentation source (policies, identity, system API) and the OpenAPI document
in `vault-client-go`; not run against a live Vault. Marked `UNVERIFIED` in the code where it
matters:

- The `default` policy is attached to every token of the alias mount.
- The capabilities the deprecated `policy = "read|write|sudo"` attribute maps to.
- `identity/lookup/entity` answers 204 for no match (an empty `data` is also taken as none).
- `sys/policies/acl/<name>` wraps `policy` in `data` (the top-level form is also read).

## Test

`go test ./internal/integrations/vault/` runs a fake Vault validated against the OpenAPI document
when `HALLPASS_SPECS_DIR` holds `vault.spec` (`test/specs/fetch.sh`). The fake has an OIDC mount,
entities with direct and inherited groups, a disabled entity, a `root` entity, HCL and JSON
policies with globs, `+` segments, templates, a legacy `policy` attribute, parameter and wrapping
constraints, KV v1 and v2 mounts and a PKI mount, and an AppRole login. `FuzzParseTarget` checks
the path validation and `FuzzPolicy` that the policy parser and evaluator never panic.
