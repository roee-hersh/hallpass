# aws

One connection is one AWS account. hallpass assumes a read-only role in that account, works out which
IAM principals the user can act as (the `AWSReservedSSO_*` roles of their IAM Identity Center permission
sets, a static email/group -> role map, or an IAM user), and asks `iam:SimulatePrincipalPolicy` whether
each principal may perform the action on the ARN. IAM evaluates the principal's identity policies,
permissions boundary and the organization's SCPs. Any principal allowed answers allow; nothing is written.

## Credential

hallpass needs two things: a credential to start from, and a role to assume in the account.

### The starting credential

`credential` is a secret (`env:` or `file:`) whose value is either

- JSON static keys: `{"access_key_id":"AKIA...","secret_access_key":"...","session_token":"..."}`
  (`session_token` optional), or
- the literal `ambient:auto`, `ambient:container`, `ambient:web_identity` or `ambient:imds`, meaning
  "use the credentials of the environment hallpass runs in": environment keys, the ECS/EKS Pod Identity
  container endpoint, IRSA (`AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE`) or the EC2 instance metadata
  service. `auto` tries them in that order.

The config loader only accepts `env:`/`file:` references for secrets, so an ambient mode is written as a
reference to a variable holding the literal:

```sh
export HALLPASS_AWS_CRED=ambient:imds
```

```yaml
    credential: env:HALLPASS_AWS_CRED
```

The secret is re-read whenever the assumed-role credentials are refreshed (about every 55 minutes), so a
rotated key file is picked up without a restart. Ambient and assumed-role credentials are cached and
refreshed 5 minutes before they expire.

### The role in the account (`role_arn`)

A role in `account_id` that trusts the starting credential (with `external_id` if set). Minimum policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Simulate",
      "Effect": "Allow",
      "Action": ["iam:SimulatePrincipalPolicy", "iam:GetContextKeysForPrincipalPolicy"],
      "Resource": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/*"
    },
    { "Sid": "ListRoles", "Effect": "Allow", "Action": "iam:ListRoles", "Resource": "*" },
    { "Sid": "WhoAmI", "Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*" }
  ]
}
```

For `static_map` the `Simulate` statement's resource must cover the roles named in the map file; for
`iam_user` it must cover `arn:aws:iam::123456789012:user/*` and the role also needs `iam:GetUser`.
`sts:GetCallerIdentity` is always allowed and is listed only for clarity.

### The Identity Center role (`identity_center_role_arn`, mode `identity_center`)

A role in the organization's management account or the Identity Center delegated administrator account,
trusting the same starting credential:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "identitystore:GetUserId",
        "identitystore:DescribeUser",
        "identitystore:ListGroupMembershipsForMember",
        "sso:ListAccountAssignmentsForPrincipal",
        "sso:DescribePermissionSet",
        "sso:ListInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

`hallpass probe` assumes both roles, reports the caller ARN, counts the `AWSReservedSSO_*` roles in the
account and, in `identity_center` mode, checks that `sso_instance_arn` and `identity_store_id` match what
`sso:ListInstances` returns. It always warns that `iam:SimulatePrincipalPolicy` discloses information
about the permissions granted to other users: that is what hallpass is for, but the role should be held
by hallpass alone.

## Connection

```yaml
  - id: aws-prod
    integration: aws
    account_id: "123456789012"
    role_arn: arn:aws:iam::123456789012:role/hallpass-read
    external_id: 7f3a...                          # optional
    partition: aws                                # aws (default), aws-us-gov, aws-cn
    region: eu-west-1                             # STS endpoint region
    credential: env:HALLPASS_AWS_CRED             # JSON keys, or ambient:<mode>
    identity_mode: identity_center                # identity_center (default), static_map, iam_user
    identity_center_role_arn: arn:aws:iam::999999999999:role/hallpass-identity-center-read
    identity_center_region: eu-west-1
    identity_store_id: d-9367xxxxxx
    sso_instance_arn: arn:aws:sso:::instance/ssoins-6987xxxxxxxxxxxx
    context_entries: "aws:MultiFactorAuthPresent=boolean:true;aws:SourceIp=ip:10.0.0.1"   # optional
    implicit_deny_as: deny                        # deny (default) or unknown
    session_name: hallpass                        # optional
```

| Key | Meaning |
|---|---|
| `account_id` | the 12-digit account this connection answers for. `role_arn` must be in it |
| `role_arn` | hallpass's read role in the account |
| `external_id` | sent as `ExternalId` on every `AssumeRole` (both roles) |
| `partition` | `aws`, `aws-us-gov` or `aws-cn`; picks the endpoints and must match every ARN |
| `region` | region of the STS endpoint used for `AssumeRole` |
| `credential` | the starting credential, see above |
| `identity_mode` | how an email becomes IAM principals, see below |
| `identity_center_role_arn` | `identity_center`: read role in the Identity Center account |
| `identity_center_region` | `identity_center`: the region Identity Center is enabled in (Identity Store and SSO Admin endpoints) |
| `identity_store_id` | `identity_center`: `d-` + 10 hex digits |
| `sso_instance_arn` | `identity_center`: `arn:aws:sso:::instance/ssoins-...` |
| `role_map_file` | `static_map`: the map file, see below |
| `context_entries` | condition keys for the simulation: `key=type:value;key=type:value`; types `string`, `stringList` (comma-separated values), `numeric`, `boolean`, `ip`, `binary`, `date` |
| `implicit_deny_as` | what "no statement matched" (and, for `identity_center`, "no permission set assigned") answers: `deny` (default) or `unknown` |
| `session_name` | `RoleSessionName`, default `hallpass` |

Endpoints: STS `https://sts.<region>.amazonaws.com`, IAM `https://iam.amazonaws.com` (signed for
`us-east-1`; `iam.us-gov.amazonaws.com` for GovCloud), Identity Store
`https://identitystore.<identity_center_region>.amazonaws.com` (JSON 1.1, `X-Amz-Target:
AWSIdentityStore.<Op>`), SSO Admin `https://sso.<identity_center_region>.amazonaws.com` (JSON 1.1,
`SWBExternalService.<Op>`). Every call is a SigV4-signed POST.

### Identity modes

| Mode | Lookup | Principals |
|---|---|---|
| `identity_center` | `identitystore:GetUserId` by `emails.value`, then by `userName`; `DescribeUser`; `ListGroupMembershipsForMember`; `sso:ListAccountAssignmentsForPrincipal` for the user and for each group, filtered to `account_id`; `sso:DescribePermissionSet` for the names; `iam:ListRoles` under `/aws-reserved/sso.amazonaws.com/` | the account's `AWSReservedSSO_<PermissionSet>_<16 hex>` role of every assigned permission set. The name match is anchored, so `Admin` never matches permission set `Adm` |
| `static_map` | `role_map_file`, matched case-insensitively against the email and the request's groups | every mapped role ARN, union |
| `iam_user` | `iam:GetUser` with the email's local part, then the full email | the IAM user |

`identity_center`: a user with no permission set assigned in the account has nothing to simulate; that
is an implicit deny, so it answers deny ("no permission set assigned in account ...") or, with
`implicit_deny_as: unknown`, unknown. Only assignment rows whose `AccountId` is exactly `account_id`
count; rows for other accounts or without one are skipped. A permission set whose role is not in the
account (not yet provisioned, or recreated with a new suffix) answers `resource_not_visible` unless
another permission set allows. The role list and the permission set names are cached in the connection
for 10 minutes; a `NoSuchEntity` from the simulation drops the role list. The email -> principals mapping
itself is the identity, which the engine caches for `identity_cache_seconds` (per connection, email and
groups); the connection keeps no copy, so a vanished role is simulated again until that entry expires.

`static_map` file format, one mapping per line, `#` comments, whitespace separated:

```
# email or group        role ARN
dana@example.com        arn:aws:iam::123456789012:role/Deployer
platform-team           arn:aws:iam::123456789012:role/PlatformAdmin
platform-team           arn:aws:iam::123456789012:role/ReadOnly
```

The file must exist and parse when hallpass starts and is re-read at most every 60 seconds; a broken
re-read keeps the last good map and logs a warning. Groups come from the caller's `groups` field.

## Resources

| Resource | Meaning |
|---|---|
| `arn:<partition>:<service>:<region>:<account>:<resource>` | that ARN, verbatim (`arn:aws:s3:::bucket/key`, `arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc`). The account field is empty or 12 digits; the partition must match the connection |
| `all` | every resource (`*`); the simulation then reports the action's overall decision |

`catalog.ParseResource` splits at the first colon, so an ARN arrives as type `arn`; hallpass uses the raw
string. An ARN whose account field names another account answers `unsupported`: cross-account access
depends on the resource policy in that account, which the simulation does not see.

## Actions

| Action | IAM action |
|---|---|
| `raw:<service>:<Action>` | exactly that, e.g. `raw:s3:GetObject`, `raw:ec2:Describe*`, `raw:iam:*` |
| `s3.read` / `s3.write` / `s3.list` | `s3:GetObject` / `s3:PutObject` / `s3:ListBucket` |
| `ec2.stop` / `ec2.start` / `ec2.terminate` | `ec2:StopInstances` / `ec2:StartInstances` / `ec2:TerminateInstances` |
| `lambda.invoke` | `lambda:InvokeFunction` |
| `iam.passrole` | `iam:PassRole` |
| `secretsmanager.read` | `secretsmanager:GetSecretValue` |
| `ssm.session` | `ssm:StartSession` |
| `sts.assume` | `sts:AssumeRole` |
| `rds.delete` | `rds:DeleteDBInstance` |
| `eks.describe` | `eks:DescribeCluster` |

One check costs one `SimulatePrincipalPolicy` per candidate principal until one allows.

## Decisions

Per principal, the action-level `EvalDecision` and the `ResourceSpecificResults` entry for the requested
ARN are merged: `allowed` only when both say so, otherwise the more restrictive wins (`explicitDeny` >
`implicitDeny` > `allowed`). An `allowed` whose result lists `MissingContextValues` is not an allow: IAM
skipped every statement conditioned on those keys, Deny statements included. Across principals:

| IAM says | hallpass answers |
|---|---|
| any principal `allowed` with no `MissingContextValues` | allow, naming the permission set / role / user |
| a principal `allowed` but with `MissingContextValues`, and no principal allowed outright | unknown (`unsupported`), naming the keys; set `context_entries` |
| action-level and resource-level decisions disagree | the more restrictive one, then as below |
| every principal `explicitDeny` | deny ("explicitly deny"; "denied by SCP" when `AllowedByOrganizations` is false, "blocked by the permissions boundary" when `AllowedByPermissionsBoundary` is false) |
| some `implicitDeny`, none allowed, `implicit_deny_as: deny` | deny |
| some `implicitDeny`, none allowed, `implicit_deny_as: unknown` | unknown (`unsupported`) |
| `MissingContextValues` non-empty and nothing allowed | unknown (`unsupported`), naming the keys; set `context_entries` |
| resource ARN in another account | unknown (`unsupported`) |
| `PolicyEvaluation` error | unknown (`unsupported`) |
| `NoSuchEntity` for the principal | unknown (`resource_not_visible`): the role vanished; the role list is dropped now, the identity is re-resolved after `identity_cache_seconds` expires |
| Identity Center user with `UserStatus` `DISABLED` | deny |
| no permission set assigned in the account, `implicit_deny_as: deny` | deny |
| no permission set assigned in the account, `implicit_deny_as: unknown` | unknown (`unsupported`) |
| no Identity Center user / IAM user / map entry for the email | `user_not_found` |
| `Throttling`, `ThrottlingException`, 429 | unknown (`upstream_rate_limited`) |
| `AccessDenied`, `InvalidClientTokenId`, `ExpiredToken`, 401/403 | unknown (`credential_rejected`): a role trust or one of the policies above is missing |

## What it cannot see

The simulation covers identity-based policies, permissions boundaries and SCPs. It does not evaluate:

- resource control policies (RCPs), resource-based policies (bucket, key, queue, secret, role trust
  policies), VPC endpoint policies, session policies of a real session, or role chaining;
- KMS grants, S3 ACLs and access points, Lake Formation permissions;
- real condition context: request tags, resource tags, MFA, source IP and every other key are whatever
  `context_entries` says (missing keys answer unknown), not what the user's session would carry;
- the IAM "account access manager" (`sso:` account access) role assignments made outside permission sets;
- for `identity_center`, that the user can actually sign in (Identity Center session policies, device or
  network conditions of the identity provider).

`iam:SimulatePrincipalPolicy` discloses permissions of other principals to whoever holds `role_arn`.

## Unverified

Marked `# UNVERIFIED:` in the code:

- `identitystore:DescribeUser` returning a `UserStatus` field; when present and `DISABLED` the user is
  denied every action, otherwise the field is ignored.
- Whether `sso:ListAccountAssignmentsForPrincipal` for a `USER` already includes assignments inherited
  through groups; hallpass asks for the user and for every group and unions the result, so the answer is
  the same either way at the cost of extra calls.
- `AWSReservedSSO_*` roles under `/aws-reserved/sso.amazonaws.com/<region>/`; `iam:ListRoles` with the
  parent `PathPrefix` is a prefix match so they are expected to be listed.
- For resource `all`, `ResourceArns` is omitted so IAM applies its documented default of `*`, rather than
  sending `*` as an ARN.
- The China partition IAM endpoint and signing region (`hallpass/authx`).
- Whether SCP evaluation (`OrganizationsDecisionDetail`) needs any `organizations:*` permission on
  `role_arn`; none is granted in the policy above.

## Test

Unit tests run against one fake server that serves STS, IAM (Query/XML), Identity Store and SSO Admin
(JSON 1.1 by `X-Amz-Target`) and IMDSv2, checking the SigV4 credential scope of every call. There is no
live test; after configuring, run `hallpass probe` and one check for a user you know is allowed.
