# Integrations

Twenty-one systems. Two are exercised against the real thing in CI; most validate every request
their tests make against the vendor's published API description; none has yet been confirmed
against a live account beyond those two. The live test ([`examples/live-cases.yaml`](../../examples/live-cases.yaml)) is there for
you to run against your own systems before you rely on an integration. Every integration's docs
end with an **Unverified** section naming what has not been confirmed; for the six marked *beta*
that list is long enough that you should read it first.

| Integration | Status | Tests run against |
|---|---|---|
| [kubernetes](kubernetes.md) | ready | a real cluster (kind), end to end |
| [argocd](argocd.md) | ready | the real `argocd` CLI evaluator (differential test) |
| [github](github.md) | ready | fake upstream, requests validated against GitHub's API description |
| [gitlab](gitlab.md) | ready | fake upstream, validated against GitLab's API description |
| [bitbucket](bitbucket.md) (Cloud and Data Center) | ready | fake upstream, validated against Bitbucket Cloud's API description |
| [jira](jira.md) (Cloud) | ready | fake upstream, validated against Jira's API description |
| [confluence](confluence.md) (Cloud) | ready | fake upstream, validated against Confluence's API descriptions |
| [slack](slack.md) | ready | fake upstream, validated against Slack's API description |
| [datadog](datadog.md) | ready | fake upstream, validated against Datadog's API descriptions |
| [pagerduty](pagerduty.md) | ready | fake upstream, validated against PagerDuty's API description |
| [aws](aws.md) | ready | fake upstream, validated against the IAM, STS and Identity Center service models |
| [googleworkspace](googleworkspace.md) | ready | fake upstream, validated against the Google API discovery documents |
| [googlecloud](googlecloud.md) | ready | fake upstream, validated against the Policy Troubleshooter discovery document |
| [microsoft365](microsoft365.md) | ready | fake upstream, validated against the Microsoft Graph API description |
| [databricks](databricks.md) | ready | fake upstream only |
| [salesforce](salesforce.md) | beta | fake upstream only; see **Unverified** in its docs |
| [snowflake](snowflake.md) | beta | fake upstream, validated against the SQL API description; see **Unverified** |
| [vault](vault.md) | beta | fake upstream, validated against Vault's API description; see **Unverified** |
| [azure](azure.md) | beta | fake upstream, validated against the Azure authorization API descriptions; see **Unverified** |
| [linear](linear.md) | beta | fake upstream, validated against Linear's GraphQL schema; see **Unverified** |
| [zendesk](zendesk.md) | beta | fake upstream, validated against Zendesk's API description; see **Unverified** |
| fake | for smoke tests | |

Each page covers the credential to create, the minimum permissions it needs, how the email maps to
an account, the actions and resources, and what it cannot see. `hallpass catalog <integration>`
prints the same keys and actions from the binary. To add a system, see
[integration authoring](../development/integration-authoring.md).
