# hallpass documentation

hallpass answers one question before your agent acts for someone: *may this user do this action on
this resource in this system?* It asks the system itself, live, and answers `allow`, `deny` or
`unknown`.

## Get started

- [Quickstart](quickstart.md): run hallpass, ask a question, and guard an agent tool in five minutes.

## Concepts

- [Architecture](concepts/architecture.md): the parts, how one check flows, what is cached, and the
  trust boundaries.

## Guides

- [Deploy](guides/deploy.md): sidecar or shared service, TLS, Docker, a binary, Kubernetes with Helm,
  scaling and a production checklist.
- [Agent tools](guides/agent-tools.md): where the user comes from, where to put the check, and
  working code for LangChain, LangGraph, Strands, the Claude Agent SDK, MCP and the Vercel AI SDK.
- [Operating](guides/operating.md): health, the decision log, what each `unknown` means, and
  rotating secrets.

## Reference

- [HTTP API](reference/api.md): `POST /check`, every decision code, fresh checks, `GET /healthz`.
- [Configuration](reference/configuration.md): `hallpass.yaml`, top-level and per-connection keys.
- [Command line](reference/cli.md): `serve`, `validate`, `probe`, `check` and `catalog`.
- [Integrations](integrations/README.md): the twenty-one systems, their status, and one page each.
- [Client SDKs](../sdk/README.md): `hallpass-client` for Python and Node.
- [Helm chart values](../deploy/helm/hallpass/README.md).

## Development

- [Writing an integration](development/integration-authoring.md).
- [Testing](development/testing.md): unit, spec-validated, contract, end-to-end, differential, live
  and fuzz tests.
- [Contributing](../CONTRIBUTING.md) and [security reports](../SECURITY.md).
