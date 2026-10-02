# toolpass documentation

These pages cover toolpass's permission checks: the engine behind `Toolpass`, `guarded` and
`permission_check`. For the secure-tools toolkit (scope limits, approval, the untrusted-input and
exfiltration guards, credential injection), see [the package README](../toolpass-py/README.md).

toolpass answers one question before your agent acts for someone: *may this user do this action on
this resource in this system?* It asks the system itself, live, and answers `allow`, `deny` or
`unknown`. It is a Python package: the engine runs in your agent's process, or as a server that
agents in any language call.

## Get started

- [Permission checks](permission-checks.md): what they do, how they differ from policy engines
  and OAuth, and its security model.
- [Quickstart](quickstart.md): install toolpass, ask a question, guard an agent tool, and run it as
  a server, in five minutes.

## Concepts

- [Architecture](concepts/architecture.md): the parts, how one check flows, what is cached, and the
  trust boundaries.

## Guides

- [Deploy](guides/deploy.md): in-process, sidecar or shared service, TLS, Docker, pip, Kubernetes
  with Helm, scaling and a production checklist.
- [Add toolpass to your agent](guides/agent-tools.md): which tools to guard, where the user comes
  from, and the adapters for Strands, LangChain and LangGraph, MCP, the OpenAI Agents SDK, the
  Claude Agent SDK, Google ADK, CrewAI, Pydantic AI, LlamaIndex and the Vercel AI SDK.
- [Operating](guides/operating.md): health, the decision log, what each `unknown` means, and
  rotating secrets.

## Reference

- [Python API](reference/client.md): `Toolpass` in-process and remote, `check`, `require`,
  `guarded`, the framework adapters, and the Node client.
- [HTTP API](reference/api.md): `POST /check`, every decision code, fresh checks, `GET /healthz`.
- [Configuration](reference/configuration.md): `toolpass.yaml`, top-level and per-connection keys,
  and the same connections given in code.
- [Command line](reference/cli.md): `serve`, `validate`, `probe`, `check` and `catalog`.
- [Integrations](integrations/README.md): the twenty-one systems, their status, and one page each.
- [Packages and releases](../toolpass-py/RELEASING.md): `toolpass`, the Node client, the image and
  the chart, and how they are released.
- [Helm chart values](../deploy/helm/toolpass/README.md).

## Development

- [Writing an integration](development/integration-authoring.md).
- [Testing](development/testing.md): unit, spec-validated, property, framework, real-system,
  end-to-end and differential tests.
- [Contributing](../CONTRIBUTING.md) and [security reports](../SECURITY.md).
