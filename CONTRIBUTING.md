# Contributing to hallpass

Thanks for taking the time. Bug reports, integration requests and pull requests are all welcome.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Security problems go through [SECURITY.md](SECURITY.md), not public issues.
- Writing your change with an AI assistant is fine; it is how much of the project was written.
  The tests in the PR are what gets reviewed, so include them, and say in the PR what you ran.

## Development

```sh
go test -race ./...          # unit tests against fake upstreams
gofmt -l .                   # must print nothing
go vet ./...
```

CI also runs contract tests against vendor OpenAPI descriptions, a Kubernetes end-to-end run on
kind and an Argo CD differential test. See the Testing section of the README to run them locally.

## Adding an integration

Read [docs/integration-authoring.md](docs/integration-authoring.md). A new integration needs:

- a read-only credential and the minimum permissions it requires, documented in
  `docs/integrations/<name>.md`;
- tests against a fake upstream;
- `unknown`, never `deny`, whenever the upstream answer cannot be evaluated.

## Pull requests

- Keep each PR focused on one change.
- Add or update tests for the behaviour you change.
- By contributing you agree that your contribution is licensed under the Apache License 2.0.
