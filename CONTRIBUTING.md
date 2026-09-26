# Contributing to hallpass

Thanks for taking the time. Bug reports, integration requests and pull requests are all welcome.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Security problems go through [SECURITY.md](SECURITY.md), not public issues.
- Writing your change with an AI assistant is fine; it is how much of the project was written.
  The tests in the PR are what gets reviewed, so include them, and say in the PR what you ran.

## Development

hallpass is a Python package in `hallpass-py/` (Python 3.10 or later). From there:

```sh
pip install -e ".[crypto]" pytest pytest-timeout hypothesis ruff mypy types-PyYAML
ruff format --check src tests examples   # must report nothing to reformat
ruff check src tests examples
mypy --strict src/hallpass
python -m pytest -q             # unit tests against fake upstreams
```

The Node client is in `hallpass-ts/` (`npm ci && npm test`). CI also validates every integration's
requests against the vendors' API descriptions, runs a Kubernetes end-to-end test on kind and an
Argo CD differential test. See [docs/development/testing.md](docs/development/testing.md) to run
them locally.

## Adding an integration

Read [docs/development/integration-authoring.md](docs/development/integration-authoring.md). A new integration needs:

- a read-only credential and the minimum permissions it requires, documented in
  `docs/integrations/<name>.md`;
- tests against a fake upstream, including a `test_action_<name>_allow` and `_deny` for each
  action;
- `unknown`, never `deny`, whenever the upstream answer cannot be evaluated.

## Pull requests

- Keep each PR focused on one change.
- Add or update tests for the behaviour you change.
- By contributing you agree that your contribution is licensed under the Apache License 2.0.
