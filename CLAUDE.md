# Working in this repository

## Finishing a change

Do not stop at a pushed branch. A merge into `main` ships in the next daily
release (03:00 UTC), so merge only complete, working changes.

1. Run `/code-review main high` on the diff and fix every finding.
2. Run `/security-review` and fix every finding.
3. Run the local checks, after the review fixes, and get them clean
   (in `hallpass-py/`, with `pip install -e ".[crypto]" pytest pytest-timeout hypothesis ruff mypy types-PyYAML`):
   - `ruff format --check src tests examples`, `ruff check src tests examples`,
     `mypy --strict src/hallpass`, `python -m pytest -q`
   - when an integration or `tests/harness` changed: fetch the API descriptions with
     `test/specs/fetch.sh /tmp/specs`, then `HALLPASS_SPECS_DIR=/tmp/specs python -m pytest -q tests/integrations tests/harness_tests tests/contract`
   - when a framework adapter (`src/hallpass/<framework>.py`) changed: install its extra
     (`pip install -e ".[<extra>]"`) and run `python -m pytest tests/frameworks/test_<framework>.py`
   - when the vault integration changed: `HALLPASS_REAL=1 python -m pytest tests/real` (needs docker)
   - when packaging (`pyproject.toml`) changed: build the wheel (`python -m build -o /tmp/dist .`),
     install it into a fresh venv, then run `tests` with that venv's Python from outside the repository
   - when `hallpass-ts` changed: `cd hallpass-ts && npm ci && npm test`, and run the `examples/agent-ts`
     tests, which exercise it
   - when `examples/agent-ts` changed: `cd examples/agent-ts && npm ci && npm test`
   - when any Markdown changed: `python3 test/docs/linkcheck.py`
   - when `deploy/helm` changed: `helm lint deploy/helm/hallpass --strict --set apiKey.value=x`
   - when the `Dockerfile` changed: `docker build .` and the smoke test in the `docker` CI job
4. Open a pull request using `.github/pull_request_template.md`. Mention the
   issue it closes when there is one.
5. Wait for CI on the pull request to pass, then squash-merge with the PR
   title and `(#N)` suffix, as the history on `main` does. If CI is red, fix
   and push; never merge over a failure, and never skip or disable a test to
   get green. A failure in code the change does not touch (a vendor spec, Prism or
   the argocd CLI failing to download, for example) may be re-run once; if it
   fails again, say so and stop.

The maintainer asked for this flow. Ask first only for changes that are
destructive or clearly outside what was requested.
