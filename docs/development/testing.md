# Testing hallpass

The Python package lives in `hallpass-py/`; run these from there, in a virtual environment with
Python 3.10 or later:

```sh
pip install -e ".[crypto]" pytest pytest-timeout hypothesis ruff mypy types-PyYAML
ruff format --check src tests && ruff check src tests
mypy --strict src/hallpass
python -m pytest -q                        # unit, integration, harness and server tests
```

This is what CI's `hallpass-py` job runs, on Python 3.10 and 3.13, on Linux and Windows; on Linux
it then builds the wheel, installs it into a clean environment and runs the tests again from
outside the checkout (`HALLPASS_REQUIRE_INSTALLED=1` makes them fail if they picked up the source
tree instead).

| Directory | What it tests | Needs |
|---|---|---|
| `tests/core`, `tests/authx`, `tests/net`, `test_cli.py`, `test_server.py` | the engine, config, caches, signing, the HTTP client, the command and the server | nothing |
| `tests/integrations/<name>` | each integration against a fake of its API over TLS, with injected failures (500, 429, 401, timeout), and a check that no secret reaches a log line | nothing; `HALLPASS_SPECS_DIR` to validate requests (below) |
| `tests/integrations/test_registry.py` | the coverage gate: `test_action_<name>_allow` and `_deny` for every action | nothing |
| `tests/harness`, `tests/harness_tests` | the fake upstream, spec validation, and their own tests | nothing |
| `tests/frameworks` | each framework adapter through the framework's real agent loop, with a scripted model and a real in-process engine | the framework's extra, e.g. `pip install -e ".[strands]"`; each file skips without it. `ANTHROPIC_API_KEY` for the live tests, which drive the same scenario with Claude |
| `tests/real` | the vault integration against a real Vault dev server in Docker, every answer compared with Vault's own `sys/capabilities` | Docker and the `hashicorp/vault:1.17` image, present locally (never pulled); `HALLPASS_REAL=1` turns a skip into a failure |
| `tests/e2e` | the kubernetes integration and the server against a real cluster | a cluster named in `HALLPASS_E2E_KUBERNETES_URL`, `_TOKEN_FILE` and `_CA_FILE`; `test/kind/run.sh` creates a kind cluster, seeds it and exports them |
| `tests/contract` | integrations against Prism, a mock server that answers from the vendor's OpenAPI description and rejects requests that violate it | `HALLPASS_SPECS_DIR` and `npx` on the PATH (Prism is fetched by npx) |
| `tests/live` | your own cases against real systems ([below](#against-your-own-systems)) | `HALLPASS_LIVE_CASES` naming a cases file, and the credentials |
| `tests/differential` | the Argo CD RBAC evaluator against `argocd admin settings rbac can` | the `argocd` binary on the PATH |
| `tests/parity` | recorded scenarios from the port from Go: the Python engine's decisions and reasons against the expected ones, and against the Go build too when `HALLPASS_GO_BIN` names one. Removed with the Go code | nothing |

Every integration's tests run against a fake of its API. With the vendors' published API
descriptions present, every request the fakes receive is also validated against the description:
path, method, required parameters, body fields, AWS operation members, GraphQL fields and
arguments.

```sh
../test/specs/fetch.sh ../.specs                         # from hallpass-py/
HALLPASS_SPECS_DIR=$PWD/../.specs python -m pytest -q tests/integrations
```

Every resource parser has property tests (`tests/integrations/<name>/test_fuzz.py`, Hypothesis)
that assert an accepted resource is made only of validated pieces before it reaches a URL or query.
They run at Hypothesis's default size with the rest of the suite; `HYPOTHESIS_PROFILE=nightly` and
`HALLPASS_FUZZ_SCALE=<n>` make them run much longer.

Outside `hallpass-py`:

```sh
test/kind/run.sh                          # kubernetes end to end on a kind cluster
test/kind/helm.sh                         # the Helm chart and the Docker image on a kind cluster
(cd hallpass-ts && npm ci && npm test)    # the Node client
(cd examples/agent-ts && npm ci && npm test)
python3 test/docs/linkcheck.py            # relative links and anchors in every Markdown file
```

## Against your own systems

The live test takes a cases file (see [`examples/live-cases.yaml`](../../examples/live-cases.yaml))
that names a config file and the answers you expect from your own systems; run it once after
setting up each connection:

```sh
HALLPASS_LIVE_CASES=$PWD/cases.yaml python -m pytest tests/live      # from hallpass-py/
```

It probes every connection first and ends with a summary per connection: passed, failed, or not
configured, naming the environment variables or files that were missing on this machine.
`HALLPASS_LIVE_REQUIRE=1` turns a connection that is not configured into a failure.
