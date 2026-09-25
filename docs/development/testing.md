# Testing hallpass


```sh
go test -race ./...                                   # unit tests against fake upstreams
test/kind/run.sh                                      # kubernetes end to end on a kind cluster
test/kind/helm.sh                                     # the Helm chart on a kind cluster
go test -tags differential ./test/differential/      # Argo CD evaluator vs the argocd CLI
HALLPASS_LIVE_CASES=$PWD/cases.yaml go test -tags live ./test/live/   # real systems, opt-in
```

Every integration's tests run against a fake of its API with injected failures (500, 429, 401,
timeout) and assert that no secret ever reaches a log line. With the vendors' published API
descriptions present (`test/specs/fetch.sh`, then `HALLPASS_SPECS_DIR=$PWD/.specs go test ./...`)
every request the fakes receive is also validated against the description: path, method, required
parameters, body fields, AWS operation members. The contract tests run the integrations against
Prism, which answers from those descriptions with request validation
(`go test -tags contract ./test/contract/`, needs node). The live test takes a cases file (see
`examples/live-cases.yaml`) that names a config file and the answers you expect from your own
systems; run it once after setting up each connection. Every resource parser has a fuzz target
(`go test -run '^$' -fuzz=Fuzz ./internal/integrations/<name>/`) that asserts an accepted resource is
made only of validated pieces before it reaches a URL or query; CI runs them nightly.
