# Working in this repository

## Finishing a change

Do not stop at a pushed branch. A merge into `main` ships in the next daily
release (03:00 UTC), so merge only complete, working changes.

1. Run `/code-review main high` on the diff and fix every finding.
2. Run `/security-review` and fix every finding.
3. Run the local checks, after the review fixes, and get them clean:
   - `gofmt -l .` (must print nothing), `go vet ./...`,
     `go vet -tags "e2e differential live contract" ./test/...`,
     `go test -race ./...`
   - when `examples/agent` changed: `pip install -r examples/agent/requirements.txt`
     then `HALLPASS_EXAMPLE_REQUIRE_DEPS=1 python3 -m unittest discover -s examples/agent`
   - when `examples/agent-ts` changed: `cd examples/agent-ts && npm ci && npm test`
   - when `deploy/helm` changed: `helm lint deploy/helm/hallpass --strict --set apiKey.value=x`
4. Open a pull request using `.github/pull_request_template.md`. Mention the
   issue it closes when there is one.
5. Wait for CI on the pull request to pass, then squash-merge with the PR
   title and `(#N)` suffix, as the history on `main` does. If CI is red, fix
   and push; never merge over a failure, and never skip or disable a test to
   get green. A failure in code the change does not touch (a vendor spec or
   the argocd CLI failing to download, for example) may be re-run once; if it
   fails again, say so and stop.

The maintainer asked for this flow. Ask first only for changes that are
destructive or clearly outside what was requested.
