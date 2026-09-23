# Working in this repository

## Finishing a change

Do not stop at a pushed branch. When the change is complete and the local
checks pass (`go test -race ./...`, `gofmt -l .`, `go vet ./...`, and
`python3 -m unittest discover -s examples/agent` when `examples/agent` changed):

1. Run `/code-review` on the diff against `main` and fix every finding.
2. Run `/security-review` and fix every finding.
3. Open a pull request using `.github/pull_request_template.md`. Mention the
   issue it closes.
4. Wait for CI on the pull request to pass, then merge it. If CI is red,
   fix and push; never merge over a failure, and never skip or disable a test
   to get green.

Ask first only for changes that are destructive or clearly outside what was
requested.
