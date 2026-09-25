# Command-line reference

One binary, `hallpass`, with five commands. Every command that reads a config takes
`-config FILE`, defaulting to `/etc/hallpass/hallpass.yaml`.

| Command | What it does |
|---|---|
| `hallpass serve -config FILE` | Run the service |
| `hallpass validate -config FILE` | Check the file, credential references and certificates. No network |
| `hallpass probe -config FILE [-connection ID]` | Call each system with its credential and report |
| `hallpass check -config FILE -connection ID -user EMAIL -action NAME -resource RES [-group G]... [-json]` | Answer one question from the command line |
| `hallpass check -server URL [-api-key REF] [-ca-file PEM] [-timeout D] [-fresh] ...` | Ask a running hallpass the same question; `-fresh` skips its caches |
| `hallpass catalog [INTEGRATION]` | List integrations, config keys and actions |

At startup `serve` probes every connection and logs warnings. A broken connection never stops the
service from starting.

`check` runs the same code path as `POST /check` in-process, so it needs the config file and the
connection's credential but no running server and no API key. It prints the decision and reason
(`-json` prints the HTTP response body) and exits 0 for `allow`, 1 for `deny`, 3 for `unknown` and
2 when no decision was reached (bad flags, a config that does not load, an interrupted run), so
`if hallpass check ...` treats `unknown` as deny. Only the connection asked about is built, so a
sibling whose credential is missing on this machine does not get in the way.

```sh
$ hallpass check -config hallpass.yaml -connection jira-main \
    -user dana@example.com -action DELETE_ISSUES -resource issue:PAY-123
deny
  denied: Dana Levi does not hold DELETE_ISSUES on issue PAY-123
```

With `-server URL` the same question goes to a running hallpass over `POST /check`, so it can be
asked from a machine that holds the API key but none of the upstream credentials. `-api-key` is an
`env:NAME` or `file:/path` reference (default `env:HALLPASS_API_KEY`); a key value on the command
line is rejected. The URL must be `https://` unless it is `localhost` or a loopback address.
Output and exit codes are the same; a reply that is not a decision (wrong host, proxy error page)
or none within `-timeout` (default `1m`) exits 2.

```sh
hallpass check -server https://hallpass.internal -connection jira-main \
    -user dana@example.com -action DELETE_ISSUES -resource issue:PAY-123
```

`serve` also takes `-listen ADDR`, which overrides `listen` in the file, and
`-log-level debug|info|warn|error` (default `info`).
