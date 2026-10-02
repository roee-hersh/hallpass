# toolpass

**A pass for every tool call: secure-by-default tools for AI agents, under any agent framework.**

> Alpha. The API may still change.

Teams write custom tools for their own agents: open a pull request against the GitOps repository,
scale a deployment, read customer records, post to Slack. Those tools usually run with one service
credential for everyone who talks to the agent, and every team rebuilds the same safety checks
by hand, or skips them. toolpass is a decorator that adds those checks to a plain Python
function:

```python
from toolpass import ApprovalQueue, Session, Toolkit, hallpass_check

approvals = ApprovalQueue()
tools = Toolkit(approver=approvals, credentials={"github-bot": github_token}, limits={"destructive": 3})


@tools.tool(
    effect="write",
    scope={"repo": "acme/gitops-*"},                 # the tool itself can touch nothing else
    authorize=hallpass_check(hp, "github-acme", "pull_request.create", "repo:{repo}"),
    approve=True,                                     # a person confirms, out of band
    credential="github-bot",                          # injected below; the model never sees it
)
def open_gitops_pr(repo: str, title: str, change: str, *, credential: str) -> str:
    ...


with Session("dana@example.com").active():           # the user your app authenticated
    agent.run(prompt)
```

The decorated function keeps its signature (minus the injected `credential`), so LangChain,
Pydantic AI, CrewAI, the OpenAI Agents SDK or your own loop can put their own `@tool` on top. No
adapter is needed.

## What a tool can declare

| Protection | Declared with | What it guarantees |
|---|---|---|
| User from the session | `Session(user).active()` | The user comes from your app, never from the model's arguments |
| Argument validation | type hints, `validate={...}` | `str` is a `str`, `Literal` is one of its values; your validators run before anything else |
| Scope limits | `scope={"repo": "acme/gitops-*"}` | The tool can only touch what it declares, whoever asks |
| Action limits | `limit=`, `Toolkit(limits={"destructive": 3})` | A loop or an injection cannot run 200 deletes in one session |
| User authorization | `authorize=hallpass_check(...)` or any callable | The call runs only if the person asking may do it |
| Untrusted-input check | `untrusted_output=True` on readers | An action whose arguments repeat untrusted content (an email, a web page) is refused |
| Fencing | automatic for untrusted string output | Untrusted text reaches the model inside a nonce-tagged block marked as data |
| Exfiltration guard | `reads_private=True`, `sends_out=True` | Once a session has read private data and seen untrusted content, nothing is sent out without approval |
| Human approval | `approve=True` or a predicate, `preview=` | A person confirms, out of band, the exact call; the approval is used once |
| Credential injection | `credential="name"` | The secret is fetched after every check and never enters the model's context; echoes of it in the output are redacted |
| Audit | `Toolkit(audit=...)` | One event per call, refused or run, with who asked and why it was decided |

## The order of checks

Every call goes through the same steps. A failed step refuses the call before the tool's body runs,
and anything that cannot be evaluated (an authorizer that raises, an approver that is down) refuses
too.

1. **Session.** No current session means no call.
2. **Arguments.** Types, then validators, then scope rules.
3. **Limits.** One slot is taken from each cap, and given back if the call never reaches its body.
4. **Authorization.** Only an explicit allow lets the call through.
5. **Untrusted input.** Arguments repeating six or more consecutive words of untrusted output
   are refused (or sent for approval, with `on_untrusted_input="approve"`).
6. **Exfiltration.** A `sends_out` tool in a session that has read private data and seen
   untrusted content needs approval (or is refused, with `exfiltration="refuse"`).
7. **Approval.** When the tool, step 5 or step 6 asks for it.
8. **Credential.** Fetched only now.
9. **The body.** Its output is redacted, recorded if untrusted, and fenced.
10. **Audit.** One event, whatever happened.

## The exfiltration guard

An agent can be made to leak data only when one session has all three of what Simon Willison calls
the lethal trifecta: access to private data, exposure to untrusted content, and a way to send data
out. Tools already declare which of these they are, so the toolkit tracks the first two per
session and guards the third:

```python
@tools.tool(effect="read", reads_private=True)
def read_customers() -> str: ...

@tools.tool(effect="read", untrusted_output=True)
def read_email(id: str) -> str: ...

@tools.tool(effect="write", sends_out=True)
def post_slack(channel: str, text: str) -> str: ...
```

After `read_customers` and `read_email` have both run in a session, `post_slack` waits for a person.
This does not depend on spotting injected words, so a model that paraphrases the injection does not
get past it.

## Approval, out of band

`ApprovalQueue` keeps a call that needs approval until a person decides. The tool raises
`ApprovalPending`, whose message tells the model to ask the user and retry. Your app shows the
request to a person and approves it; the same call from the same session then runs once.

```python
approvals.on_request(lambda req: slack.post("#approvals", req.describe()))   # who, what, why, preview

# later, from the Slack button handler:
approvals.approve(request_id, by="dana@example.com")
```

An approval is bound to the session, the tool and the exact arguments, and it expires after `ttl`
seconds (15 minutes by default). Any callable that returns True, False or None can be the approver
instead, for example a prompt in a CLI.

## Refusals

A refused call raises `ToolRefused` with a `code` (`out_of_scope`, `not_authorized`,
`untrusted_input`, `approval_pending`, ...) and a message written for the model. Most frameworks pass
the exception's text back to the model. Where a framework hides it, `Toolkit(on_refuse=str)`
returns the message as the tool's result instead. A check that itself fails unexpectedly (a
validator that raises, a session source that is down) refuses with `check_error`.

An exception from the tool's own body passes through unchanged, unless its message contains the
injected credential: then it is raised as `ToolError`, with the secret redacted from the message and
the original exception kept on `.original` for your own logs.

## Permission checks with hallpass

`hallpass_check` asks [hallpass](../docs/permission-checks.md), the permission engine in this repository, whether the session's user may perform the action,
live, in the system that owns the resource (GitHub, Jira, Kubernetes, AWS, and 17 more). It works
with `Hallpass.from_config(...)` in-process or `Hallpass.remote(...)` against a hallpass server.
Any callable that returns `AuthDecision`, `True` or `False` can be the authorizer instead.

## Limits

- **The untrusted-input check matches words, not meaning.** A model that paraphrases injected text,
  or an argument shorter than six words, is not caught. The exfiltration guard and approval on
  writes cover that gap; don't rely on this check alone.
- **Fencing helps, it does not guarantee.** Models can still be talked past markers.
- **Only string output is fenced.** Structured output is recorded as untrusted but returned as is.
- **Sessions live in memory.** Counts, flags and the approval queue do not survive a restart or
  span processes yet.
- **Redaction matches the credential's literal text.** An encoded or split echo of it (base64, a
  hex dump) is not caught, and strings shorter than 8 characters are never redacted.
- **`hallpass_check` puts argument values into the resource string as they are.** Give such
  arguments a scope rule or validator, so a value carrying `?`, `@` or `#` cannot make hallpass
  check a different resource from the one the tool acts on.
- **Check and action are not atomic.** Authorization is checked, then the body runs; a permission
  revoked in between is not noticed.
- **Session state reaches worker threads only through context.** Frameworks that run tools in
  threads must copy the context (LangChain and `asyncio.to_thread` do).

## Run the example and the tests

```sh
pip install -e ".[permissions]" pytest pytest-timeout
python examples/ops_agent.py
python -m pytest -q
```

`examples/ops_agent.py` runs a scripted ops-agent session with no network: an injected email, a
blocked exfiltration attempt, a pull request that waits for approval, and a hallpass denial.
