# Quickstart

In about five minutes: install toolpass, ask it a question, put it in front of an agent tool, then
run the same thing as a server. You need Python 3.10 or later; step 3 also uses Docker (or
nothing more than the same `pip install`) and, for the Node client, Node 18.17 or later. Nothing
here touches a real system; step 4 connects one.

## 1. Install and ask

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install toolpass
curl -sO https://raw.githubusercontent.com/roee-hersh/toolpass/main/examples/toolpass.yaml
```

The example config has a `demo` connection that talks to nothing. In it, `admin@example.com` may
write and `dana@example.com` may not. The engine runs in your process:

```sh
python3 -c '
from toolpass import Toolpass
tp = Toolpass.from_config("toolpass.yaml")
print(tp.check("dana@example.com", "demo", "thing.write", "thing:1"))
'
```

```text
Decision(decision='deny', reason='denied: dana@example.com is not an admin', status=200)
```

Change the user to `admin@example.com` and the answer is `allow`. Try `nobody@example.com` and it is
`deny` with `user_not_found`. Every answer is also a JSON line on stderr: that is the
[decision log](guides/operating.md#decision-log), set by `decision_log` in the file.

The command line asks the same question without any code:

```sh
toolpass check -config toolpass.yaml -connection demo \
  -user dana@example.com -action thing.write -resource thing:1
```

## 2. Guard a tool

Wrap the function your agent calls, so it runs only after toolpass said `allow`. The user comes from
your application, never from the model. Save as `quickstart.py`:

```python
from contextvars import ContextVar
from toolpass import Toolpass, PermissionDenied, guarded

tp = Toolpass.from_config("toolpass.yaml")
current_user: ContextVar[str] = ContextVar("current_user")

@guarded(tp, "demo", "thing.write", "thing:{thing_id}", user=current_user)
def write_thing(thing_id: str) -> str:
    return f"wrote thing {thing_id}"  # your real action goes here

for who in ["admin@example.com", "dana@example.com"]:
    current_user.set(who)  # in a real agent: the signed-in user, never the model
    try:
        print(who, "->", write_thing(thing_id="1"))
    except PermissionDenied as e:
        print(who, "-> refused:", e.decision.reason)
```

```sh
python3 quickstart.py 2>/dev/null   # stderr carries the decision log
```

```text
admin@example.com -> wrote thing 1
dana@example.com -> refused: denied: dana@example.com is not an admin
```

In a real agent, use your framework's adapter instead, configured once on the agent
(`toolpass.strands`, `toolpass.langchain`, `toolpass.mcp`, ...), or put the framework's tool
decorator on top of `guarded`. The [agent guide](guides/agent-tools.md) covers each framework and
where the user comes from.

## 3. Run it as a server

In-process, the agent's process holds toolpass's lookup credentials. To keep them out of it, run
the same engine as a service and point the agent at it:

```sh
docker run --rm -p 8080:8080 -e TOOLPASS_API_KEY=change-me \
  -v "$PWD/toolpass.yaml:/etc/toolpass/toolpass.yaml:ro" ghcr.io/roee-hersh/toolpass
```

No Docker? The package you installed is the server too:
`TOOLPASS_API_KEY=change-me toolpass serve -config toolpass.yaml`.

In a second terminal:

```sh
curl -X POST localhost:8080/check -H 'Authorization: Bearer change-me' \
  -d '{"user":"dana@example.com","connection":"demo","action":"thing.write","resource":"thing:1"}'
```

```json
{"decision":"deny","reason":"denied: dana@example.com is not an admin"}
```

In `quickstart.py`, change one line and run it again; the output is the same:

```python
tp = Toolpass.remote("http://localhost:8080", "change-me")  # or TOOLPASS_URL and TOOLPASS_API_KEY
```

**Node** talks to the server with `toolpass-client`. Save as `quickstart.mjs` (the `.mjs`
extension lets it use `import`):

```sh
npm install toolpass-client
```

```js
import { AsyncLocalStorage } from "node:async_hooks";
import { Toolpass, PermissionDenied, guarded } from "toolpass-client";

const tp = new Toolpass(); // reads TOOLPASS_URL and TOOLPASS_API_KEY
const currentUser = new AsyncLocalStorage();

const writeThing = guarded(tp, "demo", "thing.write", "thing:{thingId}", { user: currentUser })(
  async ({ thingId }) => `wrote thing ${thingId}`, // your real action goes here
);

for (const who of ["admin@example.com", "dana@example.com"]) {
  try {
    console.log(who, "->", await currentUser.run(who, () => writeThing({ thingId: "1" })));
  } catch (e) {
    if (!(e instanceof PermissionDenied)) throw e;
    console.log(who, "-> refused:", e.decision.reason);
  }
}
```

```sh
TOOLPASS_URL=http://localhost:8080 TOOLPASS_API_KEY=change-me node quickstart.mjs
```

## 4. Connect a real system

Pick the system your agent acts in, follow its [integration page](integrations/README.md) to create
a read-only credential, and add a connection to `toolpass.yaml`. For example, Jira:

```yaml
connections:
  - id: jira-main
    integration: jira
    url: https://acme.atlassian.net
    username: toolpass-bot@acme.com
    credential: env:JIRA_TOKEN
```

Then check the file and the credential before you rely on it:

```sh
export JIRA_TOKEN=...              # the token from the integration page
export TOOLPASS_API_KEY=change-me  # validate reads api_key when the file has one
toolpass validate -config toolpass.yaml
toolpass probe    -config toolpass.yaml -connection jira-main
toolpass check    -config toolpass.yaml -connection jira-main \
  -user you@acme.com -action DELETE_ISSUES -resource issue:PAY-123
```

`toolpass catalog jira` lists the actions you can ask about. The integrations that sign with a
private key (a GitHub App, Google service accounts, Snowflake key pairs, Salesforce JWT, Microsoft
365 certificates) need `pip install "toolpass[crypto]"`; the Docker image has it.

## Next

- [Architecture](concepts/architecture.md): how a check flows, what is cached, and the trust boundaries.
- [Deploy](guides/deploy.md): in-process or as a server, with Docker, pip or Helm, and how to reach it over TLS.
- [Add toolpass to your agent](guides/agent-tools.md): the adapters for Strands, LangChain and
  LangGraph, MCP, the OpenAI Agents SDK, the Claude Agent SDK, Google ADK, CrewAI, Pydantic AI,
  LlamaIndex, and the TypeScript client.
