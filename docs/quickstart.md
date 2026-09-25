# Quickstart

In about five minutes: run hallpass, ask it a question, and put it in front of an agent tool. You
need Docker, plus Python 3.9+ or Node 18+ for step 3. Nothing here touches a real system; step 4
connects one.

## 1. Run hallpass

The example config has a `demo` connection that talks to nothing. In it, `admin@example.com` may
write and `dana@example.com` may not.

```sh
curl -sO https://raw.githubusercontent.com/roee-hersh/hallpass/main/examples/hallpass.yaml
docker run --rm -p 8080:8080 -e HALLPASS_API_KEY=change-me \
  -v "$PWD/hallpass.yaml:/etc/hallpass/hallpass.yaml:ro" ghcr.io/roee-hersh/hallpass
```

No Docker? Download a binary from [Releases](https://github.com/roee-hersh/hallpass/releases) and
run `HALLPASS_API_KEY=change-me hallpass serve -config hallpass.yaml`.

## 2. Ask a question

In a second terminal:

```sh
curl -X POST localhost:8080/check -H 'Authorization: Bearer change-me' \
  -d '{"user":"dana@example.com","connection":"demo","action":"thing.write","resource":"thing:1"}'
```

```json
{"decision":"deny","reason":"denied: dana@example.com is not an admin"}
```

Change the user to `admin@example.com` and the answer is `allow`. Try `nobody@example.com` and it is
`deny` with `user_not_found`. Every answer is also a JSON line in the first terminal: that is the
[decision log](guides/operating.md#decision-log).

## 3. Guard a tool

Wrap the function your agent calls, so it runs only after hallpass said `allow`. The user comes from
your application, never from the model.

**Python**, saved as `quickstart.py`:

```sh
pip install hallpass-client
```

```python
from contextvars import ContextVar
from hallpass_client import Hallpass, PermissionDenied, guarded

hp = Hallpass()  # reads HALLPASS_URL and HALLPASS_API_KEY
current_user: ContextVar[str] = ContextVar("current_user")

@guarded(hp, "demo", "thing.write", "thing:{thing_id}", user=current_user)
def write_thing(thing_id: str) -> str:
    return f"wrote thing {thing_id}"  # your real action goes here

for who in ["admin@example.com", "dana@example.com"]:
    current_user.set(who)  # in a real agent: the signed-in user, never the model
    try:
        print(who, "->", write_thing(thing_id="1"))
    except PermissionDenied as e:
        print(who, "-> refused:", e.decision.reason)
```

**Node**, saved as `quickstart.mjs` (the `.mjs` extension lets it use `import`):

```sh
npm install hallpass-client
```

```js
import { AsyncLocalStorage } from "node:async_hooks";
import { Hallpass, PermissionDenied, guarded } from "hallpass-client";

const hp = new Hallpass(); // reads HALLPASS_URL and HALLPASS_API_KEY
const currentUser = new AsyncLocalStorage();

const writeThing = guarded(hp, "demo", "thing.write", "thing:{thingId}", { user: currentUser })(
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

Run either one:

```sh
export HALLPASS_URL=http://localhost:8080 HALLPASS_API_KEY=change-me
python quickstart.py     # or: node quickstart.mjs
```

```text
admin@example.com -> wrote thing 1
dana@example.com -> refused: denied: dana@example.com is not an admin
```

In a real agent, put your framework's tool decorator on top of `guarded` (`@tool` in LangChain or
Strands, `tool()` in the Vercel AI SDK). The [agent guide](guides/agent-tools.md) covers each
framework and where the user comes from.

## 4. Connect a real system

Pick the system your agent acts in, follow its [integration page](integrations/README.md) to create
a read-only credential, and add a connection to `hallpass.yaml`. For example, Jira:

```yaml
connections:
  - id: jira-main
    integration: jira
    url: https://acme.atlassian.net
    username: hallpass-bot@acme.com
    credential: env:JIRA_TOKEN
```

Then check the file and the credential before you rely on it:

```sh
hallpass validate -config hallpass.yaml
hallpass probe    -config hallpass.yaml -connection jira-main
hallpass check    -config hallpass.yaml -connection jira-main \
  -user you@acme.com -action DELETE_ISSUES -resource issue:PAY-123
```

`hallpass catalog jira` lists the actions you can ask about.

## Next

- [Architecture](concepts/architecture.md): how a check flows, what is cached, and the trust boundaries.
- [Deploy](guides/deploy.md): Docker, a binary, or Kubernetes with Helm, and how to reach hallpass over TLS.
- [Add hallpass to your agent](guides/agent-tools.md): the full guide for LangChain, LangGraph, Strands, the Claude Agent SDK, MCP and the Vercel AI SDK.
