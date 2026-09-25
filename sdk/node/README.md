# hallpass-client

The Node.js and TypeScript client for [hallpass](https://github.com/roee-hersh/hallpass): before
your AI agent acts for a user, ask the system that owns the resource whether that user may do it.

```sh
npm install hallpass-client
```

It is on [npm](https://www.npmjs.com/package/hallpass-client), published with provenance by the
hallpass release workflow. Its version matches the hallpass release, so pin the one you run.

It needs a running hallpass service. The client has no dependencies; it uses Node's built-in `fetch`
(Node 18.17 or later). It ships as an ES module with type declarations.

```ts
import { AsyncLocalStorage } from "node:async_hooks";
import { Hallpass, guarded } from "hallpass-client";

const hp = new Hallpass(); // HALLPASS_URL and HALLPASS_API_KEY from the environment
const currentUser = new AsyncLocalStorage<string>();

const deleteIssue = guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", { user: currentUser, fresh: true })(
  async ({ key }: { key: string }) => {
    await jira.deleteIssue(key); // the agent's own credential, only after hallpass said allow
    return `deleted ${key}`;
  },
);

// per request or session, from your auth:
await currentUser.run(req.user.email, () => generateText({ model, tools, prompt }));
```

- **The model never picks the user.** It comes from `user`: a string, a zero-argument function,
  or an `AsyncLocalStorage` your application enters. A `user` key in the tool's arguments is ignored.
- **It fails closed.** `deny`, `unknown` and hallpass being unreachable all reject with
  `PermissionDenied` before the body runs. Pass `deny` to return a message to the model instead.
- **One package covers every framework.** The wrapped function takes one object of arguments,
  which is what the Vercel AI SDK, the MCP SDK and most agent frameworks pass to a tool.

Without a wrapper:

```ts
const d = await hp.check("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123");
d.decision, d.reason;   // "deny", "denied: ..."
await hp.require(...);  // rejects with PermissionDenied unless allow
```

Framework examples: [examples/agent-ts](https://github.com/roee-hersh/hallpass/tree/main/examples/agent-ts).
The guide: [docs/agents.md](https://github.com/roee-hersh/hallpass/blob/main/docs/agents.md).
