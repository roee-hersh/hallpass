# toolpass-client

The Node.js and TypeScript client for [toolpass](https://github.com/roee-hersh/toolpass): before
your AI agent acts for a user, ask the system that owns the resource whether that user may do it.

```sh
npm install toolpass-client
```

It is on [npm](https://www.npmjs.com/package/toolpass-client). Its version matches the toolpass
release, so in a project pin the one you run (`npm install toolpass-client@0.6.0`). From 0.4.1 on,
the toolpass release workflow publishes it with npm provenance.

It needs a running toolpass server: the `ghcr.io/roee-hersh/toolpass` image, the Helm chart, or
`pip install toolpass` and `toolpass serve -config toolpass.yaml` (toolpass itself is a Python
package; in Python you can also run its engine in-process, with no server). The client has no
dependencies; it uses Node's built-in `fetch` (Node 18.17 or later). It ships as an ES module with
type declarations. Its source is in
[`toolpass-ts`](https://github.com/roee-hersh/toolpass/tree/main/toolpass-ts).

```ts
import { AsyncLocalStorage } from "node:async_hooks";
import { Toolpass, guarded } from "toolpass-client";

const tp = new Toolpass(); // TOOLPASS_URL and TOOLPASS_API_KEY from the environment
const currentUser = new AsyncLocalStorage<string>();

const deleteIssue = guarded(tp, "jira-main", "DELETE_ISSUES", "issue:{key}", { user: currentUser, fresh: true })(
  async ({ key }: { key: string }) => {
    await jira.deleteIssue(key); // the agent's own credential, only after toolpass said allow
    return `deleted ${key}`;
  },
);

// per request or session, from your auth:
await currentUser.run(req.user.email, () => generateText({ model, tools, prompt }));
```

- **The model never picks the user.** It comes from `user`: a string, a zero-argument function,
  or an `AsyncLocalStorage` your application enters. A `user` key in the tool's arguments is ignored.
- **It fails closed.** `deny`, `unknown` and toolpass being unreachable all reject with
  `PermissionDenied` before the body runs. Pass `deny` to return a message to the model instead.
- **One package covers every framework.** The wrapped function takes one object of arguments,
  which is what the Vercel AI SDK, the MCP SDK and most agent frameworks pass to a tool.

Without a wrapper:

```ts
const d = await tp.check("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123");
d.decision, d.reason;   // "deny", "denied: ..."
await tp.require(...);  // rejects with PermissionDenied unless allow
```

Framework examples: [examples/agent-ts](https://github.com/roee-hersh/toolpass/tree/main/examples/agent-ts).
The guide: [docs/guides/agent-tools.md](https://github.com/roee-hersh/toolpass/blob/main/docs/guides/agent-tools.md).
