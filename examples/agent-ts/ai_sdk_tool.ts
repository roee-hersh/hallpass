/**
 * Vercel AI SDK tools that check with hallpass before they act.
 *
 * The tools are defined once. The application enters `session` for the
 * request before it runs the model, so the acting user is never chosen by
 * the model:
 *
 *     session.run({ user: req.user.email, groups: req.user.groups }, () =>
 *       generateText({ model, tools, prompt }));
 *
 * Needs `ai` and `zod` (npm install). The tools do not depend on any
 * particular model provider.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { pathToFileURL } from "node:url";
import { tool } from "ai";
import { z } from "zod";
import { Hallpass, current, guarded } from "../../hallpass-ts/src/index.ts"; // in your project: from "hallpass-client"

export const hp = new Hallpass();

/** Who the agent acts for, set by the application for each request. */
export interface Session {
  user: string;
  groups?: readonly string[];
}

export const session = new AsyncLocalStorage<Session>();
const user = () => current(session).user;
const groups = () => current(session).groups ?? [];

export const checkPermission = tool({
  description:
    "Ask whether the current user may perform an action in a system. " +
    "connection is a hallpass connection id (e.g. jira-main), action one of its " +
    "actions (e.g. DELETE_ISSUES), resource the target (e.g. issue:PAY-123). " +
    "Only 'allow' permits the action; 'unknown' is a deny.",
  inputSchema: z.object({ connection: z.string(), action: z.string(), resource: z.string() }),
  execute: async ({ connection, action, resource }) => {
    const d = await hp.check(user(), connection, action, resource, groups());
    return { decision: d.decision, reason: d.reason, allowed: d.allowed };
  },
});

// The refusal is returned as the tool's output rather than thrown, so the
// model reads hallpass's reason whatever the SDK does with a thrown error.
export const writeThing = tool({
  description:
    "Write content to a thing in the demo system. Refused unless the current user holds thing.write on it.",
  inputSchema: z.object({ thing_id: z.string(), content: z.string() }),
  execute: guarded(hp, "demo", "thing.write", "thing:{thing_id}", {
    user,
    groups,
    deny: (e) => `refused: ${e.message}`,
  })(async ({ thing_id, content }: { thing_id: string; content: string }) => {
    // The real action goes here, run with the agent's own credential.
    return `wrote ${content.length} bytes to thing:${thing_id} as ${user()}`;
  }),
});

export const tools = { check_permission: checkPermission, write_thing: writeThing };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  // Smoke test without an LLM: call the tools' execute directly.
  // Demo only: the command line stands in for the user a real request was
  // authenticated as (see docs/guides/agent-tools.md, "Set the user from your login").
  const who = process.argv[2] ?? "dana@example.com";
  await session.run({ user: who }, async () => {
    const opts = { toolCallId: "smoke", messages: [], context: {} };
    console.log(await checkPermission.execute({ connection: "demo", action: "thing.write", resource: "thing:1" }, opts));
    console.log(await writeThing.execute({ thing_id: "1", content: "hello" }, opts));
  });
}
