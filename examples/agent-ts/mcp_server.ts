/**
 * An MCP server that checks with hallpass before it acts.
 *
 * Two tools:
 *
 *   check_permission   ask hallpass whether the current user may do something
 *   write_thing        an example action that runs only after an allow
 *
 * The user the agent acts for is fixed when the server starts (AGENT_USER),
 * not passed by the model. A tool argument is something the model can make
 * up; the identity of the person behind the session is not. Set it from the
 * host that launches this server, one server process per user session.
 *
 * Run:
 *
 *     export HALLPASS_URL=http://localhost:8080 HALLPASS_API_KEY=change-me
 *     export AGENT_USER=dana@example.com
 *     node mcp_server.ts           # speaks MCP over stdio
 *
 * Needs `@modelcontextprotocol/sdk` and `zod` (npm install).
 */

import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { Hallpass, guarded } from "../../sdk/node/src/index.ts"; // in your project: from "hallpass-client"

const hp = new Hallpass();
const AGENT_USER = process.env.AGENT_USER ?? "";
if (!AGENT_USER) {
  throw new Error("AGENT_USER missing: set it to the email of the user this server acts for");
}
// Optional group memberships, for systems that grant by group (e.g. Kubernetes).
const AGENT_GROUPS = (process.env.AGENT_GROUPS ?? "")
  .split(",")
  .map((g) => g.trim())
  .filter((g) => g !== "");

export const server = new McpServer(
  { name: "hallpass", version: "1.0.0" },
  {
    instructions:
      `Tools act on behalf of ${AGENT_USER}. Call check_permission before ` +
      "suggesting an action the user may not be allowed to do. A decision of " +
      "'deny' or 'unknown' means the action must not be performed.",
  },
);

server.registerTool(
  "check_permission",
  {
    description:
      "Ask hallpass whether the current user may perform an action. " +
      "connection: the hallpass connection id, e.g. \"jira-main\" or \"k8s-prod-eu\". " +
      "action: an action of that integration, e.g. \"DELETE_ISSUES\". " +
      "resource: the target, e.g. \"issue:PAY-123\" or \"namespace:payments\". " +
      "Returns decision (allow / deny / unknown), reason and allowed. Only " +
      "allowed=true permits the action; unknown means hallpass could not tell " +
      "and must be treated as deny.",
    inputSchema: { connection: z.string(), action: z.string(), resource: z.string() },
    outputSchema: { decision: z.string(), reason: z.string(), allowed: z.boolean() },
  },
  async ({ connection, action, resource }) => {
    const d = await hp.check(AGENT_USER, connection, action, resource, AGENT_GROUPS);
    const out = { decision: d.decision, reason: d.reason, allowed: d.allowed };
    return { content: [{ type: "text", text: JSON.stringify(out) }], structuredContent: out };
  },
);

// A thrown error becomes an isError result carrying its message, so the
// model learns why the action was refused.
server.registerTool(
  "write_thing",
  {
    description: "Write content to a thing in the demo system. Requires thing.write.",
    inputSchema: { thing_id: z.string(), content: z.string() },
  },
  guarded(hp, "demo", "thing.write", "thing:{thing_id}", { user: AGENT_USER, groups: AGENT_GROUPS })(
    async ({ thing_id, content }: { thing_id: string; content: string }) => {
      // The action itself, with the agent's own credential. Replace with a
      // real call (delete a Jira issue, scale a deployment, ...) and keep the
      // shape: the wrapper checks first, the body runs only on allow.
      return {
        content: [{ type: "text" as const, text: `wrote ${content.length} bytes to thing:${thing_id} as ${AGENT_USER}` }],
      };
    },
  ),
);

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await server.connect(new StdioServerTransport());
}
