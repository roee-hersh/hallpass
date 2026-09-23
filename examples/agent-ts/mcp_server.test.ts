/**
 * Drives the MCP server through an MCP client over an in-memory transport,
 * against a fake hallpass.
 */

import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { API_KEY, DANA, FakeHallpass } from "./fake_hallpass.ts";

let fake: FakeHallpass;
let client: Client;

before(async () => {
  fake = await FakeHallpass.start();
  // The example reads its configuration from the environment at import.
  process.env.HALLPASS_URL = fake.url;
  process.env.HALLPASS_API_KEY = API_KEY;
  process.env.AGENT_USER = DANA;
  process.env.AGENT_GROUPS = "platform-team, sre";
  const { server } = await import("./mcp_server.ts");
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: "test", version: "0" });
  await client.connect(clientTransport);
});
after(async () => {
  await client.close();
  await fake.close();
});
beforeEach(() => fake.clear());

async function call(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  return (await client.callTool({ name, arguments: args })) as CallToolResult;
}

function text(res: CallToolResult): string {
  const first = res.content[0];
  assert.equal(first?.type, "text");
  return (first as { text: string }).text;
}

describe("mcp server", () => {
  test("tools and schemas", async () => {
    const tools = (await client.listTools()).tools;
    assert.deepEqual(tools.map((t) => t.name).sort(), ["check_permission", "write_thing"]);
    const write = tools.find((t) => t.name === "write_thing")!;
    assert.deepEqual(Object.keys(write.inputSchema.properties ?? {}).sort(), ["content", "thing_id"],
      "user must not be in the tool schema");
  });

  test("check_permission", async () => {
    const res = await call("check_permission", { connection: "demo", action: "thing.write", resource: "thing:timeout" });
    assert.equal(res.isError, undefined);
    const out = res.structuredContent as { decision: string; allowed: boolean };
    assert.equal(out.decision, "unknown");
    assert.equal(out.allowed, false);
    assert.deepEqual([fake.lastRequest().user, fake.lastRequest().groups], [DANA, ["platform-team", "sre"]]);
  });

  test("write_thing", async () => {
    let res = await call("write_thing", { thing_id: "allowed", content: "hi" });
    assert.equal(res.isError, undefined);
    assert.match(text(res), /wrote 2 bytes/);
    assert.deepEqual(fake.lastRequest().groups, ["platform-team", "sre"]);
    // A model-supplied user does not change who is checked.
    res = await call("write_thing", { thing_id: "allowed", content: "hi", user: "admin@example.com" });
    assert.equal(res.isError, undefined, text(res));
    assert.equal(fake.lastRequest().user, DANA);
    for (const thing of ["denied", "timeout", "badline"]) {
      res = await call("write_thing", { thing_id: thing, content: "hi" });
      assert.equal(res.isError, true);
      assert.ok(text(res).startsWith(`dana@example.com may not thing.write on thing:${thing}`), text(res));
    }
    assert.equal(fake.seen.length, 5);
  });
});
