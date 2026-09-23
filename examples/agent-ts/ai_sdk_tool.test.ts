/**
 * Drives the AI SDK tools through `generateText` with a mock model that
 * emits tool calls, against a fake hallpass.
 */

import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";
import { generateText } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { API_KEY, DANA, FakeHallpass } from "./fake_hallpass.ts";

let fake: FakeHallpass;
let mod: typeof import("./ai_sdk_tool.ts");

before(async () => {
  fake = await FakeHallpass.start();
  // The example builds its client from the environment at import.
  process.env.HALLPASS_URL = fake.url;
  process.env.HALLPASS_API_KEY = API_KEY;
  mod = await import("./ai_sdk_tool.ts");
});
after(() => fake.close());
beforeEach(() => fake.clear());

/** A model whose one answer is a call of `name` with `input`. */
function modelCalling(name: string, input: Record<string, unknown>) {
  return new MockLanguageModelV3({
    doGenerate: {
      content: [{ type: "tool-call", toolCallId: "c1", toolName: name, input: JSON.stringify(input) }],
      finishReason: { unified: "tool-calls", raw: "tool_use" },
      usage: {
        inputTokens: { total: 1, noCache: 1, cacheRead: undefined, cacheWrite: undefined },
        outputTokens: { total: 1, text: 1, reasoning: undefined },
      },
      warnings: [],
    },
  });
}

/** Run one tool call the way the SDK does, as the given session. */
async function call(name: string, input: Record<string, unknown>, session = { user: DANA, groups: ["platform-team"] }) {
  const model = modelCalling(name, input);
  const result = await mod.session.run(session, () =>
    generateText({ model, tools: mod.tools, prompt: "do the thing" }));
  return { result, model };
}

describe("ai sdk tools", () => {
  test("the model sees no user parameter", async () => {
    const { model } = await call("check_permission", { connection: "demo", action: "thing.write", resource: "thing:allowed" });
    const offered = model.doGenerateCalls[0]!.tools!;
    const schemas = Object.fromEntries(offered.map((t) => [t.name, t.type === "function" ? t.inputSchema : undefined]));
    assert.deepEqual(Object.keys(schemas).sort(), ["check_permission", "write_thing"]);
    const props = (s: unknown) => Object.keys((s as { properties: object }).properties).sort();
    assert.deepEqual(props(schemas.write_thing), ["content", "thing_id"]);
    assert.deepEqual(props(schemas.check_permission), ["action", "connection", "resource"]);
  });

  test("check_permission", async () => {
    const { result } = await call("check_permission", { connection: "demo", action: "thing.write", resource: "thing:timeout" });
    const [r] = result.toolResults;
    assert.equal(r?.type, "tool-result");
    assert.deepEqual(r?.output, { decision: "unknown", reason: "upstream_timeout: jira took too long", allowed: false });
    assert.deepEqual([fake.lastRequest().user, fake.lastRequest().groups], [DANA, ["platform-team"]]);
  });

  test("write_thing", async () => {
    // A model-supplied user is dropped by the schema; the check is still for dana.
    let { result } = await call("write_thing", { thing_id: "allowed", content: "hi", user: "admin@example.com" });
    assert.equal(result.toolResults[0]?.output, `wrote 2 bytes to thing:allowed as ${DANA}`);
    assert.deepEqual([fake.lastRequest().user, fake.lastRequest().groups], [DANA, ["platform-team"]]);
    for (const thing of ["denied", "timeout", "badline"]) {
      ({ result } = await call("write_thing", { thing_id: thing, content: "hi" }));
      const out = result.toolResults[0]?.output;
      assert.equal(typeof out, "string");
      assert.ok(String(out).startsWith(`refused: dana@example.com may not thing.write on thing:${thing}`), String(out));
    }
    assert.equal(fake.seen.length, 4);
  });

  test("no session, no request", async () => {
    const model = modelCalling("write_thing", { thing_id: "allowed", content: "hi" });
    const result = await generateText({ model, tools: mod.tools, prompt: "do the thing" });
    const [part] = result.content.filter((p) => p.type === "tool-error");
    assert.ok(part, "the call must fail");
    assert.match(String((part as { error: unknown }).error), /no user set for this session/);
    assert.equal(fake.seen.length, 0);
  });
});
