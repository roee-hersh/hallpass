/**
 * Tests for the client and `guarded` against a fake hallpass.
 *
 *     npm test
 *
 * These need nothing beyond Node. The framework tests are in
 * ai_sdk_tool.test.ts and mcp_server.test.ts.
 */

import assert from "node:assert/strict";
import { AsyncLocalStorage } from "node:async_hooks";
import { after, before, beforeEach, describe, test } from "node:test";
import { API_KEY, DANA, FakeHallpass, silentServer, unusedPort } from "./fake_hallpass.ts";
import { type Decision, Hallpass, PermissionDenied, current, guarded } from "./hallpass_client.ts";

let fake: FakeHallpass;
let hp: Hallpass;

before(async () => {
  fake = await FakeHallpass.start();
  hp = new Hallpass({ url: fake.url, apiKey: API_KEY, timeoutMs: 2000 });
});
after(() => fake.close());
beforeEach(() => fake.clear());

function check(thing: string, groups?: readonly string[] | null): Promise<Decision> {
  return hp.check(DANA, "demo", "thing.write", "thing:" + thing, groups);
}

describe("client", () => {
  test("allow", async () => {
    const d = await check("allowed");
    assert.deepEqual([d.decision, d.code, d.status], ["allow", "allowed", 200]);
    assert.equal(d.allowed, true);
  });

  test("deny is not allowed", async () => {
    for (const thing of ["denied", "nobody"]) {
      const d = await check(thing);
      assert.equal(d.decision, "deny");
      assert.equal(d.allowed, false);
    }
    assert.equal((await check("nobody")).code, "user_not_found");
  });

  test("unknown is not allowed", async () => {
    const d = await check("timeout");
    assert.deepEqual([d.decision, d.code], ["unknown", "upstream_timeout"]);
    assert.equal(d.allowed, false);
  });

  test("400 carries the reason", async () => {
    const d = await check("badreq");
    assert.deepEqual([d.decision, d.code, d.status], ["unknown", "unknown_action", 400]);
    assert.equal(d.allowed, false);
  });

  test("wrong API key is unknown", async () => {
    const d = await new Hallpass({ url: fake.url, apiKey: "wrong", timeoutMs: 2000 }).check(
      DANA, "demo", "thing.write", "thing:allowed");
    assert.deepEqual([d.decision, d.code, d.status], ["unknown", "unauthorized", 401]);
    assert.equal(d.allowed, false);
  });

  test("unusable responses are unknown", async () => {
    for (const thing of ["garbage", "weird", "proxyallow", "boom", "badline", "short"]) {
      const d = await check(thing);
      assert.equal(d.decision, "unknown", thing);
      assert.equal(d.code, "client_error", thing);
      assert.equal(d.allowed, false, thing);
    }
  });

  test("redirect is not followed", async () => {
    const d = await check("redirect");
    assert.deepEqual([d.decision, d.code, d.status], ["unknown", "client_error", 302]);
    assert.equal(d.allowed, false);
    assert.deepEqual(fake.sinkSeen, [], "the API key must not be sent to the redirect target");
  });

  test("unreachable is unknown", async () => {
    const port = await unusedPort();
    const d = await new Hallpass({ url: `http://127.0.0.1:${port}`, apiKey: API_KEY, timeoutMs: 1000 }).check(
      "u", "demo", "thing.read", "thing:1");
    assert.deepEqual([d.decision, d.code, d.status], ["unknown", "client_error", 0]);
    assert.equal(d.allowed, false);
  });

  test("timeout is unknown", async () => {
    const silent = await silentServer(); // accepts the connection and never answers
    try {
      const d = await new Hallpass({ url: silent.url, apiKey: API_KEY, timeoutMs: 200 }).check(
        "u", "demo", "thing.read", "thing:allowed");
      assert.deepEqual([d.decision, d.code, d.status], ["unknown", "client_error", 0]);
      assert.match(d.reason, /timeout/i);
    } finally {
      await silent.close();
    }
  });

  test("url rules", () => {
    for (const ok of [
      "https://hallpass.internal", "http://localhost:8080/", "http://127.0.0.1:1", "http://127.1.2.3",
      "http://[::1]:8080", "http://[::ffff:127.0.0.1]:1", "http://[::ffff:7f00:1]:1",
    ]) {
      new Hallpass({ url: ok, apiKey: API_KEY });
    }
    for (const bad of [
      "http://hallpass.internal", "localhost:8080", "ftp://x", "http://10.0.0.5:8080", "http://[::2]:1",
      "http://[::ffff:10.0.0.5]:1", "http://[::ffff:a00:1]:1", "http://[fe80::1]:1",
      "https://hallpass.internal/?debug=1", "https://hallpass.internal/#x",
      "https://user:pw@hallpass.internal", "https://hallpass.internal /",
    ]) {
      assert.throws(() => new Hallpass({ url: bad, apiKey: API_KEY }), bad);
    }
    assert.equal(new Hallpass({ url: "http://localhost:8080/", apiKey: API_KEY }).url, "http://localhost:8080");
  });

  test("request shape", async () => {
    await check("allowed", ["platform-team"]);
    const req = fake.seen[fake.seen.length - 1]!;
    assert.equal(req.headers.authorization, "Bearer " + API_KEY);
    assert.equal(req.headers["content-type"], "application/json");
    assert.deepEqual(req.body, {
      user: DANA, groups: ["platform-team"], connection: "demo", action: "thing.write", resource: "thing:allowed",
    });
    await check("allowed");
    assert.equal("groups" in fake.lastRequest(), false, "groups omitted when not given");
    await check("allowed", null);
    assert.equal("groups" in fake.lastRequest(), false, "groups omitted when null");
    // A string is not a list of groups.
    await assert.rejects(check("allowed", "platform-team" as unknown as string[]), TypeError);
    await assert.rejects(check("allowed", ["ok", 1] as unknown as string[]), TypeError);
    assert.equal(fake.seen.length, 3);
    assert.equal("fresh" in fake.lastRequest(), false, "fresh omitted when not asked");
    await hp.check(DANA, "demo", "thing.write", "thing:allowed", { fresh: true });
    assert.deepEqual(fake.lastRequest(), {
      user: DANA, connection: "demo", action: "thing.write", resource: "thing:allowed", fresh: true,
    });
    await hp.check(DANA, "demo", "thing.write", "thing:allowed", { groups: ["a"], fresh: true });
    assert.deepEqual(fake.lastRequest(), {
      user: DANA, groups: ["a"], connection: "demo", action: "thing.write", resource: "thing:allowed", fresh: true,
    });
    await hp.check(DANA, "demo", "thing.write", "thing:allowed", { fresh: false });
    assert.equal("fresh" in fake.lastRequest(), false);
    await hp.check(DANA, "demo", "thing.write", "thing:allowed", {});
    assert.equal("groups" in fake.lastRequest(), false);
    // A bare boolean in the options slot is a clear error, not a request.
    await assert.rejects(hp.check(DANA, "demo", "thing.write", "thing:allowed", true as unknown as string[]), /pass \{ fresh: true \}/);
  });

  test("require and allowed", async () => {
    assert.equal(await hp.allowed("u", "demo", "thing.write", "thing:allowed"), true);
    assert.equal(await hp.allowed("u", "demo", "thing.write", "thing:timeout"), false);
    await hp.require("u", "demo", "thing.write", "thing:allowed");
    assert.equal("fresh" in fake.lastRequest(), false);
    await hp.require("u", "demo", "thing.write", "thing:allowed", { fresh: true });
    assert.equal(fake.lastRequest().fresh, true);
    assert.equal(await hp.allowed("u", "demo", "thing.write", "thing:allowed", { fresh: true }), true);
    assert.equal(fake.lastRequest().fresh, true);
    await assert.rejects(hp.require("u", "demo", "thing.write", "thing:timeout"), (e: unknown) => {
      assert.ok(e instanceof PermissionDenied);
      assert.equal(e.decision.code, "upstream_timeout");
      assert.match(e.message, /unknown/);
      return true;
    });
  });

  test("missing API key", () => {
    const saved = process.env.HALLPASS_API_KEY;
    delete process.env.HALLPASS_API_KEY;
    try {
      assert.throws(() => new Hallpass({ url: fake.url }), /HALLPASS_API_KEY/);
    } finally {
      if (saved !== undefined) {
        process.env.HALLPASS_API_KEY = saved;
      }
    }
  });

  test("the API key is not a visible property", () => {
    assert.equal(JSON.stringify(hp).includes(API_KEY), false);
    assert.equal(Object.keys(hp).some((k) => /key/i.test(k)), false);
  });
});

describe("guarded", () => {
  type WriteArgs = { thing_id: string; content?: string };

  test("runs only on allow", async () => {
    const ran: string[] = [];
    const write = guarded(hp, "demo", "thing.write", "thing:{thing_id}", { user: DANA, groups: ["platform-team"] })(
      async ({ thing_id }: WriteArgs) => {
        ran.push(thing_id);
        return "ok";
      },
    );
    assert.equal(await write({ thing_id: "allowed" }), "ok");
    for (const thing of ["denied", "timeout", "garbage", "badline"]) {
      await assert.rejects(write({ thing_id: thing }), PermissionDenied);
    }
    assert.deepEqual(ran, ["allowed"]);
    assert.deepEqual(fake.lastRequest(), {
      user: DANA, groups: ["platform-team"], connection: "demo", action: "thing.write", resource: "thing:badline",
    });
  });

  test("fresh", async () => {
    const remove = guarded(hp, "demo", "thing.write", "thing:{thing_id}", { user: DANA, fresh: true })(
      async (_: WriteArgs) => "gone",
    );
    assert.equal(await remove({ thing_id: "allowed" }), "gone");
    assert.deepEqual(fake.lastRequest(), {
      user: DANA, connection: "demo", action: "thing.write", resource: "thing:allowed", fresh: true,
    });
    await assert.rejects(remove({ thing_id: "denied" }), PermissionDenied);
    assert.equal(fake.lastRequest().fresh, true);
  });

  test("user is never an argument", async () => {
    const write = guarded(hp, "demo", "thing.write", "thing:{thing_id}", { user: DANA })(
      async (args: WriteArgs) => "ok " + JSON.stringify(args),
    );
    assert.equal(write.name, "");
    // A user key in the arguments is ignored, not honoured; the arguments
    // reach the body unchanged.
    assert.equal(await write({ thing_id: "allowed", user: "admin@example.com" } as WriteArgs),
      'ok {"thing_id":"allowed","user":"admin@example.com"}');
    assert.equal(fake.lastRequest().user, DANA);
    // Anything but one object of arguments is a TypeError before any request.
    for (const bad of ["allowed", ["allowed"], null, undefined, 1]) {
      await assert.rejects(write(bad as unknown as WriteArgs), TypeError);
    }
    assert.equal(fake.seen.length, 1);
  });

  test("resource template", async () => {
    const write = guarded(hp, "demo", "thing.write", "thing:{thing_id}", { user: DANA })(
      async (_: Record<string, unknown>) => "ok",
    );
    assert.equal(await write({ thing_id: "allowed" }), "ok");
    assert.equal(fake.lastRequest().resource, "thing:allowed");
    // Cannot form the resource: no request, no action.
    await assert.rejects(write({ content: "no thing_id" }), /thing_id/);
    await assert.rejects(write({ thing_id: { nested: true } }), /thing_id/);
    await assert.rejects(write({ thing_id: undefined }), /thing_id/);
    assert.equal(fake.seen.length, 1);
    // Several placeholders, a number among them, and literal text around them.
    const move = guarded(hp, "demo", "thing.write", "{kind}{n}:{id}", { user: DANA })(
      async (_: Record<string, unknown>) => "ok",
    );
    await move({ kind: "thing", n: 7, id: "allowed" });
    assert.equal(fake.lastRequest().resource, "thing7:allowed");
  });

  test("user sources", async () => {
    const seen: Array<[unknown, unknown]> = [];
    const make = (user: Parameters<typeof guarded>[4]["user"], groups?: Parameters<typeof guarded>[4]["groups"]) =>
      guarded(hp, "demo", "thing.write", "thing:{thing_id}", { user, groups })(async (_: WriteArgs) => "ok");
    const record = () => {
      const r = fake.lastRequest();
      seen.push([r.user, r.groups]);
    };

    await make("fixed@example.com")({ thing_id: "allowed" });
    record();
    await make(() => "called@example.com", () => ["g1"])({ thing_id: "allowed" });
    record();
    const store = new AsyncLocalStorage<string>();
    const gstore = new AsyncLocalStorage<readonly string[]>();
    await store.run("context@example.com", () => gstore.run(["g2"], () => make(store, gstore)({ thing_id: "allowed" })));
    record();
    assert.deepEqual(seen, [
      ["fixed@example.com", undefined],
      ["called@example.com", ["g1"]],
      ["context@example.com", ["g2"]],
    ]);
    // Nothing set for the session: fail before any request.
    await assert.rejects(make(new AsyncLocalStorage<string>())({ thing_id: "allowed" }), /no user set/);
    await assert.rejects(make(() => undefined)({ thing_id: "allowed" }), /no user set/);
    await assert.rejects(make("")({ thing_id: "allowed" }), /non-empty/);
    await assert.rejects(make(DANA, "platform-team" as unknown as string[])({ thing_id: "allowed" }), TypeError);
    await assert.rejects(make(DANA, new AsyncLocalStorage())({ thing_id: "allowed" }), /no groups set/);
    assert.equal(fake.seen.length, 3);
  });

  test("current", () => {
    const store = new AsyncLocalStorage<string>();
    assert.throws(() => current(store), /no user set for this session/);
    assert.throws(() => current(store, "groups"), /no groups set for this session/);
    assert.deepEqual(
      [store.run("x", () => current(store)), current(() => "y"), current("z")],
      ["x", "y", "z"],
    );
  });

  test("extra arguments pass through", async () => {
    const write = guarded(hp, "demo", "thing.write", "thing:{thing_id}", { user: DANA })(
      async ({ thing_id }: WriteArgs, extra: { id: string }) => `${thing_id} ${extra.id}`,
    );
    assert.equal(await write({ thing_id: "allowed" }, { id: "call-1" }), "allowed call-1");
  });

  test("deny hook", async () => {
    const write = guarded(hp, "demo", "thing.write", "thing:{thing_id}", {
      user: DANA,
      deny: (e) => `refused: ${e.message}`,
    })(async (_: WriteArgs) => "ok");
    assert.equal(await write({ thing_id: "allowed" }), "ok");
    const out = await write({ thing_id: "denied" });
    assert.ok(out.startsWith("refused: dana@example.com may not thing.write on thing:denied"), out);
    // Only a refusal goes through the hook; other errors still reject.
    await assert.rejects(write({ content: "no thing_id" } as unknown as WriteArgs), /thing_id/);
    await assert.rejects(write("x" as unknown as WriteArgs), TypeError);
    assert.equal(fake.seen.length, 2);
  });
});
