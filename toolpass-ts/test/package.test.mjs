// Checks the built package, not the source: what `npm install toolpass-client` gives you.
// The client's behaviour is tested in examples/agent-ts/toolpass_client.test.ts.
//
//     npm test
//
// With TOOLPASS_TS_PACKED=1, CI imports the package from a tarball made by `npm pack`
// and installed into a scratch project, so a missing file in "files" fails here.

import assert from "node:assert/strict";
import { AsyncLocalStorage } from "node:async_hooks";
import { createServer } from "node:http";
import { after, before, test } from "node:test";

const mod = process.env.TOOLPASS_TS_PACKED === "1" ? "toolpass-client" : "../dist/index.js";
const { Toolpass, PermissionDenied, guarded } = await import(mod);

let server;
let tp;

before(async () => {
  server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const body = JSON.parse(raw);
      const ok = req.headers.authorization === "Bearer k" && body.user === "admin@example.com";
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ decision: ok ? "allow" : "deny", reason: ok ? "allowed: x" : "denied: x" }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  tp = new Toolpass({ url: `http://127.0.0.1:${server.address().port}`, apiKey: "k", timeoutMs: 2000 });
});
after(() => server.close());

test("allow and deny", async () => {
  assert.equal((await tp.check("admin@example.com", "demo", "thing.write", "thing:1")).decision, "allow");
  await assert.rejects(tp.require("dana@example.com", "demo", "thing.write", "thing:1"), PermissionDenied);
});

test("unreachable is unknown", async () => {
  const down = new Toolpass({ url: "http://127.0.0.1:9", apiKey: "k", timeoutMs: 1000 });
  assert.equal((await down.check("admin@example.com", "demo", "thing.write", "thing:1")).decision, "unknown");
});

test("guarded", async () => {
  const user = new AsyncLocalStorage();
  const write = guarded(tp, "demo", "thing.write", "thing:{id}", { user })(async ({ id }) => `wrote ${id}`);
  assert.equal(await user.run("admin@example.com", () => write({ id: "1" })), "wrote 1");
  await assert.rejects(user.run("dana@example.com", () => write({ id: "1" })), PermissionDenied);
});
