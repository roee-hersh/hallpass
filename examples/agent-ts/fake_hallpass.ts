/**
 * A fake hallpass for the tests: answers per resource id, records every
 * request, and misbehaves on request (garbage, truncation, redirects).
 * The same table as ../agent/test_hallpass_client.py.
 */

import http from "node:http";
import type { AddressInfo } from "node:net";

export const API_KEY = "test-key";
export const DANA = "dana@example.com";

type Answer = [status: number, body: unknown] | null;

// What the fake answers per resource id. (status, body); null means the fake
// writes something that is not an HTTP response.
const ANSWERS: Record<string, Answer> = {
  allowed: [200, { decision: "allow", reason: "allowed: admin" }],
  denied: [200, { decision: "deny", reason: "denied: not an admin" }],
  nobody: [200, { decision: "deny", reason: "user_not_found: no account" }],
  timeout: [200, { decision: "unknown", reason: "upstream_timeout: jira took too long" }],
  badreq: [400, { decision: "unknown", reason: "unknown_action: no such action" }],
  garbage: [200, "<html>not json</html>"],
  weird: [200, { decision: "maybe", reason: "allowed: ?" }],
  proxyallow: [502, { decision: "allow", reason: "allowed: from a broken proxy" }],
  boom: [500, "internal error"],
  redirect: [302, { decision: "allow", reason: "allowed: from the redirect itself" }],
  badline: null, // the fake writes a non-HTTP response
  short: null, // the fake announces more bytes than it sends
};

export interface Seen {
  headers: http.IncomingHttpHeaders;
  body: Record<string, unknown>;
}

export class FakeHallpass {
  readonly url: string;
  /** Every request the fake received. */
  readonly seen: Seen[] = [];
  /** Every request that reached the redirect target. Must stay empty. */
  readonly sinkSeen: http.IncomingHttpHeaders[] = [];
  readonly #server: http.Server;
  readonly #sink: http.Server;

  private constructor(server: http.Server, sink: http.Server) {
    this.#server = server;
    this.#sink = sink;
    this.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  static async start(): Promise<FakeHallpass> {
    const sink = http.createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        fake.sinkSeen.push(req.headers);
        const raw = '{"decision":"allow","reason":"allowed: by the sink"}';
        res.writeHead(200, { "Content-Length": raw.length });
        res.end(raw);
      });
    });
    const server = http.createServer((req, res) => {
      let data = "";
      req.setEncoding("utf8");
      req.on("data", (c: string) => (data += c));
      req.on("end", () => {
        const body = JSON.parse(data) as Record<string, unknown>;
        fake.seen.push({ headers: req.headers, body });
        const thing = String(body.resource).split(":", 2)[1] ?? "";
        const socket = req.socket;
        if (thing === "badline") {
          socket.write("garbage\r\n\r\n");
          socket.destroy();
          return;
        }
        if (thing === "short") {
          socket.write('HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n{"decision":"allow"}');
          socket.destroy();
          return;
        }
        let status: number;
        let ans: unknown;
        if (req.headers.authorization !== "Bearer " + API_KEY) {
          [status, ans] = [401, { decision: "unknown", reason: "unauthorized: missing or wrong API key" }];
        } else {
          const a = ANSWERS[thing];
          if (!a) {
            throw new Error(`fake hallpass: no answer for ${thing}`);
          }
          [status, ans] = a;
        }
        const raw = typeof ans === "string" ? ans : JSON.stringify(ans);
        const headers: http.OutgoingHttpHeaders = { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(raw) };
        if (status === 302) {
          // An allow at the other end of a redirect must not count.
          headers.Location = `http://127.0.0.1:${(sink.address() as AddressInfo).port}/check`;
        }
        res.writeHead(status, headers);
        res.end(raw);
      });
    });
    await listen(sink);
    await listen(server);
    const fake = new FakeHallpass(server, sink);
    return fake;
  }

  lastRequest(): Record<string, unknown> {
    const last = this.seen[this.seen.length - 1];
    if (!last) {
      throw new Error("fake hallpass: no request seen");
    }
    return last.body;
  }

  clear(): void {
    this.seen.length = 0;
    this.sinkSeen.length = 0;
  }

  async close(): Promise<void> {
    this.#server.closeAllConnections();
    this.#sink.closeAllConnections();
    await Promise.all([close(this.#server), close(this.#sink)]);
  }
}

function listen(s: http.Server): Promise<void> {
  return new Promise((resolve) => s.listen(0, "127.0.0.1", resolve));
}

function close(s: http.Server): Promise<void> {
  return new Promise((resolve, reject) => s.close((err) => (err ? reject(err) : resolve())));
}

/** A port on 127.0.0.1 nobody listens on. */
export async function unusedPort(): Promise<number> {
  const s = http.createServer();
  await listen(s);
  const port = (s.address() as AddressInfo).port;
  await close(s);
  return port;
}
