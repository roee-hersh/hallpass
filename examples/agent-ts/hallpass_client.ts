/**
 * A minimal hallpass client for agents. Node's built-in fetch, no dependencies.
 *
 * The one rule an agent has to follow: perform an action on behalf of a user
 * only when hallpass answered `allow`. `deny` and `unknown` both mean "do not
 * act", and so does any failure to reach hallpass at all.
 *
 *     const hp = new Hallpass(); // HALLPASS_URL and HALLPASS_API_KEY from the environment
 *     await hp.require("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123");
 *     await jira.deleteIssue("PAY-123"); // only reached when the answer was allow
 *
 * Or, for a tool an agent framework exposes to a model, `guarded`:
 *
 *     const currentUser = new AsyncLocalStorage<string>();
 *
 *     const deleteIssue = guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", { user: currentUser })(
 *       async ({ key }: { key: string }) => {
 *         await jira.deleteIssue(key);
 *         return `deleted ${key}`;
 *       },
 *     );
 *
 * The user comes from the application, never from the tool's arguments.
 *
 * This is the TypeScript counterpart of ../agent/hallpass_client.py and
 * follows the same contract; the tests in hallpass_client.test.ts spell it
 * out. Copy this file into your project.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { isIPv4, isIPv6 } from "node:net";

export const ALLOW = "allow";
export const DENY = "deny";
export const UNKNOWN = "unknown";

export type DecisionValue = typeof ALLOW | typeof DENY | typeof UNKNOWN;

/**
 * One answer from `POST /check`.
 *
 * `decision` is `allow`, `deny` or `unknown`. `reason` is `"<code>: <text>"`
 * as hallpass sent it, or `"client_error: ..."` when the request never
 * produced a usable answer. `status` is the HTTP status, 0 when no response
 * arrived.
 */
export class Decision {
  readonly decision: DecisionValue;
  readonly reason: string;
  readonly status: number;

  constructor(decision: DecisionValue, reason: string, status = 200) {
    this.decision = decision;
    this.reason = reason;
    this.status = status;
    Object.freeze(this);
  }

  /** True only for a positive `allow`. `unknown` is not allowed. */
  get allowed(): boolean {
    return this.decision === ALLOW;
  }

  /** The machine-readable code in front of the colon, e.g. `user_not_found`. */
  get code(): string {
    return (this.reason.split(":", 1)[0] ?? "").trim();
  }
}

/** Thrown by `Hallpass.require` when the answer was not `allow`. */
export class PermissionDenied extends Error {
  readonly decision: Decision;
  readonly user: string;
  readonly connection: string;
  readonly action: string;
  readonly resource: string;

  constructor(decision: Decision, user: string, connection: string, action: string, resource: string) {
    super(`${user} may not ${action} on ${resource} in ${connection}: ${decision.decision} (${decision.reason})`);
    this.name = "PermissionDenied";
    this.decision = decision;
    this.user = user;
    this.connection = connection;
    this.action = action;
    this.resource = resource;
  }
}

export interface HallpassOptions {
  /** Defaults to `$HALLPASS_URL` or `http://localhost:8080`. */
  url?: string;
  /** Defaults to `$HALLPASS_API_KEY`. */
  apiKey?: string;
  /** Total budget for one check, connection and body included. Default 10 s. */
  timeoutMs?: number;
}

/**
 * Client for one hallpass service.
 *
 * The URL must be `https://`; plain `http://` is accepted only for
 * `localhost` or a loopback address, the same rule hallpass applies to its
 * own upstream URLs, because the API key travels in a header. hallpass
 * itself waits up to the connection's `timeout` (8 s by default) for the
 * upstream system, so keep `timeoutMs` a little above that.
 *
 * Redirects are not followed. A redirect would re-send the API key to
 * whatever host the `Location` header names, and its answer would not be
 * hallpass's, so a 3xx becomes an `unknown` decision like any other
 * unusable response.
 */
export class Hallpass {
  readonly url: string;
  readonly timeoutMs: number;
  readonly #apiKey: string;

  constructor(options: HallpassOptions = {}) {
    this.url = validateUrl(options.url || process.env.HALLPASS_URL || "http://localhost:8080");
    this.#apiKey = options.apiKey ?? process.env.HALLPASS_API_KEY ?? "";
    if (!this.#apiKey) {
      throw new Error("hallpass API key missing: pass apiKey or set HALLPASS_API_KEY");
    }
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  /** Ask hallpass. Never rejects on transport: every failure becomes an `unknown` decision. */
  async check(
    user: string,
    connection: string,
    action: string,
    resource: string,
    groups?: readonly string[],
  ): Promise<Decision> {
    const body: Record<string, unknown> = { user, connection, action, resource };
    if (groups !== undefined) {
      body.groups = groupList(groups);
    }
    let response: Response;
    let raw: string;
    try {
      response = await fetch(this.url + "/check", {
        method: "POST",
        headers: {
          Authorization: "Bearer " + this.#apiKey,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(body),
        redirect: "manual",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      // 400 and 401 still carry a decision body; anything else is unusable
      // and parse() says so. A body cut short or a malformed response
      // rejects here and lands in the catch below.
      raw = await response.text();
    } catch (e) {
      return new Decision(UNKNOWN, `client_error: hallpass unreachable: ${describe(e)}`, 0);
    }
    return parse(response.status, raw);
  }

  /** True only when hallpass said `allow`. */
  async allowed(
    user: string,
    connection: string,
    action: string,
    resource: string,
    groups?: readonly string[],
  ): Promise<boolean> {
    return (await this.check(user, connection, action, resource, groups)).allowed;
  }

  /** Resolve to the decision when it is `allow`; reject with `PermissionDenied` otherwise. */
  async require(
    user: string,
    connection: string,
    action: string,
    resource: string,
    groups?: readonly string[],
  ): Promise<Decision> {
    const d = await this.check(user, connection, action, resource, groups);
    if (!d.allowed) {
      throw new PermissionDenied(d, user, connection, action, resource);
    }
    return d;
  }
}

/** The rule hallpass applies to its own upstream URLs (ValidateHTTPSURL). */
function validateUrl(url: string): string {
  if (/[\s?#]/.test(url)) {
    throw new Error(`hallpass url ${JSON.stringify(url)} must not contain whitespace, '?' or '#'`);
  }
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error(`hallpass url ${JSON.stringify(url)} must start with https:// (http:// only for localhost)`);
  }
  if (u.username || u.password) {
    throw new Error(`hallpass url ${JSON.stringify(url)} must not contain userinfo`);
  }
  if (u.protocol === "https:" && u.hostname) {
    return url.replace(/\/+$/, "");
  }
  if (u.protocol === "http:" && isLoopback(u.hostname)) {
    return url.replace(/\/+$/, "");
  }
  throw new Error(`hallpass url ${JSON.stringify(url)} must start with https:// (http:// only for localhost)`);
}

function isLoopback(hostname: string): boolean {
  if (hostname === "localhost") {
    return true;
  }
  const host = hostname.replace(/^\[|\]$/g, ""); // URL keeps the brackets around an IPv6 literal
  if (isIPv4(host)) {
    return host.startsWith("127.");
  }
  return isIPv6(host) && host === "::1";
}

function groupList(groups: readonly string[]): string[] {
  if (typeof groups === "string" || !Array.isArray(groups) || !groups.every((g) => typeof g === "string")) {
    throw new TypeError("groups must be an array of strings");
  }
  return [...groups];
}

function describe(e: unknown): string {
  if (!(e instanceof Error)) {
    return String(e);
  }
  // fetch reports "fetch failed" and keeps the socket error in cause.
  const cause = e.cause instanceof Error ? `: ${e.cause.message}` : "";
  return e.message + cause;
}

function parse(status: number, raw: string): Decision {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return new Decision(UNKNOWN, `client_error: unexpected response (HTTP ${status})`, status);
  }
  if (typeof data !== "object" || data === null || !("decision" in data)) {
    return new Decision(UNKNOWN, `client_error: unexpected response (HTTP ${status})`, status);
  }
  const { decision, reason } = data as { decision: unknown; reason?: unknown };
  if (decision !== ALLOW && decision !== DENY && decision !== UNKNOWN) {
    return new Decision(UNKNOWN, `client_error: unexpected decision ${JSON.stringify(decision)}`, status);
  }
  if (decision === ALLOW && status !== 200) {
    // hallpass never allows with a non-200 status; do not trust a proxy that does.
    return new Decision(UNKNOWN, `client_error: allow with HTTP ${status}`, status);
  }
  return new Decision(decision, reason === undefined ? "" : String(reason), status);
}

/**
 * Where the acting user (or their groups) comes from: a fixed value, a
 * zero-argument function, or an `AsyncLocalStorage` the application enters
 * for the current session or request. Resolved on every call.
 */
export type Source<T> = T | (() => T | undefined) | AsyncLocalStorage<T>;
export type UserSource = Source<string>;
export type GroupsSource = Source<readonly string[]>;

/**
 * Resolve a user or groups source now.
 *
 * An `AsyncLocalStorage` with nothing set for this session throws an error
 * saying so, rather than handing an `undefined` to a framework.
 */
export function current<T>(source: Source<T>, what = "user"): T {
  let value: T | undefined;
  if (source instanceof AsyncLocalStorage) {
    value = source.getStore();
    if (value === undefined) {
      throw new Error(`no ${what} set for this session: the AsyncLocalStorage has no store here`);
    }
    return value;
  }
  if (typeof source === "function") {
    value = (source as () => T | undefined)();
    if (value === undefined) {
      throw new Error(`no ${what} set for this session: the ${what} function returned undefined`);
    }
    return value;
  }
  return source;
}

export interface GuardedOptions<D = never> {
  /** Where the acting user comes from. Never the tool's arguments. */
  user: UserSource;
  /** The user's groups, from the same kinds of source. Must yield an array. */
  groups?: GroupsSource;
  /**
   * Called with the `PermissionDenied` instead of throwing it; its return
   * value is returned to the caller. For frameworks that hide a thrown
   * error's text from the model.
   */
  deny?: (e: PermissionDenied) => D | Promise<D>;
}

/** The shape every agent framework hands a tool: one object of arguments, then whatever else it passes. */
export type Args = Record<string, unknown>;

/**
 * Wrap a function so it runs only after hallpass allowed it.
 *
 * The user the check is for comes from `options.user`: a string, a
 * zero-argument function, or an `AsyncLocalStorage` the application enters
 * for the current session. It is never read from the call's arguments, so a
 * framework's tool definition can take the wrapped function directly and
 * the model cannot pick who it acts as; a `user` key in the arguments is
 * ignored, never honoured. `groups` works the same way and must yield an
 * array.
 *
 * `resource` is a template over the call's arguments, e.g. `"issue:{key}"`.
 * A call whose arguments cannot fill it makes no request and runs nothing.
 * The wrapped function is called with the same arguments it was given, so
 * an agent framework's extra parameters (tool call id, abort signal, ...)
 * pass through.
 *
 * Any answer other than `allow` rejects with `PermissionDenied` before the
 * body runs. With `options.deny` given, its return value is returned instead.
 */
export function guarded<D = never>(
  hp: Hallpass,
  connection: string,
  action: string,
  resource: string,
  options: GuardedOptions<D>,
): <A extends Args, Rest extends unknown[], R>(
  fn: (args: A, ...rest: Rest) => R | Promise<R>,
) => (args: A, ...rest: Rest) => Promise<R | D> {
  const { user, groups, deny } = options;
  return <A extends Args, Rest extends unknown[], R>(fn: (args: A, ...rest: Rest) => R | Promise<R>) => {
    const name = fn.name || "the guarded function";
    const inner = async (args: A, ...rest: Rest): Promise<R | D> => {
      if (typeof args !== "object" || args === null || Array.isArray(args)) {
        throw new TypeError(`${name} takes one object of arguments`);
      }
      // Everything below happens before any request, so a bad call is an
      // error to the caller, never a check on one resource and an action on
      // another.
      const target = fill(resource, args);
      const who = current(user, "user");
      if (typeof who !== "string" || who === "") {
        throw new Error("guarded: user must be a non-empty string");
      }
      const grp = groups === undefined ? undefined : current(groups, "groups");
      try {
        await hp.require(who, connection, action, target, grp);
      } catch (e) {
        if (e instanceof PermissionDenied && deny !== undefined) {
          return deny(e);
        }
        throw e;
      }
      return fn(args, ...rest);
    };
    Object.defineProperty(inner, "name", { value: fn.name });
    return inner;
  };
}

/** `"thing:{thing_id}"` over `{thing_id: "1"}` gives `"thing:1"`. */
function fill(template: string, args: Args): string {
  return template.replace(/\{([^{}]*)\}/g, (_, key: string) => {
    const v = args[key];
    if (typeof v === "string") {
      return v;
    }
    if (typeof v === "number" || typeof v === "boolean") {
      return String(v);
    }
    throw new Error(`guarded: resource ${JSON.stringify(template)} needs a string argument ${JSON.stringify(key)}`);
  });
}
