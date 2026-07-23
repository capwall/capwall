/**
 * `net`/`http`/`https` capability shim — mediates OUTBOUND network egress (roadmap M4, issue #5).
 *
 * On every capability-sensitive call the shim (1) derives `{host, port}` from the call's
 * arguments, (2) asks the shared `guard()` helper (attribute → evaluate → report →
 * throw-on-enforce-deny), then (3) forwards to the real API. Signatures of the real API are
 * preserved: wrappers forward all arguments verbatim, so correct code is unaffected.
 *
 * Coverage & limits (kept in sync with docs/threat-model.md):
 *  - `net`: `connect`/`createConnection` are wrapped (they are aliases of the same underlying
 *    function in Node — both are guarded identically here). Everything else (`Socket`,
 *    `Server`, constants, …) passes through unchanged.
 *  - `http`/`https`: `request`/`get` are wrapped. Shimming `net` alone does NOT mediate HTTP
 *    traffic, so `http`/`https` need their own wrappers rather than inheriting coverage from
 *    the `net` shim. Mechanically: capwall's require interception patches `Module._load`,
 *    which is the CJS *user*-module loader — `require("net")` calls made by application/
 *    dependency code go through it and get capwall's shim. But Node's OWN internal
 *    implementation (e.g. `lib/_http_client.js` requiring `net` to open the socket) loads
 *    through Node's internal bootstrap loader, a separate path that never calls
 *    `Module._load`. So even with `net`'s require fully gated, `http.request`/`.get` still
 *    reach the real, un-shimmed `net` internally — confirmed empirically in net.test.ts by
 *    reproducing the `Module._load` patch directly and showing a real `http.get()` is
 *    completely unmediated by it (no thrown `CapabilityError`, no recorded decision).
 *  - Inbound `server.listen(...)` is intentionally NOT gated on either module — capwall's
 *    scope is egress (what a package can reach OUT to), not binding a local port. A package
 *    that wants to run a server is a distinct concern from one that wants to phone home; the
 *    threat model targets the latter (exfiltration, C2, supply-chain callbacks).
 *  - IPC / unix-domain-socket connects (`net.connect({path})`, `net.connect(path)`) have no
 *    host:port pair. We approximate them as `{host: "<ipc>", port: 0}` so they still flow
 *    through deny-by-default rather than silently bypassing the guard. This is a coarse
 *    approximation, not a precise policy surface for IPC — documented here and in the threat
 *    model rather than pretended away. A policy wanting to allow IPC explicitly must grant
 *    `{hosts: ["<ipc>"], ports: [0]}`.
 *  - Guarding happens synchronously BEFORE the real `connect`/`request`/`get` is invoked, so
 *    an enforce-mode denial throws before any socket opens — no connection is ever attempted.
 *  - Host/port derivation is best-effort argument parsing (options object, positional
 *    `(port, host)`/`(port)`, `(path)`, `url` string/`URL` instance, `(url, options)`). Forms
 *    this doesn't recognize fall back to `{host: "<ipc>", port: 0}` (net) or
 *    `{host: "localhost", port: <module default>}` (http/https) — conservative, deny-leaning
 *    fallbacks rather than accidentally-permissive ones.
 */
import realNet from "node:net";
import realHttp from "node:http";
import realHttps from "node:https";
import { guard, type ShimContext, type ShimRegistry } from "./runtime.js";

export type { DecisionSink, ShimContext } from "./runtime.js";

type AnyFn = (...args: unknown[]) => unknown;

/** Sentinel host for IPC/unix-domain-socket connects, which have no host:port pair. */
const IPC_HOST = "<ipc>";

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/**
 * Derive `{host, port}` from `net.connect`/`net.createConnection` arguments. Node accepts:
 *   - `connect(options[, connectListener])` — TCP: `{host?, port}`, or IPC: `{path}`
 *   - `connect(port[, host][, connectListener])` — TCP, positional
 *   - `connect(path[, connectListener])` — IPC, positional string
 *
 * IPC connects (a `path` option, or a bare string path argument) have no host:port pair and
 * are approximated as `{host: "<ipc>", port: 0}` — see the module doc comment.
 */
function deriveNetTarget(args: unknown[]): { host: string; port: number } {
  const first = args[0];
  if (typeof first === "number") {
    const host = typeof args[1] === "string" ? args[1] : "localhost";
    return { host, port: first };
  }
  if (typeof first === "string") {
    return { host: IPC_HOST, port: 0 }; // positional path form — IPC
  }
  if (isPlainObject(first)) {
    if (typeof first["path"] === "string") return { host: IPC_HOST, port: 0 };
    const host = typeof first["host"] === "string" ? first["host"] : "localhost";
    const rawPort = first["port"];
    let port = 0;
    if (typeof rawPort === "number") {
      port = rawPort;
    } else if (typeof rawPort === "string") {
      const n = Number(rawPort);
      if (Number.isFinite(n)) port = n;
    }
    return { host, port };
  }
  return { host: IPC_HOST, port: 0 };
}

function wrapConnect(orig: AnyFn, ctx: ShimContext): AnyFn {
  const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
    const { host, port } = deriveNetTarget(args);
    guard(ctx, { kind: "net", host, port }); // throws on enforce-deny, before any socket opens
    return orig.apply(this, args);
  };
  Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
  return wrapped;
}

/**
 * Build a shimmed `net` module: `connect`/`createConnection` are guarded (they are aliases —
 * both wrapped identically, sharing one guarded closure); everything else (`Socket`, `Server`,
 * constants, …) is the real thing, passed through. `server.listen` is deliberately untouched.
 */
export function createNetShim(ctx: ShimContext): typeof import("node:net") {
  const shim: Record<string, unknown> = {};
  for (const key of Object.keys(realNet)) {
    shim[key] = (realNet as unknown as Record<string, unknown>)[key];
  }
  const wrapped = wrapConnect(realNet.connect as unknown as AnyFn, ctx);
  shim["connect"] = wrapped;
  shim["createConnection"] = wrapped;
  return shim as unknown as typeof import("node:net");
}

/**
 * Derive `{host, port}` from `http.request`/`http.get`/`https.request`/`https.get` arguments.
 * Node accepts:
 *   - `request(options[, callback])`
 *   - `request(url[, options][, callback])` — `url` is a string or `URL` instance
 * (and identically for `get`). An `options` argument overrides fields a `url` argument set
 * (matches Node's own merge order). `defaultPort` is 80 for http, 443 for https.
 */
function deriveHttpTarget(args: unknown[], defaultPort: number): { host: string; port: number } {
  let host: string | undefined;
  let port: number | undefined;

  const applyUrl = (u: URL): void => {
    host = u.hostname;
    if (u.port !== "") port = Number(u.port);
  };
  const applyOptions = (o: Record<string, unknown>): void => {
    if (typeof o["hostname"] === "string") host = o["hostname"];
    else if (typeof o["host"] === "string") host = o["host"];
    const rawPort = o["port"];
    if (typeof rawPort === "number") {
      port = rawPort;
    } else if (typeof rawPort === "string" && rawPort !== "") {
      const n = Number(rawPort);
      if (Number.isFinite(n)) port = n;
    }
  };

  const first = args[0];
  if (typeof first === "string") {
    try {
      applyUrl(new URL(first));
    } catch {
      /* not a parseable absolute URL; fall through — an options arg (if any) still applies */
    }
  } else if (first instanceof URL) {
    applyUrl(first);
  } else if (isPlainObject(first)) {
    applyOptions(first);
  }

  const second = args[1];
  if (isPlainObject(second)) {
    applyOptions(second);
  }

  return { host: host ?? "localhost", port: port ?? defaultPort };
}

function wrapHttpFn(orig: AnyFn, ctx: ShimContext, defaultPort: number): AnyFn {
  const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
    const { host, port } = deriveHttpTarget(args, defaultPort);
    guard(ctx, { kind: "net", host, port }); // throws on enforce-deny, before any socket opens
    return orig.apply(this, args);
  };
  Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
  return wrapped;
}

/**
 * Build a shimmed `http`/`https` module: `request`/`get` are guarded; everything else
 * (`Agent`, `Server`, constants, …) is the real thing, passed through. `server.listen` is
 * deliberately untouched (capwall mediates egress, not binding).
 */
function wrapHttpModule<T extends object>(real: T, ctx: ShimContext, defaultPort: number): T {
  const shim: Record<string, unknown> = {};
  for (const key of Object.keys(real)) {
    shim[key] = (real as unknown as Record<string, unknown>)[key];
  }
  const realRecord = real as unknown as Record<string, unknown>;
  for (const name of ["request", "get"]) {
    const orig = realRecord[name];
    if (typeof orig !== "function") continue;
    shim[name] = wrapHttpFn(orig as AnyFn, ctx, defaultPort);
  }
  return shim as unknown as T;
}

export function createHttpShim(ctx: ShimContext): typeof import("node:http") {
  return wrapHttpModule(realHttp, ctx, 80);
}

export function createHttpsShim(ctx: ShimContext): typeof import("node:https") {
  return wrapHttpModule(realHttps, ctx, 443);
}

/**
 * Register the net/http/https shims' specifiers into the loader registry. Each module is
 * built once and shared across its specifier aliases.
 */
export function registerNetShim(reg: ShimRegistry, ctx: ShimContext): void {
  const netShim = createNetShim(ctx);
  reg.set("net", netShim);
  reg.set("node:net", netShim);

  const httpShim = createHttpShim(ctx);
  reg.set("http", httpShim);
  reg.set("node:http", httpShim);

  const httpsShim = createHttpsShim(ctx);
  reg.set("https", httpsShim);
  reg.set("node:https", httpsShim);
}
