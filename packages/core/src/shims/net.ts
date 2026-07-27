/**
 * `net`/`http`/`https`/`tls`/`http2`/`dgram` capability shim — mediates OUTBOUND network
 * egress (roadmap M4, issue #5; hardened after two security reviews).
 *
 * The shim derives `{host, port}` from a call's arguments, asks the shared `guard()` helper
 * (attribute → evaluate → report → throw-on-enforce-deny), then forwards to the real API.
 *
 * ROBUST CLASS GUARDING. Capability-bearing classes (`net.Socket`, `tls.TLSSocket`,
 * `http.ClientRequest`, `http.Agent`, `dgram.Socket`) are guarded by exposing a **guarded
 * subclass** whose prototype method (or constructor) runs the guard, NOT a construct-trap
 * Proxy. A Proxy only wraps the class object, so `(new net.Socket()).constructor` and
 * `net.Socket.prototype.connect` reach the real, unguarded class/method — a trivial bypass a
 * review demonstrated. A subclass guards the prototype method itself and, via a
 * `Symbol.hasInstance` override, keeps `instanceof` working for BOTH real and guarded
 * instances. Residual (documented in threat-model.md): climbing two prototype levels
 * (`Object.getPrototypeOf(Object.getPrototypeOf(sock)).connect`) reaches the real method —
 * determined-attacker territory, the same class as un-patching.
 *
 * Under opt-in HARDENED MODE (#17) each guarded subclass and its prototype are frozen, so
 * `net.Socket.prototype.connect = evil` fails instead of silently removing the guard for the
 * whole process. The residual above is unaffected — freezing our subclass says nothing about
 * the real class above it. See `harden.ts`.
 *
 * Coverage & limits (kept in sync with docs/threat-model.md):
 *  - `net`: `connect`/`createConnection` and `new net.Socket().connect()`.
 *  - `http`/`https`: `request`/`get`, `new ClientRequest()`, and `Agent.createConnection`.
 *    Shimming `net` alone does NOT mediate HTTP: Node's own HTTP client loads `net` through
 *    the internal bootstrap loader, which never hits `Module._load`, so each egress module is
 *    shimmed separately (a dependency could otherwise bypass the control by choosing another).
 *  - `tls`: `tls.connect` (BOTH `(options)` and positional `(port, host)` forms) and
 *    `new tls.TLSSocket().connect()`. Default port 443.
 *  - `http2`: `http2.connect(authority)`. Default port 443.
 *  - `dgram`: socket `send`/`connect` (UDP), on both `createSocket()` results and
 *    `new dgram.Socket()`. A `send` on a *connected* socket (no destination args) is not
 *    re-gated (the `connect` was). Reads attributed to `<app>` are not gated, which also
 *    prevents a crash: Node auto-binds an unbound socket and REPLAYS `send` on an internal
 *    tick whose stack has no dependency frame (attributes to `<app>`).
 *  - Inbound `server.listen` is deliberately NOT gated (egress, not binding).
 *  - IPC/unix-socket connects have no host:port and are approximated as `{ "<ipc>", 0 }`.
 *  - `dns` is NOT shimmed (a lookup moves no payload; DNS tunneling is out of scope).
 */
import realNet from "node:net";
import realHttp from "node:http";
import realHttps from "node:https";
import realTls from "node:tls";
import realHttp2 from "node:http2";
import realDgram from "node:dgram";
import { APP_ROOT, attributeCaller } from "../attribution/index.js";
import { evaluate } from "../policy/evaluate.js";
import { CapabilityError } from "../errors.js";
import { guard, type ShimContext, type ShimRegistry } from "./runtime.js";
import { guardedPropFlags, harden, hardenClass } from "./harden.js";

export type { DecisionSink, ShimContext } from "./runtime.js";

type AnyFn = (...args: unknown[]) => unknown;
/* eslint-disable @typescript-eslint/no-explicit-any */
type AnyCtor = new (...args: any[]) => any;

/** Sentinel host for IPC/unix-domain-socket connects, which have no host:port pair. */
const IPC_HOST = "<ipc>";

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/**
 * Derive `{host, port}` from `net.connect`/`net.createConnection`/`tls.connect` arguments:
 *   - `(options[, cb])` — TCP `{host?, port}`, or IPC `{path}`
 *   - `(port[, host][, ...])` — TCP positional
 *   - `(path[, cb])` — IPC positional string
 * IPC connects are approximated as `{host: "<ipc>", port: 0}`.
 */
function deriveNetTarget(args: unknown[], defaultPort = 0): { host: string; port: number } {
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
    const host =
      typeof first["host"] === "string"
        ? first["host"]
        : typeof first["hostname"] === "string"
          ? first["hostname"]
          : "localhost";
    const rawPort = first["port"];
    let port = defaultPort;
    if (typeof rawPort === "number") port = rawPort;
    else if (typeof rawPort === "string" && rawPort !== "") {
      const n = Number(rawPort);
      if (Number.isFinite(n)) port = n;
    }
    return { host, port };
  }
  return { host: IPC_HOST, port: 0 };
}

/**
 * Derive `{host, port}` from `http(s).request`/`get` arguments:
 *   - `(options[, cb])`
 *   - `(url[, options][, cb])` — url is a string or URL; options overrides url fields.
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
    if (typeof rawPort === "number") port = rawPort;
    else if (typeof rawPort === "string" && rawPort !== "") {
      const n = Number(rawPort);
      if (Number.isFinite(n)) port = n;
    }
  };
  const first = args[0];
  if (typeof first === "string") {
    try {
      applyUrl(new URL(first));
    } catch {
      /* not an absolute URL */
    }
  } else if (first instanceof URL) {
    applyUrl(first);
  } else if (isPlainObject(first)) {
    applyOptions(first);
  }
  if (isPlainObject(args[1])) applyOptions(args[1] as Record<string, unknown>);
  return { host: host ?? "localhost", port: port ?? defaultPort };
}

/**
 * Derive `{host, port}` for `tls.connect`/`TLSSocket.connect`. Node accepts the net-style
 * positional/options forms AND merges a trailing options object OVER the positionals
 * (`normalizeConnectArgs` → `ObjectAssign(options, args[2])`). So we derive net-style first,
 * then overlay `host`/`hostname`/`port` from ANY plain-object argument — otherwise
 * `tls.connect(443, "granted.host", { host: "evil.host" })` would guard the granted target
 * while Node connects to the evil one (a false-allow egress bypass a review found).
 */
function deriveTlsTarget(args: unknown[]): { host: string; port: number } {
  const t = deriveNetTarget(args, 443);
  for (const a of args) {
    if (!isPlainObject(a) || a instanceof URL) continue;
    if (typeof a["hostname"] === "string") t.host = a["hostname"];
    else if (typeof a["host"] === "string") t.host = a["host"];
    const rawPort = a["port"];
    if (typeof rawPort === "number") t.port = rawPort;
    else if (typeof rawPort === "string" && rawPort !== "") {
      const n = Number(rawPort);
      if (Number.isFinite(n)) t.port = n;
    }
  }
  return t;
}

function wrapFn(orig: AnyFn, derive: (args: unknown[]) => { host: string; port: number }, ctx: ShimContext): AnyFn {
  const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
    const { host, port } = derive(args);
    guard(ctx, { kind: "net", host, port }); // throws on enforce-deny, before any socket opens
    return orig.apply(this, args);
  };
  Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
  return harden(ctx, wrapped);
}

/**
 * Expose a guarded SUBCLASS of `RealClass` whose prototype `method` runs `derive`+guard
 * before delegating to the real method. `Symbol.hasInstance` is overridden so `instanceof`
 * matches any instance of the real class (guarded or not).
 */
function guardedSubclassMethod(
  RealClass: AnyCtor,
  method: string,
  derive: (args: unknown[]) => { host: string; port: number } | null,
  ctx: ShimContext,
): AnyCtor {
  const realMethod = (RealClass.prototype as Record<string, unknown>)[method];
  // NOTE: returns the REAL class untouched when the method is absent — so nothing below this
  // line may harden it (freezing a builtin is off the table; see harden.ts).
  if (typeof realMethod !== "function") return RealClass;
  const Guarded = class extends RealClass {};
  Object.defineProperty(Guarded.prototype, method, {
    value: function (this: unknown, ...args: unknown[]) {
      const target = derive(args);
      if (target) guard(ctx, { kind: "net", host: target.host, port: target.port });
      return (realMethod as AnyFn).apply(this, args);
    },
    writable: true,
    configurable: true,
  });
  Object.defineProperty(Guarded, Symbol.hasInstance, {
    value: (x: unknown) => x instanceof RealClass,
    configurable: true,
  });
  Object.defineProperty(Guarded, "name", { value: RealClass.name, configurable: true });
  // Hardened mode: freeze the SUBCLASS's prototype, closing `net.Socket.prototype.connect =
  // evil` — a one-line removal of the guard for every caller in the process.
  hardenClass(ctx, Guarded);
  return Guarded;
}

/** Guarded subclass of `http.ClientRequest`: the constructor initiates the connection. */
function guardedClientRequestClass(RealClass: AnyCtor, ctx: ShimContext, defaultPort: number): AnyCtor {
  const Guarded = class extends RealClass {
    constructor(...args: unknown[]) {
      const { host, port } = deriveHttpTarget(args, defaultPort);
      guard(ctx, { kind: "net", host, port }); // before super() → before the connection
      super(...args);
    }
  };
  Object.defineProperty(Guarded, Symbol.hasInstance, {
    value: (x: unknown) => x instanceof RealClass,
    configurable: true,
  });
  Object.defineProperty(Guarded, "name", { value: RealClass.name, configurable: true });
  hardenClass(ctx, Guarded); // hardened mode only — see harden.ts
  return Guarded;
}

/**
 * Build a shimmed `net` module: `connect`/`createConnection` and the `Socket` class's
 * `connect` are guarded. `server.listen` is untouched (egress, not binding).
 */
export function createNetShim(ctx: ShimContext): typeof import("node:net") {
  const shim: Record<string, unknown> = {};
  for (const key of Object.keys(realNet)) {
    shim[key] = (realNet as unknown as Record<string, unknown>)[key];
  }
  const wrapped = wrapFn(realNet.connect as unknown as AnyFn, deriveNetTarget, ctx);
  shim["connect"] = wrapped;
  shim["createConnection"] = wrapped;
  if (typeof realNet.Socket === "function") {
    shim["Socket"] = guardedSubclassMethod(
      realNet.Socket as unknown as AnyCtor,
      "connect",
      deriveNetTarget,
      ctx,
    );
  }
  return harden(ctx, shim) as unknown as typeof import("node:net");
}

/**
 * Build a shimmed `http`/`https` module: `request`/`get`, `new ClientRequest()`, and
 * `Agent.createConnection` are guarded. `server.listen` is untouched.
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
    shim[name] = wrapFn(orig as AnyFn, (a) => deriveHttpTarget(a, defaultPort), ctx);
  }
  if (typeof realRecord["ClientRequest"] === "function") {
    shim["ClientRequest"] = guardedClientRequestClass(realRecord["ClientRequest"] as AnyCtor, ctx, defaultPort);
  }
  // Agent.createConnection is Node's internal net.createConnection, captured at bootstrap —
  // it never routes through Module._load, so a bare Agent's createConnection is un-gated egress.
  if (typeof realRecord["Agent"] === "function") {
    shim["Agent"] = guardedSubclassMethod(
      realRecord["Agent"] as AnyCtor,
      "createConnection",
      (a) => deriveNetTarget(a, defaultPort),
      ctx,
    );
  }
  return harden(ctx, shim) as unknown as T;
}

export function createHttpShim(ctx: ShimContext): typeof import("node:http") {
  return wrapHttpModule(realHttp, ctx, 80);
}

export function createHttpsShim(ctx: ShimContext): typeof import("node:https") {
  return wrapHttpModule(realHttps, ctx, 443);
}

/**
 * Build a shimmed `tls` module: `tls.connect` (options AND positional forms) and
 * `new tls.TLSSocket().connect()` are guarded. Default port 443. `createServer` untouched.
 */
export function createTlsShim(ctx: ShimContext): typeof import("node:tls") {
  const shim: Record<string, unknown> = {};
  for (const key of Object.keys(realTls)) {
    shim[key] = (realTls as unknown as Record<string, unknown>)[key];
  }
  // tls.connect takes net-style positional (port, host) AND a trailing options object that
  // OVERRIDES the positionals — deriveTlsTarget handles the combined form (deriveNetTarget
  // alone would ignore the override and false-allow).
  shim["connect"] = wrapFn(realTls.connect as unknown as AnyFn, deriveTlsTarget, ctx);
  if (typeof realTls.TLSSocket === "function") {
    shim["TLSSocket"] = guardedSubclassMethod(
      realTls.TLSSocket as unknown as AnyCtor,
      "connect",
      deriveTlsTarget,
      ctx,
    );
  }
  return harden(ctx, shim) as unknown as typeof import("node:tls");
}

/** Build a shimmed `http2` module: `http2.connect(authority)` is guarded (default port 443). */
export function createHttp2Shim(ctx: ShimContext): typeof import("node:http2") {
  const shim: Record<string, unknown> = {};
  for (const key of Object.keys(realHttp2)) {
    shim[key] = (realHttp2 as unknown as Record<string, unknown>)[key];
  }
  const realConnect = realHttp2.connect as unknown as AnyFn;
  shim["connect"] = function (this: unknown, ...args: unknown[]): unknown {
    const authority = args[0];
    let host = "localhost";
    let port = 443;
    try {
      const u = authority instanceof URL ? authority : new URL(String(authority));
      host = u.hostname;
      if (u.port !== "") port = Number(u.port);
    } catch {
      /* unparseable authority — deny-leaning localhost:443 */
    }
    // Node honors options.host/port over the authority (http2.connect(authority, options)).
    const opts = args[1];
    if (isPlainObject(opts)) {
      if (typeof opts["host"] === "string") host = opts["host"];
      const rawPort = opts["port"];
      if (typeof rawPort === "number") port = rawPort;
      else if (typeof rawPort === "string" && rawPort !== "") {
        const n = Number(rawPort);
        if (Number.isFinite(n)) port = n;
      }
    }
    guard(ctx, { kind: "net", host, port });
    return realConnect.apply(this, args);
  };
  harden(ctx, shim["connect"] as object);
  return harden(ctx, shim) as unknown as typeof import("node:http2");
}

/** Attribute a dgram op and guard it, EXCEPT reads attributed to `<app>` (see header — this
 * also prevents the auto-bind replay crash, where Node re-invokes send on an internal tick). */
function guardDgram(ctx: ShimContext, host: string, port: number): void {
  const pkg = attributeCaller(ctx.projectRoot !== undefined ? { projectRoot: ctx.projectRoot } : {});
  if (pkg === APP_ROOT) return;
  const decision = evaluate(ctx.policy, ctx.mode, pkg, { kind: "net", host, port });
  ctx.onDecision(pkg, decision);
  if (!decision.allowed) throw new CapabilityError(decision.reason, pkg);
}

/** `send(msg[, offset, length], port[, address][, cb])`: last number = port, last string = host.
 * Returns null for a connected-socket `send(msg[, cb])` (no destination → the connect was gated). */
function deriveDgramSend(args: unknown[]): { host: string; port: number } | null {
  let port: number | undefined;
  let host: string | undefined;
  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (typeof a === "number") port = a;
    else if (typeof a === "string") host = a;
  }
  if (port === undefined) return null; // connected send — no destination args
  return { host: host ?? "localhost", port };
}

/** `connect(port[, address][, cb])`. */
function deriveDgramConnect(args: unknown[]): { host: string; port: number } {
  const port = typeof args[0] === "number" ? args[0] : 0;
  const host = typeof args[1] === "string" ? args[1] : "localhost";
  return { host, port };
}

/** Install guarded `send`/`connect` on a dgram socket instance (used for createSocket results).
 * Under hardened mode these OWN properties are installed non-writable/non-configurable
 * (`guardedPropFlags`) so `socket.send = evil` cannot strip the guard off a socket capwall
 * handed out. The socket itself is never frozen — it needs its mutable internal state. */
function guardDgramInstance(socket: Record<string, unknown>, ctx: ShimContext): void {
  const realSend = socket["send"];
  const realConnect = socket["connect"];
  if (typeof realSend === "function") {
    Object.defineProperty(socket, "send", {
      value: function (this: unknown, ...args: unknown[]) {
        const t = deriveDgramSend(args);
        if (t) guardDgram(ctx, t.host, t.port);
        return (realSend as AnyFn).apply(this, args);
      },
      ...guardedPropFlags(ctx),
    });
  }
  if (typeof realConnect === "function") {
    Object.defineProperty(socket, "connect", {
      value: function (this: unknown, ...args: unknown[]) {
        const t = deriveDgramConnect(args);
        guardDgram(ctx, t.host, t.port);
        return (realConnect as AnyFn).apply(this, args);
      },
      ...guardedPropFlags(ctx),
    });
  }
}

/** Build a shimmed `dgram` module: sockets from `createSocket` AND `new dgram.Socket()` gate send/connect. */
export function createDgramShim(ctx: ShimContext): typeof import("node:dgram") {
  const shim: Record<string, unknown> = {};
  for (const key of Object.keys(realDgram)) {
    shim[key] = (realDgram as unknown as Record<string, unknown>)[key];
  }
  const realCreate = realDgram.createSocket as unknown as AnyFn;
  shim["createSocket"] = harden(ctx, function (this: unknown, ...args: unknown[]): unknown {
    const socket = realCreate.apply(this, args) as Record<string, unknown>;
    guardDgramInstance(socket, ctx);
    return socket;
  });
  const RealDgramSocket = (realDgram as unknown as Record<string, unknown>)["Socket"];
  if (typeof RealDgramSocket === "function") {
    const Guarded = class extends (RealDgramSocket as AnyCtor) {};
    const proto = (RealDgramSocket as AnyCtor).prototype as Record<string, unknown>;
    for (const method of ["send", "connect"] as const) {
      const realMethod = proto[method];
      if (typeof realMethod !== "function") continue;
      Object.defineProperty(Guarded.prototype, method, {
        value: function (this: unknown, ...args: unknown[]) {
          const t = method === "send" ? deriveDgramSend(args) : deriveDgramConnect(args);
          if (t) guardDgram(ctx, t.host, t.port);
          return (realMethod as AnyFn).apply(this, args);
        },
        writable: true,
        configurable: true,
      });
    }
    Object.defineProperty(Guarded, Symbol.hasInstance, {
      value: (x: unknown) => x instanceof (RealDgramSocket as AnyCtor),
      configurable: true,
    });
    Object.defineProperty(Guarded, "name", {
      value: (RealDgramSocket as { name: string }).name,
      configurable: true,
    });
    hardenClass(ctx, Guarded); // hardened mode only — see harden.ts
    shim["Socket"] = Guarded;
  }
  return harden(ctx, shim) as unknown as typeof import("node:dgram");
}

/**
 * Register the network egress shims' specifiers into the loader registry: net, http, https,
 * tls, http2, and dgram. Each module is built once and shared across its specifier aliases.
 * (dns is intentionally NOT shimmed — see the module doc comment and docs/threat-model.md.)
 */
export function registerNetShim(reg: ShimRegistry, ctx: ShimContext): void {
  const pairs: Array<[string, unknown]> = [
    ["net", createNetShim(ctx)],
    ["http", createHttpShim(ctx)],
    ["https", createHttpsShim(ctx)],
    ["tls", createTlsShim(ctx)],
    ["http2", createHttp2Shim(ctx)],
    ["dgram", createDgramShim(ctx)],
  ];
  for (const [name, shim] of pairs) {
    reg.set(name, shim);
    reg.set(`node:${name}`, shim);
  }
}
