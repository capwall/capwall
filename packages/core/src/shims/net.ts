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
 *
 * GETTER-TOCTOU CLOSED (issue #26). Every derive function above reads `host`/`hostname`/
 * `port` off the caller's options object (or URL) to compute the guarded target, then —
 * historically — the SAME object was forwarded to the real API. If those fields were accessor
 * (getter) properties — including a caller-supplied `URL` instance with an OWN shadowed
 * `hostname`/`port` accessor, which Node happily honors — they could legally return a
 * different value on Node's later internal re-read than they did during capwall's derivation:
 * capwall would guard `granted.host:443` while Node opened a socket to `evil.host:443`. Fixed
 * two ways, applied together at every options/URL-taking egress entry point (`net.connect`/
 * `createConnection`/`Socket#connect`, `http(s).request`/`get`/`new ClientRequest()`/
 * `Agent#createConnection`, `tls.connect`/`TLSSocket#connect`, and `http2.connect`):
 *  1. Plain options objects — `pinTarget` + the `normalize*Args` helpers: after deriving the
 *     primitive `{host, port}` (reading each getter exactly once), forward a shallow clone with
 *     `host`/`hostname`/`port` overwritten by those PINNED primitives, never the original
 *     object. Positional `(port, host)` forms already pass primitives (no getter surface).
 *  2. URL instances passed to `http(s).request`/`get`/`new ClientRequest()` or as an
 *     `http2.connect` authority — `snapshotUrl` reads every field Node would otherwise
 *     re-derive from the URL EXACTLY ONCE, and the URL itself is never forwarded: `http(s)`
 *     gets a synthesized plain options object built from that one-time snapshot
 *     (`resolveHttpCall`); `http2` gets a synthesized authority STRING (`resolveHttpCall`'s
 *     http2 counterpart) — both immutable to Node's internal re-read. A string first-arg
 *     (`http.get("https://...")`) is parsed into capwall's own fresh `URL` first (no external
 *     getter surface) and goes through the same single-read snapshot for uniformity.
 * In both cases Node ends up reading only plain data properties / immutable strings equal to
 * what was guarded — a getter has no chance to diverge because it is never consulted again.
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
import { attributionOptionsFor, guard, type ShimContext, type ShimRegistry } from "./runtime.js";

export type { DecisionSink, ShimContext } from "./runtime.js";

type AnyFn = (...args: unknown[]) => unknown;
/* eslint-disable @typescript-eslint/no-explicit-any */
type AnyCtor = new (...args: any[]) => any;

/** Sentinel host for IPC/unix-domain-socket connects, which have no host:port pair. */
const IPC_HOST = "<ipc>";

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/** Like {@link isPlainObject} but excludes `URL` instances — URL args are immutable and
 * carry their `hostname`/`port` on prototype accessors, not own properties; treating one as
 * a pinnable options object would silently strip it down to an empty `{}` clone. */
function isPinnableOptions(v: unknown): v is Record<string, unknown> {
  return isPlainObject(v) && !(v instanceof URL);
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
    const rawPath = first["path"]; // read once — reused below, never re-read off `first`
    if (typeof rawPath === "string") return { host: IPC_HOST, port: 0 };
    const rawHost = first["host"]; // each read once: a getter must not see a second call
    const rawHostname = first["hostname"];
    const host = typeof rawHost === "string" ? rawHost : typeof rawHostname === "string" ? rawHostname : "localhost";
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
 * Fields Node's own `urlToHttpOptions` (and http2's authority parsing) derive from a URL,
 * captured with EACH property read exactly once. A caller-supplied `URL` instance can carry an
 * OWN shadowed accessor for any of these (e.g.
 * `Object.defineProperty(url, "port", { get(){ return firstCall ? granted : evil; } })`) that
 * legally returns a different value on a second read — reading twice (once to guard, once when
 * building what gets forwarded) is exactly the TOCTOU this closes (issue #26, URL-argument
 * follow-up). Every consumer below builds its guarded target AND its forwarded args from this
 * ONE snapshot; the URL itself is never consulted again.
 */
interface UrlSnapshot {
  protocol: string;
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
  username: string;
  password: string;
}
function snapshotUrl(u: URL): UrlSnapshot {
  return {
    protocol: u.protocol,
    hostname: u.hostname,
    port: u.port, // read once — reused for both the "has a port" check and Number(...) below
    pathname: u.pathname,
    search: u.search,
    hash: u.hash,
    username: u.username,
    password: u.password,
  };
}

/** Build a Node `urlToHttpOptions`-shaped plain options object from a single-read snapshot.
 * `hostname`/`port` are ALWAYS present (defaulting `port` to `defaultPort` when the URL had
 * none) so whatever forwards this object always carries an explicit, pinnable target. */
function urlSnapshotToOptions(s: UrlSnapshot, defaultPort: number): Record<string, unknown> {
  const options: Record<string, unknown> = {
    protocol: s.protocol,
    hostname: s.hostname,
    port: s.port !== "" ? Number(s.port) : defaultPort,
    hash: s.hash,
    search: s.search,
    pathname: s.pathname,
    path: `${s.pathname || ""}${s.search || ""}`,
  };
  if (s.username || s.password) {
    options["auth"] = `${decodeURIComponent(s.username)}:${decodeURIComponent(s.password)}`;
  }
  return options;
}

/**
 * Resolve ONE `http(s).request`/`get`/`new ClientRequest()` call: derive the guarded
 * `{host, port}` AND build the exact args to forward, IN A SINGLE PASS, so nothing that decided
 * the guard is ever read a second time (issue #26 — closed for both plain options objects and
 * `URL` instances). Accepted forms:
 *   - `(options[, cb])`
 *   - `(url[, options][, cb])` — url is a string or URL; options overrides url fields.
 *
 * When `args[0]` is a url/string, Node's own `ClientRequest` constructor converts it via its
 * internal `urlToHttpOptions(url)` and merges any options object over the result — re-reading
 * the SAME url a second time, on Node's side, is exactly what a shadowed accessor exploits. So
 * whenever a url/string is present, this returns a synthesized, ALREADY-MERGED plain options
 * object (built purely from the single-read snapshot plus the overlay's own fields) as the sole
 * options arg, with `hostname`/`port` pinned — Node never touches the url again.
 */
function resolveHttpCall(args: unknown[], defaultPort: number): { host: string; port: number; args: unknown[] } {
  const first = args[0];
  let urlOptions: Record<string, unknown> | undefined;
  let host: string | undefined;
  let port: number | undefined;

  const fromUrl = (u: URL): void => {
    const snap = snapshotUrl(u); // the ONLY read of this URL's fields
    const opts = urlSnapshotToOptions(snap, defaultPort);
    urlOptions = opts;
    host = opts["hostname"] as string;
    port = opts["port"] as number;
  };

  if (typeof first === "string") {
    try {
      fromUrl(new URL(first)); // capwall's own freshly-parsed URL — no external getter surface
    } catch {
      /* not an absolute URL */
    }
  } else if (first instanceof URL) {
    fromUrl(first); // the caller's URL instance — read exactly once, via snapshotUrl
  } else if (isPlainObject(first)) {
    const rawHostname = first["hostname"]; // read once each — a getter must not see a 2nd call
    const rawHost = first["host"];
    if (typeof rawHostname === "string") host = rawHostname;
    else if (typeof rawHost === "string") host = rawHost;
    const rawPort = first["port"];
    if (typeof rawPort === "number") port = rawPort;
    else if (typeof rawPort === "string" && rawPort !== "") {
      const n = Number(rawPort);
      if (Number.isFinite(n)) port = n;
    }
  }

  const overlay = isPinnableOptions(args[1]) ? args[1] : undefined;
  if (overlay) {
    const rawHostname = overlay["hostname"]; // read once each
    const rawHost = overlay["host"];
    if (typeof rawHostname === "string") host = rawHostname;
    else if (typeof rawHost === "string") host = rawHost;
    const rawPort = overlay["port"];
    if (typeof rawPort === "number") port = rawPort;
    else if (typeof rawPort === "string" && rawPort !== "") {
      const n = Number(rawPort);
      if (Number.isFinite(n)) port = n;
    }
  }

  const finalHost = host ?? "localhost";
  const finalPort = port ?? defaultPort;

  let outArgs = args;
  if (urlOptions) {
    // A url/string was present: synthesize ONE merged, pinned options object and forward it as
    // `(options, cb)` — the exact 2-slot shape Node's own `ClientRequest` constructor collapses
    // a url(+options)(+cb) call into internally, so runtime behavior is unchanged except the
    // url is never re-consulted.
    const merged: Record<string, unknown> = {};
    copyOwnFieldsExceptTarget(merged, urlOptions);
    if (overlay) copyOwnFieldsExceptTarget(merged, overlay);
    merged["hostname"] = finalHost; // always explicit — this call's target IS a url/string
    merged["port"] = finalPort;
    const cb = typeof args[1] === "function" ? args[1] : typeof args[2] === "function" ? args[2] : undefined;
    outArgs = cb !== undefined ? [merged, cb] : [merged];
  } else if (isPinnableOptions(first) || overlay) {
    const out = args.slice();
    if (isPinnableOptions(out[0])) out[0] = pinTarget(out[0], finalHost, finalPort);
    if (overlay) out[1] = pinTarget(overlay, finalHost, finalPort);
    outArgs = out;
  }

  return { host: finalHost, port: finalPort, args: outArgs };
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
    const rawHostname = a["hostname"]; // read once each — a getter must not see a second call
    const rawHost = a["host"];
    if (typeof rawHostname === "string") t.host = rawHostname;
    else if (typeof rawHost === "string") t.host = rawHost;
    const rawPort = a["port"];
    if (typeof rawPort === "number") t.port = rawPort;
    else if (typeof rawPort === "string" && rawPort !== "") {
      const n = Number(rawPort);
      if (Number.isFinite(n)) t.port = n;
    }
  }
  return t;
}

/** Copy every OWN property of `src` onto `dst` — `Reflect.ownKeys` + descriptor-preserving
 * `defineProperty`, so non-enumerable and symbol-keyed fields survive too (a plain
 * enumerable-only, by-value copy silently drops those), skipping `host`/`hostname`/`port` (the
 * caller pins those separately, to a primitive, never a copied accessor). Never reads a
 * `host`/`hostname`/`port` accessor: those three keys are skipped before `getOwnPropertyDescriptor`
 * would otherwise need to touch them, and every other field's descriptor is copied, not
 * invoked, so no property is READ as part of this copy at all. */
function copyOwnFieldsExceptTarget(dst: Record<string, unknown>, src: object): void {
  for (const key of Reflect.ownKeys(src)) {
    if (key === "host" || key === "hostname" || key === "port") continue;
    const desc = Object.getOwnPropertyDescriptor(src, key);
    if (desc) Object.defineProperty(dst, key, desc);
  }
}

/**
 * Shallow-clone `obj`, pinning whichever of `host`/`hostname`/`port` it already carries to the
 * given PRIMITIVE values (issue #26 — see the module doc comment). Existence is checked with
 * `in`, which never invokes an accessor; every other own field is preserved losslessly via
 * {@link copyOwnFieldsExceptTarget}. `host`/`hostname`/`port` are never read off `obj` here —
 * the caller already derived them, once, during guard evaluation.
 */
function pinTarget(obj: Record<string, unknown>, host: string, port: number): Record<string, unknown> {
  const clone: Record<string, unknown> = {};
  copyOwnFieldsExceptTarget(clone, obj);
  if ("host" in obj) clone["host"] = host;
  if ("hostname" in obj) clone["hostname"] = host;
  if ("port" in obj) clone["port"] = port;
  return clone;
}

/** `net.connect`/`createConnection`/`Socket#connect`: only `args[0]` can be an options object
 * (the positional `(port, host)` form is already primitives — no getter surface). */
function normalizeNetArgs(args: unknown[], host: string, port: number): unknown[] {
  if (!isPinnableOptions(args[0])) return args;
  const out = args.slice();
  out[0] = pinTarget(args[0], host, port);
  return out;
}

/**
 * `tls.connect`/`TLSSocket#connect`: pin EVERY plain-object argument, not just the first.
 * `deriveTlsTarget` already resolves the net-style positional and any trailing options-object
 * OVERLAY into a single final `{host, port}` (mirroring Node's own `normalizeConnectArgs`
 * merge); pinning that same final value onto every object argument means whichever one Node's
 * internal merge reads last, it reads the pinned value — no divergence regardless of merge
 * order.
 */
function normalizeTlsArgs(args: unknown[], host: string, port: number): unknown[] {
  let changed = false;
  const out = args.map((a) => {
    if (!isPinnableOptions(a)) return a;
    changed = true;
    return pinTarget(a, host, port);
  });
  return changed ? out : args;
}

/** Pins `args[1]`'s `host`/`hostname`/`port` (the `http2.connect(authority, options)` overlay),
 * if it is an options object — the authority itself is pinned separately, by
 * {@link createHttp2Shim}, into an immutable STRING before this runs. */
function normalizeHttp2Args(args: unknown[], host: string, port: number): unknown[] {
  if (!isPinnableOptions(args[1])) return args;
  const out = args.slice();
  out[1] = pinTarget(args[1], host, port);
  return out;
}

function wrapFn(
  orig: AnyFn,
  derive: (args: unknown[]) => { host: string; port: number },
  ctx: ShimContext,
  normalize: (args: unknown[], host: string, port: number) => unknown[],
): AnyFn {
  const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
    const { host, port } = derive(args);
    guard(ctx, { kind: "net", host, port }); // throws on enforce-deny, before any socket opens
    return orig.apply(this, normalize(args, host, port)); // pinned clone, never the original
  };
  Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
  return wrapped;
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
  normalize?: (args: unknown[], host: string, port: number) => unknown[],
): AnyCtor {
  const realMethod = (RealClass.prototype as Record<string, unknown>)[method];
  if (typeof realMethod !== "function") return RealClass;
  const Guarded = class extends RealClass {};
  Object.defineProperty(Guarded.prototype, method, {
    value: function (this: unknown, ...args: unknown[]) {
      const target = derive(args);
      let forwardArgs = args;
      if (target) {
        guard(ctx, { kind: "net", host: target.host, port: target.port });
        if (normalize) forwardArgs = normalize(args, target.host, target.port); // pinned clone
      }
      return (realMethod as AnyFn).apply(this, forwardArgs);
    },
    writable: true,
    configurable: true,
  });
  Object.defineProperty(Guarded, Symbol.hasInstance, {
    value: (x: unknown) => x instanceof RealClass,
    configurable: true,
  });
  Object.defineProperty(Guarded, "name", { value: RealClass.name, configurable: true });
  return Guarded;
}

/** Wrap an `http(s).request`/`get` function: resolves the call (guard target + normalized
 * args) in one pass via {@link resolveHttpCall}, so a url/options-object/getter is read once. */
function wrapHttpFn(orig: AnyFn, defaultPort: number, ctx: ShimContext): AnyFn {
  const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
    const resolved = resolveHttpCall(args, defaultPort);
    guard(ctx, { kind: "net", host: resolved.host, port: resolved.port }); // before any socket opens
    return orig.apply(this, resolved.args); // pinned/synthesized args, never the original
  };
  Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
  return wrapped;
}

/** Guarded subclass of `http.ClientRequest`: the constructor initiates the connection. */
function guardedClientRequestClass(RealClass: AnyCtor, ctx: ShimContext, defaultPort: number): AnyCtor {
  const Guarded = class extends RealClass {
    constructor(...args: unknown[]) {
      const resolved = resolveHttpCall(args, defaultPort);
      guard(ctx, { kind: "net", host: resolved.host, port: resolved.port }); // before super()
      super(...resolved.args); // pinned/synthesized args, never the original
    }
  };
  Object.defineProperty(Guarded, Symbol.hasInstance, {
    value: (x: unknown) => x instanceof RealClass,
    configurable: true,
  });
  Object.defineProperty(Guarded, "name", { value: RealClass.name, configurable: true });
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
  const wrapped = wrapFn(realNet.connect as unknown as AnyFn, deriveNetTarget, ctx, normalizeNetArgs);
  shim["connect"] = wrapped;
  shim["createConnection"] = wrapped;
  if (typeof realNet.Socket === "function") {
    shim["Socket"] = guardedSubclassMethod(
      realNet.Socket as unknown as AnyCtor,
      "connect",
      deriveNetTarget,
      ctx,
      normalizeNetArgs,
    );
  }
  return shim as unknown as typeof import("node:net");
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
    shim[name] = wrapHttpFn(orig as AnyFn, defaultPort, ctx);
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
      normalizeNetArgs,
    );
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
  shim["connect"] = wrapFn(realTls.connect as unknown as AnyFn, deriveTlsTarget, ctx, normalizeTlsArgs);
  if (typeof realTls.TLSSocket === "function") {
    shim["TLSSocket"] = guardedSubclassMethod(
      realTls.TLSSocket as unknown as AnyCtor,
      "connect",
      deriveTlsTarget,
      ctx,
      normalizeTlsArgs,
    );
  }
  return shim as unknown as typeof import("node:tls");
}

/**
 * Build a shimmed `http2` module: `http2.connect(authority)` is guarded (default port 443).
 * The authority (a url string OR a `URL` instance) is read via {@link snapshotUrl} — EACH
 * field exactly once — then rebuilt as a pinned, immutable STRING and forwarded in place of
 * the original: Node's own `connect` internally re-parses/re-reads the authority a second
 * time, which is exactly what a `URL` instance with a shadowed `hostname`/`port` accessor could
 * exploit (issue #26, URL-argument follow-up). A plain string authority is rebuilt too, for
 * uniformity, though strings have no getter surface to begin with.
 */
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
    let pinnedAuthority: string | undefined;
    try {
      const u = authority instanceof URL ? authority : new URL(String(authority));
      const snap = snapshotUrl(u); // the ONLY read of the authority's URL fields
      const protocol = snap.protocol || "https:";
      host = snap.hostname || "localhost";
      port = snap.port !== "" ? Number(snap.port) : 443;
      pinnedAuthority = `${protocol}//${host}:${port}`;
    } catch {
      /* unparseable authority — deny-leaning localhost:443; forwarded unchanged below, so Node
       * raises the same parse error the un-shimmed API would */
    }
    // Node honors options.host/port over the authority (http2.connect(authority, options)).
    const opts = args[1];
    if (isPlainObject(opts)) {
      const rawHost = opts["host"]; // read once — a getter must not see a second call
      if (typeof rawHost === "string") host = rawHost;
      const rawPort = opts["port"];
      if (typeof rawPort === "number") port = rawPort;
      else if (typeof rawPort === "string" && rawPort !== "") {
        const n = Number(rawPort);
        if (Number.isFinite(n)) port = n;
      }
    }
    guard(ctx, { kind: "net", host, port });
    const out = args.slice();
    if (pinnedAuthority !== undefined) out[0] = pinnedAuthority; // a STRING, never the original
    return realConnect.apply(this, normalizeHttp2Args(out, host, port)); // + pinned options overlay
  };
  return shim as unknown as typeof import("node:http2");
}

/** Attribute a dgram op and guard it, EXCEPT reads attributed to `<app>` (see header — this
 * also prevents the auto-bind replay crash, where Node re-invokes send on an internal tick). */
function guardDgram(ctx: ShimContext, host: string, port: number): void {
  const pkg = attributeCaller(attributionOptionsFor(ctx));
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

/** Install guarded `send`/`connect` on a dgram socket instance (used for createSocket results). */
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
      writable: true,
      configurable: true,
    });
  }
  if (typeof realConnect === "function") {
    Object.defineProperty(socket, "connect", {
      value: function (this: unknown, ...args: unknown[]) {
        const t = deriveDgramConnect(args);
        guardDgram(ctx, t.host, t.port);
        return (realConnect as AnyFn).apply(this, args);
      },
      writable: true,
      configurable: true,
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
  shim["createSocket"] = function (this: unknown, ...args: unknown[]): unknown {
    const socket = realCreate.apply(this, args) as Record<string, unknown>;
    guardDgramInstance(socket, ctx);
    return socket;
  };
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
    shim["Socket"] = Guarded;
  }
  return shim as unknown as typeof import("node:dgram");
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
