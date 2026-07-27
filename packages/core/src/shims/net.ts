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
 *  - `http2`: `http2.connect(authority)`. Scheme-aware default port, matching Node: 80 for an
 *    `http:` authority (h2c/cleartext), 443 for `https:`.
 *  - `dgram`: socket `send`/`connect` (UDP), on both `createSocket()` results and
 *    `new dgram.Socket()`. A `send` on a *connected* socket (no destination args) is not
 *    re-gated (the `connect` was). Reads attributed to `<app>` are not gated, which also
 *    prevents a crash: Node auto-binds an unbound socket and REPLAYS `send` on an internal
 *    tick whose stack has no dependency frame (attributes to `<app>`).
 *  - Inbound `server.listen` is deliberately NOT gated (egress, not binding).
 *  - IPC/unix-socket connects have no host:port and are approximated as `{ "<ipc>", 0 }`.
 *  - `dns` is NOT shimmed (a lookup moves no payload; DNS tunneling is out of scope).
 *
 * GETTER-TOCTOU CLOSED (issues #26 and #56). Every resolve function below reads the fields
 * that decide the destination off the caller's options object (or URL) to compute the guarded
 * target, then — historically — the SAME object was forwarded to the real API. If those fields
 * were accessor (getter) properties — including a caller-supplied `URL` instance with an OWN
 * shadowed `hostname`/`port` accessor, which Node happily honors — they could legally return a
 * different value on Node's later internal re-read than they did during capwall's derivation:
 * capwall would guard `granted.host:443` while Node opened a socket to `evil.host:443`. Closed
 * at every options/URL-taking egress entry point (`net.connect`/`createConnection`/
 * `Socket#connect`, `http(s).request`/`get`/`new ClientRequest()`/`Agent#createConnection`,
 * `tls.connect`/`TLSSocket#connect`, and `http2.connect`) by TWO rules applied together:
 *
 *  1. THE PINNING INVARIANT (read this before adding a field). Each entry point resolves the
 *     guarded target AND the exact arguments to forward in ONE pass. Every capability-relevant
 *     key — the named, per-flavor sets {@link NET_TARGET_KEYS} / {@link HTTP_TARGET_KEYS} — is
 *     read EXACTLY ONCE and that single read is written straight back onto a clone as a plain
 *     DATA property; the original object is never forwarded. Adding a new field that can
 *     redirect a connection means adding it to the matching set — that is the ONE rule.
 *  2. FAIL-CLOSED BACKSTOP, so rule 1 being incomplete is not a silent bypass. The clone is
 *     built by {@link copyOwnFieldsExcept}, which FLATTENS every own accessor it copies:
 *     the getter runs once, there, and its result is frozen into a data property. The object
 *     handed to Node therefore contains NO accessors at all, on any key — so Node's reads are
 *     stable by construction even for a key capwall does not (yet) know is capability-relevant.
 *     Issue #56 was exactly that miss: `path` (the unix-socket/pipe destination) was absent
 *     from the old skip list, so its accessor rode into the clone live and Node read it a
 *     second time — a dep granted one TCP endpoint could reach any unix socket by returning
 *     `undefined` on read #1 and `/var/run/docker.sock` on read #2.
 *  3. URL instances passed to `http(s).request`/`get`/`new ClientRequest()` or as an
 *     `http2.connect` authority — `snapshotUrl` reads every field Node would otherwise
 *     re-derive from the URL EXACTLY ONCE, and the URL itself is never forwarded: `http(s)`
 *     gets a synthesized plain options object built from that one-time snapshot
 *     (`urlSnapshotToOptions`, a deliberate re-implementation of Node's internal
 *     `urlToHttpOptions` — see its comment for the per-field audit); `http2` gets a synthesized
 *     authority STRING — both immutable to Node's internal re-read. A string first-arg
 *     (`http.get("https://...")`) is parsed into capwall's own fresh `URL` first (no external
 *     getter surface) and goes through the same single-read snapshot for uniformity.
 * Node ends up reading only plain data properties / immutable strings equal to what was
 * guarded — a getter has no chance to diverge because it is never consulted again.
 *
 * HOST SPELLING. An IPv6 literal is guarded (and therefore written in policy) UNBRACKETED —
 * `::1`, not `[::1]` — because that is what Node itself dials: `urlToHttpOptions` and
 * `http2.connect` both strip the brackets a `URL` keeps on `.hostname`. Brackets are put back
 * only when composing a URL/authority STRING, where `http://::1:8080` would not parse.
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

/** Like {@link isPlainObject} but excludes `URL` instances. Used where Node itself would NOT
 * treat a URL as an options bag: the `http(s)` overlay argument and the `http2.connect`
 * options argument are merged with `ObjectAssign`/spread, which copies a URL's OWN enumerable
 * properties — of which a plain URL has none — so pinning one there would invent fields Node
 * would never have seen. (`net`/`tls` are the opposite case: they take ANY object as the
 * options bag and read `host`/`port` off it through the prototype chain, so a URL passed there
 * IS pinned — see {@link pinNetOptions}.) */
function isPinnableOptions(v: unknown): v is Record<string, unknown> {
  return isPlainObject(v) && !(v instanceof URL);
}

/**
 * CAPABILITY-RELEVANT KEYS for NET-STYLE options bags — `net.connect`/`createConnection`/
 * `Socket#connect`, `tls.connect`/`TLSSocket#connect`, `http(s).Agent#createConnection`, and
 * the `http2.connect` options overlay. Each of these decides WHICH endpoint the socket reaches,
 * so each is read exactly once and pinned (see the module header's PINNING INVARIANT):
 *  - `path` — a unix-domain socket or Windows named pipe. A STRING here makes the connect an
 *    IPC connect and makes Node ignore `host`/`port` entirely; capwall models that as the
 *    gated pseudo-target `<ipc>:0`. Its omission from the old skip list was issue #56.
 *  - `host` — the TCP destination Node dials.
 *  - `port` — the TCP port.
 *  - `hostname` — NOT read by `net`/`tls` (verified against Node 20/22: `net.connect({hostname:
 *    'x', port: p})` dials `localhost`, not `x`), so it does not decide the target here. It is
 *    pinned anyway: it is capability-relevant on the `http` flavor, and keeping one list of
 *    "target-ish" keys means an accessor on it can never survive into a forwarded clone.
 * ADDING A FIELD THAT CAN REDIRECT A CONNECTION? Add it here.
 */
const NET_TARGET_KEYS: readonly string[] = ["host", "hostname", "port", "path"];

/**
 * CAPABILITY-RELEVANT KEYS for HTTP-STYLE options bags (`http(s).request`/`get`/
 * `new ClientRequest()`). Deliberately NOT the same set as {@link NET_TARGET_KEYS}:
 *  - `path` here is the REQUEST path (`/a?b=c`), not a socket path. Node overwrites it with
 *    `socketPath` (or `null`) before handing options to `createConnection`, so it cannot
 *    redirect the endpoint and is deliberately NOT pinned — pinning it would corrupt the
 *    request line.
 *  - `socketPath` is http's unix-socket field — the true `path` equivalent, so it IS pinned,
 *    and a string here yields the same `<ipc>:0` pseudo-target `net` uses (before this it was
 *    not modelled at all: a package granted `localhost:80` could reach `/var/run/docker.sock`).
 *  - `defaultPort` participates in Node's port resolution — `_http_client.js` computes
 *    `port = options.port || options.defaultPort || agent.defaultPort || <scheme default>` —
 *    so it can redirect the connection whenever `port` is absent.
 * ADDING A FIELD THAT CAN REDIRECT A CONNECTION? Add it here.
 */
const HTTP_TARGET_KEYS: readonly string[] = ["host", "hostname", "port", "socketPath", "defaultPort"];

/** Nothing skipped — a lossless descriptor copy (still accessor-flattening). */
const NO_SKIPPED_KEYS: readonly string[] = [];

/** One egress call, fully resolved: the target to guard AND the exact args to forward. */
interface ResolvedCall {
  host: string;
  port: number;
  args: unknown[];
}

/**
 * A `URL` keeps an IPv6 literal BRACKETED (`new URL("http://[::1]/").hostname === "[::1]"`),
 * but everything that actually dials strips them: Node's `urlToHttpOptions` and
 * `http2.connect` both hand `::1` to `net`/`dns`. capwall guards the UNBRACKETED form so a
 * policy author writes `::1` (the same spelling `net.connect({host})` and the policy's exact
 * host match use) — and so the guarded host is the string Node resolves. Forgetting this made
 * every IPv6 http(s) URL fail with `ENOTFOUND [::1]` once capwall started synthesizing options.
 */
function stripIpv6Brackets(hostname: string): string {
  return hostname.length > 2 && hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

/** Inverse of {@link stripIpv6Brackets}, for the one place brackets are required: composing a
 * URL/authority STRING. `http://::1:8080` is not a parseable URL; `http://[::1]:8080` is. */
function bracketIpv6(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

/** Coerce an ALREADY-READ raw `port` value to a number; `undefined` when it names no port.
 * Reads nothing — the caller performed the single read. */
function coercePort(raw: unknown): number | undefined {
  if (typeof raw === "number") return raw;
  if (typeof raw === "string" && raw !== "") {
    const n = Number(raw);
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

/**
 * A net-style options bag with every capability-relevant key read EXACTLY ONCE, plus the clone
 * to forward. `host`/`port`/`ipc` are `undefined` when the object does not speak to that field
 * at all, which is what lets a caller layer objects in Node's own merge order.
 */
interface PinnedNetOptions {
  /** `host` if this object supplies a string one, else undefined. */
  host: string | undefined;
  /** `port` if this object supplies a usable one, else undefined. */
  port: number | undefined;
  /** `true`/`false` when this object HAS a `path` key (string → IPC), `undefined` when it has
   * no `path` key at all — the distinction matters because Node's `ObjectAssign` merge lets an
   * overlay's `path: undefined` overwrite a base's real path. */
  ipc: boolean | undefined;
  /** The clone to forward: same fields, every one a data property, no accessor anywhere. */
  pinned: Record<string, unknown>;
}

/**
 * Copy every OWN property of `src` onto `dst` except the keys in `skip` (which the caller pins
 * itself, from its own single read). `Reflect.ownKeys` + `defineProperty` so non-enumerable and
 * symbol-keyed fields survive — a plain enumerable-only, by-value copy silently drops those.
 *
 * SECURITY: every copied property lands on `dst` as a DATA property. An own ACCESSOR is invoked
 * EXACTLY ONCE, here, and its result frozen into a value; its descriptor is never copied. That
 * is the fail-closed half of the pinning invariant (module header): the object handed to Node
 * contains no getters at all, so Node cannot observe a value different from the one this pass
 * saw — even on a key capwall does not (yet) treat as capability-relevant. The previous version
 * copied descriptors verbatim, which is how a `path` accessor (#56) rode through live.
 *
 * A getter that THROWS propagates rather than being swallowed: capwall will not forward an
 * options object it could not pin, and Node would have thrown on the same read anyway.
 */
function copyOwnFieldsExcept(dst: Record<string, unknown>, src: object, skip: readonly string[]): void {
  for (const key of Reflect.ownKeys(src)) {
    if (typeof key === "string" && skip.includes(key)) continue;
    const desc = Object.getOwnPropertyDescriptor(src, key);
    if (!desc) continue;
    if (desc.get !== undefined || desc.set !== undefined) {
      const value = desc.get !== undefined ? desc.get.call(src) : undefined; // the ONLY invocation
      Object.defineProperty(dst, key, {
        value,
        writable: true,
        enumerable: desc.enumerable === true,
        configurable: true,
      });
    } else {
      Object.defineProperty(dst, key, desc);
    }
  }
}

/**
 * Read a net-style options bag's capability-relevant keys ONCE each and build the pinned clone.
 *
 * Presence is tested with `in` (never invokes an accessor, and matches how Node reads these off
 * an options object — through the prototype chain). The value written back onto the clone is
 * the RAW single read, not a re-derived one, so the forwarded object behaves exactly like the
 * caller's for every shape Node accepts (numeric-string ports, `path: undefined`, …) while
 * being immutable to a second read. Pinned keys are written as own ENUMERABLE data properties
 * so that Node's own `ObjectAssign`/spread-based merges see exactly what capwall saw.
 */
function pinNetOptions(src: Record<string, unknown>): PinnedNetOptions {
  const hasHost = "host" in src;
  const hasHostname = "hostname" in src;
  const hasPort = "port" in src;
  const hasPath = "path" in src;
  const rawHost = hasHost ? src["host"] : undefined; // each of these is the ONE read of that key
  const rawHostname = hasHostname ? src["hostname"] : undefined;
  const rawPort = hasPort ? src["port"] : undefined;
  const rawPath = hasPath ? src["path"] : undefined;

  const pinned: Record<string, unknown> = {};
  copyOwnFieldsExcept(pinned, src, NET_TARGET_KEYS);
  if (hasHost) pinned["host"] = rawHost;
  if (hasHostname) pinned["hostname"] = rawHostname;
  if (hasPort) pinned["port"] = rawPort;
  if (hasPath) pinned["path"] = rawPath;

  return {
    host: typeof rawHost === "string" ? rawHost : undefined,
    port: coercePort(rawPort),
    ipc: hasPath ? typeof rawPath === "string" : undefined,
    pinned,
  };
}

/**
 * Resolve ONE `net.connect`/`net.createConnection`/`Socket#connect`/`Agent#createConnection`
 * call — guarded target AND forwarded args — in a single pass. Accepted forms:
 *   - `(options[, cb])` — TCP `{host?, port}`, or IPC `{path}`
 *   - `(port[, host][, ...])` — TCP positional (primitives already: no getter surface)
 *   - `(path[, cb])` — IPC positional string
 * IPC connects are approximated as `{host: "<ipc>", port: 0}`.
 */
function resolveNetCall(args: unknown[], defaultPort = 0): ResolvedCall {
  const first = args[0];
  if (typeof first === "number") {
    const host = typeof args[1] === "string" ? args[1] : "localhost";
    return { host, port: first, args };
  }
  if (typeof first === "string") {
    return { host: IPC_HOST, port: 0, args }; // positional path form — IPC
  }
  if (isPlainObject(first)) {
    // Any object is the options bag here, including a `URL` (nonsensical but legal — Node
    // reads `.host`, which on a URL carries the port suffix; pinning reproduces that exactly
    // instead of leaving the URL's accessors live for a second read).
    const p = pinNetOptions(first);
    const out = args.slice();
    out[0] = p.pinned;
    if (p.ipc === true) return { host: IPC_HOST, port: 0, args: out };
    // `hostname` is deliberately NOT a fallback: Node's net/tls ignore it and dial `localhost`,
    // so honoring it would guard a host the socket never reaches (a false-allow).
    return { host: p.host ?? "localhost", port: p.port ?? defaultPort, args: out };
  }
  return { host: IPC_HOST, port: 0, args };
}

/**
 * Resolve ONE `tls.connect`/`TLSSocket#connect` call. Node accepts the net-style positional and
 * options forms AND merges a trailing options object OVER the positionals, so the guarded
 * target must mirror that merge or a call like `tls.connect(443, "granted.host",
 * { host: "evil.host" })` would guard the granted target while Node connects to the evil one.
 *
 * The merge Node performs (`lib/_tls_wrap.js` `normalizeConnectArgs`) is exactly:
 *   options = net._normalizeArgs(args)[0]                         // args[0] object, or (port[, host])
 *   ObjectAssign(options, args[1] if object, ELSE args[2] if object)
 * — the FIRST of those two slots only. Following that rule precisely matters in both
 * directions: an options object at any other index is ignored by Node, so treating it as an
 * overlay guarded a target Node never dials (`tls.connect(443, "evil.host", {}, { host:
 * "granted.host" })` guarded granted.host and connected to evil.host — a false-allow).
 *
 * EVERY object argument is pinned regardless of whether it participates in the merge: an
 * accessor must never reach Node, and pinning normalizes each object's target keys to own
 * enumerable data properties so Node's `ObjectAssign` sees precisely what capwall read.
 */
function resolveTlsCall(args: unknown[]): ResolvedCall {
  const out = args.slice();
  const pins: Array<PinnedNetOptions | undefined> = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!isPlainObject(a)) {
      pins.push(undefined);
      continue;
    }
    const p = pinNetOptions(a);
    pins.push(p);
    out[i] = p.pinned;
  }

  let host: string | undefined;
  let port: number | undefined;
  let ipc = false;
  const first = args[0];
  if (typeof first === "number") {
    port = first;
    if (typeof args[1] === "string") host = args[1];
  } else if (typeof first === "string") {
    ipc = true; // positional path form
  }
  const base = pins[0];
  if (base) {
    host = base.host ?? host;
    port = base.port ?? port;
    if (base.ipc !== undefined) ipc = base.ipc;
  }
  const overlay = pins[1] ?? pins[2];
  if (overlay) {
    host = overlay.host ?? host;
    port = overlay.port ?? port;
    if (overlay.ipc !== undefined) ipc = overlay.ipc; // ObjectAssign overwrites, even with undefined
  }
  if (ipc) return { host: IPC_HOST, port: 0, args: out };
  return { host: host ?? "localhost", port: port ?? 443, args: out };
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
  href: string;
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
    href: u.href,
    username: u.username,
    password: u.password,
  };
}

/**
 * Build the plain options object Node's internal `urlToHttpOptions(url)` would have built, from
 * capwall's single-read snapshot instead of from the (re-readable) URL.
 *
 * Re-implementing a Node internal means the divergences have to be deliberate and written down.
 * Audited field by field against `lib/internal/url.js` (Node 20/22):
 *  - `protocol`, `hash`, `search`, `pathname`, `path` (= pathname + search), `auth` (only when
 *    the URL carries a username/password) — IDENTICAL.
 *  - `hostname` — Node STRIPS the brackets a URL keeps on an IPv6 literal
 *    (`new URL("http://[::1]/").hostname === "[::1]"` → `"::1"`). capwall passed `s.hostname`
 *    through verbatim, so `net` treated `"[::1]"` as a DNS name and every IPv6 http(s) URL
 *    failed `ENOTFOUND` in BOTH observe and enforce mode. FIXED — {@link stripIpv6Brackets}.
 *  - `href` — Node includes it; capwall used to drop it. Nothing in Node's client dials with
 *    it, but it is observable to a custom `Agent`/instrumentation, so dropping it was a
 *    gratuitous divergence. FIXED — carried through from the snapshot (and, exactly like
 *    Node's, left as the URL's original href even when an overlay overrides host/port).
 *  - `port` — Node OMITS the key when the URL has no port, so that
 *    `options.defaultPort`/`agent.defaultPort` can supply it later. This function mirrors that
 *    omission, but {@link resolveHttpCall} then always writes an EXPLICIT `port` onto the object
 *    it forwards. That is DELIBERATE and load-bearing: an absent port is resolved by Node long
 *    after capwall's guard ran, from an `agent.defaultPort` capwall cannot pin, which would let
 *    a call guarded as `host:443` connect to `host:8123`. `resolveHttpCall` instead resolves
 *    the same precedence Node uses (`options.port || options.defaultPort || agent.defaultPort ||
 *    <scheme default>`) ITSELF, guards that, and pins it — so a custom `Agent({ defaultPort })`
 *    still works AND the guarded port is the connected port.
 *  - `...url` (Node spreads the URL's OWN enumerable properties first, "in case the url object
 *    was extended by the user") — DELIBERATELY NOT replicated. Copying arbitrary own properties
 *    off a caller-supplied URL is precisely the smuggling channel this PR closes: an own
 *    `socketPath`/`defaultPort`/`agent` on the URL would ride straight into the forwarded
 *    options. The cost is that a URL "extended" with extra properties loses them; the benefit is
 *    that only the nine snapshot fields above can ever come out of a URL. Fail-closed on purpose.
 */
function urlSnapshotToOptions(s: UrlSnapshot): Record<string, unknown> {
  const options: Record<string, unknown> = {
    protocol: s.protocol,
    hostname: stripIpv6Brackets(s.hostname),
    hash: s.hash,
    search: s.search,
    pathname: s.pathname,
    path: `${s.pathname || ""}${s.search || ""}`,
    href: s.href,
  };
  if (s.port !== "") options["port"] = Number(s.port);
  if (s.username || s.password) {
    options["auth"] = `${decodeURIComponent(s.username)}:${decodeURIComponent(s.password)}`;
  }
  return options;
}

/** An http-style options bag with every capability-relevant key read EXACTLY ONCE, plus the
 * clone to forward. See {@link HTTP_TARGET_KEYS} for why the set differs from the net flavor. */
interface PinnedHttpOptions {
  host: string | undefined;
  port: number | undefined;
  defaultPort: number | undefined;
  socketPath: string | undefined;
  /** Whether the object HAS a `socketPath` key — an overlay's `socketPath: undefined` erases a
   * base's under Node's `ObjectAssign` merge, which "no socketPath" alone cannot express. */
  hasSocketPath: boolean;
  pinned: Record<string, unknown>;
}

/** Read an http-style options bag's capability-relevant keys once each and build the pinned
 * clone. Same contract as {@link pinNetOptions} — raw single reads written straight back — with
 * http's key set and http's precedence rules. */
function pinHttpOptions(src: Record<string, unknown>): PinnedHttpOptions {
  const hasHost = "host" in src;
  const hasHostname = "hostname" in src;
  const hasPort = "port" in src;
  const hasSocketPath = "socketPath" in src;
  const hasDefaultPort = "defaultPort" in src;
  const rawHost = hasHost ? src["host"] : undefined; // each of these is the ONE read of that key
  const rawHostname = hasHostname ? src["hostname"] : undefined;
  const rawPort = hasPort ? src["port"] : undefined;
  const rawSocketPath = hasSocketPath ? src["socketPath"] : undefined;
  const rawDefaultPort = hasDefaultPort ? src["defaultPort"] : undefined;

  const pinned: Record<string, unknown> = {};
  copyOwnFieldsExcept(pinned, src, HTTP_TARGET_KEYS);
  if (hasHost) pinned["host"] = rawHost;
  if (hasHostname) pinned["hostname"] = rawHostname;
  if (hasPort) pinned["port"] = rawPort;
  if (hasSocketPath) pinned["socketPath"] = rawSocketPath;
  if (hasDefaultPort) pinned["defaultPort"] = rawDefaultPort;

  return {
    // Node: `hostname` wins over `host` here (unlike `net`, which reads only `host`).
    host: typeof rawHostname === "string" ? rawHostname : typeof rawHost === "string" ? rawHost : undefined,
    // Node resolves the port with `||`, so a FALSY port (0, "", null) names no port at all.
    port: rawPort ? coercePort(rawPort) : undefined,
    defaultPort: rawDefaultPort ? coercePort(rawDefaultPort) : undefined,
    socketPath: typeof rawSocketPath === "string" ? rawSocketPath : undefined,
    hasSocketPath,
    pinned,
  };
}

/** Last step of Node's port precedence: `agent.defaultPort`. Read here ONCE off the pinned
 * clone (where `agent` is already a data property, so this cannot be a second accessor read)
 * purely so capwall can guard — and then pin — the port Node would actually have used. Once
 * `options.port` is explicit Node never consults the agent's default again. */
function agentDefaultPort(opts: Record<string, unknown>): number | undefined {
  const agent = opts["agent"];
  if (!isPlainObject(agent)) return undefined;
  const raw = agent["defaultPort"];
  return raw ? coercePort(raw) : undefined;
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
 * object (built purely from the single-read snapshot plus the overlay's pinned fields) as the
 * sole options arg, with `hostname`/`port` pinned — Node never touches the url again.
 *
 * `socketPath` (http's unix-socket field, the `path` equivalent — see {@link HTTP_TARGET_KEYS})
 * makes the call an IPC connect, guarded as `<ipc>:0` exactly like `net.connect({path})`.
 */
function resolveHttpCall(args: unknown[], defaultPort: number): ResolvedCall {
  const first = args[0];
  let urlOptions: Record<string, unknown> | undefined;
  let urlHost: string | undefined;
  let urlPort: number | undefined;

  const fromUrl = (u: URL): void => {
    const snap = snapshotUrl(u); // the ONLY read of this URL's fields
    urlOptions = urlSnapshotToOptions(snap);
    urlHost = stripIpv6Brackets(snap.hostname) || undefined; // unbracketed: what Node dials
    urlPort = snap.port !== "" ? coercePort(snap.port) : undefined;
  };

  if (typeof first === "string") {
    try {
      fromUrl(new URL(first)); // capwall's own freshly-parsed URL — no external getter surface
    } catch {
      /* not an absolute URL */
    }
  } else if (first instanceof URL) {
    fromUrl(first); // the caller's URL instance — read exactly once, via snapshotUrl
  }

  // Node's `ClientRequest` treats `args[1]` as an options OVERLAY only when `args[0]` was a
  // url/string; when `args[0]` is itself an options object it does `cb = options; options =
  // input`, i.e. `args[1]` is the CALLBACK. Treating it as an overlay anyway would guard a
  // target Node never merges — `http.request({hostname: "evil"}, {hostname: "granted"})` would
  // have been guarded as `granted`.
  const overlay = urlOptions !== undefined && isPinnableOptions(args[1]) ? pinHttpOptions(args[1]) : undefined;
  const base = urlOptions === undefined && isPinnableOptions(first) ? pinHttpOptions(first) : undefined;

  // Build the object to forward BEFORE resolving the port: every field on it is already a
  // pinned data property, so the `agent.defaultPort` lookup below cannot be a second read of a
  // caller accessor.
  let forwarded: Record<string, unknown> | undefined;
  if (urlOptions !== undefined) {
    // Node's own merged options here are the NULL-PROTOTYPE object `urlToHttpOptions` returns
    // with the overlay `ObjectAssign`ed onto it; mirroring the null prototype keeps a polluted
    // `Object.prototype` from injecting fields into a synthesized options bag.
    forwarded = Object.create(null) as Record<string, unknown>;
    copyOwnFieldsExcept(forwarded, urlOptions, NO_SKIPPED_KEYS);
    if (overlay) copyOwnFieldsExcept(forwarded, overlay.pinned, NO_SKIPPED_KEYS);
  } else if (base) {
    forwarded = base.pinned;
  }

  // An overlay `socketPath` key wins even when its value is undefined (ObjectAssign overwrites).
  const socketPath = overlay?.hasSocketPath === true ? overlay.socketPath : base?.socketPath;
  const finalHost = overlay?.host ?? base?.host ?? urlHost ?? "localhost";
  // Node: `options.port || options.defaultPort || agent.defaultPort || <scheme default>`.
  const finalPort =
    overlay?.port ??
    base?.port ??
    urlPort ??
    overlay?.defaultPort ??
    base?.defaultPort ??
    (forwarded !== undefined ? agentDefaultPort(forwarded) : undefined) ??
    defaultPort;

  if (forwarded !== undefined) {
    // Pin the endpoint onto the forwarded object. `port` is written UNCONDITIONALLY (even when
    // the caller supplied none) — that is what removes `agent.defaultPort`/`options.defaultPort`
    // from Node's later resolution and makes the guarded port provably the connected port.
    if (urlOptions !== undefined || "hostname" in forwarded) forwarded["hostname"] = finalHost;
    if ("host" in forwarded) forwarded["host"] = finalHost;
    forwarded["port"] = finalPort;
  }

  let outArgs = args;
  if (urlOptions !== undefined && forwarded !== undefined) {
    // Forward as `(options, cb)` — the exact 2-slot shape Node's own `ClientRequest` constructor
    // collapses a url(+options)(+cb) call into internally, so runtime behavior is unchanged
    // except that the url is never re-consulted.
    const cb = typeof args[1] === "function" ? args[1] : typeof args[2] === "function" ? args[2] : undefined;
    outArgs = cb !== undefined ? [forwarded, cb] : [forwarded];
  } else if (forwarded !== undefined) {
    outArgs = args.slice();
    outArgs[0] = forwarded;
  }

  if (typeof socketPath === "string") return { host: IPC_HOST, port: 0, args: outArgs };
  return { host: finalHost, port: finalPort, args: outArgs };
}

/** Wrap an egress function: `resolve` produces the guarded target AND the pinned argument list
 * in ONE pass (see the module header's PINNING INVARIANT), so nothing that decided the guard is
 * ever read a second time. */
function wrapFn(orig: AnyFn, resolve: (args: unknown[]) => ResolvedCall, ctx: ShimContext): AnyFn {
  const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
    const call = resolve(args);
    guard(ctx, { kind: "net", host: call.host, port: call.port }); // throws on enforce-deny, before any socket opens
    return orig.apply(this, call.args); // pinned clone, never the original
  };
  Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
  return harden(ctx, wrapped);
}

/**
 * Expose a guarded SUBCLASS of `RealClass` whose prototype `method` runs `resolve`+guard
 * before delegating to the real method with the PINNED args. `Symbol.hasInstance` is
 * overridden so `instanceof` matches any instance of the real class (guarded or not).
 */
function guardedSubclassMethod(
  RealClass: AnyCtor,
  method: string,
  resolve: (args: unknown[]) => ResolvedCall | null,
  ctx: ShimContext,
): AnyCtor {
  const realMethod = (RealClass.prototype as Record<string, unknown>)[method];
  // NOTE: returns the REAL class untouched when the method is absent — so nothing below this
  // line may harden it (freezing a builtin is off the table; see harden.ts).
  if (typeof realMethod !== "function") return RealClass;
  const Guarded = class extends RealClass {};
  Object.defineProperty(Guarded.prototype, method, {
    value: function (this: unknown, ...args: unknown[]) {
      const call = resolve(args);
      let forwardArgs = args;
      if (call) {
        guard(ctx, { kind: "net", host: call.host, port: call.port });
        forwardArgs = call.args; // pinned clone, never the original
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
  // Hardened mode (#17): freeze the SUBCLASS's prototype, closing
  // `net.Socket.prototype.connect = evil` — otherwise a one-line removal of the guard for
  // every caller in the process. No-op by default.
  hardenClass(ctx, Guarded);
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
  return harden(ctx, wrapped);
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
  hardenClass(ctx, Guarded); // hardened mode only (#17) — see harden.ts
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
  const wrapped = wrapFn(realNet.connect as unknown as AnyFn, (a) => resolveNetCall(a), ctx);
  shim["connect"] = wrapped;
  shim["createConnection"] = wrapped;
  if (typeof realNet.Socket === "function") {
    shim["Socket"] = guardedSubclassMethod(
      realNet.Socket as unknown as AnyCtor,
      "connect",
      (a) => resolveNetCall(a),
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
    shim[name] = wrapHttpFn(orig as AnyFn, defaultPort, ctx);
  }
  if (typeof realRecord["ClientRequest"] === "function") {
    shim["ClientRequest"] = guardedClientRequestClass(realRecord["ClientRequest"] as AnyCtor, ctx, defaultPort);
  }
  // Agent.createConnection is Node's internal net.createConnection, captured at bootstrap —
  // it never routes through Module._load, so a bare Agent's createConnection is un-gated egress.
  if (typeof realRecord["Agent"] === "function") {
    // `Agent#createConnection` receives NET-style options (Node has already rewritten http's
    // `socketPath` into `path` and blanked the request `path` by this point), so it resolves
    // through the net flavor.
    shim["Agent"] = guardedSubclassMethod(
      realRecord["Agent"] as AnyCtor,
      "createConnection",
      (a) => resolveNetCall(a, defaultPort),
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
  // OVERRIDES the positionals — resolveTlsCall handles the combined form (resolveNetCall alone
  // would ignore the override and false-allow).
  shim["connect"] = wrapFn(realTls.connect as unknown as AnyFn, resolveTlsCall, ctx);
  if (typeof realTls.TLSSocket === "function") {
    shim["TLSSocket"] = guardedSubclassMethod(realTls.TLSSocket as unknown as AnyCtor, "connect", resolveTlsCall, ctx);
  }
  return harden(ctx, shim) as unknown as typeof import("node:tls");
}

/**
 * Build a shimmed `http2` module: `http2.connect(authority[, options])` is guarded.
 * The authority (a url string OR a `URL` instance) is read via {@link snapshotUrl} — EACH
 * field exactly once — then rebuilt as a pinned, immutable STRING and forwarded in place of
 * the original: Node's own `connect` internally re-parses/re-reads the authority a second
 * time, which is exactly what a `URL` instance with a shadowed `hostname`/`port` accessor could
 * exploit (issue #26, URL-argument follow-up). A plain string authority is rebuilt too, for
 * uniformity, though strings have no getter surface to begin with.
 *
 * Rebuilding the authority means reproducing Node's own defaults exactly (`lib/internal/http2/
 * core.js`), and getting either of these wrong silently breaks a legitimate call:
 *  - the default port is SCHEME-AWARE — 80 for `http:` (h2c/cleartext), 443 for `https:`.
 *    Defaulting both to 443 broke every `http2.connect("http://internal-svc")`, which worked
 *    before the authority was rebuilt at all.
 *  - an IPv6 host must be re-BRACKETED in the composed string (`http://[::1]:8080`);
 *    `http://::1:8080` is not a parseable URL, so Node would throw on its own re-parse. The
 *    GUARDED host stays unbracketed — that is what Node dials and what a policy lists.
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
    let ipc = false;
    let pinnedAuthority: string | undefined;
    try {
      const u = authority instanceof URL ? authority : new URL(String(authority));
      const snap = snapshotUrl(u); // the ONLY read of the authority's URL fields
      const protocol = snap.protocol || "https:";
      host = stripIpv6Brackets(snap.hostname) || "localhost"; // Node strips them before dialing
      port = coercePort(snap.port) ?? (protocol === "http:" ? 80 : 443); // scheme-aware, like Node
      pinnedAuthority = `${protocol}//${bracketIpv6(host)}:${port}`; // brackets back for the STRING
    } catch {
      /* unparseable authority — deny-leaning localhost:443; forwarded unchanged below, so Node
       * raises the same parse error the un-shimmed API would */
    }
    // Node honors options.host/port over the authority: both branches of its connect end up
    // spreading the options object over `{port, host}` (`net.connect({port, host, ...options})`
    // for h2c, `tls.connect(port, host, {...options})` for h2). `options.path` would make it an
    // IPC connect, so the overlay resolves through the NET flavor.
    const out = args.slice();
    const opts = args[1];
    if (isPinnableOptions(opts)) {
      const p = pinNetOptions(opts); // one read per capability-relevant key
      out[1] = p.pinned;
      if (p.host !== undefined) host = p.host;
      if (p.port !== undefined) port = p.port;
      if (p.ipc === true) ipc = true;
    }
    guard(ctx, ipc ? { kind: "net", host: IPC_HOST, port: 0 } : { kind: "net", host, port });
    if (pinnedAuthority !== undefined) out[0] = pinnedAuthority; // a STRING, never the original
    return realConnect.apply(this, out);
  };
  harden(ctx, shim["connect"] as object);
  return harden(ctx, shim) as unknown as typeof import("node:http2");
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

/** Install guarded `send`/`connect` on a dgram socket instance (used for createSocket results).
 * Under hardened mode (#17) these OWN properties are installed non-writable/non-configurable
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
    hardenClass(ctx, Guarded); // hardened mode only (#17) — see harden.ts
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
