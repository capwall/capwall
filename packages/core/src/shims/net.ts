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
 * review demonstrated. A subclass guards the prototype method itself and, via the shared
 * {@link defineGuardedClassIdentity}, keeps `instanceof` working for BOTH real and guarded
 * instances WITHOUT leaking that answer down the static chain to a dependency's own
 * `class Mine extends net.Socket {}` (#71). Residual (documented in threat-model.md): climbing
 * two prototype levels
 * (`Object.getPrototypeOf(Object.getPrototypeOf(sock)).connect`) reaches the real method —
 * determined-attacker territory, the same class as un-patching.
 *
 * GUARDING INSTANCES, NOT ONLY CLASSES (issue #65). A builtin namespace also exposes pre-built
 * INSTANCES that carry the same capability its classes do, and the copy loop in each `create*Shim`
 * duplicates those onto the shim verbatim — real methods and all. `http.globalAgent` /
 * `https.globalAgent` are live `Agent` instances, so `http.globalAgent.createConnection({host,
 * port})` opened a socket with the guard never firing and NOTHING recorded, under a deny-all
 * enforce policy. They are now wrapped by {@link guardedInstanceMethods} (a Proxy over a VIRTUAL
 * target — see there for why an instance is the one place a Proxy is the right tool, why patching
 * the real agent is forbidden, and why every structural operation on the view is refused rather
 * than forwarded to the process-global agent, #88). The audit behind #65 covered every
 * object-valued export of every shimmed namespace;
 * `globalAgent` on `http`/`https` was the only capability-bearing one. The rest are inert data
 * (`fs.constants`, `http.METHODS`/`STATUS_CODES`, `tls.rootCertificates`, `http2.constants`,
 * `vm.constants`, `worker_threads.resourceLimits`) or an already-shimmed sub-namespace
 * (`fs.promises`).
 *
 * Under opt-in HARDENED MODE (#17) each guarded subclass and its prototype are frozen, so
 * `net.Socket.prototype.connect = evil` fails instead of silently removing the guard for the
 * whole process. The residual above is unaffected — freezing our subclass says nothing about
 * the real class above it. See `harden.ts`.
 *
 * Coverage & limits (kept in sync with docs/threat-model.md):
 *  - `net`: `connect`/`createConnection` and `new net.Socket().connect()`.
 *  - `http`/`https`: `request`/`get`, `new ClientRequest()`, `Agent.createConnection`, the
 *    `globalAgent` instance's `createConnection`, and (Node ≥22) the `http.WebSocket`
 *    re-export of the global `WebSocket` class — see `shims/global-egress.ts` (#80).
 *    Shimming `net` alone does NOT mediate HTTP: Node's own HTTP client loads `net` through
 *    the internal bootstrap loader, which never hits `Module._load`, so each egress module is
 *    shimmed separately (a dependency could otherwise bypass the control by choosing another).
 *  - `tls`: `tls.connect` (BOTH `(options)` and positional `(port, host)` forms) and
 *    `new tls.TLSSocket().connect()`. Default port 443.
 *  - `http2`: `http2.connect(authority)`. Scheme-aware default port, matching Node: 80 for an
 *    `http:` authority (h2c/cleartext), 443 for `https:`.
 *  - `dgram`: socket `send`/`connect` (UDP), on both `createSocket()` results and
 *    `new dgram.Socket()` — the same guards installed the same way on both, so the two paths
 *    cannot drift (#86). The destination is derived POSITIONALLY, mirroring Node's own
 *    argument normalization, because Node accepts a port as a numeric string — see
 *    `deriveDgramSend`. A `send` on a *connected* socket (no destination args) is not
 *    re-gated (the `connect` was). Ops attributed to `<app>` are not gated (the app is the
 *    trust root) — but since #60 that means a positively-identified application frame, not
 *    "the stack walk found nothing", which is now `<unknown>` and IS gated. Node's auto-bind
 *    `send` replay, which used to ride on that fail-open, is handled by state instead — see
 *    `forwardAuthorizedDgramSend` for the mechanism and why a stolen authorization is worth
 *    nothing.
 *  - Inbound `server.listen` is deliberately NOT gated (egress, not binding).
 *  - IPC/unix-socket connects have no host:port; they are guarded as the separate `ipc`
 *    capability carrying the concrete socket path / named pipe (#72), canonicalized by
 *    `policy/ipc.ts`. Before that they all collapsed onto one `<ipc>:0` pseudo-target.
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
 *     `http2.connect` authority — `snapshotUrl` (now shared, in `shims/url-snapshot.ts`, with
 *     the global egress guard so the two cannot drift apart) reads every field Node would
 *     otherwise
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
 * ARGUMENT NORMALIZATION MIRRORS NODE'S SOURCE, NOT THE SIGNATURE (issue #99). Reading a field
 * once is only half the problem: the RULE that decides WHICH argument holds the destination has
 * to be Node's rule too, or the guarded target and the real target diverge for a second reason
 * having nothing to do with getters. Every resolver below therefore quotes the Node function it
 * mirrors — `net._normalizeArgs`/`isPipeName` (`lib/net.js`), `normalizeConnectArgs`
 * (`lib/internal/tls/wrap.js`), `ClientRequest` + `urlToHttpOptions` (`lib/_http_client.js`,
 * `lib/internal/url.js`), `connect` (`lib/internal/http2/core.js`), `Socket.prototype.send` and
 * `lookup4`/`lookup6` (`lib/dgram.js`, `lib/internal/dgram.js`) — and anywhere capwall knowingly
 * differs says so, and why. IF YOU CHANGE A DERIVATION, READ THE NODE FUNCTION FIRST. The holes
 * this rule exists to prevent all read as reasonable interpretations of a documented signature:
 * a numeric-string port `validatePort` accepts (#95, gate skipped entirely); an options object
 * read from an index Node never merges (#46, granted host guarded, evil host dialled); a
 * positional numeric STRING that `isPipeName` says is a port and capwall called a socket path; a
 * `path: ""` that Node's `pipe = !!path` treats as no path at all; a `URL` in a MERGE slot whose
 * prototype accessors `ObjectAssign` never copies; and a plain object that is a perfectly legal
 * `http2` authority.
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
import { evaluate, type CapabilityRequest } from "../policy/evaluate.js";
// #72 — IPC destinations carry their concrete socket path now, canonicalized here (once, at the
// point of observation) exactly as `shims/fs.ts` canonicalizes an fs argument.
import { canonicalIpcPath, UNKNOWN_IPC_PATH } from "../policy/ipc.js";
import { CapabilityError } from "../errors.js";
import {
  attributionOptionsFor,
  defineGuardedClassIdentity,
  guard,
  guardedInstanceMethods,
  type AnyFn,
  type ShimContext,
  type ShimRegistry,
} from "./runtime.js";
import { defineGuardedAccessor, harden, hardenClass } from "./harden.js";
// The accessor-flattening clone helper moved to `shims/pin.ts` (#89) with NO behavior change, so
// the child_process shim applies the identical rule rather than growing a second copy of it.
import { copyOwnFieldsExcept, NO_SKIPPED_KEYS, pinAllOwnFields } from "./pin.js";
import { guardedWebSocketClass } from "./global-egress.js";
// The single-read URL pinning helpers live in their own module so the global egress guard
// (#80) can share this exact implementation without an import cycle — see url-snapshot.ts.
import {
  bracketIpv6,
  coercePort,
  isNodeUrlLike,
  snapshotUrl,
  stripIpv6Brackets,
  type UrlSnapshot,
} from "./url-snapshot.js";

export type { DecisionSink, ShimContext } from "./runtime.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type AnyCtor = new (...args: any[]) => any;

/**
 * Legacy sentinel host for IPC/unix-domain-socket connects, which have no host:port pair.
 * Since #72 an IPC connect is guarded as its own `ipc` capability carrying the socket path;
 * this string survives only as the `ResolvedCall.host` filler and as the pre-#72 policy token
 * (`net.hosts: ["<ipc>"]` = all IPC, still honored — see `policy/evaluate.ts`).
 */
const IPC_HOST = "<ipc>";

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/**
 * Node's `isPipeName` (`lib/net.js`, identical on Node 20 and 22):
 *
 *     function toNumber(x) { return (x = Number(x)) >= 0 ? x : false; }
 *     function isPipeName(s) { return typeof s === 'string' && toNumber(s) === false; }
 *
 * A STRING first argument to `net.connect`/`tls.connect`/`Socket#connect` is a unix-socket /
 * named-pipe PATH **only when it does not coerce to a non-negative number**. Everything else —
 * `"9999"`, `" 9999 "`, `"0x270f"`, even `""` — lands in Node's `([port][, host])` branch and
 * opens a TCP connection.
 *
 * capwall used to treat EVERY string first argument as an IPC path, so
 * `net.connect("9999", "evil.host")` was guarded as the `ipc` capability on the path `"9999"`
 * while Node dialled `evil.host:9999` — the same shape as #95 (a numeric-string port that
 * Node's `validatePort` accepts and capwall's heuristic did not), one module over. A package
 * holding any IPC grant reached arbitrary TCP egress through it. Tracked as #105.
 */
function isPipeName(s: string): boolean {
  const n = Number(s);
  return !(n >= 0); // NaN or negative → Node's `toNumber` returns `false` → it is a pipe name
}

/**
 * Does Node's `ObjectAssign(options, source)` merge copy anything from `source`?
 *
 * `tls.connect`'s overlay slot and `http2.connect`'s `{ ...options }` are MERGES, not
 * property reads: they copy `source`'s OWN ENUMERABLE properties and nothing else. Primitives
 * contribute nothing capability-relevant (a string's own properties are its character indices),
 * and `null`/`undefined` contribute nothing at all — so only objects and functions can move a
 * destination. Note this deliberately INCLUDES functions (`ObjectAssign` copies an own
 * enumerable `host` off a function just as happily) and EXCLUDES nothing that Node includes.
 */
function isMergeSource(v: unknown): v is object {
  return (typeof v === "object" || typeof v === "function") && v !== null;
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
 *    gated `ipc` capability, keyed on the path itself since #72. Its omission from the old
 *    skip list was issue #56.
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
 *    and a string here yields the same path-keyed `ipc` capability `net` uses (before this it was
 *    not modelled at all: a package granted `localhost:80` could reach `/var/run/docker.sock`).
 *  - `defaultPort` participates in Node's port resolution — `_http_client.js` computes
 *    `port = options.port || options.defaultPort || agent.defaultPort || <scheme default>` —
 *    so it can redirect the connection whenever `port` is absent.
 * ADDING A FIELD THAT CAN REDIRECT A CONNECTION? Add it here.
 */
const HTTP_TARGET_KEYS: readonly string[] = ["host", "hostname", "port", "socketPath", "defaultPort"];

/** One egress call, fully resolved: the target to guard AND the exact args to forward. */
interface ResolvedCall {
  host: string;
  port: number;
  args: unknown[];
  /**
   * Set — and only set — when this call is an IPC connect (#72): the unix-socket / named-pipe
   * destination, canonicalized. `host`/`port` then still carry the legacy `<ipc>:0` pseudo-
   * target but nothing reads them; {@link targetRequest} is the one place that decides.
   */
  ipcPath?: string;
}

/**
 * The capability request for a resolved call. IPC is its own capability carrying the concrete
 * socket path (#72) instead of collapsing to the single `<ipc>:0` pseudo-target that made a
 * grant for one socket a grant for the Docker socket.
 */
function targetRequest(call: ResolvedCall): CapabilityRequest {
  if (call.ipcPath !== undefined) return { kind: "ipc", path: call.ipcPath };
  return { kind: "net", host: call.host, port: call.port };
}

/** Build the IPC half of a {@link ResolvedCall}. `raw` is undefined when the call's shape hid
 * the destination — recorded as `<unknown>`, which only an all-IPC grant covers (fail closed). */
function ipcCall(raw: string | undefined, args: unknown[]): ResolvedCall {
  return {
    host: IPC_HOST,
    port: 0,
    args,
    ipcPath: raw === undefined ? UNKNOWN_IPC_PATH : canonicalIpcPath(raw),
  };
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
  /** The socket path this object supplies, from the SAME single read as `ipc` (#72). */
  ipcPath: string | undefined;
  /** The clone to forward: same fields, every one a data property, no accessor anywhere. */
  pinned: Record<string, unknown>;
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
    // Node: `const host = options.host || 'localhost'` — a FALSY host names no host, which is
    // why the empty string does not survive as a guarded target here (#99). A truthy non-string
    // fails Node's `validateString(host)`, so `undefined` (→ `localhost`) is the fail-closed
    // answer for that too: capwall guards loopback and Node throws.
    host: typeof rawHost === "string" && rawHost !== "" ? rawHost : undefined,
    port: coercePort(rawPort),
    // Node decides pipe-vs-TCP with `const { path } = options; const pipe = !!path;` — pure
    // TRUTHINESS, not "is a string". `{ path: "", host, port }` is therefore an ordinary TCP
    // connect, which capwall used to guard as an `ipc` capability on the empty path while Node
    // dialled `host:port` (#99). A truthy NON-string `path` is a pipe to Node right up until
    // `validateString(path, 'options.path')` throws — `ipcPath` stays undefined there, so the
    // call is guarded as IPC-to-`<unknown>` (fail closed) and then throws exactly as it would
    // have without capwall.
    ipc: hasPath ? Boolean(rawPath) : undefined,
    ipcPath: typeof rawPath === "string" && rawPath !== "" ? rawPath : undefined,
    pinned,
  };
}

/**
 * The overlay-slot counterpart of {@link pinNetOptions}: the same information, read with the
 * semantics of Node's `ObjectAssign(options, source)` / `{ ...source }` MERGE rather than of a
 * property read.
 *
 * Two differences, both load-bearing, both found by the #99 audit:
 *
 *  1. ONLY OWN ENUMERABLE PROPERTIES COUNT. `ObjectAssign` copies exactly those. Reading through
 *     the prototype chain here invents a merge Node never performs — and the case that matters is
 *     a `URL`, whose `host`/`port` live on `URL.prototype` and are therefore copied by NOTHING.
 *     `tls.connect(443, "evil.host", new URL("https://granted.host"))` was guarded as
 *     `granted.host` and connected to `evil.host`; the URL contributed nothing to Node's merge.
 *  2. THE CLONE IS BUILT FIRST, and the target keys are read back off it. `pinAllOwnFields`
 *     invokes each own accessor EXACTLY ONCE; reading the source again afterwards would be a
 *     second invocation, i.e. the very TOCTOU this file exists to close. The clone's fields are
 *     plain data properties by then, so reading them is free of that hazard.
 */
function pinNetOverlay(src: object): PinnedNetOptions {
  const pinned = pinAllOwnFields(src); // every own accessor runs here, exactly once
  const own = (key: string): { has: boolean; value: unknown } => {
    const desc = Object.getOwnPropertyDescriptor(pinned, key);
    if (desc === undefined || desc.enumerable !== true) return { has: false, value: undefined };
    return { has: true, value: desc.value };
  };
  const host = own("host");
  const port = own("port");
  const path = own("path");
  return {
    host: typeof host.value === "string" && host.value !== "" ? host.value : undefined,
    port: coercePort(port.value),
    ipc: path.has ? Boolean(path.value) : undefined,
    ipcPath: typeof path.value === "string" && path.value !== "" ? path.value : undefined,
    pinned,
  };
}

/**
 * Resolve ONE `net.connect`/`net.createConnection`/`Socket#connect`/`Agent#createConnection`
 * call — guarded target AND forwarded args — in a single pass.
 *
 * This mirrors Node's `net._normalizeArgs` (`lib/net.js`) branch for branch, rather than the
 * signature's three documented overloads, because the two do not agree (#99):
 *
 *     if (typeof arg0 === 'object' && arg0 !== null) options = arg0;      // (options[…][, cb])
 *     else if (isPipeName(arg0))                     options.path = arg0; // (path[…][, cb])
 *     else { options.port = arg0;                                        // ([port][, host][…])
 *            if (args.length > 1 && typeof args[1] === 'string') options.host = args[1]; }
 *
 * The `else` is the catch-all: a numeric STRING is not a pipe name (see {@link isPipeName}), and
 * neither is a number, a boolean, `null`, or `undefined`. All of them are ports.
 * IPC connects resolve to the `ipc` capability, carrying the canonicalized socket path (#72).
 */
function resolveNetCall(args: unknown[], defaultPort = 0): ResolvedCall {
  const first = args[0];
  if (typeof first === "string" && isPipeName(first)) {
    return ipcCall(first, args); // (path[, cb]) — the ONLY positional string form that is IPC
  }
  if (!isPlainObject(first)) {
    // ([port][, host][, …]) — Node's catch-all branch. `port` is coerced the way `validatePort`
    // coerces it, so `net.connect("9999", "evil.host")` derives `evil.host:9999` (a TCP connect)
    // instead of an IPC path. A port Node will reject (`true`, `{}`, …) coerces to `undefined`
    // here: capwall guards the default, and the call then throws exactly as it would have.
    // Primitives have no getter surface, so there is nothing to pin — args pass through.
    const host = args.length > 1 && typeof args[1] === "string" && args[1] !== "" ? args[1] : "localhost";
    return { host, port: coercePort(first) ?? defaultPort, args };
  }
  // (options[…][, cb]) — ANY non-null object is the options bag here, including a `URL`
  // (nonsensical but legal: Node reads `.host`, which on a URL carries the port suffix, THROUGH
  // THE PROTOTYPE CHAIN — so unlike the `tls`/`http2` overlay slots, a URL in this position
  // really does supply a host, and pinning reproduces that exactly instead of leaving the URL's
  // accessors live for a second read).
  const p = pinNetOptions(first);
  const out = args.slice();
  out[0] = p.pinned;
  if (p.ipc === true) return ipcCall(p.ipcPath, out);
  // `hostname` is deliberately NOT a fallback: Node's net/tls ignore it and dial `localhost`,
  // so honoring it would guard a host the socket never reaches (a false-allow).
  return { host: p.host ?? "localhost", port: p.port ?? defaultPort, args: out };
}

/**
 * Resolve ONE `tls.connect`/`TLSSocket#connect` call. Node accepts the net-style positional and
 * options forms AND merges a trailing options object OVER the positionals, so the guarded
 * target must mirror that merge or a call like `tls.connect(443, "granted.host",
 * { host: "evil.host" })` would guard the granted target while Node connects to the evil one.
 *
 * The merge Node performs (`lib/internal/tls/wrap.js` `normalizeConnectArgs`) is exactly:
 *
 *     const options = net._normalizeArgs(listArgs)[0];   // args[0] object, or (port[, host])
 *     if (listArgs[1] !== null && typeof listArgs[1] === 'object') ObjectAssign(options, listArgs[1]);
 *     else                                                        ObjectAssign(options, listArgs[2]);
 *
 * Three rules come out of those two lines, and getting any of them wrong is a false-allow:
 *
 *  1. EXACTLY ONE overlay slot is consulted, chosen by whether `args[1]` is a non-null OBJECT —
 *     never both. An options object at any other index is ignored by Node, so treating it as an
 *     overlay guarded a target Node never dials (`tls.connect(443, "evil.host", {},
 *     { host: "granted.host" })` guarded granted.host and connected to evil.host — issue #46).
 *  2. If `args[1]` IS an object, `args[2]` is not consulted AT ALL — not even when `args[1]`
 *     turns out to contribute nothing. Falling back to `args[2]` in that case was the residue of
 *     #46 that #99 found: `tls.connect(443, "evil.host", new URL("https://granted.host"))` put a
 *     `URL` in slot 1, and capwall read `granted.host` off its PROTOTYPE while Node's
 *     `ObjectAssign` copied nothing (a `URL` has no own enumerable properties) and connected to
 *     `evil.host` (#105).
 *  3. The overlay is a MERGE, so only OWN ENUMERABLE properties of it move anything — which is
 *     what {@link pinNetOverlay} reads, as opposed to the prototype-chain read
 *     {@link pinNetOptions} correctly performs for the BASE slot, where Node does
 *     `options = arg0` and then reads `options.host`.
 *
 * Every object argument is still PINNED, whether or not it participates in the merge: an
 * accessor must never reach Node, and pinning flattens each object's fields to data properties
 * so Node's `ObjectAssign` sees precisely what capwall read.
 */
function resolveTlsCall(args: unknown[]): ResolvedCall {
  const out = args.slice();

  let host: string | undefined;
  let port: number | undefined;
  let ipc = false;
  // Tracked alongside `ipc` so the guarded socket PATH follows the same merge order as the
  // ipc flag itself (#72) — the last object to speak to `path` decides both.
  let ipcPath: string | undefined;

  // ── The BASE: net._normalizeArgs(args), which is resolveNetCall's rule set verbatim ────────
  const first = args[0];
  let base: PinnedNetOptions | undefined;
  if (isPlainObject(first)) {
    base = pinNetOptions(first);
    out[0] = base.pinned;
    host = base.host;
    port = base.port;
    if (base.ipc !== undefined) {
      ipc = base.ipc;
      ipcPath = base.ipcPath;
    }
  } else if (typeof first === "string" && isPipeName(first)) {
    ipc = true; // (path[, …]) — only a NON-numeric string is a pipe name; see isPipeName (#99)
    ipcPath = first;
  } else {
    port = coercePort(first); // ([port][, host][, …]) — including the numeric-string port
    if (args.length > 1 && typeof args[1] === "string" && args[1] !== "") host = args[1];
  }

  // ── The OVERLAY: exactly one slot, chosen by Node's own test, merged with ObjectAssign ─────
  const overlayIndex = isPlainObject(args[1]) ? 1 : 2;
  const overlaySource = args[overlayIndex];
  if (isMergeSource(overlaySource)) {
    const overlay = pinNetOverlay(overlaySource);
    // Substitute the pinned clone for a plain OBJECT only. A FUNCTION in this slot is the
    // caller's callback — `normalizeArgs` takes the last function argument as `cb`, and
    // `ObjectAssign` merges it as well, harmlessly, since a callback carries no own enumerable
    // `host`/`port`/`path`. Replacing it with a clone would delete the callback, so it is
    // forwarded untouched; the residual is that an own ACCESSOR on a callback function would be
    // read twice. Pathological, and accepted rather than traded for a broken `tls.connect`.
    if (isPlainObject(overlaySource)) out[overlayIndex] = overlay.pinned;
    host = overlay.host ?? host;
    port = overlay.port ?? port;
    if (overlay.ipc !== undefined) {
      ipc = overlay.ipc; // ObjectAssign overwrites, even with a falsy path
      ipcPath = overlay.ipcPath;
    }
  }
  // The slot Node did NOT consult is still pinned when it is an object — an accessor on it must
  // not be able to run inside the real call — but it contributes nothing to the target.
  const unusedIndex = overlayIndex === 1 ? 2 : 1;
  const unused = args[unusedIndex];
  if (isPlainObject(unused)) out[unusedIndex] = pinAllOwnFields(unused);

  if (ipc) return ipcCall(ipcPath, out);
  return { host: host ?? "localhost", port: port ?? 443, args: out };
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
  /**
   * `hostname` and `host` are kept SEPARATE, not collapsed into one "the host this object names"
   * field (#99). Node resolves them on the MERGED object —
   * `validateHost(options.hostname) || validateHost(options.host) || 'localhost'` — so a
   * `hostname` from the url and a `host` from the overlay do not compete as peers: the
   * `hostname` still wins. Collapsing them made `http.request(new URL("http://a/"),
   * { host: "b" })` resolve to `b`, where Node resolves to `a`.
   */
  hostname: string | undefined;
  host: string | undefined;
  /** Whether the object HAS the key at all — an overlay's `hostname: undefined` ERASES a base's
   * under Node's `ObjectAssign` merge, which "names no host" alone cannot express. */
  hasHostname: boolean;
  hasHost: boolean;
  port: number | undefined;
  defaultPort: number | undefined;
  socketPath: string | undefined;
  /** Whether the object HAS a `socketPath` key — same `ObjectAssign` reasoning as above. */
  hasSocketPath: boolean;
  pinned: Record<string, unknown>;
}

/**
 * Read an http-style options bag's capability-relevant keys once each and build the pinned
 * clone. Same contract as {@link pinNetOptions} — raw single reads written straight back — with
 * http's key set and http's precedence rules.
 *
 * DELIBERATE DIVERGENCE (#99), do not "fix" it back: presence is tested with `in`, i.e. THROUGH
 * THE PROTOTYPE CHAIN, whereas Node reaches these fields only through `ObjectAssign`/spread
 * copies of OWN ENUMERABLE properties (`ObjectAssign(input || {}, options)` in `ClientRequest`,
 * and `{ __proto__: null, ...options }` a line later). So an inherited `hostname` is guarded here
 * and ignored by Node. That is safe in BOTH of the shapes it can occur in, which is why it is
 * kept: for the base slot the inherited value is guarded and then dropped from the forwarded
 * clone (capwall names a host the socket never reaches — it can only DENY a call Node would have
 * allowed), and for the overlay slot the endpoint is PINNED onto the forwarded object, so the
 * host capwall guarded is the host Node dials. Either way the guarded target and the real target
 * agree. The alternative — a second, subtly different reader for a shape
 * (`http.request(Object.create({hostname: …}))`) no real caller writes — buys nothing and is one
 * more place for the two derivations to drift apart. `tls`/`http2`, where the merge slot is NOT
 * backed by an endpoint pin and the same distinction really is a false-ALLOW, do use
 * own-enumerable semantics — see {@link pinNetOverlay}.
 */
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
    // Node: `validateHost(options.hostname) || validateHost(options.host) || 'localhost'`, so a
    // FALSY value — including the empty string — names no host and falls through to the next
    // candidate. `hostname: ""` used to survive here as the guarded host while Node went on to
    // use `host` (#99). A truthy NON-string fails `validateHost`, so `undefined` is again the
    // fail-closed answer: capwall guards `localhost` and the call then throws.
    hostname: typeof rawHostname === "string" && rawHostname !== "" ? rawHostname : undefined,
    host: typeof rawHost === "string" && rawHost !== "" ? rawHost : undefined,
    hasHostname,
    hasHost,
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
 * makes the call an IPC connect, guarded on the socket path exactly like `net.connect({path})`.
 *
 * WHICH ARGUMENT IS THE URL is decided by Node's own DUCK-TYPED {@link isNodeUrlLike}, not by
 * `instanceof URL` (#99). `ClientRequest` does
 *
 *     if (typeof input === 'string')  input = urlToHttpOptions(new URL(input));
 *     else if (isURL(input))          input = urlToHttpOptions(input);
 *     else { cb = options; options = input; input = null; }
 *
 * so ANY object with a truthy `href` and `protocol` and no `auth`/`path` is a URL to Node — and
 * that decision is also what makes `args[1]` an options OVERLAY rather than the callback.
 * capwall's `instanceof` test therefore classified
 * `http.request({href, protocol, hostname: "granted.host"}, {hostname: "evil.host"})` as
 * "options bag + callback", guarded `granted.host`, and let Node merge and dial `evil.host` (#105).
 */
function resolveHttpCall(args: unknown[], defaultPort: number): ResolvedCall {
  const first = args[0];
  let urlOptions: Record<string, unknown> | undefined;
  let urlHostname: string | undefined;
  let urlPort: number | undefined;

  const fromUrl = (u: URL): void => {
    const snap = snapshotUrl(u); // the ONLY read of this URL's fields
    urlOptions = urlSnapshotToOptions(snap);
    urlHostname = stripIpv6Brackets(snap.hostname) || undefined; // unbracketed: what Node dials
    urlPort = snap.port !== "" ? coercePort(snap.port) : undefined;
  };

  // A url-like object that is NOT a real `URL`: Node still runs it through `urlToHttpOptions`,
  // whose `...url` spread carries its OWN properties into the merged options. Those own fields
  // are read here — once, via `pinHttpOptions` — so `host`/`socketPath`/`defaultPort` sitting on
  // such an object are guarded rather than smuggled past the guard. (A real `URL` instance has
  // no own enumerable properties, and capwall deliberately does not replicate the `...url`
  // spread for one — see {@link urlSnapshotToOptions}.)
  let urlOwn: PinnedHttpOptions | undefined;

  if (typeof first === "string") {
    try {
      fromUrl(new URL(first)); // capwall's own freshly-parsed URL — no external getter surface
    } catch {
      /* not an absolute URL */
    }
  } else if (isNodeUrlLike(first)) {
    if (!(first instanceof URL)) urlOwn = pinHttpOptions(first as Record<string, unknown>);
    fromUrl(first as URL); // read exactly once, via snapshotUrl
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
    // `Object.prototype` from injecting fields into a synthesized options bag. The layer order
    // is Node's: `{ ...url, <normalized url fields> }` then the overlay on top.
    forwarded = Object.create(null) as Record<string, unknown>;
    if (urlOwn) copyOwnFieldsExcept(forwarded, urlOwn.pinned, NO_SKIPPED_KEYS);
    copyOwnFieldsExcept(forwarded, urlOptions, NO_SKIPPED_KEYS);
    if (overlay) copyOwnFieldsExcept(forwarded, overlay.pinned, NO_SKIPPED_KEYS);
  } else if (base) {
    forwarded = base.pinned;
  }

  // Every field below is resolved on the MERGED object, exactly as `ClientRequest` resolves it:
  // a key PRESENT on the overlay wins even when its value is undefined (ObjectAssign overwrites),
  // and only then does the layer beneath it speak.
  const socketPath = overlay?.hasSocketPath === true ? overlay.socketPath : (urlOwn ?? base)?.socketPath;
  // `hostname` and `host` are resolved as two independent merged fields and only THEN combined
  // with Node's `hostname || host || 'localhost'` (#99). Collapsing them per-layer made an
  // overlay `host` beat a url `hostname`, which Node never does.
  const mergedHostname = overlay?.hasHostname === true ? overlay.hostname : (urlHostname ?? urlOwn?.hostname ?? base?.hostname);
  const mergedHost = overlay?.hasHost === true ? overlay.host : (urlOwn ?? base)?.host;
  const finalHost = mergedHostname ?? mergedHost ?? "localhost";
  // Node: `options.port || options.defaultPort || agent.defaultPort || <scheme default>`.
  const finalPort =
    overlay?.port ??
    base?.port ??
    urlPort ??
    urlOwn?.port ??
    overlay?.defaultPort ??
    base?.defaultPort ??
    urlOwn?.defaultPort ??
    (forwarded !== undefined ? agentDefaultPort(forwarded) : undefined) ??
    defaultPort;

  if (forwarded !== undefined) {
    // Pin the endpoint onto the forwarded object. `port` is written UNCONDITIONALLY (even when
    // the caller supplied none) — that is what removes `agent.defaultPort`/`options.defaultPort`
    // from Node's later resolution and makes the guarded port provably the connected port.
    // BOTH `hostname` and `host` are set to the ALREADY-RESOLVED host, so Node's own
    // `hostname || host || 'localhost'` can only land on the value that was guarded no matter
    // which of the two it reaches first.
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

  if (typeof socketPath === "string") return ipcCall(socketPath, outArgs);
  return { host: finalHost, port: finalPort, args: outArgs };
}

/** Wrap an egress function: `resolve` produces the guarded target AND the pinned argument list
 * in ONE pass (see the module header's PINNING INVARIANT), so nothing that decided the guard is
 * ever read a second time. */
function wrapFn(orig: AnyFn, resolve: (args: unknown[]) => ResolvedCall, ctx: ShimContext): AnyFn {
  const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
    const call = resolve(args);
    guard(ctx, targetRequest(call)); // throws on enforce-deny, before any socket opens
    return orig.apply(this, call.args); // pinned clone, never the original
  };
  Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
  return harden(ctx, wrapped);
}

/**
 * Expose a guarded SUBCLASS of `RealClass` whose prototype `method` runs `resolve`+guard
 * before delegating to the real method with the PINNED args. Class identity (`name` and the
 * receiver-checking `Symbol.hasInstance`) comes from the shared
 * {@link defineGuardedClassIdentity} — see there for why the receiver check is load-bearing
 * (#71).
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
        guard(ctx, targetRequest(call));
        forwardArgs = call.args; // pinned clone, never the original
      }
      return (realMethod as AnyFn).apply(this, forwardArgs);
    },
    writable: true,
    configurable: true,
  });
  defineGuardedClassIdentity(Guarded, RealClass);
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
    guard(ctx, targetRequest(resolved)); // before any socket opens
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
      guard(ctx, targetRequest(resolved)); // before super()
      super(...resolved.args); // pinned/synthesized args, never the original
    }
  };
  defineGuardedClassIdentity(Guarded, RealClass);
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
 * Resolver for `Agent#createConnection`, shared by the guarded `Agent` SUBCLASS (a dependency
 * building its own agent) and the guarded `globalAgent` INSTANCE (#65) so both gate identically —
 * a divergence between the two would be a bypass that reads as a refactor.
 *
 * It resolves through the NET flavor, not the http one: by the time Node calls
 * `agent.createConnection` it has already rewritten http's `socketPath` into `path` and blanked
 * the request `path`, so what arrives is a net-style options bag.
 */
function agentConnectionResolver(defaultPort: number): (args: unknown[]) => ResolvedCall {
  return (args) => resolveNetCall(args, defaultPort);
}

/**
 * Build a shimmed `http`/`https` module: `request`/`get`, `new ClientRequest()`,
 * `Agent.createConnection`, and the `globalAgent` INSTANCE are guarded. `server.listen` is
 * untouched.
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
      agentConnectionResolver(defaultPort),
      ctx,
    );
  }
  // ISSUE #65 — the CLASS guard above was not enough. `globalAgent` is a live `Agent` INSTANCE,
  // which the copy loop above duplicated onto the shim verbatim, REAL `createConnection` and
  // all: `http.globalAgent.createConnection({host, port})` connected with no guard and no log
  // line, under a deny-all enforce policy, from any dependency. Guard the exposed instance;
  // never the process-global one it wraps (see `guardedInstanceMethods` for why a Proxy, and
  // why patching the real agent is off the table).
  // ISSUE #80 — Node ≥22 re-exports the GLOBAL `WebSocket` class onto the `http` namespace, and
  // the copy loop above duplicates it through unguarded. While `globalThis.WebSocket` was itself
  // un-mediated, shimming this copy bought nothing (the global was right there). Now that the
  // global IS guarded, `require("http").WebSocket` is the remaining one-liner, so it gets the
  // same guarded subclass — built through the shared factory so repeated shim builds do not mint
  // new classes. Absent on Node 20 (and on 22 without `--experimental-websocket`), hence the
  // presence check.
  const realWebSocket = realRecord["WebSocket"];
  if (typeof realWebSocket === "function") {
    shim["WebSocket"] = guardedWebSocketClass(ctx, realWebSocket as AnyCtor);
  }
  const realGlobalAgent = realRecord["globalAgent"];
  if (typeof realGlobalAgent === "object" && realGlobalAgent !== null) {
    shim["globalAgent"] = guardedInstanceMethods(
      ctx,
      realGlobalAgent,
      new Map([
        ["createConnection", (realMethod: AnyFn) => wrapFn(realMethod, agentConnectionResolver(defaultPort), ctx)],
      ]),
    );
  }
  // Freeze AFTER installing the guarded instance, so the frozen namespace pins it: a dep
  // cannot swap `http.globalAgent` for a raw Agent. `Object.freeze` here freezes the shim
  // NAMESPACE only — never the guarded view, which refuses `preventExtensions` outright (#88)
  // and whose Proxy target is a capwall-owned object rather than the real agent anyway.
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
    // ...but `TLSSocket#connect` is the NET rule, not the tls one (#99). `normalizeConnectArgs`
    // and its `ObjectAssign` overlay live in `tls.connect` alone; `TLSSocket` defines no
    // `connect` of its own and inherits `net.Socket.prototype.connect`, which normalizes with
    // plain `net._normalizeArgs` and merges nothing. Applying the tls resolver here let
    // `new tls.TLSSocket().connect(443, "evil.host", { host: "granted.host" })` be guarded as
    // `granted.host` while Node dialled `evil.host` — the #46 false-allow, reintroduced by
    // sharing a resolver between two entry points that only LOOK like the same signature (#105).
    shim["TLSSocket"] = guardedSubclassMethod(
      realTls.TLSSocket as unknown as AnyCtor,
      "connect",
      (a) => resolveNetCall(a, 443),
      ctx,
    );
  }
  return harden(ctx, shim) as unknown as typeof import("node:tls");
}

/**
 * Build a shimmed `http2` module: `http2.connect(authority[, options])` is guarded.
 *
 * WHAT NODE ACCEPTS AS AN AUTHORITY (`lib/internal/http2/core.js`, identical on Node 20 and 22):
 *
 *     if (typeof authority === 'string') authority = new URL(authority);
 *     assertIsObject(authority, 'authority', ['string', 'Object', 'URL']);
 *     const protocol = authority.protocol || options.protocol || 'https:';
 *     const port = '' + (authority.port !== '' ? authority.port
 *                                              : (authority.protocol === 'http:' ? 80 : 443));
 *     let host = 'localhost';
 *     if (authority.hostname) { host = authority.hostname; if (host[0] === '[') host = host.slice(1, -1); }
 *     else if (authority.host) { host = authority.host; }
 *
 * — so a PLAIN OBJECT is a first-class authority, not only a string or a `URL`. capwall used to
 * run every non-`URL` authority through `new URL(String(authority))`, which for a plain object
 * parses `"[object Object]"`, throws, and falls back to guarding `localhost:443` while Node went
 * on to dial `{hostname: "evil.host", port: 9999, protocol: "http:"}` (#99, #105). A grant for
 * loopback was therefore a grant for anywhere, and an `observe` trace recorded the wrong target.
 *
 * SO THE THREE SHAPES ARE HANDLED SEPARATELY, each reading every field EXACTLY ONCE:
 *  - a STRING — parsed into capwall's own `URL` (no external getter surface), then rebuilt as a
 *    pinned authority STRING that is forwarded in place of the original.
 *  - a `URL` INSTANCE — read via {@link snapshotUrl}, then likewise replaced by the rebuilt
 *    string. Node's own `connect` re-reads the authority, which is exactly what a shadowed
 *    `hostname`/`port` accessor exploits (issue #26, URL-argument follow-up).
 *  - any other OBJECT — the four fields Node reads are read once each and forwarded as a fresh,
 *    inert 4-field object. It is deliberately NOT rebuilt into a URL string: an object authority
 *    without a `port` makes Node compute the literal port `"undefined"` and throw
 *    `ERR_SOCKET_BAD_PORT`, and synthesizing a valid authority there would turn a call Node
 *    rejects into one it performs.
 *
 * Rebuilding an authority STRING means reproducing Node's own defaults exactly, and getting
 * either of these wrong silently breaks a legitimate call:
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
  const guardedConnect: AnyFn = function (this: unknown, ...args: unknown[]): unknown {
    const authority = args[0];
    let host = "localhost";
    let port = 443;
    let ipc = false;
    let ipcPath: string | undefined;
    const out = args.slice();

    if (typeof authority === "string" || authority instanceof URL) {
      try {
        // capwall's own freshly-parsed URL for the string form — no external getter surface.
        const snap = snapshotUrl(typeof authority === "string" ? new URL(authority) : authority);
        const protocol = snap.protocol || "https:";
        host = stripIpv6Brackets(snap.hostname) || "localhost"; // Node strips them before dialing
        port = coercePort(snap.port) ?? (protocol === "http:" ? 80 : 443); // scheme-aware, like Node
        out[0] = `${protocol}//${bracketIpv6(host)}:${port}`; // a STRING, never the original
      } catch {
        /* unparseable authority — deny-leaning localhost:443, and args[0] is left as the caller
         * wrote it so Node raises the same parse error the un-shimmed API would */
      }
    } else if (isPlainObject(authority)) {
      // The four fields Node reads off an object authority, one read each, forwarded inert.
      const rawProtocol = authority["protocol"];
      const rawPort = authority["port"];
      const rawHostname = authority["hostname"];
      const rawHost = authority["host"];
      host =
        typeof rawHostname === "string" && rawHostname !== ""
          ? stripIpv6Brackets(rawHostname)
          : typeof rawHost === "string" && rawHost !== ""
            ? rawHost
            : "localhost";
      // Node's own expression, including its use of the RAW `authority.protocol` — not the
      // `options.protocol` fallback — to pick the default port.
      port = (rawPort !== "" ? coercePort(rawPort) : undefined) ?? (rawProtocol === "http:" ? 80 : 443);
      const pinnedAuthority: Record<string, unknown> = {};
      if (rawProtocol !== undefined) pinnedAuthority["protocol"] = rawProtocol;
      pinnedAuthority["port"] = rawPort;
      pinnedAuthority["hostname"] = rawHostname;
      pinnedAuthority["host"] = rawHost;
      out[0] = pinnedAuthority;
    }
    // Node honors options.host/port over the authority: both branches of its connect end up
    // spreading the options object over `{port, host}` (`net.connect({port, host, ...options})`
    // for h2c, `tls.connect(port, host, {...options})` for h2). Both are `ObjectAssign`-shaped
    // MERGES of `{ ...options }`, so only OWN ENUMERABLE properties of the overlay move the
    // destination — {@link pinNetOverlay}, not the prototype-chain read (#99). `options.path`
    // would make it an IPC connect.
    const opts = args[1];
    if (isMergeSource(opts)) {
      const p = pinNetOverlay(opts); // one read per capability-relevant key
      if (isPlainObject(opts)) out[1] = p.pinned;
      if (p.host !== undefined) host = p.host;
      if (p.port !== undefined) port = p.port;
      if (p.ipc === true) {
        ipc = true;
        ipcPath = p.ipcPath;
      }
    }
    guard(ctx, targetRequest(ipc ? ipcCall(ipcPath, out) : { host, port, args: out }));
    return realConnect.apply(this, out); // pinned authority + options, never the originals
  };
  // ISSUE #96 — every guarded wrapper capwall hands out reports the REAL function's `name`, and
  // this one did not: assigning through a computed member (`shim["connect"] = function …`) does
  // not trigger JS name inference, so `http2.connect.name` was `""`. Cosmetic on its own, except
  // that the `harden` below FREEZES the wrapper under hardened mode, making the empty name
  // permanent for any consumer doing feature detection on it. Set it BEFORE the freeze.
  Object.defineProperty(guardedConnect, "name", { value: realConnect.name, configurable: true });
  shim["connect"] = harden(ctx, guardedConnect);
  return harden(ctx, shim) as unknown as typeof import("node:http2");
}

/**
 * Attribute a dgram op and guard it, EXCEPT ops attributed to `<app>` — the app is the trust
 * root, exactly as in the `process.env` shim.
 *
 * Since #60 that exemption applies ONLY to a positively-identified application frame:
 * attribution no longer falls off the end of the stack into `<app>`, it returns `<unknown>`,
 * which is evaluated like any other principal. The auto-bind replay this exemption used to
 * absorb is handled properly, by state, in {@link applyAuthorizedDgramSend}.
 */
function guardDgram(ctx: ShimContext, host: string, port: number): void {
  const pkg = attributeCaller(attributionOptionsFor(ctx));
  if (pkg === APP_ROOT) return;
  const decision = evaluate(ctx.policy, ctx.mode, pkg, { kind: "net", host, port });
  ctx.onDecision(pkg, decision);
  if (!decision.allowed) throw new CapabilityError(decision.reason, pkg);
}

/** A dgram destination derived from a call's arguments. */
interface DgramTarget {
  readonly host: string;
  readonly port: number;
}

/**
 * The ONE piece of state that means "capwall has already authorized this exact send", live
 * only for the synchronous duration of the forward that authorized it. See
 * {@link forwardAuthorizedDgramSend} for the whole mechanism and its security argument.
 *
 * It is a module-scoped `let` on purpose: nothing a dependency can reach names it, so unlike a
 * flag parked on the socket (`socket.__capwallSending = true`) it cannot be set from outside.
 */
interface DgramAuthorization {
  /** The socket the authorized send is running on — an authorization is never socket-portable. */
  readonly socket: object;
  /** The destination the policy actually allowed. A token can authorize NOTHING else. */
  readonly host: string;
  readonly port: number;
  readonly realSend: AnyFn;
  readonly guardedSend: AnyFn;
}
let dgramAuthorization: DgramAuthorization | null = null;

/**
 * Forward an ALREADY-AUTHORIZED `send` so Node's auto-bind replay cannot re-enter the guard.
 *
 * THE PROBLEM. `send` on an unbound socket makes Node bind the socket and defer the datagram:
 * it evaluates `this.send` — capwall's guarded wrapper — binds it, queues it, and re-invokes
 * it from the socket's `'listening'` event, on a stack with no caller frame at all. That
 * replay used to attribute to `<app>` and be exempted; since #60 it attributes to
 * `<unknown>`, and re-guarding it would throw a `CapabilityError` for a send the policy
 * already allowed, from inside Node's internals where the caller cannot catch it (the DoS
 * regression covered in `test/routing.test.ts`).
 *
 * WHY THIS CANNOT BE FIXED BY LOOKING AT THE STACK. The replay's stack is byte-for-byte the
 * same shape as `setTimeout(sock.send.bind(sock), 0, …)` — precisely the laundering trick #60
 * is about — so no stack-based rule can tell an authorized replay from an attack. The
 * difference has to be carried as state, because only capwall knows it: here we KNOW the send
 * was authorized, because we just authorized it, for a destination we can name.
 *
 * THE MECHANISM. `send` is an ACCESSOR (see `defineGuardedAccessor`), so capwall chooses what
 * Node's `this.send` read yields without ever redefining the property — which is what lets
 * this coexist with hardened mode's pin (#86; the previous implementation redefined the
 * property and therefore threw for every allowed send under `CAPWALL_HARDENED=1`). While an
 * authorized forward is in progress the getter yields a **replay token** minted by
 * {@link mintDgramReplayToken} instead of the guarded wrapper, and Node queues that token.
 *
 * WHY A STOLEN TOKEN IS WORTH NOTHING (the security question this design has to answer). The
 * token is not a "we are authorized" boolean — it carries the authorization's CONTENT, and
 * refuses to be anything else:
 *  - it is bound to ONE socket (`this !== auth.socket` → falls back to the full guard);
 *  - it is bound to ONE destination — the host:port the policy just allowed — so it can never
 *    widen what was granted, no matter what arguments it is called with;
 *  - it is single-use, so it cannot become a standing exemption;
 *  - every rejected case delegates to the ordinary guarded wrapper rather than to the real
 *    method, so there is no path through a token that skips a policy check;
 *  - it exists only while an authorized forward is on the stack, and the only code that can
 *    run inside that window is Node's own `send` — a dependency has to arrange to be called
 *    from inside it (e.g. an accessor on an element of a buffer LIST argument) merely to
 *    obtain a token whose whole power is "send once, to the address you were just granted".
 * There is no path by which manufacturing state gets an unauthorized destination forwarded:
 * the state does not say "allowed", it says "allowed to reach 127.0.0.1:9999, once".
 *
 * A further improvement over the previous implementation: the real, unguarded `send` is never
 * installed on the socket at all, so the window in which it was readable as an own property is
 * gone.
 */
function forwardAuthorizedDgramSend(
  receiver: unknown,
  target: DgramTarget | null,
  realSend: AnyFn,
  guardedSend: AnyFn,
  args: unknown[],
): unknown {
  if (target === null || typeof receiver !== "object" || receiver === null) {
    // No destination (a connected-socket send — the `connect` was gated) or an odd receiver:
    // nothing was authorized here and there is nothing to key an authorization on.
    return realSend.apply(receiver, args);
  }
  const previous = dgramAuthorization; // restore, don't null: a send nested inside a send
  dgramAuthorization = {
    socket: receiver,
    host: target.host,
    port: target.port,
    realSend,
    guardedSend,
  };
  try {
    return realSend.apply(receiver, args);
  } finally {
    dgramAuthorization = previous;
  }
}

/** What the guarded `send` accessor yields: the replay token while an authorized forward for
 * THIS socket is on the stack, the guarded wrapper at every other moment. A fresh token per
 * read, so a token a dependency contrives to read cannot starve Node's replay of its own. */
function readGuardedDgramSend(receiver: unknown, guardedSend: AnyFn): AnyFn {
  const auth = dgramAuthorization;
  if (auth !== null && auth.socket === receiver) return mintDgramReplayToken(auth);
  return guardedSend;
}

/** One socket, one destination, one use — see {@link forwardAuthorizedDgramSend}. */
function mintDgramReplayToken(auth: DgramAuthorization): AnyFn {
  let spent = false;
  const token: AnyFn = function replayAuthorizedSend(this: unknown, ...args: unknown[]): unknown {
    const target = deriveDgramSend(args, this);
    if (
      spent ||
      this !== auth.socket ||
      target === null ||
      target.host !== auth.host ||
      target.port !== auth.port
    ) {
      // Not the replay this token was minted for, so there is no authorization to spend.
      // Behave EXACTLY like the guarded method — attribute, evaluate, deny if denied.
      return auth.guardedSend.apply(this, args);
    }
    spent = true;
    // The replay can itself hit an unbound socket (it cannot in practice — Node flushes the
    // queue from 'listening' — but the invariant should not depend on that), so forward
    // through the same path, which arms a fresh authorization for the same destination.
    return forwardAuthorizedDgramSend(this, target, auth.realSend, auth.guardedSend, args);
  };
  // The token IS what `socket.send` reads back while an authorized forward is on the stack, so
  // it carries the same `name` as the wrapper it stands in for (#96) — a value that changed
  // mid-flight would be a capwall-introduced divergence in the one window it is observable.
  Object.defineProperty(token, "name", { value: auth.guardedSend.name, configurable: true });
  return token;
}

/**
 * Derive the destination of `send(msg[, offset, length], port[, address][, cb])`, or null for
 * a connected-socket `send(msg[, cb])` (no destination → the `connect` was gated).
 *
 * This mirrors Node's own POSITIONAL normalization in `dgram.Socket.prototype.send` rather
 * than guessing from argument types, for two reasons:
 *  1. SECURITY. Node accepts a port as a numeric STRING (`validatePort` coerces `"9999"`,
 *     `" 9999 "`, even `"0x270f"`). A "last number argument is the port" rule sees no number
 *     in `send(buf, "9999", "10.0.0.1")`, concludes there is no destination, and skips the
 *     guard entirely — un-gated, unlogged UDP egress under a deny-all policy. Reading the port
 *     from the position Node reads it from, and coercing it the way Node coerces it, closes
 *     that. It also removes the mirror-image hazard, where a numeric-looking *address*
 *     (`send(buf, 9999, "3232235777")`) would be mistaken for the port.
 *  2. CORRECTNESS OF THE REPLAY MATCH. The replay re-enters with Node's normalized
 *     `(list, port, address, callback)`. Deriving positionally makes the derivation a fixed
 *     point — the replay's destination is identical to the one authorized — which is what
 *     {@link mintDgramReplayToken} matches on.
 */
function deriveDgramSend(args: unknown[], receiver: unknown): DgramTarget | null {
  // Node: `if (address || (port && typeof port !== 'function'))` picks the 6-argument form
  // `(buffer, offset, length, port, address, callback)`; otherwise the arguments shift down to
  // `(buffer, port, address, callback)`.
  const long = Boolean(args[4]) || (Boolean(args[3]) && typeof args[3] !== "function");
  const rawPort = long ? args[3] : args[1];
  const rawAddress = long ? args[4] : args[2];
  const port = coercePort(rawPort);
  if (port === undefined) return null; // connected send — no destination args
  return { host: typeof rawAddress === "string" && rawAddress !== "" ? rawAddress : defaultDgramHost(receiver), port };
}

/**
 * The address a `dgram` socket sends to when the call names none.
 *
 * NOT `"localhost"`. Node resolves an absent/empty address inside the socket's own bound lookup
 * helper (`lib/internal/dgram.js`):
 *
 *     function lookup4(lookup, address, callback) { return lookup(address || '127.0.0.1', 4, callback); }
 *     function lookup6(lookup, address, callback) { return lookup(address || '::1', 6, callback); }
 *
 * so the default depends on the socket TYPE and is a literal IP, never a name. capwall guarded
 * `localhost` for both, which is a policy-spelling divergence in the direction that hurts a
 * round trip: `capwall observe` recorded `localhost`, and a policy written the way an operator
 * would (`"127.0.0.1"`) then denied the very call that produced the trace (#99). The socket's
 * `type` is a plain data property Node sets in the `dgram.Socket` constructor.
 */
function defaultDgramHost(receiver: unknown): string {
  if (typeof receiver === "object" && receiver !== null) {
    const type = (receiver as { type?: unknown }).type;
    if (type === "udp6") return "::1";
  }
  return "127.0.0.1";
}

/** `connect(port[, address][, cb])`. The port is coerced the way Node's `validatePort` does,
 * for the same reason as in {@link deriveDgramSend} — a string port must not derive a
 * different destination from the one Node dials. Node normalizes an absent address to `''`
 * and then resolves it through the same {@link defaultDgramHost} rule `send` uses. */
function deriveDgramConnect(args: unknown[], receiver: unknown): DgramTarget {
  const port = coercePort(args[0]) ?? 0;
  const host = typeof args[1] === "string" && args[1] !== "" ? args[1] : defaultDgramHost(receiver);
  return { host, port };
}

/** Build the guarded `send`: check the policy, then forward through the authorized path so
 * Node's auto-bind replay is served by a token rather than by a second policy check. */
function guardedDgramSend(ctx: ShimContext, realSend: AnyFn): AnyFn {
  const guarded: AnyFn = function (this: unknown, ...args: unknown[]): unknown {
    const target = deriveDgramSend(args, this);
    if (target) guardDgram(ctx, target.host, target.port);
    return forwardAuthorizedDgramSend(this, target, realSend, guarded, args);
  };
  // #96, same rule as every other wrapper: report the REAL method's name, whatever it is — for
  // `dgram` that is the empty string, because Node assigns `Socket.prototype.send = function …`
  // through a member expression and so gets no name inference either. Parity with Node, not a
  // prettier name; `const guarded = …` would otherwise have leaked "guarded" to every consumer.
  Object.defineProperty(guarded, "name", { value: realSend.name, configurable: true });
  return harden(ctx, guarded);
}

/** Build the guarded `connect`. No replay token: Node's `connect` on an unbound socket queues
 * its INTERNAL `_connect` (`FunctionPrototypeBind(_connect, this, …)`), not `this.connect`, so
 * the guard is never re-entered from the `'listening'` flush. Verified against Node 20 and 22
 * and pinned by the unbound-connect regression in `test/routing.test.ts`, which would fail
 * loudly (an uncatchable `CapabilityError` from Node's internals) if that ever changed. */
function guardedDgramConnect(ctx: ShimContext, realConnect: AnyFn): AnyFn {
  const guarded: AnyFn = function (this: unknown, ...args: unknown[]): unknown {
    const target = deriveDgramConnect(args, this);
    guardDgram(ctx, target.host, target.port);
    return realConnect.apply(this, args);
  };
  Object.defineProperty(guarded, "name", { value: realConnect.name, configurable: true }); // #96
  return harden(ctx, guarded);
}

/** Install guarded `send`/`connect` on a dgram socket instance (used for createSocket results).
 * Under hardened mode (#17) these OWN properties are pinned non-configurable and setter-less
 * (`defineGuardedAccessor`) so `socket.send = evil` cannot strip the guard off a socket capwall
 * handed out. The socket itself is never frozen — it needs its mutable internal state. */
function guardDgramInstance(socket: Record<string, unknown>, ctx: ShimContext): void {
  const realSend = socket["send"];
  const realConnect = socket["connect"];
  if (typeof realSend === "function") {
    const guarded = guardedDgramSend(ctx, realSend as AnyFn);
    defineGuardedAccessor(ctx, socket, "send", function (this: unknown): unknown {
      return readGuardedDgramSend(this, guarded);
    });
  }
  if (typeof realConnect === "function") {
    const guarded = guardedDgramConnect(ctx, realConnect as AnyFn);
    defineGuardedAccessor(ctx, socket, "connect", () => guarded);
  }
}

/** Build a shimmed `dgram` module: sockets from `createSocket` AND `new dgram.Socket()` gate send/connect. */
export function createDgramShim(ctx: ShimContext): typeof import("node:dgram") {
  const shim: Record<string, unknown> = {};
  for (const key of Object.keys(realDgram)) {
    shim[key] = (realDgram as unknown as Record<string, unknown>)[key];
  }
  const realCreate = realDgram.createSocket as unknown as AnyFn;
  const guardedCreateSocket: AnyFn = function (this: unknown, ...args: unknown[]): unknown {
    const socket = realCreate.apply(this, args) as Record<string, unknown>;
    guardDgramInstance(socket, ctx);
    return socket;
  };
  // Same `name` restoration as every other wrapper (#96) — this site had the identical drift as
  // `http2.connect`, for the identical reason (assignment through a computed member).
  Object.defineProperty(guardedCreateSocket, "name", { value: realCreate.name, configurable: true });
  shim["createSocket"] = harden(ctx, guardedCreateSocket);
  const RealDgramSocket = (realDgram as unknown as Record<string, unknown>)["Socket"];
  if (typeof RealDgramSocket === "function") {
    const Guarded = class extends (RealDgramSocket as AnyCtor) {};
    const proto = (RealDgramSocket as AnyCtor).prototype as Record<string, unknown>;
    // The SAME guards and the SAME accessor installer as the `createSocket` path above — one
    // mechanism, not two. #86 happened because the two dgram paths diverged (the instance one
    // was pinned by hardened mode, the prototype one was not), so the interaction that broke
    // the pinned path was invisible from the other.
    const realSend = proto["send"];
    if (typeof realSend === "function") {
      const guarded = guardedDgramSend(ctx, realSend as AnyFn);
      defineGuardedAccessor(ctx, Guarded.prototype, "send", function (this: unknown): unknown {
        return readGuardedDgramSend(this, guarded);
      });
    }
    const realConnect = proto["connect"];
    if (typeof realConnect === "function") {
      const guarded = guardedDgramConnect(ctx, realConnect as AnyFn);
      defineGuardedAccessor(ctx, Guarded.prototype, "connect", () => guarded);
    }
    defineGuardedClassIdentity(Guarded, RealDgramSocket as AnyCtor);
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
