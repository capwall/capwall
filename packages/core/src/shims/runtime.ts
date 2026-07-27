/**
 * Shared shim runtime — the attribute→evaluate→report→(forward|throw) sequence every
 * capability shim follows, extracted so each shim is a thin wrapper (roadmap M4, issue #10).
 *
 * A shim asks {@link guard} "may the calling package do this?" for each capability-sensitive
 * operation. `guard` attributes the caller, evaluates the request against the policy under
 * the active mode, reports the decision to `onDecision` (the observe log / gen-policy trace
 * sink), and — in enforce mode only — throws a {@link CapabilityError} on denial. In observe
 * mode `evaluate` always allows, so `guard` records and returns without throwing.
 */
import {
  attributeCallerDetailed,
  type Attribution,
  type AttributionOptions,
} from "../attribution/index.js";
import { evaluate, type CapabilityRequest, type Decision } from "../policy/evaluate.js";
import { CapabilityError } from "../errors.js";
import { hardenClass, isHardened } from "./harden.js";
import type { Mode, Policy } from "@capwall/policy-schema";

/** Callback capwall invokes on every decision (log sink in observe, collector for gen-policy). */
export type DecisionSink = (pkg: string, decision: Decision) => void;

export interface ShimContext {
  policy: Policy;
  mode: Mode;
  onDecision: DecisionSink;
  /** Absolute project root; used for attribution and policy-glob resolution. */
  projectRoot?: string;
  /**
   * Frame budget for the attribution stack walk (issue #15). Already validated by `install()`
   * / the preload; absent means "use the attribution default".
   */
  maxFrames?: number;
  /**
   * Opt-in HARDENED MODE (#17): freeze the shim surfaces handed to dependencies so a
   * dependency cannot monkey-patch away mediation. **Off by default** — it breaks
   * `graceful-fs` and every other legitimate `fs` patcher. See `shims/harden.ts` for exactly
   * what is (and is not) frozen, and docs/threat-model.md for what it does not protect.
   */
  hardened?: boolean;
}

/**
 * Build the attribution options for `ctx`. Centralized so every attribution site (this
 * module, the env guard, the dgram path) walks with the SAME budget — a shim that quietly
 * kept the default while the rest honored a raised cap would attribute the same call to a
 * different package depending on which capability it touched.
 */
export function attributionOptionsFor(ctx: ShimContext): AttributionOptions {
  return {
    ...(ctx.projectRoot !== undefined ? { projectRoot: ctx.projectRoot } : {}),
    ...(ctx.maxFrames !== undefined ? { maxFrames: ctx.maxFrames } : {}),
  };
}

/** A shim contributes zero or more `specifier → module object` entries to the loader registry. */
export type ShimRegistry = Map<string, unknown>;

/*
 * ───────────────────────────────────────────────────────────────────────────────────────────
 * KEY-SCOPED ENV AUTHORIZATION (issue #89)
 * ───────────────────────────────────────────────────────────────────────────────────────────
 *
 * WHAT THIS REPLACES. Until #89 this was `suspendEnvGate()`/`resumeEnvGate()`: a process-wide
 * boolean depth counter that the `child_process` shim raised around the ENTIRE real spawn call,
 * and which made `shims/env.ts` `decide()` return `null` — no gate, no record — for EVERY key
 * and EVERY package for the duration. Node reads the caller's own options object inside that
 * window, so a getter on `options.cwd` ran with the env gate globally off and copied all 85
 * values out of `process.env`, with nothing but the `child_process` decision in the trace. It
 * was not even scoped to the spawning package: a second dependency with no grants at all read
 * ungated too, purely because someone else happened to be inside a spawn.
 *
 * WHY AN AUTHORIZATION IS STILL NEEDED AT ALL. Node's own `lib/child_process.js` reads
 * `process.env` while assembling the child's environment block. Those reads happen with the
 * spawning dependency as the nearest stack frame and are indistinguishable — same trap, same
 * `(target, key)`, byte-for-byte the same caller stack — from that dependency reading the key
 * itself. Gating them would deny a granted package its own legitimate spawn (a child with no
 * PATH/HOME), which is a functional break, not a security win.
 *
 * WHAT IS AUTHORIZED NOW. The bulk of those reads is gone rather than exempted: the
 * child_process shim supplies an explicit `options.env` built from the un-proxied environment,
 * so Node's `options.env || { ...process.env }` never enumerates the proxy (see
 * `shims/child_process.ts`). What remains is a fixed, audited handful of NON-SECRET keys Node
 * reads by NAME regardless of what the caller supplied. Those — and ONLY those, by exact string
 * match — pass ungated, and only while a real spawn is on the stack. Every other key stays
 * gated and recorded, for every package, including inside the spawn.
 *
 * So a caller accessor that still runs inside the real call (see the enumeration in
 * `shims/child_process.ts`) reaches an authorization worth nothing: it can learn whether
 * `NODE_V8_COVERAGE` is set, and nothing else.
 *
 * The set is supplied by the CALLER rather than defined here, so the knowledge of which keys
 * Node reads lives next to the shim that knows why — this module holds only the mechanism.
 */
let authorizedEnvKeys: ReadonlySet<string> | null = null;

/**
 * Run `fn` with `keys` — and nothing else — exempt from the env read gate. Save/restore rather
 * than a counter, so nesting composes and an inner window can never widen an outer one beyond
 * its own set.
 */
export function withAuthorizedEnvKeys<T>(keys: ReadonlySet<string>, fn: () => T): T {
  const previous = authorizedEnvKeys;
  authorizedEnvKeys = keys;
  try {
    return fn();
  } finally {
    authorizedEnvKeys = previous;
  }
}

/** True when `key` is one of the keys the currently-running real call is authorized to read. */
export function isAuthorizedEnvKey(key: string): boolean {
  return authorizedEnvKeys !== null && authorizedEnvKeys.has(key);
}

/**
 * The environment object Node's own spawn would have enumerated, WITHOUT the read gate in front
 * of it — registered by `installEnvGuard` (the only code that holds the un-proxied reference)
 * and consumed by the child_process shim to build the child's environment block.
 *
 * This is a captured OBJECT REFERENCE, not a permission flag: reading it confers no authority
 * that `installEnvGuard` did not already hold, and it is not time-windowed, so it has none of
 * the properties that made the old `suspendEnvGate` seam dangerous.
 *
 * FAILS CLOSED when unset. With no env guard installed, `process.env` IS the real object, so the
 * fallback is exact; if a guard were somehow installed without registering, the fallback reads
 * through the proxy and every key is gated and recorded — noisy, never permissive.
 */
let unproxiedEnv: NodeJS.ProcessEnv | undefined;

export function setUnproxiedEnv(env: NodeJS.ProcessEnv | undefined): void {
  unproxiedEnv = env;
}

export function unproxiedProcessEnv(): NodeJS.ProcessEnv {
  return unproxiedEnv ?? process.env;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
/** Any constructor. `any` is required here: a mixin base must be `new (...a: any[]) => any`. */
export type AnyCtor = new (...args: any[]) => any;

/** Any function. Shims receive raw builtin arguments, so they stay `unknown[]` end to end. */
export type AnyFn = (...args: unknown[]) => unknown;

/**
 * ECMA-262 `OrdinaryHasInstance` in userland: does `x`'s prototype chain contain
 * `C.prototype`? Used as the fallback inside a guarded subclass's `Symbol.hasInstance`
 * override — see {@link guardedConstructorSubclass} for why the fallback is needed.
 */
function ordinaryHasInstance(C: unknown, x: unknown): boolean {
  if (typeof C !== "function") return false;
  const proto: unknown = (C as { prototype?: unknown }).prototype;
  if (typeof proto !== "object" || proto === null) return false;
  if (x === null || (typeof x !== "object" && typeof x !== "function")) return false;
  let cur: object | null = Object.getPrototypeOf(x as object) as object | null;
  while (cur !== null) {
    if (cur === proto) return true;
    cur = Object.getPrototypeOf(cur) as object | null;
  }
  return false;
}

/**
 * Give a guarded class the identity a dependency observes: `RealClass`'s `name`, and the ONE
 * correct `Symbol.hasInstance` (issue #71). Every guarded class in every shim goes through
 * here, so there is a single implementation of this reasoning rather than one per site.
 *
 * WHY AN OVERRIDE AT ALL. `instanceof` must keep answering correctly for instances the real
 * builtin's own factories produce: `fs.createReadStream()` and `http.request()` build REAL
 * instances that never touch capwall's subclass, yet `stream instanceof fs.ReadStream` and
 * `req instanceof http.ClientRequest` have to stay true against the class capwall hands out.
 * Ordinary prototype-chain semantics would say false, because the guarded class's prototype is
 * one level BELOW the real one.
 *
 * WHY THE RECEIVER CHECK (this is #71). `Symbol.hasInstance` is inherited down the STATIC
 * chain. A dependency writing the perfectly ordinary
 *
 *     class Mine extends net.Socket {}
 *
 * inherits this method on `Mine`, so a naive body — one that only asks "is `x` an instance of
 * the real class?" — makes `someUnrelatedRealSocket instanceof Mine` return TRUE. Un-shimmed
 * Node returns false, and silently inverting a package's type dispatch is the kind of
 * correctness deviation that gets blamed on anything but the capability firewall. So: answer
 * the permissive way ONLY when the receiver is the guarded class itself, and fall back to
 * ordinary prototype-chain semantics for any further subclass.
 */
export function defineGuardedClassIdentity(Guarded: AnyCtor, RealClass: AnyCtor): void {
  Object.defineProperty(Guarded, Symbol.hasInstance, {
    // `this` is the constructor on the RIGHT of `instanceof` — the guarded class for
    // `x instanceof net.Socket`, but a dependency's subclass for `x instanceof Mine`.
    value: function (this: unknown, x: unknown): boolean {
      if (this !== Guarded) return ordinaryHasInstance(this, x);
      return x instanceof RealClass;
    },
    configurable: true,
  });
  Object.defineProperty(Guarded, "name", {
    value: (RealClass as { name: string }).name,
    configurable: true,
  });
}

/**
 * Expose a guarded SUBCLASS of `RealClass` whose CONSTRUCTOR runs `check(args)` before
 * delegating to the real constructor (issue #64).
 *
 * WHY A SUBCLASS AND NOT A CONSTRUCT-TRAP `Proxy`. A `Proxy` only wraps the class OBJECT. It
 * forwards `get` to its target, so `Wrapped.prototype` IS the real prototype and
 * `Wrapped.prototype.constructor` IS the real, unguarded class:
 *
 *     new (fs.ReadStream.prototype.constructor)(deniedPath)   // guard never runs
 *
 * That one-liner defeated every construct-trap wrapper in the codebase (#64), which is why
 * `net.Socket`/`ChildProcess`/etc. were converted to guarded subclasses during the M4 reviews
 * and why the remaining Proxy sites (`fs.ReadStream`/`WriteStream`, `vm.Script`/
 * `SourceTextModule`/`SyntheticModule`, `worker_threads.Worker`) now use this helper. A
 * subclass owns its OWN `.prototype` object, whose `.constructor` is the guarded class, so the
 * walk lands back on the guard.
 *
 * A second, deliberate consequence: unlike a Proxy — where `Object.freeze` forwards
 * `[[PreventExtensions]]` to the TARGET and would freeze the real builtin class process-wide,
 * outliving `uninstall()` — a guarded subclass is an object capwall CREATED, so it is safe to
 * freeze. Hardened mode (#17) therefore freezes what this helper builds, and it does so HERE
 * rather than at each call site, so a future call site cannot forget to opt in.
 *
 * RESIDUAL (documented in docs/threat-model.md, same as the `net` sites): climbing PAST the
 * guarded subclass — `Object.getPrototypeOf(Guarded.prototype).constructor`, one hop up —
 * still reaches the real class. That is the same class of escape as un-patching the shim
 * outright: in-process code deliberately climbing above the guard, which capwall does not
 * claim to stop.
 *
 * The check runs BEFORE `super(...)`. That ordering is load-bearing: the real constructor is
 * what opens the fd / compiles the code / spawns the OS thread, so an enforce-mode denial has
 * to throw before it runs. Nothing before `super()` touches `this` (which would be illegal) —
 * `check` only inspects the constructor arguments.
 */
export function guardedConstructorSubclass<T extends AnyCtor>(
  RealClass: T,
  check: (args: unknown[]) => void,
  ctx: ShimContext,
): T {
  const Guarded = class extends RealClass {
    constructor(...args: any[]) {
      check(args); // throws on enforce-deny, before the real constructor does anything
      super(...args);
    }
  };
  defineGuardedClassIdentity(Guarded, RealClass);
  // Hardened mode only (#17): freeze the subclass + its own prototype. No-op by default.
  hardenClass(ctx, Guarded);
  return Guarded as unknown as T;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

/**
 * Expose a guarded VIEW of a pre-built builtin INSTANCE — the instance-shaped counterpart of
 * {@link guardedConstructorSubclass} (issue #65; every trap below is issue #88).
 *
 * WHY THIS EXISTS. Each shim guards the capability-bearing FUNCTIONS and CLASSES on a builtin
 * namespace and copies the rest of the namespace through by value. But a namespace can also
 * export a live, pre-built INSTANCE that already carries the capability, and a copied-through
 * instance carries the REAL, unguarded method:
 *
 *     http.globalAgent.createConnection({ host, port })   // connects; no guard, no log line
 *
 * `http.globalAgent`/`https.globalAgent` were exactly that (#65): un-gated AND unlogged egress
 * reachable from any dependency, so `observe` and `capwall diff` never saw it either. Egress is
 * the payload step of the supply-chain attacks capwall exists to stop, which is what made an
 * *unlogged* egress path the worst shape this class of bug can take.
 *
 * WHY A `Proxy` HERE, when a CLASS is always guarded with a subclass and never a Proxy. The
 * objection to a construct-trap Proxy (#64) is specific to classes — a Proxy forwards `get`, so
 * `Wrapped.prototype.constructor` is the real, unguarded class. An instance has no `.prototype`
 * to leak through, and every non-Proxy alternative breaks the property that makes `globalAgent`
 * special: it is a SHARED, MUTABLE, PROCESS-GLOBAL connection pool.
 *   - Handing out a freshly constructed guarded `Agent` gives the caller a DIFFERENT pool, so
 *     the ubiquitous `http.globalAgent.maxSockets = 100` would silently stop affecting the
 *     requests it is meant to tune, and pooled sockets would stop being shared.
 *   - `Object.create(realAgent)` reads through but shadows every WRITE onto the derived object —
 *     same silent breakage, plus half-updated agent bookkeeping.
 *   - Patching the method on the real instance mutates a process-global that outlives
 *     `uninstall()`. That is the constraint that kept real builtins unfrozen in #63; not an
 *     option.
 *
 * ─────────────────────────────────────────────────────────────────────────────────────────────
 * WHY A **VIRTUAL** TARGET (issue #88 — the part that was wrong until it was written down)
 * ─────────────────────────────────────────────────────────────────────────────────────────────
 * #65 proxied the REAL agent and implemented only a `get` trap. Every other operation therefore
 * took its DEFAULT behaviour, which is "forward to the target" — and the target was a
 * process-global builtin. So `http.globalAgent.createConnection = evil`,
 * `Object.defineProperty(http.globalAgent, …)`, `delete http.globalAgent.createConnection` and
 * `Object.freeze(http.globalAgent)` all landed on the real agent, through capwall's own guarded
 * view, and `uninstall()` could not undo any of it. The freeze was the sharp end: it made every
 * subsequent `http.request()` in the process throw `Cannot assign to read only property
 * 'totalSocketCount'`. That is precisely the hazard `harden.ts` cites as the reason #64 converted
 * the guarded CLASSES off Proxies, re-introduced one level down, at the instance.
 *
 * The guard itself always held — the `get` trap re-wraps whatever the underlying method
 * currently is, so no authority was gained — but "a dependency can permanently wedge a
 * process-global through capwall" is not a property a capability firewall may have.
 *
 * The fix is to stop making the real object the Proxy's target. The target here is an EMPTY,
 * extensible, capwall-owned object that is never written to, never frozen, and never handed out;
 * every trap forwards to `instance` EXPLICITLY, for the operations where forwarding is what the
 * caller means, and refuses otherwise. Two properties fall out:
 *
 *  1. **A missing or future trap fails INERT, not through.** With a real target the default for
 *     any trap capwall did not write was "mutate the process-global"; with a virtual target it is
 *     "do nothing to the process-global". That is the difference between the #88 default and a
 *     safe one, and it is why this is a target change rather than four more traps.
 *  2. **The Proxy invariants can never fire.** An exotic-object invariant forces `get` to return
 *     the target's ACTUAL value for a non-configurable, non-writable target property, and forces
 *     `getOwnPropertyDescriptor` never to report a non-configurable descriptor the target does
 *     not have. Against the real agent, one `Object.defineProperty(realAgent, "createConnection",
 *     {writable: false, configurable: false})` from ANY un-mediated code (the app, or a dep that
 *     went through `process.getBuiltinModule`) therefore turned every read of
 *     `http.globalAgent.createConnection` in the process into a `TypeError` — un-shimmed Node
 *     returns a value — and the only invariant-satisfying alternative would have been to hand
 *     back the UNGUARDED pinned method. A target with no own properties, kept extensible for
 *     life, satisfies every invariant unconditionally, so the guarded wrapper can always be
 *     returned. `test/net.test.ts` pins both halves.
 *
 * WHAT EACH TRAP DOES, and the rule behind it. Operations on this view fall into three classes:
 *
 *  - **Live state** (`get`/`set` of a non-guarded key, `has`, `ownKeys`,
 *    `getOwnPropertyDescriptor`, `getPrototypeOf`) — FORWARDED to the real instance. This is the
 *    whole reason a view exists rather than a copy: `maxSockets`, `keepAlive`, `sockets`/
 *    `freeSockets` and Node's own pool bookkeeping (Node writes those through `this` when the
 *    agent is passed to a request) must stay shared and live. A `set` here does mutate a
 *    process-global and does outlive `uninstall()` — deliberately, because that is also exactly
 *    what un-shimmed `http.globalAgent.maxSockets = 100` does, and shadowing it would silently
 *    detune the default request path (which pools through the REAL agent) while the caller
 *    believed it had tuned it. capwall does not turn a shared pool into a private one.
 *  - **Guarded methods** (the keys in `guards`) — a read always yields capwall's wrapper, and a
 *    write is kept in a per-view SHADOW instead of being forwarded. Those keys are not pool
 *    state, so nothing legitimate needs them shared; keeping the write local means a write and a
 *    later read still agree (ordinary JS semantics, and the view's own consumers — including
 *    Node, when this agent is passed to a request — see the replacement), the guard still wraps
 *    whatever was installed, and the whole edit disappears with the view at `uninstall()`. The
 *    divergence this buys is bounded and stated in docs/threat-model.md: a package that replaces
 *    `createConnection` on the guarded view does not replace it for code holding the RAW agent.
 *  - **Structural operations** (`defineProperty`, `deleteProperty`, `preventExtensions`,
 *    `setPrototypeOf`) — REFUSED, for every key, guarded or not. These change an object's SHAPE
 *    rather than its state; forwarded, each is an irreversible edit to a process-global
 *    (`Object.freeze` / a non-writable pin on `totalSocketCount` / `delete agent.sockets` all
 *    wedge the process's HTTP client), and none of them is something a dependency needs to do to
 *    an agent. Refusing means the trap returns `false`, so the operation throws a `TypeError` at
 *    the call site under strict mode — loud and local, where forwarding was silent and global.
 *
 * HARDENED MODE (#17) makes the guarded keys read-only as well: `set` refuses instead of
 * shadowing, matching what `defineGuardedAccessor` does for a `dgram` socket's `send`. The view
 * itself is never frozen — freezing it is `preventExtensions`, which is refused, and freezing the
 * agent BEHIND it is the process-wide breakage above. `hardened` is read once, at build time,
 * because that is when every other hardened decision is taken (a frozen object cannot be
 * un-frozen, and `loader/live-context.ts` memoizes one registry per hardened-ness).
 *
 * `guards` is a `Map`, deliberately NOT a plain object: an object lookup would resolve
 * inherited keys, so `agent.constructor` would find `Object.prototype.constructor` and be
 * "wrapped" with it. Prototype pollution is already listed as out of scope in the threat model;
 * that is a reason not to hand it a fresh lever, not a reason to shrug.
 *
 * RESIDUAL (documented in docs/threat-model.md, the same class as every other guard here):
 * `Object.getPrototypeOf(agent).createConnection.call(agent, opts)` reaches the real method.
 * That is in-process code deliberately climbing above the guard, which capwall does not claim
 * to stop.
 */
export function guardedInstanceMethods<T extends object>(
  ctx: ShimContext,
  instance: T,
  guards: ReadonlyMap<string, (realMethod: AnyFn) => AnyFn>,
): T {
  // Memoized per UNDERLYING function so `agent.createConnection === agent.createConnection`
  // (a fresh wrapper per read would break identity comparisons and defeat inline caches),
  // while still honoring a later legitimate replacement of the underlying method.
  const wrappers = new WeakMap<AnyFn, AnyFn>();
  /** Writes to GUARDED keys, kept here instead of on the process-global. Per view, so it dies
   * with the install. Never populated under hardened mode, where such writes are refused. */
  const shadow = new Map<string, unknown>();
  const pinned = isHardened(ctx);
  /** The Proxy's target: capwall's own object, permanently empty and permanently extensible.
   * Nothing reads it and nothing writes it — it exists so that no default trap behaviour and no
   * Proxy invariant can reach `instance`. See the "VIRTUAL TARGET" section above. */
  const virtualTarget = Object.create(null) as T;
  /** The real object, seen as a plain `object`. Only a typing convenience: the `Reflect` helpers
   * specialize on `T` and would otherwise demand `T`-keyed values from traps that legitimately
   * deal in `unknown`. */
  const underlying: object = instance;

  /** The value this view exposes for `prop`: capwall's guarded wrapper for a guarded method,
   * the underlying value untouched for everything else. */
  const expose = (prop: string, value: unknown): unknown => {
    const make = guards.get(prop);
    if (make === undefined || typeof value !== "function") return value;
    const real = value as AnyFn;
    let wrapped = wrappers.get(real);
    if (wrapped === undefined) {
      wrapped = make(real);
      wrappers.set(real, wrapped);
    }
    return wrapped;
  };

  return new Proxy(virtualTarget, {
    get(_target, prop, receiver): unknown {
      if (typeof prop !== "string") return Reflect.get(underlying, prop, receiver);
      if (shadow.has(prop)) return expose(prop, shadow.get(prop));
      // Exactly ONE read of the underlying property. Reading it twice (once to test, once to
      // wrap) would re-invoke a caller-installed accessor and reopen the very TOCTOU shape the
      // net shim's option pinning closes — in the one place that must not create a new one.
      // `receiver` is the Proxy, so an accessor on the real prototype still sees the guarded
      // view as `this` and its own reads/writes stay mediated.
      return expose(prop, Reflect.get(underlying, prop, receiver));
    },

    set(_target, prop, value): boolean {
      if (typeof prop === "string" && guards.has(prop)) {
        if (pinned) return false; // hardened (#17): the guarded surface is not replaceable
        shadow.set(prop, value);
        return true;
      }
      // Live pool state — forwarded. Deliberately WITHOUT a receiver: `Reflect.set(underlying,
      // prop, value, thisProxy)` would perform the final `CreateDataProperty` on the RECEIVER,
      // i.e. re-enter the `defineProperty` trap (which refuses), so an ordinary
      // `agent.maxSockets = 8` would silently fail. Assigning with the real instance as its own
      // receiver is what an un-shimmed write does.
      return Reflect.set(underlying, prop, value);
    },

    /* Structural operations — refused, never forwarded. Each one applied to the real agent is an
     * irreversible edit to a process-global that `uninstall()` cannot take back, and two of them
     * (a non-writable pin, a delete of pool state) wedge the process's HTTP client exactly as
     * `Object.freeze` did. Returning `false` surfaces as a `TypeError` at the caller under strict
     * mode. Nothing legitimate reshapes an `Agent`. */
    defineProperty(): boolean {
      return false;
    },
    deleteProperty(_target, prop): boolean {
      if (typeof prop === "string") {
        if (pinned && guards.has(prop)) return false; // hardened: pinned, like `set`
        shadow.delete(prop); // dropping capwall's OWN shadow is not a process-global mutation
      }
      // Report what ordinary `delete` would: success iff the key is no longer an own property of
      // the view. False (→ TypeError under strict mode) when the underlying object still has it,
      // because capwall will not delete it there.
      return Reflect.getOwnPropertyDescriptor(underlying, prop) === undefined;
    },
    preventExtensions(): boolean {
      return false; // `Object.freeze`/`seal`/`preventExtensions` on the view — see #88
    },
    setPrototypeOf(): boolean {
      return false;
    },

    /* Reflection — forwarded, but normalized so it can never contradict `get` or trip an
     * invariant. */
    has(_target, prop): boolean {
      return (typeof prop === "string" && shadow.has(prop)) || Reflect.has(underlying, prop);
    },
    ownKeys(): Array<string | symbol> {
      const keys = Reflect.ownKeys(underlying);
      if (shadow.size === 0) return keys;
      // A duplicate key in the result is itself a TypeError, so union rather than concatenate.
      return [...new Set<string | symbol>([...keys, ...shadow.keys()])];
    },
    getOwnPropertyDescriptor(_target, prop): PropertyDescriptor | undefined {
      if (typeof prop === "string" && shadow.has(prop)) {
        return {
          value: expose(prop, shadow.get(prop)),
          writable: !pinned,
          enumerable: true,
          configurable: true,
        };
      }
      const desc = Reflect.getOwnPropertyDescriptor(underlying, prop);
      if (desc === undefined) return undefined;
      // The virtual target owns NO properties, so a Proxy may only report CONFIGURABLE
      // descriptors here — reporting a non-configurable one for a property the target does not
      // have is an invariant violation and throws. It is also the honest answer for this view:
      // `defineProperty`/`deleteProperty` are refused above whatever the descriptor claims, so
      // no caller can act on the difference.
      desc.configurable = true;
      if (typeof prop === "string" && guards.has(prop) && "value" in desc) {
        // A descriptor read must not hand back the UNWRAPPED method that `get` guards.
        desc.value = expose(prop, desc.value);
        if (pinned) desc.writable = false;
      }
      return desc;
    },
    getPrototypeOf(): object | null {
      // Keeps `instanceof http.Agent` and `Object.getPrototypeOf(agent) === http.Agent.prototype`
      // answering exactly as they do for the real instance.
      return Reflect.getPrototypeOf(underlying);
    },
    isExtensible(target): boolean {
      // Must equal the target's real extensibility or the engine throws; the virtual target is
      // never made non-extensible, so this is always `true`.
      return Reflect.isExtensible(target);
    },
  }) as T;
}

/**
 * Attribute the current caller, evaluate `req`, report the decision, and throw on an
 * enforce-mode denial. Returns the attributed package name (useful when a shim wants to log
 * or branch on it). Never throws in observe mode.
 */
export function guard(ctx: ShimContext, req: CapabilityRequest): string {
  return guardAttributed(ctx, attributeCallerDetailed(attributionOptionsFor(ctx)), req);
}

/**
 * The decide→report→(allow|throw) half of {@link guard}, for the rare gate that has ALREADY
 * attributed the caller and needs the answer before it knows which request to raise.
 *
 * Exists for the `_compile` gate (#93), which must compare the attributed package against the
 * filename being compiled to recognize a package compiling its own source. Walking the stack a
 * second time inside `guard` would be wasted work and — worse — would make the decision rest on
 * two independent walks that a reviewer then has to reason about agreeing. One walk, one answer.
 */
export function guardAttributed(
  ctx: ShimContext,
  attribution: Attribution,
  req: CapabilityRequest,
): string {
  const { pkg, budgetExhausted } = attribution;
  const decision = evaluate(ctx.policy, ctx.mode, pkg, req);
  // A budget-exhausted `<unknown>` attribution is a possible mis-attribution (#15): flag it
  // for the sink so an operator can spot it and raise CAPWALL_MAX_FRAMES rather than reaching
  // for an `<unknown>` grant. The decision itself is untouched — since #60 the outcome is
  // already fail-closed, and the flag only says WHY. The copy is taken only on the rare
  // flagged path, so the hot path allocates nothing extra.
  ctx.onDecision(pkg, budgetExhausted ? { ...decision, attributionTruncated: true } : decision);
  if (!decision.allowed) throw new CapabilityError(decision.reason, pkg);
  return pkg;
}
