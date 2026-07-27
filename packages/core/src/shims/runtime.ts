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
import { attributeCallerDetailed, type AttributionOptions } from "../attribution/index.js";
import { evaluate, type CapabilityRequest, type Decision } from "../policy/evaluate.js";
import { CapabilityError } from "../errors.js";
import { hardenClass } from "./harden.js";
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

/**
 * Reentrancy guard for the env shim. When a shim performs a real operation that itself reads
 * `process.env` as an implementation detail — chiefly `child_process` spawning, where Node
 * enumerates `process.env` to build the child's environment block — those reads would
 * otherwise be attributed to the spawning dependency and soft-denied, stripping the child's
 * environment. The child_process shim brackets the real spawn with suspend/resume so the
 * env shim passes those internal reads through untouched. Depth-counted for nesting.
 */
let envGateSuspendDepth = 0;
export function suspendEnvGate(): void {
  envGateSuspendDepth++;
}
export function resumeEnvGate(): void {
  if (envGateSuspendDepth > 0) envGateSuspendDepth--;
}
export function isEnvGateSuspended(): boolean {
  return envGateSuspendDepth > 0;
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
 * {@link guardedConstructorSubclass} (issue #65).
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
 * A `Proxy` forwards reads AND writes to the one real agent, so pool state, `maxSockets`,
 * keep-alive, `agent.sockets`/`freeSockets` and `instanceof` all stay live and shared; only the
 * named methods are replaced.
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
  instance: T,
  guards: ReadonlyMap<string, (realMethod: AnyFn) => AnyFn>,
): T {
  // Memoized per UNDERLYING function so `agent.createConnection === agent.createConnection`
  // (a fresh wrapper per read would break identity comparisons and defeat inline caches),
  // while still honoring a later legitimate replacement of the underlying method.
  const wrappers = new WeakMap<AnyFn, AnyFn>();
  return new Proxy(instance, {
    get(target, prop, receiver): unknown {
      // Exactly ONE read of the underlying property. Reading it twice (once to test, once to
      // wrap) would re-invoke a caller-installed accessor and reopen the very TOCTOU shape the
      // net shim's option pinning closes — in the one place that must not create a new one.
      const value: unknown = Reflect.get(target, prop, receiver);
      if (typeof prop !== "string" || typeof value !== "function") return value;
      const make = guards.get(prop);
      if (make === undefined) return value;
      const real = value as AnyFn;
      let wrapped = wrappers.get(real);
      if (wrapped === undefined) {
        wrapped = make(real);
        wrappers.set(real, wrapped);
      }
      return wrapped;
    },
  });
}

/**
 * Attribute the current caller, evaluate `req`, report the decision, and throw on an
 * enforce-mode denial. Returns the attributed package name (useful when a shim wants to log
 * or branch on it). Never throws in observe mode.
 */
export function guard(ctx: ShimContext, req: CapabilityRequest): string {
  const { pkg, budgetExhausted } = attributeCallerDetailed(attributionOptionsFor(ctx));
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
