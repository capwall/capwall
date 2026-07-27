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
 * freeze. Every call site of this helper is therefore a valid `hardenClass()` target once
 * hardened mode (#17 / PR #63) lands; wire them up when it merges.
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
): T {
  const Guarded = class extends RealClass {
    constructor(...args: any[]) {
      check(args); // throws on enforce-deny, before the real constructor does anything
      super(...args);
    }
  };
  Object.defineProperty(Guarded, Symbol.hasInstance, {
    // `this` is the constructor on the RIGHT of `instanceof`. For the guarded class itself,
    // accept every instance of the real class — instances made by an internal factory
    // (`fs.createReadStream`, which builds a REAL ReadStream) must still satisfy
    // `x instanceof fs.ReadStream`. For a FURTHER subclass written by a dependency
    // (`class Mine extends fs.ReadStream {}`), this method is inherited down the static chain
    // and would otherwise make `anyRealStream instanceof Mine` true — so fall back to ordinary
    // prototype-chain semantics whenever the receiver is not the guarded class itself.
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
  return Guarded as unknown as T;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

/**
 * Attribute the current caller, evaluate `req`, report the decision, and throw on an
 * enforce-mode denial. Returns the attributed package name (useful when a shim wants to log
 * or branch on it). Never throws in observe mode.
 */
export function guard(ctx: ShimContext, req: CapabilityRequest): string {
  const { pkg, budgetExhausted } = attributeCallerDetailed(attributionOptionsFor(ctx));
  const decision = evaluate(ctx.policy, ctx.mode, pkg, req);
  // A budget-exhausted `<app>` attribution is a possible mis-attribution (#15): flag it for
  // the sink so an operator can spot it and raise CAPWALL_MAX_FRAMES. The decision itself is
  // untouched — enforcement behavior does not change, only its observability. The copy is
  // taken only on the rare flagged path, so the hot path allocates nothing extra.
  ctx.onDecision(pkg, budgetExhausted ? { ...decision, attributionTruncated: true } : decision);
  if (!decision.allowed) throw new CapabilityError(decision.reason, pkg);
  return pkg;
}
