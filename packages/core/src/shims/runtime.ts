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
