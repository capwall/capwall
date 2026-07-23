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
import { attributeCaller } from "../attribution/index.js";
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
}

/** A shim contributes zero or more `specifier → module object` entries to the loader registry. */
export type ShimRegistry = Map<string, unknown>;

/**
 * Attribute the current caller, evaluate `req`, report the decision, and throw on an
 * enforce-mode denial. Returns the attributed package name (useful when a shim wants to log
 * or branch on it). Never throws in observe mode.
 */
export function guard(ctx: ShimContext, req: CapabilityRequest): string {
  const pkg = attributeCaller(
    ctx.projectRoot !== undefined ? { projectRoot: ctx.projectRoot } : {},
  );
  const decision = evaluate(ctx.policy, ctx.mode, pkg, req);
  ctx.onDecision(pkg, decision);
  if (!decision.allowed) throw new CapabilityError(decision.reason, pkg);
  return pkg;
}
