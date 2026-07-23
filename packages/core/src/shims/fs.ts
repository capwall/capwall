/**
 * `fs` capability shim — the FIRST shim to implement (roadmap M1), the vertical slice that
 * proves the whole observe→policy→enforce loop end-to-end.
 *
 * A shim wraps the real core module and, on every capability-sensitive call, (1) asks
 * `attributeCaller()` who is calling, (2) asks `evaluate()` for a decision, then (3)
 * forwards to the real API, logs (observe), or throws (enforce). Signatures and error
 * semantics of the real API must be preserved so correct code is unaffected.
 */
import { attributeCaller } from "../attribution/index.js";
import { evaluate, type Decision } from "../policy/evaluate.js";
import type { Mode, Policy } from "@capwall/policy-schema";

/** Callback capwall invokes on every decision (log sink in observe, collector for gen-policy). */
export type DecisionSink = (pkg: string, decision: Decision) => void;

export interface ShimContext {
  policy: Policy;
  mode: Mode;
  onDecision: DecisionSink;
}

/**
 * Build a shimmed `fs` module.
 *
 * TODO(capwall): wrap the read family (readFile, readFileSync, createReadStream, open, …)
 * and write family (writeFile, appendFile, createWriteStream, mkdir, rm, …). For each,
 * derive the target path, build an fs CapabilityRequest, attribute + evaluate, then forward
 * or deny. Watch fd/symlink escapes (documented as out-of-scope in the threat model).
 */
export function createFsShim(_ctx: ShimContext): typeof import("node:fs") {
  // TODO(capwall): return a Proxy/wrapper over node:fs enforcing per-package fs policy.
  // The reference call path each wrapped method should follow:
  //   const pkg = attributeCaller({ projectRoot: ... });
  //   const decision = evaluate(ctx.policy, ctx.mode, pkg, { kind: "fs", access, path });
  //   ctx.onDecision(pkg, decision);
  //   if (!decision.allowed) throw new CapabilityError(decision.reason);
  //   return realFs[method](...args);
  void attributeCaller;
  void evaluate;
  throw new Error("capwall: fs shim not yet implemented — see roadmap M1");
}
