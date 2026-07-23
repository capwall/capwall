/**
 * @capwall/core — public entry point.
 *
 * `install(policy, mode)` turns capwall on for the current process: it patches the CJS
 * loader (and, later, registers the ESM hook) so that subsequent requires/imports of
 * capability-sensitive core modules return capwall's shims, which attribute each call to its
 * owning package and evaluate it against `policy` under `mode`.
 *
 * SCAFFOLD: `install` wires the (stubbed) loaders and returns a handle, but the loaders and
 * shims are not implemented yet — nothing is actually intercepted. The policy evaluator
 * (`evaluate`) and loader (`loadPolicy`) are real. See docs/roadmap.md for build order.
 */
import { patchRequire, type RequirePatchHandle } from "./loader/require.js";
import { registerEsmHook, type EsmHookHandle } from "./loader/esm-hook.js";
import type { Mode, Policy } from "@capwall/policy-schema";

/** Error thrown when a package attempts a capability it is not granted (enforce mode). */
export class CapabilityError extends Error {
  override readonly name = "CapabilityError";
  constructor(
    message: string,
    readonly pkg: string,
  ) {
    super(message);
  }
}

export interface InstallHandle {
  /** Remove capwall's interception (best-effort for ESM). Primarily for tests/teardown. */
  uninstall(): void;
}

export interface InstallOptions {
  /** Also register the ESM loader hook (roadmap M5). Off by default while CJS-first. */
  esm?: boolean;
}

/**
 * Install capwall into the current process.
 *
 * @param policy validated policy (use {@link loadPolicy} to read a capabilities.json).
 * @param mode `"observe"` (log, never block) or `"enforce"` (deny-by-default, throw).
 */
export function install(
  policy: Policy,
  mode: Mode,
  options: InstallOptions = {},
): InstallHandle {
  const handles: Array<RequirePatchHandle | EsmHookHandle> = [];
  handles.push(patchRequire(policy, mode));
  if (options.esm) {
    handles.push(registerEsmHook(policy, mode));
  }
  return {
    uninstall() {
      for (const h of handles) h.uninstall();
    },
  };
}

// Re-export the real, usable pieces so consumers have one import surface.
export { evaluate, isGranted } from "./policy/evaluate.js";
export type { CapabilityRequest, Decision } from "./policy/evaluate.js";
export { loadPolicy, loadPolicyFromObject } from "./policy/load.js";
export type {
  Policy,
  PackagePolicy,
  Mode,
  CapabilityKind,
} from "@capwall/policy-schema";
