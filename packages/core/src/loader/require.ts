/**
 * CJS loader interception (the PRIMARY, first-implemented interception path).
 *
 * Approach: patch the CommonJS module machinery (`Module._load` and/or
 * `Module.prototype.require`) so that when any module requires a capability-sensitive core
 * builtin (`fs`, `net`, `http`, `https`, `child_process`, `worker_threads`, `vm`), it
 * receives capwall's SHIMMED version instead of the raw builtin. Non-sensitive requires pass
 * through untouched to keep overhead near zero.
 *
 * Install as early as possible (before any dependency is required) so no package captures a
 * raw, un-shimmed reference first. Note the monkey-patch-robustness caveat in
 * docs/threat-model.md: this is a JS-level patch and a determined attacker can try to reach
 * the original builtin via internal caches / `process.binding`.
 */
import type { Mode, Policy } from "@capwall/policy-schema";

/** Core modules capwall mediates; requiring any of these returns a shim once installed. */
export const MEDIATED_MODULES = [
  "fs",
  "node:fs",
  "fs/promises",
  "node:fs/promises",
  "net",
  "node:net",
  "http",
  "node:http",
  "https",
  "node:https",
  "child_process",
  "node:child_process",
  "worker_threads",
  "node:worker_threads",
  "vm",
  "node:vm",
] as const;

export interface RequirePatchHandle {
  /** Restore the original loader (used by tests and teardown). */
  uninstall(): void;
}

/**
 * Patch the CJS loader to return shimmed builtins for mediated modules.
 *
 * TODO(capwall): implement by wrapping `Module._load`. On a mediated specifier, return the
 * shim (built from `policy` + `mode`) instead of delegating to the real loader; cache the
 * per-specifier shim. Roadmap M1 wires this for `fs` first.
 */
export function patchRequire(_policy: Policy, _mode: Mode): RequirePatchHandle {
  // TODO(capwall): wrap Module._load; intercept MEDIATED_MODULES; return shims.
  return {
    uninstall() {
      /* TODO(capwall): restore original Module._load. */
    },
  };
}
