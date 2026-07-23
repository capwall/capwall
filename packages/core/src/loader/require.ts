/**
 * CJS loader interception (the PRIMARY, first-implemented interception path).
 *
 * Approach: patch `Module._load` so that when any module requires a capability-sensitive
 * core builtin, it receives capwall's SHIMMED version instead of the raw builtin.
 * Non-sensitive requires pass through untouched to keep overhead near zero.
 *
 * Install as early as possible (before any dependency is required) so no package captures a
 * raw, un-shimmed reference first — the CLI does this with a `--import` preload. Note the
 * monkey-patch-robustness caveat in docs/threat-model.md: this is a JS-level patch and a
 * determined attacker can try to reach the original builtin via internal caches /
 * `process.binding`.
 *
 * CURRENT SCOPE (roadmap M1–M3): only the `fs` family is intercepted. The other entries in
 * {@link MEDIATED_MODULES} are listed for M4 and currently pass through un-shimmed.
 */
import Module from "node:module";
import { createFsShim, type DecisionSink } from "../shims/fs.js";
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

/** The subset of {@link MEDIATED_MODULES} actually shimmed today (fs vertical slice). */
const FS_SPECIFIERS = new Set(["fs", "node:fs"]);
const FS_PROMISES_SPECIFIERS = new Set(["fs/promises", "node:fs/promises"]);

export interface RequirePatchOptions {
  onDecision: DecisionSink;
  projectRoot?: string;
}

export interface RequirePatchHandle {
  /** Restore the original loader (used by tests and teardown). */
  uninstall(): void;
}

type ModuleLoad = (request: string, parent: unknown, isMain: boolean) => unknown;
interface ModuleInternals {
  _load: ModuleLoad;
}

/** Patch the CJS loader to return shimmed builtins for mediated modules. */
export function patchRequire(
  policy: Policy,
  mode: Mode,
  options: RequirePatchOptions,
): RequirePatchHandle {
  const moduleInternals = Module as unknown as ModuleInternals;
  const originalLoad = moduleInternals._load;

  // Built lazily on first mediated require; one shim instance per install.
  let fsShim: typeof import("node:fs") | null = null;
  const getFsShim = (): typeof import("node:fs") =>
    (fsShim ??= createFsShim({
      policy,
      mode,
      onDecision: options.onDecision,
      ...(options.projectRoot !== undefined ? { projectRoot: options.projectRoot } : {}),
    }));

  const patchedLoad: ModuleLoad = function (this: unknown, request, parent, isMain) {
    if (FS_SPECIFIERS.has(request)) return getFsShim();
    if (FS_PROMISES_SPECIFIERS.has(request)) return getFsShim().promises;
    return originalLoad.call(this, request, parent, isMain);
  };
  moduleInternals._load = patchedLoad;

  return {
    uninstall() {
      // Only restore if nobody patched over us in the meantime.
      if (moduleInternals._load === patchedLoad) {
        moduleInternals._load = originalLoad;
      }
    },
  };
}
