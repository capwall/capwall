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
 * The specific shims are supplied by {@link buildShimRegistry}; this module just routes a
 * required specifier to its registered shim (built lazily on first mediated require) and
 * passes everything else through. Which specifiers are *candidates* is {@link MEDIATED_MODULES};
 * which are *actually shimmed* is whatever the registry contains — as of M4 that is fs,
 * net/http(s), child_process, worker_threads, and vm. (process.env is guarded separately, not
 * via require — see shims/env.ts.)
 */
import Module from "node:module";
import { buildShimRegistry, type ShimRegistry } from "../shims/index.js";
import type { DecisionSink } from "../shims/runtime.js";
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
  "tls",
  "node:tls",
  "http2",
  "node:http2",
  "dgram",
  "node:dgram",
  "child_process",
  "node:child_process",
  "worker_threads",
  "node:worker_threads",
  "vm",
  "node:vm",
] as const;

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

  // The registry is built lazily on the first mediated require so no shim (and thus no
  // real-module capture) happens for a process that never touches a mediated specifier.
  let registry: ShimRegistry | null = null;
  const getRegistry = (): ShimRegistry =>
    (registry ??= buildShimRegistry({
      policy,
      mode,
      onDecision: options.onDecision,
      ...(options.projectRoot !== undefined ? { projectRoot: options.projectRoot } : {}),
    }));

  const patchedLoad: ModuleLoad = function (this: unknown, request, parent, isMain) {
    // Fast path: only the fixed candidate set can possibly be shimmed; everything else is a
    // plain delegate with no registry work.
    if ((MEDIATED_CANDIDATES as Set<string>).has(request)) {
      const reg = getRegistry();
      if (reg.has(request)) return reg.get(request);
    }
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

const MEDIATED_CANDIDATES: ReadonlySet<string> = new Set(MEDIATED_MODULES);
