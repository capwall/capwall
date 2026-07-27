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
 * The specific shims are supplied by `buildShimRegistry` via {@link liveRegistry}; this module
 * just routes a required specifier to its registered shim (built lazily on first mediated
 * require) and passes everything else through. Which specifiers are *candidates* is
 * {@link MEDIATED_MODULES}; which are *actually shimmed* is whatever the registry contains — as
 * of M4 that is fs, net/http(s), child_process, worker_threads, and vm. (process.env is guarded
 * separately, not via require — see shims/env.ts.)
 *
 * LIFECYCLE (issue #87). Each install pushes its context onto the SHARED install stack in
 * `live-context.ts` and pops it on `uninstall()`; the registry is built ONCE against that
 * stack's live context box rather than per install. Before #87 this module built a fresh
 * `ShimContext` object literal per install and never re-pointed the old one, so a module that
 * captured `fs` under a loose policy kept enforcing that loose policy after `uninstall()` AND
 * after `install(tighterPolicy)` — fail-open with respect to the new policy, while a freshly
 * required `fs` correctly denied. See `live-context.ts` for the full reasoning; it is the same
 * defect #62 fixed for ESM.
 *
 * The `_load` RELINK CHAIN (fix #22) now lives in `lifecycle/process-patch.ts` — this file was
 * one of the two sites that got it right by hand, and #107 made that shape the shared one so the
 * next site cannot get it wrong. `_load` STACKS (`defineRelinkedPatch`): two installs may route
 * to different registries, so each one's link must run.
 */
import Module from "node:module";
import { liveRegistry, popInstall, pushInstall } from "./live-context.js";
import { defineRelinkedPatch, valueSlot } from "../lifecycle/process-patch.js";
import type { ShimContext } from "../shims/runtime.js";

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
  // Not a capability surface — mediated so a dependency cannot reach `module.register` /
  // `module.registerHooks` and register a loader hook ahead of capwall's, which would
  // un-mediate the ESM import path for the whole process (#61). The shim passes everything
  // else on `node:module` (`createRequire`, `builtinModules`, the `_` internals, …) straight
  // through; see shims/module.ts.
  "module",
  "node:module",
] as const;

export interface RequirePatchHandle {
  /** Restore the original loader (used by tests and teardown). */
  uninstall(): void;
}

type ModuleLoad = (this: unknown, request: string, parent: unknown, isMain: boolean) => unknown;

/**
 * The CJS loader patch, as a shared relink chain (`lifecycle/process-patch.ts`).
 *
 * `link.next` is read at CALL time, never captured in a `const` at install time — that is what
 * lets an out-of-LIFO-order `uninstall()` relink around a removed middle layer instead of only
 * ever restoring the bottom of the stack (#22).
 */
const loadPatch = defineRelinkedPatch<ModuleLoad>("Module._load", {
  slot: valueSlot<ModuleLoad>("Module._load", () => Module as unknown as object, "_load"),
  patch: (_ctx, link) =>
    function (this: unknown, request, parent, isMain) {
      // Fast path: only the fixed candidate set can possibly be shimmed; everything else is a
      // plain delegate with no registry work. The registry itself is built on the first mediated
      // require, so a process that never touches one never constructs a shim (and so never
      // captures a real builtin).
      if ((MEDIATED_CANDIDATES as Set<string>).has(request)) {
        const reg = liveRegistry("cjs");
        if (reg.has(request)) return reg.get(request);
      }
      return link.next.call(this, request, parent, isMain);
    },
});

/**
 * Patch the CJS loader to return shimmed builtins for mediated modules.
 *
 * Takes the whole {@link ShimContext} (rather than the fields spread across an options object,
 * as before #87) because the context is now the unit of the install lifecycle: this exact
 * object is what gets pushed on the shared install stack and what `uninstall()` pops, and
 * `install()` hands the same one to the env guard, the global-egress guard and the ESM hook so
 * every mediated surface in the process agrees on which policy is live.
 */
export function patchRequire(ctx: ShimContext): RequirePatchHandle {
  // Activate this install BEFORE the patch goes live, so a require that lands between the two
  // can never be evaluated against the previous install's policy.
  pushInstall(ctx);
  let patch;
  try {
    patch = loadPatch.install(ctx);
  } catch (err) {
    // The loader refused the patch outright. Unwind the activation rather than leaving an
    // install on the stack that no handle can ever pop.
    popInstall(ctx);
    throw err;
  }

  let uninstalled = false;
  return {
    uninstall() {
      if (uninstalled) return; // idempotent
      uninstalled = true;
      // Deactivate the policy FIRST, before the `_load` relink: a shim some module captured
      // reads the live context on every call, so this — not the loader unpatching — is what
      // stops the torn-down install's grants (and its `onDecision` sink) from being used.
      // Popping first also means the two are never observed out of order.
      popInstall(ctx);
      patch.uninstall();
    },
  };
}

const MEDIATED_CANDIDATES: ReadonlySet<string> = new Set(MEDIATED_MODULES);
