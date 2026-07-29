/**
 * CJS loader interception (the PRIMARY, first-implemented interception path).
 *
 * TWO PATCHES, TWO QUESTIONS, TWO DIFFERENT LIFECYCLES — do not merge them.
 *
 *  1. **`Module._load`** ({@link loadPatch}) — *which SPECIFIER is this?* Routes a mediated
 *     builtin name to its shim. Its subject genuinely is the argument list, and it STACKS,
 *     because two installs may route to different registries.
 *  2. **`Module.prototype.load`** ({@link moduleReadGatePatch}) — *which FILE is this?* The
 *     module-read gate (#123). Its subject is the filename NODE resolved, which is why it cannot
 *     live in (1): everything (1) could say about the file a load will open it would have to
 *     reconstruct from arguments the caller supplies, and #177/#178 are what that cost. It is a
 *     SINGLE reference-counted patch, because it evaluates a policy and two links would decide
 *     one load twice.
 *
 * Approach for (1): patch `Module._load` so that when any module requires a capability-sensitive
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
import { realModule } from "../real-builtins.cjs"; // never `import … from "node:module"` — see #78
import { liveRegistry, popInstall, pushInstall } from "./live-context.js";
import { defineRelinkedPatch, definePropertyPatch, valueSlot } from "../lifecycle/process-patch.js";
import { guardCjsModuleRead } from "./module-read.js";
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
  // Not a capability surface, and NOT where #61's loader-hook gate lives — since #181 that gate
  // is a patch on `Module.register` / `Module.registerHooks` themselves, installed eagerly by
  // `install()` because `module.constructor` reaches those functions with no require at all.
  // `node:module` stays mediated for one structural rule the shim keeps as defense in depth: no
  // own key may hand back an un-shimmed route to the shimmed surface, so a value that IS the
  // module object comes back as the proxy. Everything else (`createRequire`, `builtinModules`,
  // the `_` internals, …) passes straight through; see shims/module.ts.
  "module",
  "node:module",
] as const;

export interface RequirePatchHandle {
  /** Restore the original loader (used by tests and teardown). */
  uninstall(): void;
}

/**
 * `Module._load`'s shape — VARIADIC, for the reason #128 gives about `Module.prototype._compile`.
 *
 * This site had the same latent defect and was found by the sweep that fix asked for. It used to
 * be `(request, parent, isMain)`, which matches `Module._load.length` — but `.length` stops at the
 * first defaulted parameter, and it is not the count Node passes.
 *
 * DO NOT RE-STATE AN ARITY HERE, and the reason is no longer hypothetical: this one has
 * OSCILLATED, within majors as well as across them. Read off the live function on each binary:
 *
 *   | Node    | declared signature                                       | args passed |
 *   |---------|----------------------------------------------------------|-------------|
 *   | 20.19.4 | `(request, parent, isMain)`                               | 3           |
 *   | 22.23.1 | `(request, parent, isMain, options = kEmptyObject)`       | 4           |
 *   | 23.9.0  | `(request, parent, isMain)`                              | 3           |
 *   | 24.5.0  | `(request, parent, isMain)`                              | 3           |
 *   | 24.18.0 | `(request, parent, isMain, internalOptions = kEmptyObject)` | 4        |
 *   | 26.5.0  | `(request, parent, isMain, internalOptions = kEmptyObject)` | 4        |
 *
 * So a fourth parameter appeared in 22, vanished for 23 and early 24, and came back in a 24
 * MINOR under a different name and a different payload — `shouldSkipModuleHooks` alone on 22,
 * `{ requireResolveOptions, shouldSkipModuleHooks }` on 24.18+. A wrapper pinned to any one of
 * those rows would have been wrong on at least two of the others, silently. Forward verbatim.
 */
type ModuleLoad = (this: unknown, ...args: unknown[]) => unknown;

/**
 * `Module.prototype.load(filename)` — VARIADIC for the reason {@link ModuleLoad} is (#128).
 *
 * Node's declared signature has been `(filename)` on 20/22/23/24/26 and the gate reads `args[0]`
 * POSITIONALLY, forwarding the list verbatim, so a Node that adds a parameter changes what is
 * forwarded without changing what is gated. A non-string first argument is treated as "nothing to
 * decide" by {@link guardCjsModuleRead}'s `path.isAbsolute` test, which is fail-closed only in the
 * sense that it matches what Node itself would then fail on.
 */
type ModuleProtoLoad = (this: unknown, ...args: unknown[]) => unknown;

/**
 * The CJS loader patch, as a shared relink chain (`lifecycle/process-patch.ts`).
 *
 * `link.next` is read at CALL time, never captured in a `const` at install time — that is what
 * lets an out-of-LIFO-order `uninstall()` relink around a removed middle layer instead of only
 * ever restoring the bottom of the stack (#22).
 */
const loadPatch = defineRelinkedPatch<ModuleLoad>("Module._load", {
  slot: valueSlot<ModuleLoad>("Module._load", () => realModule as unknown as object, "_load"),
  patch: (ctx, link) =>
    function (this: unknown, ...args: unknown[]) {
      // Fast path: only the fixed candidate set can possibly be shimmed; everything else is a
      // plain delegate with no registry work. The registry itself is built on the first mediated
      // require, so a process that never touches one never constructs a shim (and so never
      // captures a real builtin).
      const request = args[0];
      if (typeof request === "string" && (MEDIATED_CANDIDATES as Set<string>).has(request)) {
        const reg = liveRegistry("cjs");
        if (reg.has(request)) return reg.get(request);
      }
      // THE MODULE-READ GATE (#123) IS NOT HERE ANY MORE — it is on {@link moduleReadGatePatch}
      // below, at `Module.prototype.load`. Everything this wrapper could say about the file a
      // load will open it had to RECONSTRUCT from `args`, and `args` is the caller's, which is
      // #177 (`isMain`) and #178 (the options bag) in one sentence. `Module._load` keeps the one
      // job whose subject really is the argument list: routing a mediated builtin SPECIFIER to
      // its shim.
      return Reflect.apply(link.next, this, args);
    },
});

/**
 * THE MODULE-READ GATE (#123), at the point Node commits to a filename.
 *
 * `Module.prototype.load(filename)` is called by `Module._load` once resolution has produced a
 * concrete path, and it is what picks the extension handler that opens the file. So `filename` is
 * NODE'S OWN resolution result. That is the whole of the fix for #177 and #178: there is no second
 * resolution to steer, no options bag to classify, and no `isMain` to believe. See
 * `loader/module-read.ts` § WHICH OF THE GATES DECIDES A GIVEN LOAD for the routes this was
 * measured against on 22.22.3 / 24.18.0 / 26.5.0, including `new Module(f).load(f)`, which never
 * reaches `Module._load` and was therefore un-gated before this.
 *
 * A SINGLE PATCH, REFERENCE-COUNTED (`definePropertyPatch`), where `Module._load` above STACKS.
 * The difference is the subject. `Module._load`'s patch routes to a per-install shim REGISTRY, so
 * two installs must both run; this gate evaluates a policy, and every guard has read the policy
 * out of {@link liveCtx} since #87 — one box whose fields the install stack re-points. Stacking it
 * would take two decisions for one load under a nested install: two `DENY` lines, two trace
 * entries, two grants out of `observe`, which is exactly the duplication #152 had to design
 * against on the ESM side.
 *
 * A Node with no `Module.prototype.load` is treated as "nothing to gate" rather than crashing the
 * host process on install — the slot reads `undefined` and `definePropertyPatch` declines. That is
 * the same contract the `_compile` gate keeps, and it is load-bearing for a preload: a capability
 * firewall that will not let the application start has failed worse than one that under-gates.
 */
const moduleReadGatePatch = definePropertyPatch<ModuleProtoLoad>("Module.prototype.load", {
  slot: valueSlot<ModuleProtoLoad>(
    "Module.prototype.load",
    () => (realModule as unknown as { prototype?: object }).prototype,
    "load",
  ),
  build(ctx, realLoad) {
    const patched: ModuleProtoLoad = function (this: unknown, ...args: unknown[]): unknown {
      // Throws on an enforce-mode denial, BEFORE the extension handler opens the file. Node
      // deletes the half-built module from `Module._cache` and re-throws to the requiring code,
      // which is the same shape a `MODULE_NOT_FOUND` already has.
      const filename = args[0];
      if (typeof filename === "string") guardCjsModuleRead(ctx, filename);
      return Reflect.apply(realLoad, this, args);
    };
    // Keep `.name`/`.length` faithful: `require.extensions` tooling and bundlers feature-detect on
    // this prototype, and a wrapper that renamed the method would be a gratuitous change.
    Object.defineProperty(patched, "name", { value: "load", configurable: true });
    Object.defineProperty(patched, "length", { value: realLoad.length, configurable: true });
    return patched;
  },
});

export interface ModuleReadGateHandle {
  uninstall(): void;
}

/**
 * Install the module-read gate. Hand it {@link liveCtx}, never a per-install context — see the
 * note on {@link moduleReadGatePatch} and `shims/module.ts` § `installCompileGate`, which has the
 * identical contract for the identical reason.
 */
export function installModuleReadGate(ctx: ShimContext): ModuleReadGateHandle {
  return moduleReadGatePatch.install(ctx);
}

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
