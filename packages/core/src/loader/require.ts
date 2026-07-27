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
 */
import Module from "node:module";
import { liveRegistry, popInstall, pushInstall } from "./live-context.js";
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

type ModuleLoad = (request: string, parent: unknown, isMain: boolean) => unknown;
interface ModuleInternals {
  _load: ModuleLoad;
}

/**
 * One installed patch's link in the `_load` chain (fix #22). `next` is MUTABLE — not a
 * `const` closed over at install time — specifically so an out-of-LIFO-order `uninstall()`
 * can relink around a removed node instead of only ever restoring the bottom of the stack.
 */
interface ChainNode {
  /** This node's patched `_load` function (identity used to detect "am I still active"). */
  load: ModuleLoad;
  /** What this node currently delegates to for non-mediated / unmatched requests. */
  next: ModuleLoad;
}

/**
 * Every currently-installed patch, oldest first. A plain module-level array is enough to
 * relink around an out-of-order removal: the node immediately after the removed one (if any)
 * is exactly the node whose `next` pointed at it, because nodes are appended in install
 * order and only ever delegate to the node most recently installed before them.
 */
const installChain: ChainNode[] = [];

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
  const moduleInternals = Module as unknown as ModuleInternals;

  // Activate this install BEFORE the patch goes live, so a require that lands between the two
  // can never be evaluated against the previous install's policy.
  pushInstall(ctx);

  // `node` here is the mutable chain link this install owns; `patchedLoad` always delegates
  // via `node.next` (read at CALL time), never a captured constant, so a later relink is
  // visible to any request that arrives after it. `load` is filled in immediately below,
  // before `node` is reachable from anywhere but this closure.
  const node = { next: moduleInternals._load } as ChainNode;
  const patchedLoad: ModuleLoad = function (this: unknown, request, parent, isMain) {
    // Fast path: only the fixed candidate set can possibly be shimmed; everything else is a
    // plain delegate with no registry work. The registry itself is built on the first mediated
    // require, so a process that never touches one never constructs a shim (and so never
    // captures a real builtin).
    if ((MEDIATED_CANDIDATES as Set<string>).has(request)) {
      const reg = liveRegistry("cjs");
      if (reg.has(request)) return reg.get(request);
    }
    return node.next.call(this, request, parent, isMain);
  };
  node.load = patchedLoad;
  installChain.push(node);
  moduleInternals._load = patchedLoad;

  let uninstalled = false;
  return {
    uninstall() {
      if (uninstalled) return; // idempotent
      uninstalled = true;
      // Deactivate the policy even if the `_load` relink below bails out: a shim some module
      // captured reads the live context on every call, so this — not the loader unpatching —
      // is what stops the torn-down install's grants (and its `onDecision` sink) from being
      // used. Popping first also means the two are never observed out of order.
      popInstall(ctx);
      const idx = installChain.indexOf(node);
      if (idx === -1) return; // already removed (shouldn't happen given the guard above)
      installChain.splice(idx, 1);
      // Whatever remains at `idx` after the splice is the node installed immediately AFTER
      // this one (if any) — the only node that could have `next === node.load` — so relink
      // it straight to what this node was delegating to, skipping this node entirely. This
      // is what makes out-of-LIFO-order uninstall safe: removing a MIDDLE layer doesn't leak
      // it, because the layer above it is repointed regardless of removal order.
      const nextNewer = installChain[idx];
      if (nextNewer) {
        nextNewer.next = node.next;
      } else if (moduleInternals._load === node.load) {
        // This was the topmost tracked node and nobody outside this module has since
        // repatched `_load` — restore the loader to whatever this node delegated to.
        moduleInternals._load = node.next;
      }
      // else: `_load` was reassigned by something outside this chain after us; that's an
      // external patch we don't own and must not clobber (documented contract: safe only
      // when all installs go through `patchRequire`).
    },
  };
}

const MEDIATED_CANDIDATES: ReadonlySet<string> = new Set(MEDIATED_MODULES);
