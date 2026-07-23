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

/** Patch the CJS loader to return shimmed builtins for mediated modules. */
export function patchRequire(
  policy: Policy,
  mode: Mode,
  options: RequirePatchOptions,
): RequirePatchHandle {
  const moduleInternals = Module as unknown as ModuleInternals;

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

  // `node` here is the mutable chain link this install owns; `patchedLoad` always delegates
  // via `node.next` (read at CALL time), never a captured constant, so a later relink is
  // visible to any request that arrives after it. `load` is filled in immediately below,
  // before `node` is reachable from anywhere but this closure.
  const node = { next: moduleInternals._load } as ChainNode;
  const patchedLoad: ModuleLoad = function (this: unknown, request, parent, isMain) {
    // Fast path: only the fixed candidate set can possibly be shimmed; everything else is a
    // plain delegate with no registry work.
    if ((MEDIATED_CANDIDATES as Set<string>).has(request)) {
      const reg = getRegistry();
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
