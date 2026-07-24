/**
 * ESM runtime bridge (roadmap M5). The MAIN-THREAD half of the ESM interception.
 *
 * Node's module customization hooks (`resolve`/`load`, in `esm-hooks.ts`) run on a separate
 * loader thread and cannot touch the installed policy, attribution, or the `onDecision` sink
 * (all main-thread state). The trick capwall uses: the `load` hook returns synthetic module
 * SOURCE that re-exports capwall's shim members, and that source is EVALUATED on the main
 * thread — where it calls {@link getEsmShim} to grab the very same shim instance the CJS path
 * uses. So attribution (a main-thread stack walk) and decision logging work identically to
 * CJS; the loader thread only rewrites specifiers, it never sees policy.
 */
import { buildShimRegistry } from "../shims/index.js";
import type { ShimContext, ShimRegistry } from "../shims/runtime.js";

/** The active install's shim registry, or null when capwall is not installed with ESM on. */
let registry: ShimRegistry | null = null;

/** install() sets this so the synthetic ESM modules can resolve the same shims as CJS. */
export function setEsmContext(ctx: ShimContext | null): void {
  registry = ctx ? buildShimRegistry(ctx) : null;
}

/** The specifiers that have shims (registry keys) — the set the ESM resolve hook mediates. */
export function esmSpecifiers(): string[] {
  return registry ? [...registry.keys()] : [];
}

/**
 * Return the shim object a mediated ESM specifier should resolve to (called on the main
 * thread by the synthetic modules the load hook generates). For `node:fs`/`fs` this is the fs
 * shim; for `node:fs/promises` it is the promises surface; etc. Throws if capwall was torn
 * down between registration and evaluation (a fail-closed, visible error, not a silent bypass).
 */
export function getEsmShim(specifier: string): unknown {
  if (registry === null) {
    throw new Error(
      `capwall: ESM module '${specifier}' was mediated but capwall is no longer installed`,
    );
  }
  const shim = registry.get(specifier);
  if (shim === undefined) {
    throw new Error(`capwall: no ESM shim registered for '${specifier}'`);
  }
  return shim;
}
