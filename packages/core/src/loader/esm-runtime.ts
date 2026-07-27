/**
 * ESM runtime bridge (roadmap M5). The MAIN-THREAD half of the ESM interception.
 *
 * Node's module customization hooks (`resolve`/`load`, in `esm-hooks.ts`) run on a separate
 * loader thread and cannot touch the installed policy, attribution, or the `onDecision` sink
 * (all main-thread state). The trick capwall uses: the `load` hook returns synthetic module
 * SOURCE that re-exports capwall's shim members, and that source is EVALUATED on the main
 * thread — where it calls {@link getEsmShim} to obtain a shim built from the SAME
 * {@link ShimContext} the CJS path uses (`live-context.ts`'s `liveCtx`). So attribution (a
 * main-thread stack walk) and decision logging behave identically to CJS. NOTE: this is a
 * SEPARATE shim registry from the CJS loader's — `buildShimRegistry` makes fresh shim objects —
 * so enforcement is identical (both read the same live context) but a monkey-patch a dependency
 * makes on the CJS `fs` shim is not visible on the ESM one and vice versa. The loader thread only
 * rewrites specifiers, it never sees policy.
 *
 * WHY THE CONTEXT IS A MUTABLE BOX AND THE REGISTRY IS BUILT EXACTLY ONCE (issue #62). A
 * synthetic module runs `getEsmShim(spec)` once, at evaluation, and captures the result in `const`
 * export bindings; ESM module caching is per-process and permanent, so that capture can never be
 * revisited. Rebuilding the registry on each `install()` therefore only affected specifiers not
 * yet imported: an already-imported `node:fs` kept the shim — and with it the policy and mode —
 * from the FIRST install, forever. That reasoning, the live-context box and the install stack now
 * live in `live-context.ts`, shared with the CJS path, which had the identical bug (#87). This
 * module is just the ESM-specific surface on top of them.
 */
import { isInstalled, liveRegistry, popInstall, pushInstall } from "./live-context.js";
import type { ShimContext } from "../shims/runtime.js";

/**
 * Activate `ctx` for the ESM path. Called by `install()` via `registerEsmHook`; the newest
 * install wins, exactly as the newest `_load` patch does on the CJS side.
 */
export function pushEsmContext(ctx: ShimContext): void {
  pushInstall(ctx);
  // Force the ESM registry into existence while an install is active, because
  // `registerEsmHook` needs its keys (below) to tell the loader thread which specifiers to
  // mediate — and to build the shims with this install's hardened-ness.
  liveRegistry("esm");
}

/**
 * Deactivate a specific install. Removing one that is not on top relinks to whatever remains
 * active; removing the last one puts the process into the fail-closed torn-down state.
 * Idempotent — a second call for the same context is a no-op.
 */
export function popEsmContext(ctx: ShimContext): void {
  popInstall(ctx);
}

/** The specifiers that have shims (registry keys) — the set the ESM resolve hook mediates. */
export function esmSpecifiers(): string[] {
  return [...liveRegistry("esm").keys()];
}

/**
 * Return the shim object a mediated ESM specifier should resolve to (called on the main
 * thread by the synthetic modules the load hook generates). For `node:fs`/`fs` this is the fs
 * shim; for `node:fs/promises` it is the promises surface; etc. Throws if capwall was torn
 * down between registration and evaluation (a fail-closed, visible error, not a silent bypass).
 */
export function getEsmShim(specifier: string): unknown {
  if (!isInstalled()) {
    throw new Error(
      `capwall: ESM module '${specifier}' was mediated but capwall is no longer installed`,
    );
  }
  const shim = liveRegistry("esm").get(specifier);
  if (shim === undefined) {
    throw new Error(`capwall: no ESM shim registered for '${specifier}'`);
  }
  return shim;
}
