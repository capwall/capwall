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

/**
 * specifier → the named exports its synthetic module must declare, for every specifier the ESM
 * path mediates. This is the whole payload `registerEsmHook` ships to the loader thread: the
 * thread cannot import a mediated builtin itself (that would recurse through `resolve` and loop),
 * so the export names have to be enumerated here, on the main thread.
 *
 * Enumerated from the ESM SHIMS — the very objects `getEsmShim` will hand the synthetic modules —
 * rather than from the real builtins. The two key sets are the same (the shims copy every own
 * key), but taking them from the shim is what guarantees no generated `export const x = shim.x`
 * can name something the shim does not have. Before #78 this read the shims back through a
 * `createRequire()` of each specifier, which worked only because `Module._load` was already
 * patched by the time it ran; going straight to the registry drops that indirection along with
 * the `node:module` import it needed (see `real-builtins.cts`).
 */
export function esmExportNames(): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const [specifier, shim] of liveRegistry("esm")) {
    // `typeof shim === "function"` is NOT a defensive extra: `node:module`'s shim is a Proxy over
    // the `Module` CLASS, so an object-only test silently yields zero export names for it and the
    // synthetic module ends up with nothing but a default — which is `module.register` vanishing
    // from the ESM namespace, i.e. #61's gate disappearing rather than failing loudly.
    const enumerable = typeof shim === "object" || typeof shim === "function";
    out[specifier] = enumerable && shim !== null ? Object.keys(shim as object) : [];
  }
  return out;
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
