/**
 * ESM runtime bridge (roadmap M5). The MAIN-THREAD half of the ESM interception.
 *
 * Node's module customization hooks (`resolve`/`load`, in `esm-hooks.ts`) run on a separate
 * loader thread and cannot touch the installed policy, attribution, or the `onDecision` sink
 * (all main-thread state). The trick capwall uses: the `load` hook returns synthetic module
 * SOURCE that re-exports capwall's shim members, and that source is EVALUATED on the main
 * thread — where it calls {@link getEsmShim} to obtain a shim built from the SAME
 * {@link ShimContext} (policy, mode, onDecision) the CJS path uses. So attribution (a
 * main-thread stack walk) and decision logging behave identically to CJS. NOTE: this is a
 * SEPARATE shim registry from the CJS loader's — `buildShimRegistry` makes fresh shim
 * objects — so enforcement is identical (both share the ShimContext) but a monkey-patch a
 * dependency makes on the CJS `fs` shim is not visible on the ESM one and vice versa. The
 * loader thread only rewrites specifiers, it never sees policy.
 *
 * WHY THE CONTEXT IS A MUTABLE BOX AND THE REGISTRY IS BUILT EXACTLY ONCE (issue #62).
 * A synthetic module runs `getEsmShim(spec)` once, at evaluation, and captures the result in
 * `const` export bindings; ESM module caching is per-process and permanent, so that capture
 * can never be revisited. Rebuilding the registry on each `install()` therefore only affected
 * specifiers not yet imported: an already-imported `node:fs` kept the shim — and with it the
 * policy and mode — from the FIRST install, forever. `uninstall()` followed by
 * `install(tighterPolicy)` was a silent no-op on the ESM path, which is fail-OPEN with
 * respect to the new policy.
 *
 * The fix is to move the mutability one level down instead of wrapping every export in a
 * forwarder. Every shim reads `ctx.policy` / `ctx.mode` / `ctx.onDecision` / `ctx.projectRoot`
 * at CALL time (see `shims/runtime.ts` `guard`), never at build time, so one long-lived
 * context object whose FIELDS are re-pointed on each install/uninstall makes every already-
 * captured shim follow the live policy. Cost per intercepted call: exactly zero — no proxy, no
 * extra indirection, no change to the generated source, and the shims are still plain objects
 * a `graceful-fs`-style monkey-patcher can work with.
 *
 * Installs are tracked as a STACK rather than a single slot, mirroring what `patchRequire`
 * does for the CJS `_load` chain, so an out-of-order `uninstall()` falls back to the install
 * that is still active instead of tearing everything down.
 */
import { buildShimRegistry } from "../shims/index.js";
import type { ShimContext, ShimRegistry } from "../shims/runtime.js";
import type { Policy } from "@capwall/policy-schema";

/**
 * The policy in force when NO install is active. Deny-by-default under `enforce`, so a shim
 * reference an already-evaluated synthetic module captured while capwall WAS installed fails
 * closed after teardown rather than continuing to serve the torn-down install's grants. There
 * is no way to un-bind an ESM import, so "capwall is off again" is not on the menu; refusing
 * is the honest behavior and matches the fail-closed stance the threat model documents for a
 * post-`uninstall()` re-import.
 */
const TORN_DOWN_POLICY: Policy = { version: 1, mode: "enforce", default: {}, packages: {} };

/** Installs in order, oldest first. The last entry is the one whose policy is in force. */
const installs: ShimContext[] = [];

/**
 * The single context object every ESM shim closes over. Its identity never changes; only its
 * fields do. Never hand this object out — a caller holding it could re-point the policy.
 */
const liveCtx: ShimContext = {
  policy: TORN_DOWN_POLICY,
  mode: "enforce",
  onDecision: () => {},
};

/** Built from {@link liveCtx} on the first install and reused forever after (see above). */
let registry: ShimRegistry | null = null;

/** True while at least one install is active; drives {@link getEsmShim}'s fail-closed error. */
let installed = false;

/** Re-point {@link liveCtx} at the newest install, or at the torn-down policy if there is none. */
function applyTopOfStack(): void {
  const top = installs[installs.length - 1];
  if (top === undefined) {
    liveCtx.policy = TORN_DOWN_POLICY;
    liveCtx.mode = "enforce";
    // Drop the sink with the install that owned it: reporting a post-teardown denial into a
    // torn-down embedder's collector (or the CLI's trace file) would be a use-after-free of
    // someone else's state. The denial still throws, which is the visible part.
    liveCtx.onDecision = () => {};
    delete liveCtx.projectRoot;
    delete liveCtx.maxFrames;
    installed = false;
    return;
  }
  liveCtx.policy = top.policy;
  liveCtx.mode = top.mode;
  liveCtx.onDecision = top.onDecision;
  // `exactOptionalPropertyTypes`: an absent optional field must be ABSENT, not `undefined`, or
  // `attributionOptionsFor`'s `!== undefined` checks would pass bogus options to attribution.
  // Every OPTIONAL ShimContext field has to be handled here — a field added to ShimContext and
  // not mirrored below would silently keep the previous install's value (or none at all).
  if (top.projectRoot !== undefined) liveCtx.projectRoot = top.projectRoot;
  else delete liveCtx.projectRoot;
  if (top.maxFrames !== undefined) liveCtx.maxFrames = top.maxFrames;
  else delete liveCtx.maxFrames;
  installed = true;
}

/**
 * Activate `ctx` for the ESM path. Called by `install()` via `registerEsmHook`; the newest
 * install wins, exactly as the newest `_load` patch does on the CJS side.
 */
export function pushEsmContext(ctx: ShimContext): void {
  installs.push(ctx);
  applyTopOfStack();
  // Built once, against the live box — every later install re-points the box's fields, so the
  // shims these modules captured follow the current policy instead of pinning the first one.
  registry ??= buildShimRegistry(liveCtx);
}

/**
 * Deactivate a specific install. Removing one that is not on top relinks to whatever remains
 * active; removing the last one puts the ESM path into the fail-closed torn-down state.
 * Idempotent — a second call for the same context is a no-op.
 */
export function popEsmContext(ctx: ShimContext): void {
  const idx = installs.lastIndexOf(ctx);
  if (idx === -1) return;
  installs.splice(idx, 1);
  applyTopOfStack();
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
  if (!installed) {
    throw new Error(
      `capwall: ESM module '${specifier}' was mediated but capwall is no longer installed`,
    );
  }
  const shim = registry?.get(specifier);
  if (shim === undefined) {
    throw new Error(`capwall: no ESM shim registered for '${specifier}'`);
  }
  return shim;
}
