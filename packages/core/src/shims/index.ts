/**
 * Shim registry assembly. `buildShimRegistry(ctx)` returns a `specifier → module object`
 * map the CJS loader consumes: requiring a registered specifier hands back the shim.
 *
 * Adding a capability shim (roadmap M4) is two lines: import its `register*Shim` and call it
 * here. Each shim owns which specifiers it claims; the loader stays generic. Non-registered
 * mediated specifiers (see `loader/require.ts` MEDIATED_MODULES) simply pass through
 * un-shimmed until their shim lands.
 */
import { registerFsShim } from "./fs.js";
import type { ShimContext, ShimRegistry } from "./runtime.js";

export function buildShimRegistry(ctx: ShimContext): ShimRegistry {
  const reg: ShimRegistry = new Map();
  registerFsShim(reg, ctx);
  // M4 shims register here as they land: registerNetShim, registerChildProcessShim,
  // registerWorkerThreadsShim, registerVmShim.
  return reg;
}

export type { ShimContext, ShimRegistry, DecisionSink } from "./runtime.js";
