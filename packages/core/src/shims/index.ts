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
import { registerNetShim } from "./net.js";
import { registerChildProcessShim } from "./child_process.js";
import { registerWorkerThreadsShim } from "./worker_threads.js";
import { registerVmShim } from "./vm.js";
import { registerModuleShim } from "./module.js";
import type { ShimContext, ShimRegistry } from "./runtime.js";

export function buildShimRegistry(ctx: ShimContext): ShimRegistry {
  const reg: ShimRegistry = new Map();
  registerFsShim(reg, ctx);
  registerNetShim(reg, ctx);
  registerChildProcessShim(reg, ctx);
  registerWorkerThreadsShim(reg, ctx);
  registerVmShim(reg, ctx);
  // `node:module` is not a capability in the policy sense — it is mediated so that a
  // dependency cannot register a loader hook AHEAD of capwall's and un-mediate the ESM
  // import path process-wide (#61). See shims/module.ts for the full reasoning.
  registerModuleShim(reg, ctx);
  // Note: the process.env read shim is NOT a require()-routed module — it is installed
  // separately via installEnvGuard() in index.ts install().
  return reg;
}

export type { ShimContext, ShimRegistry, DecisionSink } from "./runtime.js";
