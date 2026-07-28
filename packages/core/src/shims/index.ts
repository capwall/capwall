/**
 * Shim registry assembly. `buildShimRegistry(ctx)` returns a `specifier → module object`
 * map the CJS loader consumes: requiring a registered specifier hands back the shim.
 *
 * Adding a capability shim is two lines: import its `register*Shim` and call it here. Each
 * shim owns which specifiers it claims; the loader stays generic. The shim itself must take its
 * REAL module from `../real-builtins.cjs` and never from a static `import … from "node:x"` — see
 * that file for why (#78); `test/real-builtins.test.ts` fails the build otherwise. Every specifier in
 * `loader/require.ts` MEDIATED_MODULES is currently claimed by a shim registered below —
 * keep it that way, since a mediated-but-unregistered specifier passes through un-shimmed
 * (silently, with no log line).
 *
 * Note that `registerNetShim` claims SIX specifiers (net, http, https, tls, http2, dgram),
 * not one. That is deliberate and load-bearing: Node's HTTP client reaches `net` through the
 * internal bootstrap loader, which never hits `Module._load`, so shimming `net` does not
 * cover `http` — and a dependency could otherwise pick `tls` or `dgram` to sidestep a
 * net-only shim. A new egress surface needs its own registration. See docs/threat-model.md.
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
