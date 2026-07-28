/**
 * ESM loader interception (roadmap M5) — registration, on the MAIN thread.
 *
 * Registers `esm-hooks.ts` as a module customization hook via `module.register()` (Node
 * ≥20.6). That hook (on the loader thread) rewrites mediated builtin specifiers to a synthetic
 * `capwall-esm:` module whose source re-exports capwall's shims from `esm-runtime.ts` — which
 * runs on THIS thread, so attribution and `onDecision` behave exactly as on the CJS path.
 *
 * Static AND dynamic imports are covered: the hook intercepts the module graph before
 * evaluation, so `import { readFile } from 'node:fs'` binds to the shim's `readFile` from the
 * start — there is no post-hoc binding swap, so the "ESM bindings are immutable" problem the
 * scaffold warned about does not arise. Known limits (see docs/threat-model.md): a module that
 * captured a raw builtin before capwall installed is not re-bound; unregistering an ESM hook
 * is best-effort (Node cannot fully remove a registered hook).
 */
// `node:module` is itself mediated, so capwall reaches `register()` through the CJS capture in
// `real-builtins.cjs` rather than a static ESM import. An `import { register } from "node:module"`
// here would put `node:module` in the ESM module cache moments before this very function
// registers the hook — and a URL already in that cache never consults the load chain, which is
// precisely what left the hook's re-mediation backstop dead (#78). `node:url`/`node:path` are not
// mediated and stay ordinary imports.
// `node:worker_threads` is mediated too, so `MessageChannel` comes out of the same CJS capture as
// `register` — a static ESM import of it here would cache that specifier raw and leave the #78
// backstop dead for it, which `test/real-builtins.test.ts`'s source scan exists to catch.
import { realModule, realWorkerThreads } from "../real-builtins.cjs";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as path from "node:path";
import { pushEsmContext, popEsmContext, esmExportNames } from "./esm-runtime.js";
import { liveCtx, onLiveContextChange } from "./live-context.js";
import type { EsmGateSnapshot } from "./module-read.js";
import type { ShimContext } from "../shims/runtime.js";
import type { Decision } from "../policy/evaluate.js";

export interface EsmHookHandle {
  /** Best-effort teardown; ESM hooks cannot be fully unregistered (Node limitation). */
  uninstall(): void;
}

/** module.register is one-shot per process for our hook; track it so a second install is a no-op. */
let hookRegistered = false;

/**
 * THE MODULE-READ GATE'S CHANNEL to the loader thread (issue #123), created once with the hook.
 *
 * WHY THE HOOK NEEDS A CHANNEL AT ALL. The `resolve` hook decides whether a dependency may
 * `import()` a file outside the dependency graph, and it runs on Node's separate loader thread —
 * which holds no capwall state and cannot synchronously ask this one, because the main thread
 * BLOCKS on hook results during synchronous module resolution and any round trip would deadlock.
 * So the policy is COPIED to that thread and re-copied whenever it changes. See
 * `loader/esm-hooks.ts` for the drain-on-every-invocation discipline that makes the copy
 * race-free, and `loader/module-read.ts` for the decision itself.
 *
 * Main → loader carries {@link EsmGateSnapshot}s. Loader → main carries decisions to record, which
 * is why this end has a listener at all: a denial is ENFORCED on the loader thread (it throws
 * there), but it still has to reach `onDecision` so `observe`, the trace file and `capwall diff`
 * see it.
 *
 * The subscription is never cancelled, deliberately: the hook it feeds cannot be unregistered
 * either (a Node limitation this module already documents), so a live subscription and a live
 * hook have exactly the same lifetime. Cancelling it would freeze the loader thread's copy at
 * whatever policy was in force when the last install went away — the stale-policy failure #62/#87
 * exist to prevent — instead of telling it that capwall is no longer installed.
 */

/** Build the snapshot the loader thread evaluates against, from the live context. */
function snapshotFor(ctx: ShimContext, installed: boolean): EsmGateSnapshot {
  return {
    installed,
    policy: ctx.policy,
    mode: ctx.mode,
    projectRoot: ctx.projectRoot,
  };
}

export function registerEsmHook(ctx: ShimContext): EsmHookHandle {
  // Make the shims resolvable on this (main) thread for the synthetic modules to import. This
  // pushes onto an install STACK whose top drives a long-lived context box, so a later
  // install's policy reaches specifiers that were already imported under an earlier one (#62)
  // — see esm-runtime.ts for why the mutability lives there rather than in the generated
  // source.
  pushEsmContext(ctx);

  if (!hookRegistered) {
    // Enumerate each mediated specifier's export names on the main thread (the loader thread
    // must not import them — that would recurse through `resolve` and loop). See
    // `esmExportNames`. Only on the FIRST install, since that is the only one whose payload is
    // ever shipped; a later install cannot change the set anyway (the registry is memoized).
    const exportsBySpecifier = esmExportNames();
    const here = path.dirname(fileURLToPath(import.meta.url));
    const hooksUrl = pathToFileURL(path.join(here, "esm-hooks.js")).href;
    const bridgeUrl = pathToFileURL(path.join(here, "esm-runtime.js")).href;

    // The module-read gate's channel (#123). `unref`ed so an idle port never holds the process
    // open — capwall must not change when a host app exits.
    const { port1, port2 } = new realWorkerThreads.MessageChannel();
    port1.on("message", (outcome: { pkg: string; decision: Decision }) => {
      // Report through the LIVE context, not the registering install's: a decision arriving one
      // event-loop turn later must land in whichever install is in force now, exactly as a
      // captured shim's decision would (#87).
      liveCtx.onDecision(outcome.pkg, outcome.decision);
    });
    port1.unref();
    // Push every subsequent policy change to the loader thread's copy. Subscribing invokes the
    // listener immediately with the current state, which is also what posts the snapshot that
    // covers the window between `register()` and the first import.
    onLiveContextChange((live, installed) => {
      try {
        port1.postMessage(snapshotFor(live, installed));
      } catch {
        // The channel is gone (a torn-down loader thread). The gate then keeps its last
        // snapshot, and the CJS half — which is a real patch and really is removed by
        // `uninstall()` — is unaffected.
      }
    });

    // The REAL `register`, never the `node:module` shim — capwall's own hook registration must
    // not be attributed and gated by #61's own gate.
    realModule.register(hooksUrl, {
      parentURL: import.meta.url,
      data: {
        bridgeUrl,
        exports: exportsBySpecifier,
        gatePort: port2,
        gateSnapshot: snapshotFor(liveCtx, true),
      },
      transferList: [port2],
    });
    hookRegistered = true;
  }

  return {
    uninstall() {
      // Best-effort: the hook stays registered. Removing this install re-points the live
      // context at whatever install is still active, or — if this was the last one — at a
      // deny-all enforce policy. Either way it is fail-closed and visible, never a silent
      // return to the raw builtin: a not-yet-imported specifier gets getEsmShim()'s explicit
      // "capwall is no longer installed" error, and a specifier some module already imported
      // gets a CapabilityError from the shim it captured (#62 — that second case previously
      // kept serving the torn-down install's grants).
      popEsmContext(ctx);
    },
  };
}
