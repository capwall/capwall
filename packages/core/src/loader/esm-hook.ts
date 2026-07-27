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
import { register } from "node:module";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as path from "node:path";
import { pushEsmContext, popEsmContext, esmSpecifiers } from "./esm-runtime.js";
import type { ShimContext } from "../shims/runtime.js";

export interface EsmHookHandle {
  /** Best-effort teardown; ESM hooks cannot be fully unregistered (Node limitation). */
  uninstall(): void;
}

/** module.register is one-shot per process for our hook; track it so a second install is a no-op. */
let hookRegistered = false;

export function registerEsmHook(ctx: ShimContext): EsmHookHandle {
  // Make the shims resolvable on this (main) thread for the synthetic modules to import. This
  // pushes onto an install STACK whose top drives a long-lived context box, so a later
  // install's policy reaches specifiers that were already imported under an earlier one (#62)
  // — see esm-runtime.ts for why the mutability lives there rather than in the generated
  // source.
  pushEsmContext(ctx);

  // Enumerate each mediated builtin's export names on the main thread (the loader thread must
  // not import them — that would recurse through `resolve` and loop). Shim keys equal the real
  // module's keys (the shims copy every own key), so this yields the right ESM named exports.
  const requireCjs = createRequire(import.meta.url);
  const exportsBySpecifier: Record<string, string[]> = {};
  for (const spec of esmSpecifiers()) {
    try {
      const real = requireCjs(spec) as Record<string, unknown>;
      exportsBySpecifier[spec] = Object.keys(real);
    } catch {
      exportsBySpecifier[spec] = [];
    }
  }

  if (!hookRegistered) {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const hooksUrl = pathToFileURL(path.join(here, "esm-hooks.js")).href;
    const bridgeUrl = pathToFileURL(path.join(here, "esm-runtime.js")).href;
    register(hooksUrl, {
      parentURL: import.meta.url,
      data: { bridgeUrl, exports: exportsBySpecifier },
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
