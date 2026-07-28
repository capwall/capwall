/**
 * ESM/CJS loader-hook REGISTRATION (roadmap M5) — the lifecycle half of module interception.
 *
 * Registers `esm-hooks.ts`'s synchronous `resolve`/`load` pair via `module.registerHooks()`
 * (Node ≥22.15, which is the supported floor). Those hooks rewrite mediated builtin specifiers to
 * a synthetic `capwall-esm:` module whose source re-exports capwall's shims from
 * `esm-runtime.ts` — all in THIS realm, so attribution and `onDecision` behave exactly as on the
 * CJS path.
 *
 * Static AND dynamic imports are covered: the hook intercepts the module graph before
 * evaluation, so `import { readFile } from 'node:fs'` binds to the shim's `readFile` from the
 * start — there is no post-hoc binding swap, so the "ESM bindings are immutable" problem the
 * scaffold warned about does not arise. Known limits (see docs/threat-model.md): a module that
 * captured a raw builtin before capwall installed is not re-bound.
 *
 * ── WHY `registerHooks()` AND NOT `module.register()` (#152, #153) ──────────────────────────
 * `module.register()` is **Stability 0 and runtime-deprecated as DEP0205 since Node 26.0.0**,
 * removal announced. It warned on stderr on every mediated run and, under `--throw-deprecation`,
 * made `install()` throw so the host application never started. Node names `registerHooks()` as
 * the replacement; it is documented rather than dying, it needs no loader thread, and it brings
 * a real {@link EsmHookHandle.uninstall}-able registration — see below.
 *
 * ── THE THREE THINGS THAT CHANGED HERE, ALL OF THEM SIMPLIFICATIONS ─────────────────────────
 *  1. **No channel.** The module-read gate (#123) used to run on Node's loader thread, which
 *     holds no capwall state, so the policy was COPIED to it over a `MessagePort` and re-copied
 *     on every change. The hooks now run in this realm and read `liveCtx` directly. The
 *     `MessageChannel`, the `onLiveContextChange` subscription, the `EsmGateSnapshot` posts and
 *     the decision-return path are all deleted, not ported. (`onLiveContextChange` ITSELF is
 *     still there and this was its only caller — `live-context.ts`'s header says why it was kept
 *     and where it is now tested.)
 *  2. **No `data` payload.** `bridgeUrl` and the export-name map used to cross a thread boundary
 *     as `register()`'s `data`; they are now an ordinary function call into the hook module.
 *  3. **A real teardown.** `module.registerHooks()` returns a handle with `deregister()`, where
 *     `module.register()`'s teardown was best-effort by Node's own admission — the limitation
 *     this file used to document. See {@link registerEsmHook}'s handle.
 *
 * `node:module` is itself mediated, so capwall reaches `registerHooks()` through the CJS capture
 * in `real-builtins.cjs` rather than a static ESM import. An `import { registerHooks } from
 * "node:module"` here would put `node:module` in the ESM module cache moments before this very
 * function registers the hook — and a URL already in that cache never consults the load chain,
 * which is precisely what left the hook's re-mediation backstop dead (#78). `node:url`/`node:path`
 * are not mediated and stay ordinary imports.
 */
import { realModule } from "../real-builtins.cjs";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as path from "node:path";
import { initialize, load, resolve } from "./esm-hooks.js";
import { pushEsmContext, popEsmContext, esmExportNames } from "./esm-runtime.js";
import type { ShimContext } from "../shims/runtime.js";

export interface EsmHookHandle {
  /** Release one activation; the last one DEREGISTERS the hooks. Idempotent, never throws. */
  uninstall(): void;
}

/** What `module.registerHooks()` hands back. Narrowed to the one member capwall uses. */
interface RegisteredHooks {
  deregister(): void;
}

/**
 * The live registration, and how many installs are relying on it.
 *
 * REFERENCE-COUNTED, exactly like every other process-level patch capwall installs
 * (`lifecycle/process-patch.ts` § `defineSharedPatch` — this one is not a SLOT, so it cannot use
 * that helper, but it obeys the same three rules: one registration per process, the count only
 * decides when to undo it, and `uninstall()` is idempotent, order-independent and never throws).
 *
 * This replaces the old one-shot `hookRegistered` boolean, which existed because
 * `module.register()` could not be undone: once true it stayed true for the life of the process,
 * a later `install()` re-used a registration whose data payload belonged to the first one, and
 * `uninstall()` left the hook running. `S7` in `test/composition-matrix.test.ts` names this slot.
 */
let hooks: RegisteredHooks | null = null;
let activations = 0;

/**
 * The PRISTINE `registerHooks`, read at module evaluation (#181).
 *
 * Since #181 the loader-hook gate is a patch on `Module.registerHooks` itself, not a wrapper the
 * `node:module` shim's `get` trap returns — that is what closed the `Module`/`module.constructor`
 * routes. It also means the ordinary property read below WOULD now reach capwall's own gate, and
 * a gate capwall trips on its own hook registration is an attribution question capwall should not
 * have to answer (in a checkout layout its own frames sit under the project root, so the answer
 * would be the application's policy applied to capwall).
 *
 * Reading it here is enough, and provably so, by the argument `real-builtins.cts` makes for its
 * own captures: this module sits in `index.js`'s STATIC import graph, ES module evaluation
 * completes the graph before the entry module's body runs, and the patch is only ever applied
 * from `install()`. There is no ordering in which a patch precedes this line.
 *
 * Destructured rather than written `const x: typeof realModule.registerHooks = …`, because
 * `test/process-patch-sites.test.ts`'s source scan reads that annotation as a WRITE to a
 * process-level location and would refuse the file. The scan is deliberately generous (its own
 * header says over-capturing only makes it stricter); this is what "stricter" costs here.
 */
const { registerHooks: pristineRegisterHooks } = realModule;

export function registerEsmHook(ctx: ShimContext): EsmHookHandle {
  // Make the shims resolvable in this realm for the synthetic modules to import. This pushes
  // onto an install STACK whose top drives a long-lived context box, so a later install's policy
  // reaches specifiers that were already imported under an earlier one (#62) — see
  // esm-runtime.ts for why the mutability lives there rather than in the generated source.
  pushEsmContext(ctx);
  activations += 1;

  if (hooks === null) {
    // Enumerate each mediated specifier's export names BEFORE the hooks go live (the hook must
    // not import a mediated builtin itself — that would recurse through `resolve` and loop), and
    // while an install is active so the registry is built with this install's hardened-ness. See
    // `esmExportNames`. Re-enumerated on a fresh registration rather than cached across one,
    // because a registration that outlived its install is exactly what #62 was about; the
    // registry is memoized underneath, so this is a map rebuild and not a shim rebuild.
    const here = path.dirname(fileURLToPath(import.meta.url));
    initialize({
      bridgeUrl: pathToFileURL(path.join(here, "esm-runtime.js")).href,
      exports: esmExportNames(),
    });
    // The PRISTINE `registerHooks`, never the `node:module` shim and (since #181) never the
    // patched property either — capwall's own hook registration must not be attributed and gated
    // by #61's own gate. See {@link pristineRegisterHooks}.
    hooks = pristineRegisterHooks.call(realModule, { resolve, load }) as RegisteredHooks;
  }

  let uninstalled = false;
  return {
    uninstall() {
      if (uninstalled) return; // idempotent — one call removes one activation, never two
      uninstalled = true;
      // Deactivate the policy FIRST. A synthetic module some dependency already imported holds a
      // shim that reads the live context on every call, so this — not the deregistration — is
      // what stops the torn-down install's grants being served (#62).
      popEsmContext(ctx);
      activations -= 1;
      if (activations > 0 || hooks === null) return;
      const live = hooks;
      hooks = null;
      try {
        // #152: this is the line `module.register()` could not offer. Until it existed, a
        // mediated builtin NOT YET IMPORTED when the last `uninstall()` ran threw "capwall is no
        // longer installed" on re-import — the ESM path was fail-closed where the CJS path was
        // genuinely restored, and docs/threat-model.md had to carry that asymmetry as a known
        // limit. Deregistering makes the two paths agree: a FRESH access after the last
        // `uninstall()` is un-mediated on both, and a stale CAPTURE fails closed on both.
        live.deregister();
      } catch (err) {
        // Never throw from a teardown — `install()` unwinds a list of handles and one failure
        // here would strand the loader patch, the env proxy and the dlopen gate still installed
        // (`lifecycle/process-patch.ts`, bug 3). Report and carry on.
        process.stderr.write(
          `[capwall] WARN could not deregister the module hooks: ` +
            `${err instanceof Error ? err.message : String(err)}\n`,
        );
      }
    },
  };
}
