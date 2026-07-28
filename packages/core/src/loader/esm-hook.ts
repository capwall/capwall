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
 * THE THIRD WINDOW (#182), and the fact capwall can still state about it.
 *
 * `deregister()` is #152's headline and it creates a gap the `--import` preload cannot close,
 * because the gap is after startup. Between the last `uninstall()` and the next `install()` there
 * are no hooks: a mediated builtin ESM-imported in that window resolves to its raw `node:` URL and
 * Node caches it there **permanently** — the ESM registry is per-process and keyed by URL. A
 * cached URL is served from cache without the load chain being consulted, so the `load`-level
 * re-mediation backstop (#78) is dead for that specifier for the rest of the process.
 *
 * WHAT IS AND IS NOT LOST. Mediation itself is unaffected: a mediated import under the new install
 * resolves to a `capwall-esm:` URL, which is a different registry key from the raw one the gap
 * import cached — `test/esm.test.ts` § #62 asserts exactly that. What is lost is the SECOND layer:
 * the backstop is capwall's only in-band signal that something else is ahead of it in the hook
 * chain, and it is what still holds when a hook registered before capwall (or by the application,
 * which is the trust root and may) short-circuits `resolve` to the raw builtin. #181 shrank the
 * attacker set here considerably — a dependency can no longer register a hook by any route — so
 * what remains needs a hook the application or the host process put there.
 *
 * WHY A WARNING AND NOT A FIX. Three fixes were considered and each costs more than it buys:
 *  - **Enumerate the affected specifiers.** There is no API to ask whether a URL is resident in
 *    the ESM registry, and probing by importing it would CAUSE the caching it is testing for.
 *    `process.moduleLoadList` is not it: it records native module compilation, fires for `require`
 *    as well as `import`, and capwall's own bootstrap requires every mediated builtin at startup,
 *    so it says "yes" for all of them in every process (measured on 22/24/26).
 *  - **Keep a dormant hook registered through the gap**, resolving mediated builtins to a
 *    pass-through synthetic URL so the raw one never enters the cache. This works, and it means
 *    capwall never really leaves: after `uninstall()` its hook is still in the chain and
 *    `import.meta.resolve("fs")` answers a capwall URL in a process that believes capwall is gone.
 *    That is the #183 class of deviation, introduced in the one state where capwall claims to have
 *    no effect, to close an embedder-only window.
 *  - **Refuse to serve a cached raw builtin** (`install({ esmStrict: true })`). Cannot be done —
 *    the cache is consulted before any hook.
 *
 * So: say it, once, loudly, at the moment the fact becomes true. Same class of statement as
 * `CAPWALL_ENV=0`'s — a control that is off while the process still looks guarded.
 */
let anEraHasEnded = false;
let gapWarned = false;

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
    // A REGISTRATION FOLLOWING A DEREGISTRATION — see {@link anEraHasEnded}. Warned here rather
    // than at `uninstall()`, because at uninstall time nothing has gone wrong yet: the gap only
    // costs something if it is ever closed, and an embedder that uninstalls and stays uninstalled
    // has simply removed capwall. Once per process: a policy swapper does this on a loop.
    if (anEraHasEnded && !gapWarned) {
      gapWarned = true;
      process.stderr.write(
        `[capwall] WARN capwall was uninstalled and re-installed. Any mediated builtin ` +
          `ESM-imported during that gap is cached in Node's ESM registry as the RAW builtin, and ` +
          `a cached URL is served without the load chain being consulted — so the load-level ` +
          `re-mediation backstop is inert for it for the rest of the process. capwall was not in ` +
          `the hook chain during the gap and cannot name which specifiers those are. Mediation ` +
          `itself is unaffected; the second layer behind a hijacked resolve hook is not (see ` +
          `docs/threat-model.md § ESM known limits)\n`,
      );
    }
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
        // Recorded only on a deregistration that actually happened — the gap is real from here
        // until the next `install()`, and #182 is what happens in it.
        anEraHasEnded = true;
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
