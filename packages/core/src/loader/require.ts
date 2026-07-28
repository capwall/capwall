/**
 * CJS loader interception (the PRIMARY, first-implemented interception path).
 *
 * Approach: patch `Module._load` so that when any module requires a capability-sensitive
 * core builtin, it receives capwall's SHIMMED version instead of the raw builtin.
 * Non-sensitive requires pass through untouched to keep overhead near zero.
 *
 * Install as early as possible (before any dependency is required) so no package captures a
 * raw, un-shimmed reference first — the CLI does this with a `--import` preload. Note the
 * monkey-patch-robustness caveat in docs/threat-model.md: this is a JS-level patch and a
 * determined attacker can try to reach the original builtin via internal caches /
 * `process.binding`.
 *
 * The specific shims are supplied by `buildShimRegistry` via {@link liveRegistry}; this module
 * just routes a required specifier to its registered shim (built lazily on first mediated
 * require) and passes everything else through. Which specifiers are *candidates* is
 * {@link MEDIATED_MODULES}; which are *actually shimmed* is whatever the registry contains — as
 * of M4 that is fs, net/http(s), child_process, worker_threads, and vm. (process.env is guarded
 * separately, not via require — see shims/env.ts.)
 *
 * LIFECYCLE (issue #87). Each install pushes its context onto the SHARED install stack in
 * `live-context.ts` and pops it on `uninstall()`; the registry is built ONCE against that
 * stack's live context box rather than per install. Before #87 this module built a fresh
 * `ShimContext` object literal per install and never re-pointed the old one, so a module that
 * captured `fs` under a loose policy kept enforcing that loose policy after `uninstall()` AND
 * after `install(tighterPolicy)` — fail-open with respect to the new policy, while a freshly
 * required `fs` correctly denied. See `live-context.ts` for the full reasoning; it is the same
 * defect #62 fixed for ESM.
 *
 * The `_load` RELINK CHAIN (fix #22) now lives in `lifecycle/process-patch.ts` — this file was
 * one of the two sites that got it right by hand, and #107 made that shape the shared one so the
 * next site cannot get it wrong. `_load` STACKS (`defineRelinkedPatch`): two installs may route
 * to different registries, so each one's link must run.
 */
import { realModule } from "../real-builtins.cjs"; // never `import … from "node:module"` — see #78
import { liveRegistry, popInstall, pushInstall } from "./live-context.js";
import { defineRelinkedPatch, valueSlot } from "../lifecycle/process-patch.js";
import { beginGatedCjsLoad, endGatedCjsLoad, guardCjsModuleRead } from "./module-read.js";
import type { ShimContext } from "../shims/runtime.js";

/** Core modules capwall mediates; requiring any of these returns a shim once installed. */
export const MEDIATED_MODULES = [
  "fs",
  "node:fs",
  "fs/promises",
  "node:fs/promises",
  "net",
  "node:net",
  "http",
  "node:http",
  "https",
  "node:https",
  "tls",
  "node:tls",
  "http2",
  "node:http2",
  "dgram",
  "node:dgram",
  "child_process",
  "node:child_process",
  "worker_threads",
  "node:worker_threads",
  "vm",
  "node:vm",
  // Not a capability surface — mediated so a dependency cannot reach `module.register` /
  // `module.registerHooks` and register a loader hook ahead of capwall's, which would
  // un-mediate the ESM import path for the whole process (#61). The shim passes everything
  // else on `node:module` (`createRequire`, `builtinModules`, the `_` internals, …) straight
  // through; see shims/module.ts.
  "module",
  "node:module",
] as const;

export interface RequirePatchHandle {
  /** Restore the original loader (used by tests and teardown). */
  uninstall(): void;
}

/**
 * `Module._load`'s shape — VARIADIC, for the reason #128 gives about `Module.prototype._compile`.
 *
 * This site had the same latent defect and was found by the sweep that fix asked for. It used to
 * be `(request, parent, isMain)`, which matches `Module._load.length` — but `.length` stops at the
 * first defaulted parameter, and it is not the count Node passes.
 *
 * DO NOT RE-STATE AN ARITY HERE, and the reason is no longer hypothetical: this one has
 * OSCILLATED, within majors as well as across them. Read off the live function on each binary:
 *
 *   | Node    | declared signature                                       | args passed |
 *   |---------|----------------------------------------------------------|-------------|
 *   | 20.19.4 | `(request, parent, isMain)`                               | 3           |
 *   | 22.23.1 | `(request, parent, isMain, options = kEmptyObject)`       | 4           |
 *   | 23.9.0  | `(request, parent, isMain)`                              | 3           |
 *   | 24.5.0  | `(request, parent, isMain)`                              | 3           |
 *   | 24.18.0 | `(request, parent, isMain, internalOptions = kEmptyObject)` | 4        |
 *   | 26.5.0  | `(request, parent, isMain, internalOptions = kEmptyObject)` | 4        |
 *
 * So a fourth parameter appeared in 22, vanished for 23 and early 24, and came back in a 24
 * MINOR under a different name and a different payload — `shouldSkipModuleHooks` alone on 22,
 * `{ requireResolveOptions, shouldSkipModuleHooks }` on 24.18+. A wrapper pinned to any one of
 * those rows would have been wrong on at least two of the others, silently. Forward verbatim.
 */
type ModuleLoad = (this: unknown, ...args: unknown[]) => unknown;

/**
 * `Module._resolveFilename`, read LIVE off the real module object — see {@link resolveQuietly}.
 *
 * VARIADIC for the same reason {@link ModuleLoad} is (#128). Its signature has been stable at
 * `(request, parent, isMain, options)` on 20/22/23/24/26 — but the OPTIONS OBJECT IS NOT
 * `Module._load`'s fourth argument, and conflating the two is what {@link resolveOptionsFrom}
 * exists to prevent.
 */
type ResolveFilename = (this: unknown, ...args: unknown[]) => string;

/**
 * The `options` argument Node itself hands `Module._resolveFilename`, derived from
 * `Module._load`'s own argument list.
 *
 * WHY THIS IS NOT JUST `args[3]`. `Module._load`'s fourth argument is an INTERNAL options bag
 * that Node unwraps before resolving; it is not `_resolveFilename`'s `ResolveFilenameOptions`.
 * Read from the live `lib/internal/modules/cjs/loader.js` on each binary:
 *
 *  - **Node 22** — `_load(request, parent, isMain, options)` calls
 *    `resolveForCJSWithHooks(request, parent, isMain, options.shouldSkipModuleHooks)`, whose
 *    default impl calls `Module._resolveFilename(specifier, parent, isMain)` — with NO options
 *    argument at all.
 *  - **Node ≥24.18 / 26** — the fourth argument is `CJSModuleLoadInternalOptions`, and
 *    `resolveForCJSWithHooks` destructures `{ requireResolveOptions, shouldSkipModuleHooks }`
 *    and passes `requireResolveOptions` — that field, not the bag — down to
 *    `Module._resolveFilename`.
 *
 * capwall used to forward `_load`'s whole argument list into `_resolveFilename`, which put the
 * internal bag where `{ paths, conditions }` belongs — and that was NOT merely untidy. Measured on
 * Node 24.18.0 and 26.5.0: `_resolveFilename` found no `paths` in the bag, resolution THREW,
 * {@link resolveQuietly} returned `null`, and the module-read gate (#123) read that as "nothing to
 * decide". A dependency calling
 *
 *   Module._load("./secrets.json", parent, false, { requireResolveOptions: { paths: [dir] } })
 *
 * under a DENY-ALL enforce policy got the file contents and produced ZERO decisions — nothing
 * thrown, nothing on stderr, nothing for `observe` or `capwall diff`. The ordinary three-argument
 * spelling of the identical read was denied and logged, which is precisely what kept it invisible.
 * Node 22 and earlier reject the form outright, so it never appeared on the CI matrix (#154).
 *
 * The durable rule, which is #128's one level up: a DERIVED argument is not a forwarded one.
 * Forwarding `args` verbatim to the primitive you wrapped is always right; forwarding it to a
 * DIFFERENT primitive is a claim that the two take the same arguments, and that claim needs the
 * same treatment as an arity — read it off Node, do not assert it.
 *
 * Anything that is not an object (`undefined` on the 3-argument majors) yields `undefined`,
 * which is what Node passes there too.
 *
 * THE FALLBACK IS NOT A GUESS EITHER. The object is classified by the fields it ACTUALLY has,
 * not by a Node version: a bag carrying `requireResolveOptions` is unwrapped; an object carrying
 * `ResolveFilenameOptions`' own fields (`paths` / `conditions`) IS the options and is passed
 * through; anything else — Node 22's `{ shouldSkipModuleHooks }` — contributes nothing, which is
 * exactly what Node 22 forwards. Given how this parameter has moved (see {@link ModuleLoad}), a
 * Node that hands `_load` the resolve options directly again is a live possibility, and dropping
 * a `paths` on the floor would put the gate back to deciding about a file Node is not opening.
 *
 * EXPORTED FOR TESTS, and that is a coverage decision rather than an API one (#176). The
 * end-to-end rows for this fix have to drive a real `Module._load` with the four-argument form,
 * which only Node ≥24.18 honours — so on **22.15, the declared `engines` floor**, they
 * `it.skipIf` out and `pnpm test` gave the fix zero coverage on the version the repo tells
 * adopters to run. The classification above is a pure function of `args` and is deliberately NOT
 * version-keyed, so it can be asserted on every runtime by calling it directly; that is what
 * `test/module-read.test.ts` § "the classification rule itself" does, and what lets the
 * `module-read-resolve-options-unwrapped` mutant be evidence of something on 22 instead of a
 * false `SURVIVED`. Not re-exported from `src/index.ts` and not on any `exports` path.
 */
export function resolveOptionsFrom(args: unknown[]): unknown {
  const internal = args[3];
  if (typeof internal !== "object" || internal === null) return undefined;
  const bag = internal as { requireResolveOptions?: unknown; paths?: unknown; conditions?: unknown };
  if (bag.requireResolveOptions !== undefined) return bag.requireResolveOptions;
  return bag.paths !== undefined || bag.conditions !== undefined ? internal : undefined;
}

/**
 * What the load described by `args` (`Module._load`'s own argument list) will resolve to, or
 * `null` when it cannot be resolved.
 *
 * WHY RESOLVE AT ALL, rather than classifying the SPECIFIER. Because the specifier is the
 * attacker's grammar and the resolved path is the ground truth — the #120/#84/#95 lesson applied
 * here before it becomes a fourth instance. A bare specifier looks like dependency-graph
 * traversal, but Node's legacy (non-`exports`) subpath resolution accepts `..` inside it; a
 * relative specifier looks like a package's own file, but `../../..` is relative too. Resolving
 * once and asking the resulting PATH which package owns it needs no model of the specifier
 * grammar at all.
 *
 * `Module._resolveFilename` is read live rather than captured, so a resolver hook (`tsx`,
 * `tsconfig-paths`, `ts-node`) that replaced it answers this question the same way it will answer
 * Node's own, one line later.
 *
 * ONE ROUTE THIS DOES NOT SEE, stated rather than implied. Since Node 22.15/23.5,
 * `Module._load` resolves through `resolveForCJSWithHooks`, so a SYNCHRONOUS
 * `module.registerHooks()` `resolve` hook that short-circuits (returns without calling
 * `nextResolve`) produces a filename `Module._resolveFilename` never computes — and the gate
 * would then decide about the default resolution rather than the one Node loads. Registering
 * such a hook is itself gated as an application-only operation (#61, `shims/module.ts`), so
 * this is a residual for the APPLICATION's own tooling, not a dependency-reachable bypass.
 *
 * COST, measured rather than asserted. Node resolves twice per load, but the second one hits
 * `Module._pathCache` (keyed by request + search paths, populated by the first). Instrumenting
 * `Module._resolveFilename` while `require`ing the whole `examples/express-app` tree: the CALL
 * count goes from 255 to 485, and the total time spent inside it does not change (~42 ms either
 * way) — the duplicate is a cache hit. An A/B of the whole `require("express")` against a build
 * without this gate is inside run-to-run variance on the same machine. Module loading is startup
 * work in any case; the per-request budget (AGENTS.md § 5) is untouched, because nothing here
 * runs per request.
 *
 * A throw means Node will throw the identical `MODULE_NOT_FOUND` a moment later. Swallowing it
 * here and delegating is what keeps the error the caller sees unchanged.
 */
function resolveQuietly(args: unknown[]): string | null {
  const resolve = (realModule as unknown as { _resolveFilename?: ResolveFilename })
    ._resolveFilename;
  if (typeof resolve !== "function") return null; // a Node without the internal — nothing to gate
  try {
    return Reflect.apply(resolve, realModule, [
      args[0],
      args[1],
      args[2],
      resolveOptionsFrom(args),
    ]);
  } catch {
    return null;
  }
}

/**
 * The CJS loader patch, as a shared relink chain (`lifecycle/process-patch.ts`).
 *
 * `link.next` is read at CALL time, never captured in a `const` at install time — that is what
 * lets an out-of-LIFO-order `uninstall()` relink around a removed middle layer instead of only
 * ever restoring the bottom of the stack (#22).
 */
const loadPatch = defineRelinkedPatch<ModuleLoad>("Module._load", {
  slot: valueSlot<ModuleLoad>("Module._load", () => realModule as unknown as object, "_load"),
  patch: (ctx, link) =>
    function (this: unknown, ...args: unknown[]) {
      // Fast path: only the fixed candidate set can possibly be shimmed; everything else is a
      // plain delegate with no registry work. The registry itself is built on the first mediated
      // require, so a process that never touches one never constructs a shim (and so never
      // captures a real builtin).
      const request = args[0];
      if (typeof request === "string" && (MEDIATED_CANDIDATES as Set<string>).has(request)) {
        const reg = liveRegistry("cjs");
        if (reg.has(request)) return reg.get(request);
      }
      // A PATH specifier is a second, previously un-gated read channel to the same bytes `fs`
      // guards (#123): `require("/abs/secrets.json")` reads through `Module._extensions['.json']`
      // and hands the contents back as a value. See loader/module-read.ts for which loads this
      // takes a decision for and, more importantly, which it deliberately does not. Throws on an
      // enforce-mode denial, BEFORE the real loader opens the file.
      //
      // `args[2]` is `isMain`: Node loading the process ENTRY POINT, which has no requiring
      // package to charge and is the application by definition.
      let decided = false;
      if (args[2] !== true && typeof request === "string" && !realModule.isBuiltin(request)) {
        const resolved = resolveQuietly(args);
        if (resolved !== null) {
          guardCjsModuleRead(ctx, resolved);
          decided = true;
        }
      }
      // Since #152 the ESM `resolve` hook is consulted for `require()` too, so it would take a
      // SECOND decision about this same load unless it is told not to. Marked only when the
      // decision above actually happened, so a load this gate could not resolve leaves the hook
      // armed — see loader/module-read.ts § WHICH OF THE GATES DECIDES A GIVEN LOAD. The
      // `guardCjsModuleRead` throw path deliberately marks nothing: nothing is delegated.
      if (!decided) return Reflect.apply(link.next, this, args);
      beginGatedCjsLoad();
      try {
        return Reflect.apply(link.next, this, args);
      } finally {
        endGatedCjsLoad();
      }
    },
});

/**
 * Patch the CJS loader to return shimmed builtins for mediated modules.
 *
 * Takes the whole {@link ShimContext} (rather than the fields spread across an options object,
 * as before #87) because the context is now the unit of the install lifecycle: this exact
 * object is what gets pushed on the shared install stack and what `uninstall()` pops, and
 * `install()` hands the same one to the env guard, the global-egress guard and the ESM hook so
 * every mediated surface in the process agrees on which policy is live.
 */
export function patchRequire(ctx: ShimContext): RequirePatchHandle {
  // Activate this install BEFORE the patch goes live, so a require that lands between the two
  // can never be evaluated against the previous install's policy.
  pushInstall(ctx);
  let patch;
  try {
    patch = loadPatch.install(ctx);
  } catch (err) {
    // The loader refused the patch outright. Unwind the activation rather than leaving an
    // install on the stack that no handle can ever pop.
    popInstall(ctx);
    throw err;
  }

  let uninstalled = false;
  return {
    uninstall() {
      if (uninstalled) return; // idempotent
      uninstalled = true;
      // Deactivate the policy FIRST, before the `_load` relink: a shim some module captured
      // reads the live context on every call, so this — not the loader unpatching — is what
      // stops the torn-down install's grants (and its `onDecision` sink) from being used.
      // Popping first also means the two are never observed out of order.
      popInstall(ctx);
      patch.uninstall();
    },
  };
}

const MEDIATED_CANDIDATES: ReadonlySet<string> = new Set(MEDIATED_MODULES);
