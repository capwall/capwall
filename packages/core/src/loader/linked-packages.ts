/**
 * OBSERVING SYMLINKED `node_modules` ENTRIES AT RESOLUTION TIME (issue #127).
 *
 * capwall names a principal from a frame's file path, and Node hands V8 the REALPATH of every
 * module it loads. A dependency installed as a symlink into `node_modules` — which is what
 * `npm i file:../x`, `npm link`, and every workspace tool produce — therefore reports a path with
 * no `node_modules` segment in it and used to attribute to `<app>`, the trust root. See
 * `attribution/link-map.ts` for the full problem statement and for the identity capwall gives
 * these packages instead.
 *
 * WHY THE OBSERVATION HAPPENS HERE. The link that made a package reachable is not recoverable
 * from the realpath, and it is not recoverable by scanning either: pnpm puts it in the IMPORTING
 * package's `node_modules` (`repo/packages/app/node_modules/@w/lib -> ../../../lib`), so there is
 * no directory capwall could enumerate at startup that is guaranteed to hold it. The one place
 * the link is unambiguous is the resolution that used it.
 *
 * WHY `Module._findPath` AND NOT `Module._load`. `_findPath` is where Node's `toRealPath()` call
 * lives, and it is handed BOTH halves of what capwall needs — the specifier and the ordered list
 * of `node_modules` directories Node searched — while returning the realpath'd result. `_load`
 * would mean re-deriving the search list and re-running resolution to learn the answer.
 * `_findPath`'s result is also cached by Node in `Module._pathCache`, so this fires roughly once
 * per distinct (specifier, search-path) pair rather than once per `require`.
 *
 * WHAT THIS IS NOT. It is not a gate, it decides nothing, and it can deny nothing: it records a
 * fact about the filesystem and returns Node's own answer untouched. A failure inside the
 * recorder is swallowed (`recordResolvedLink` is total) because a broken observation must degrade
 * attribution, never break `require`.
 *
 * SHARED, NOT STACKING (`definePropertyPatch`). Two installs would record the same links twice
 * into the same process-wide map, so a second layer buys nothing and costs a second `lstat` on
 * every resolution. Unlike `_compile` (#100) nothing here inspects its own caller, so stacking
 * would be merely wasteful rather than wrong — but the reference-counted shape is still the right
 * one, and it is what `test/process-patch-sites.test.ts` enrolls automatically.
 *
 * A runtime with no `Module._findPath` (an exotic host, a future Node that renames it) is treated
 * as "nothing to observe": the slot reads `undefined`, `definePropertyPatch` declines, and
 * attribution falls back to `link-map.ts`'s discovery path and to the out-of-project rule.
 */
import { realModule } from "../real-builtins.cjs"; // never `import … from "node:module"` — see #78
import { recordResolvedLink } from "../attribution/link-map.js";
import { definePropertyPatch, valueSlot } from "../lifecycle/process-patch.js";
import type { ShimContext } from "../shims/runtime.js";

/** Handle for {@link installLinkObserver}; mirrors the other install-time patches. */
export interface LinkObserverHandle {
  uninstall(): void;
}

/**
 * `Module._findPath`'s shape — VARIADIC, and deliberately so (#128). Node's current signature is
 * `(request, paths, isMain)`, but re-stating an arity is a claim about a Node internal that a
 * Node minor can falsify silently; the two arguments this reads are read positionally and the
 * whole list is forwarded verbatim.
 */
type FindPath = (this: unknown, ...args: unknown[]) => unknown;

const linkObserverPatch = definePropertyPatch<FindPath>("Module._findPath", {
  slot: valueSlot<FindPath>("Module._findPath", () => realModule as unknown as object, "_findPath"),
  build(_ctx, realFindPath) {
    const patched: FindPath = function (this: unknown, ...args: unknown[]): unknown {
      // Node resolves FIRST; capwall only looks at what it decided. Recording before the call
      // would mean guessing which candidate directory won, which is the guess this patch exists
      // to avoid.
      const resolved = Reflect.apply(realFindPath, this, args);
      recordResolvedLink(args[0], args[1], resolved);
      return resolved;
    };
    // Keep `.name`/`.length` faithful: `Module._findPath` is reached by resolver-patching tools
    // (`tsconfig-paths`, `module-alias`, jest's resolver), and a wrapper that renamed it or
    // changed its arity would be a gratuitous behavior change on top of a passive observer.
    Object.defineProperty(patched, "name", { value: "_findPath", configurable: true });
    Object.defineProperty(patched, "length", { value: realFindPath.length, configurable: true });
    return patched;
  },
});

/**
 * Start observing CJS resolutions for symlinked `node_modules` entries.
 *
 * The links recorded are process-wide and deliberately OUTLIVE the install that observed them:
 * they describe the filesystem, not a policy, and a module resolved under one install keeps the
 * same identity under the next. Uninstalling stops the observation; it does not un-learn.
 */
export function installLinkObserver(ctx: ShimContext): LinkObserverHandle {
  return linkObserverPatch.install(ctx);
}
