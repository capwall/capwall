/**
 * `node:module` — two gates on the module system.
 *
 *   1. The module-customization-hook registration API (`register`/`registerHooks`, issue #61),
 *      via a `Proxy` over the module object handed to `require("node:module")`.
 *   2. Direct calls to `Module.prototype._compile` (issue #93), via a patch on the PROTOTYPE
 *      itself — see {@link installCompileGate} for why the shim cannot do this one.
 *
 * ---------------------------------------------------------------------------------------------
 * Gate 1 — loader-hook registration (#61).
 *
 * WHY THIS EXISTS. M5 makes Node's loader-hook chain part of capwall's enforcement path, and
 * that chain is deliberately composable: **Node runs the most recently registered hook first**,
 * and the synchronous `module.registerHooks()` chain runs entirely ahead of the asynchronous
 * `module.register()` chain capwall lives in. So a dependency that reaches `register` /
 * `registerHooks` can short-circuit a mediated specifier straight to the real `node:` URL
 * before capwall's `resolve` is ever consulted. Because the ESM module cache is keyed by
 * resolved URL and the hook is process-wide, that de-mediates **every** package that imports
 * a mediated builtin afterwards — an innocent third dependency's ordinary
 * `import * as fs from "node:fs"` binds to the raw builtin — with no capwall log line.
 * `node:module` was not mediated, so nothing stood in the way.
 *
 * WHAT THIS DOES. Registering a loader hook is treated as an app-only operation: capwall
 * attributes the caller exactly as every other shim does and, for anything that is not the
 * application itself, refuses (`enforce`) or warns loudly (`observe` — which by contract never
 * blocks). The application is the trust root, so its own tooling (`tsx`, `ts-node`, a custom
 * loader) is untouched; the same app-vs-dependency rule the `process.env` guard uses.
 *
 * WHAT THIS DOES NOT DO. It is a gate on *reaching* the API through a mediated module, not a
 * lock on the API itself:
 *  - `process.getBuiltinModule("node:module")` returns the real, un-shimmed module (Node ≥22).
 *    That is the pre-existing, path-independent residual `docs/threat-model.md` already names,
 *    and it defeats this gate exactly as it defeats every other shim.
 *  - A hook registered BEFORE capwall installs is already ahead of it.
 *  - The gate allows `<app>` because the application is the trust root, so it inherits whatever
 *    `attributeCaller` resolves to. That used to be a fail-open: issue #60 (a `data:` URL ES
 *    module detached by one async hop leaves no filesystem frame on the stack, so attribution
 *    returned `<app>`) walked straight past this gate exactly as it walked past the
 *    `process.env` and `dgram` gates. It was one bug in attribution, not three in the gates,
 *    and fixing it there fixed this gate with them: an unattributable registration now
 *    attributes to `<unknown>`, which is not the trust root and does not pass. Verified, not
 *    assumed — see `test/attribution-laundering.test.ts`.
 *  - capwall does not re-assert first position after an allowed registration. It could
 *    (joining the synchronous chain regains the front), but doing so would silently override
 *    the application's own loader tooling — and it still would not beat a hook that
 *    short-circuits `load` as well as `resolve`. `loader/esm-hooks.ts` instead detects that
 *    case at load time, re-mediates what it can, and warns.
 * See `docs/threat-model.md` § ESM known limits; this narrows a door, it does not lock a house.
 *
 * Escape hatch: `CAPWALL_ALLOW_LOADER_HOOKS=1` allows dependency registrations (still warning
 * loudly), for a tree where a dependency legitimately installs a loader. `CAPWALL_*` keys are
 * never gated or recorded by the env guard, so reading it here is safe from inside a shim.
 */
import * as path from "node:path";
import { realModule } from "../real-builtins.cjs"; // never `import … from "node:module"` — see #78
import {
  APP_ROOT,
  attributeCaller,
  attributeCallerDetailedVia,
  packageForPath,
  type StackBoundary,
} from "../attribution/index.js";
import { CapabilityError } from "../errors.js";
import { definePropertyPatch, valueSlot } from "../lifecycle/process-patch.js";
import {
  attributionOptionsFor,
  guardAttributed,
  type ShimContext,
  type ShimRegistry,
} from "./runtime.js";

type AnyFn = (...args: unknown[]) => unknown;

/**
 * The registration entry points. `register` (async chain, Node ≥20.6) and `registerHooks`
 * (synchronous chain, Node ≥22.15) are both live routes to the same capability; the sync one
 * is strictly stronger for an attacker, since its chain runs ahead of capwall's. Anything else
 * on `node:module` (`createRequire`, `builtinModules`, `isBuiltin`, `SourceMap`, the `_`
 * internals, …) is passed through untouched — this shim gates hook registration, nothing more.
 */
const GUARDED_APIS = new Set(["register", "registerHooks"]);

/** Decide and report. Returns normally when the registration may proceed. */
function guardRegistration(ctx: ShimContext, api: string): void {
  // Same frame budget as every other attribution site (#15) — a gate that walked a different
  // depth could attribute the same call to a different package than `guard` would.
  const pkg = attributeCaller(attributionOptionsFor(ctx));
  // The application is the trust root — same rule as the env guard, where `<app>` reads pass
  // through. Since #60 this is a POSITIVE identification (a real application source file on the
  // stack), so a registration capwall cannot attribute is `<unknown>` and falls through to the
  // gate below rather than being waved past. capwall's own hook registration is unaffected: it
  // calls the REAL `node:module` binding it imported before installing, never this shim.
  if (pkg === APP_ROOT) return;

  const what = `module.${api}() — a module-customization hook is registered process-wide and Node runs the newest hook first, so this can un-mediate ESM imports for EVERY package`;

  if (process.env["CAPWALL_ALLOW_LOADER_HOOKS"] === "1") {
    process.stderr.write(
      `[capwall] WARN '${pkg}' called ${what}; allowed by CAPWALL_ALLOW_LOADER_HOOKS=1\n`,
    );
    return;
  }

  // observe mode NEVER blocks (the documented contract) — but it must not be silent either:
  // the whole point of the finding is that this bypass produced no log line at all, so an
  // observe run would have generated a policy from a poisoned trace without ever saying so.
  if (ctx.mode === "observe") {
    process.stderr.write(`[capwall] observe: WARN '${pkg}' called ${what}\n`);
    return;
  }

  const reason = `enforce: DENY '${pkg}' module.${api}() (loader-hook registration is application-only; set CAPWALL_ALLOW_LOADER_HOOKS=1 to permit it)`;
  process.stderr.write(`[capwall] ${reason}\n`);
  throw new CapabilityError(reason, pkg);
}

/**
 * Build a shimmed `node:module`.
 *
 * A `Proxy` over the REAL module object rather than a copied plain object, because
 * `node:module`'s CJS export is the `Module` **class**: copying its own keys onto `{}` would
 * break `new (require("module"))(…)`, `Module.prototype`, `instanceof`, and every consumer
 * that reaches an internal (`Module._cache`, `Module._resolveFilename`). The proxy keeps
 * identity, callability, prototype chain and own-key enumeration exact — verified that
 * `Object.keys(proxy)` equals `Object.keys(real)` and that it matches `node:module`'s ESM
 * named-export set exactly, which is what the ESM load hook generates re-exports from.
 */
export function createModuleShim(ctx: ShimContext): typeof import("node:module") {
  // Wrappers are memoised so `m.register === m.register` holds, as it does on the real module
  // (code that compares or caches the reference must not see a fresh function each read).
  const wrappers = new Map<string, AnyFn>();

  return new Proxy(realModule, {
    get(target, prop) {
      // `Reflect.get(target, prop)` WITHOUT forwarding the proxy as the receiver: any accessor
      // on a Node builtin that touches an internal slot would throw if handed the proxy.
      const value: unknown = Reflect.get(target, prop);
      if (typeof prop !== "string" || !GUARDED_APIS.has(prop) || typeof value !== "function") {
        return value;
      }
      let wrapper = wrappers.get(prop);
      if (wrapper === undefined) {
        const real = value as AnyFn;
        wrapper = function (this: unknown, ...args: unknown[]): unknown {
          guardRegistration(ctx, prop);
          return Reflect.apply(real, this === wrapper ? target : this, args);
        };
        // Keep `.name`/`.length` faithful so feature-detection and error messages read right.
        Object.defineProperty(wrapper, "name", { value: prop, configurable: true });
        Object.defineProperty(wrapper, "length", { value: real.length, configurable: true });
        wrappers.set(prop, wrapper);
      }
      return wrapper;
    },
  }) as unknown as typeof import("node:module");
}

/** Register the `node:module` shim under both spellings (bare and `node:`-prefixed). */
export function registerModuleShim(reg: ShimRegistry, ctx: ShimContext): void {
  const shim = createModuleShim(ctx);
  reg.set("module", shim);
  reg.set("node:module", shim);
}

/* ============================================================================================
 * Gate 2 — `Module.prototype._compile` (issue #93).
 * ========================================================================================== */

/** Handle for {@link installCompileGate}; mirrors the other install-time guards. */
export interface CompileGateHandle {
  uninstall(): void;
}

/**
 * `Module.prototype._compile`'s shape — deliberately VARIADIC (issue #128).
 *
 * It used to be written `(content: string, filename: string)`, with a comment asserting that
 * "Node passes exactly `(content, filename)`". That was true when it was written and stopped
 * being true in Node 22.18, which added a third parameter, `format`:
 *
 *   Module.prototype._compile = function(content, filename, format) {
 *     if (format === "commonjs-typescript" || format === "module-typescript" || …)
 *
 * `Module._extensions` passes `format: "commonjs-typescript"` for a `.ts`/`.cts` file, and it is
 * what drives Node's built-in type stripping. A wrapper that forwarded a FIXED arity dropped it,
 * so `require("./x.ts")` handed raw TypeScript to `wrapSafe` and threw `SyntaxError` — under any
 * policy, in both modes, with capwall's own frame in the stack. (`require(esm)` self-healed only
 * because `wrapSafe` re-detects ESM via `canParseAsESM`; type stripping has no second chance.)
 *
 * THE RULE THIS ENCODES, which is the durable half: a capwall wrapper over a Node primitive
 * forwards with `Reflect.apply(real, this, args)` and never re-states the primitive's parameter
 * list. Re-stating an arity is a correctness claim about a Node internal that a Node MINOR can
 * falsify silently, and it fails in both directions — dropping an argument can as easily change
 * what V8 compiles as it can break a load, so the gate would be reasoning about source Node did
 * not compile. `test/primitive-arity.test.ts` asserts the property (arguments forwarded
 * unchanged, whatever the count) rather than any particular number, so a future Node adding a
 * fourth parameter needs no code change here and cannot regress silently.
 */
type CompileFn = (this: unknown, ...args: unknown[]) => unknown;

/**
 * Frames belonging to Node's own CJS module machinery. `_compile` is called once per module
 * Node loads, from `Module._extensions[…]` inside this file, so this prefix is what separates
 * "the loader is doing its job" from "somebody called the primitive".
 */
const NODE_LOADER_FRAME_PREFIX = "node:internal/modules/";

/**
 * Is the immediate caller of the patched `_compile` Node's own module loader?
 *
 * `Error.captureStackTrace(holder, hideAbove)` drops every frame up to and INCLUDING
 * `hideAbove`, so `sites[0]` is exactly `_compile`'s caller — one frame, no walk, no
 * allocation beyond the holder. That matters: this runs once per CJS module the process loads.
 *
 * SECURITY — WHY THE FILE-NAME PREFIX IS SAFE TO TRUST HERE, when the whole issue is that file
 * names are attacker-chosen. A `node:`-prefixed file name is not a filesystem path, and the only
 * way for user code to acquire a frame reporting one is to have compiled itself under that name
 * — i.e. to have already passed this gate. It cannot: {@link guardCompile} treats a non-absolute
 * filename as never being the caller's own package, so `_compile(payload,
 * "node:internal/modules/cjs/loader")` is evaluated against the policy exactly like any other
 * foreign filename and is denied by default. The bootstrap is closed before the first frame
 * exists. (Compiling under a `node:` name is also, separately, not something any real tool does.)
 *
 * THAT ARGUMENT IS ABOUT ACQUIRING A FRAME, AND SAYS NOTHING ABOUT THE FRAMES THIS FUNCTION IS
 * HANDED. `Error.captureStackTrace` is a writable property of a primordial: one assignment
 * replaces it with a function that writes a fabricated CallSite reporting any file name at all,
 * which defeats this check and the attribution walk together, needs no real frame, and restores
 * itself on the next statement. It is out of scope for an in-process mechanism — capwall cannot
 * freeze `Error`, and a detector would run in the process the attacker controls — so it is NAMED
 * rather than defended: docs/threat-model.md § The one assumption every control rests on, and the
 * *Shared mutable primordials* residual it points at. Hardened mode does not mitigate it either.
 *
 * FAILS CLOSED. No caller frame at all — a `_compile` invoked from native code or through a
 * detached callback — is not the loader, so it is gated. The loader always has a frame.
 */
function calledByNodeLoader(hideAbove: CompileFn): boolean {
  const origPrepare = Error.prepareStackTrace;
  const origLimit = Error.stackTraceLimit;
  Error.prepareStackTrace = (_err, sites) => sites;
  Error.stackTraceLimit = 1;
  const holder: { stack?: NodeJS.CallSite[] } = {};
  Error.captureStackTrace(holder as object, hideAbove);
  const sites = holder.stack ?? [];
  Error.prepareStackTrace = origPrepare;
  Error.stackTraceLimit = origLimit;
  const caller = sites[0];
  if (caller === undefined) return false;
  // An `eval` frame can report a file name it inherited; it is never Node's loader.
  if (caller.isEval()) return false;
  const file = caller.getFileName();
  return typeof file === "string" && file.startsWith(NODE_LOADER_FRAME_PREFIX);
}

/**
 * Decide whether the calling package may compile source under `filename`. Returns normally
 * when the compile may proceed; throws {@link CapabilityError} on an enforce-mode denial.
 *
 * Two calls are waved through before the policy is consulted, and both are cases where the
 * compile GAINS THE CALLER NOTHING:
 *
 *  - **The application.** `<app>` is the trust root; every other gate in capwall treats it the
 *    same way, and it already owns the process. Since #60 this is a POSITIVE identification (a
 *    real application source file on the stack), so a compile capwall cannot attribute is
 *    `<unknown>` and falls through to the policy rather than being waved past.
 *  - **A package compiling under its own name.** A template engine, `require-from-string`, a
 *    package materializing generated source — the compiled frames report a principal the caller
 *    already is, so there is no identity to acquire. Compared as PRINCIPALS rather than as
 *    directory prefixes so an install chain is handled the same way (`a>b` compiling into `a>b`
 *    is self-compilation; `a>b` compiling into `b` is not, and must not be).
 *
 * A non-absolute `filename` is never self-compilation: `packageForPath` would resolve it to the
 * trust root, which would turn "compile under a bare label" into a free `<app>` impersonation.
 * `path.isAbsolute` is checked explicitly rather than relied on implicitly.
 *
 * `hideAbove` is the PATCHED `_compile` itself — the same function object
 * {@link calledByNodeLoader} already uses as its boundary, for the same reason: it is the frame a
 * direct caller invokes, so the caller sits directly below it and the capture materializes 3
 * CallSites instead of 25 (#143). Note what this does and does not buy. It only helps the DIRECT
 * call, which is the adversarial shape #93 is about; the per-module-load path — Node's loader
 * calling `_compile` for every CJS module in the process — short-circuits in
 * `calledByNodeLoader` above and never reaches attribution at all, so its cost is unchanged and
 * remains the one-frame capture that function performs.
 */
function guardCompile(ctx: ShimContext, filename: unknown, hideAbove: CompileFn): void {
  const attribution = attributeCallerDetailedVia(
    hideAbove as unknown as StackBoundary,
    attributionOptionsFor(ctx),
  );
  if (attribution.pkg === APP_ROOT) return;
  if (
    typeof filename === "string" &&
    path.isAbsolute(filename) &&
    packageForPath(filename, ctx.projectRoot) === attribution.pkg
  ) {
    return;
  }
  // `filename` is recorded but not matched — see the `compile` variant of CapabilityRequest.
  guardAttributed(ctx, attribution, {
    kind: "compile",
    filename: typeof filename === "string" ? filename : String(filename),
  });
}

/**
 * Patch `Module.prototype._compile` so a DIRECT call with a caller-chosen filename is a gated
 * capability (issue #93).
 *
 * WHY A PROTOTYPE PATCH AND NOT THE SHIM. `createModuleShim` is a `Proxy` over the `Module`
 * class, and its `get` trap fires for reads on the module object — `Module.register`,
 * `Module._cache`. `m._compile` is read off `Module.prototype`, an object the proxy hands
 * through untouched, so the trap never sees it. Worse, `process.getBuiltinModule("node:module")`
 * (Node ≥22) returns the real module and defeats every shim-level gate outright. There is one
 * object both routes converge on, and it is the prototype. Patching it also means the gate holds
 * for `Object.getPrototypeOf(module)._compile` and any other spelling.
 *
 * WHY THIS IS NOT A CAPABILITY ON `node:module`'s SURFACE. `_compile` is not "a module system
 * feature a package might want"; it is the one primitive that lets a caller CHOOSE what V8
 * reports as `getFileName()` on the frames of the code it runs. Since capwall names principals
 * from frame file names, that is the ability to execute as an arbitrary principal — the policy's
 * root of trust, reachable with no grant at all before this. See #93 for the PoC: `forge-dep`,
 * holding nothing, read a granted package's env and files with no log line, naming a path that
 * did not need to exist.
 *
 * COST. One `Error.captureStackTrace` with a one-frame limit per CJS module compile, on the
 * loader path — module loading is startup work, not per-request, and the per-request budget
 * (<1ms) is untouched because nothing recompiles per request. The full attribution walk runs
 * only for compiles that are NOT from Node's loader, which in a normal process is zero.
 *
 * RESIDUALS, not papered over:
 *  - `Module.prototype._compile` is writable, so in-process code can overwrite it. Doing so
 *    removes the gate — and also breaks `require` for the whole process, so it is loud rather
 *    than silent. It is the same class of escape as un-patching any shim, which capwall does not
 *    claim to stop (docs/threat-model.md § un-patching). Hardened mode does not freeze it,
 *    deliberately: `require.extensions` tooling replaces methods on this prototype.
 *  - The OTHER compile primitives are gated by the `vm` capability (`vm.Script`,
 *    `vm.compileFunction`, `vm.runInNewContext`, all of which also take a `filename`), and a
 *    `vm` grant therefore remains identity-granting in the same way `compile` is. Both are now
 *    named as such in the schema and in docs/threat-model.md.
 *  - `process.binding("contextify")` and other raw-internal routes are the pre-existing,
 *    path-independent residual the threat model already names. A prototype patch survives
 *    `getBuiltinModule`; it does not survive reaching past the module system entirely.
 *
 * EXACTLY ONE PATCH PER PROCESS, REFERENCE-COUNTED — unlike `process.dlopen` (loader/native.ts)
 * and `Module._load` (loader/require.ts), which let nested installs stack. That is not a style
 * choice; stacking would BREAK this gate, and loudly:
 *
 *   Node loader -> P2 -> P1 -> real          (two installs, P2 patched second)
 *
 * P2 asks {@link calledByNodeLoader} who called it and sees `node:internal/modules/…`, correctly.
 * P1 then asks the same question and sees *P2's frame*, which lives in capwall's own tree, not
 * `node:internal/…` — so P1 concludes a user called it and gates EVERY module load in the
 * process. A second `install()` would turn `require` itself into a denied capability. Since #87
 * every guard reads {@link liveCtx}, whose identity never changes and whose fields the install
 * stack re-points, a single patch already tracks whichever install is in force — so one patch is
 * both necessary and sufficient, and the count only decides when to put the real method back.
 *
 * THAT DIFFERENCE IS WHY #107 SHIPPED TWO NAMED HELPERS RATHER THAN ONE WITH A FLAG.
 * `defineRelinkedPatch` (stacking) and `definePropertyPatch` (single, refcounted) are separate
 * names in `lifecycle/process-patch.ts` precisely because a `{ stack: false }` option on one
 * helper is the kind of thing a future patch site copies from its neighbour without reading. The
 * two sites that MUST stack and the three that MUST NOT now say so in the function they call.
 *
 * `index.ts` hands this `liveCtx`, and the patch below captures the FIRST caller's context. Those
 * are the same object by construction; a caller that passes a per-install `ctx` instead (a test
 * constructing a gate directly) gets that context for the gate's whole lifetime, which is why the
 * production call site must not.
 *
 * A Node with no `Module.prototype._compile` (a future Node, an exotic runtime) is treated as
 * "nothing to gate" rather than crashing the host process on install — the slot reads `undefined`
 * and `definePropertyPatch` declines.
 */
const compileGatePatch = definePropertyPatch<CompileFn>("Module.prototype._compile", {
  slot: valueSlot<CompileFn>(
    "Module.prototype._compile",
    () => (realModule as unknown as { prototype?: object }).prototype,
    "_compile",
  ),
  build(ctx, realCompile) {
    const patched: CompileFn = function (this: unknown, ...args: unknown[]): unknown {
      // `args[1]` is `filename` on every Node that has ever had this method; the gate reads it
      // POSITIONALLY and forwards the list VERBATIM, so a Node that adds a parameter changes
      // what is forwarded without changing what is gated. `guardCompile` already treats a
      // non-string / non-absolute filename as "never self-compilation", so a runtime that ever
      // reordered the parameters fails closed here rather than waving the compile through.
      if (!calledByNodeLoader(patched)) guardCompile(ctx, args[1], patched);
      return Reflect.apply(realCompile, this, args);
    };
    // Keep `.name`/`.length` faithful: `require.extensions` tooling feature-detects on this
    // prototype, and a wrapper that renamed the method would be a gratuitous behavior change.
    Object.defineProperty(patched, "name", { value: "_compile", configurable: true });
    Object.defineProperty(patched, "length", { value: realCompile.length, configurable: true });
    return patched;
  },
});

/**
 * Install the `_compile` gate. Restoring is conditional on nothing else having since replaced the
 * method — the same contract the require patch keeps. Clobbering a `require.extensions` tool's own
 * patch would be worse than leaving ours in place, and leaving ours in place is safe: it reads
 * `liveCtx`, which after the last uninstall is the deny-all torn-down policy that gates nothing
 * Node itself does.
 */
export function installCompileGate(ctx: ShimContext): CompileGateHandle {
  return compileGatePatch.install(ctx);
}
