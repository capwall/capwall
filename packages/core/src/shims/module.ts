/**
 * `node:module` shim (issue #61) — gates the module-customization-hook registration API.
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
 *  - The gate allows `<app>` because the application is the trust root, so it inherits
 *    whatever `attributeCaller` fails open to. Issue #60 (a `data:` URL ES module detached by
 *    one async hop leaves no filesystem frame on the stack, so attribution returns `<app>`)
 *    therefore walks straight past this gate exactly as it walks past the `process.env` and
 *    `dgram` gates — verified, not assumed. That is one bug in attribution, not three in the
 *    gates; when #60 lands, this gate is fixed with them.
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
import realModule from "node:module";
import { APP_ROOT, attributeCaller } from "../attribution/index.js";
import { CapabilityError } from "../errors.js";
import { attributionOptionsFor, type ShimContext, type ShimRegistry } from "./runtime.js";

export type { DecisionSink, ShimContext, ShimRegistry } from "./runtime.js";

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
  // through. Node-internal frames also attribute to `<app>`, which is what we want: capwall's
  // own registration and Node's internals must not trip this.
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
