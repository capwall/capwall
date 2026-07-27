/**
 * `vm` capability shim (roadmap M4, issue #9) — gates whether a package may use Node's `vm`
 * module to compile/run code in a V8 context at all. `vm` is a boolean gate (see
 * `PackagePolicy.vm` / `CapabilityRequest { kind: "vm" }`): unlike `fs`/`net` there is no
 * finer-grained target to check — the capability is "may this package touch `vm`", full stop.
 *
 * Coverage & limits (kept in sync with docs/threat-model.md):
 *  - Gated: the code-execution/compilation entry points — `runInNewContext`,
 *    `runInThisContext`, `runInContext`, `compileFunction`, the `Script` class (construction,
 *    via a construct-trap `Proxy`, exactly like `fs.ts`'s `wrapPathClass`), its deprecated
 *    `createScript` alias (same bypass class as `Script`, wrapped for the same reason
 *    `fs.ts` wraps `FileReadStream` alongside `ReadStream`), and — defensively, only if
 *    present (they live behind Node's `--experimental-vm-modules` flag) —
 *    `SourceTextModule` / `SyntheticModule`.
 *  - NOT gated: `createContext`, `isContext`, `measureMemory`, `constants`. A context object
 *    alone cannot run anything — it only becomes capability-relevant once code is compiled or
 *    run *in* it, which is exactly the entry points above. Gating `createContext` too would
 *    add friction without adding mediation.
 *  - **This is gating, not confinement.** capwall answers "may this package use the `vm`
 *    module", nothing more: it does not sandbox what code run *inside* a granted `vm` context
 *    can do (that code shares the process and can reach back out via context globals). It
 *    also does not — cannot — stop a package from reaching the same reflective-execution
 *    power via plain `eval` or `new Function(...)`, which capwall does not and cannot
 *    mediate. This gap is called out in `docs/threat-model.md` ("`vm` / `eval` /
 *    `node:sqlite`" under "what capwall does NOT stop"); gating the `vm` module narrows one
 *    door without claiming to lock the house.
 */
import realVm from "node:vm";
import { guard, type ShimContext, type ShimRegistry } from "./runtime.js";
import { harden } from "./harden.js";

export type { DecisionSink, ShimContext, ShimRegistry } from "./runtime.js";

type AnyFn = (...args: unknown[]) => unknown;
type CtorClass = abstract new (...a: never[]) => unknown;

/** Function-kind entry points gated as plain calls (guard, then delegate). */
const GATED_FUNCTIONS = [
  "runInNewContext",
  "runInThisContext",
  "runInContext",
  "compileFunction",
  // Deprecated legacy alias for `new vm.Script(...)` — same bypass surface as the class
  // below, so it gets the same treatment (compare `fs.ts`'s `FileReadStream` alias).
  "createScript",
] as const;

/**
 * Class-kind entry points gated via a construct-trap `Proxy` (guard happens BEFORE the
 * instance is created). `Script` is always present; `SourceTextModule`/`SyntheticModule`
 * only exist under `--experimental-vm-modules`, so each is wrapped only if present.
 */
const GATED_CLASSES = ["Script", "SourceTextModule", "SyntheticModule"] as const;

/**
 * Build a shimmed `vm` module: the entry points above are guarded; everything else
 * (`createContext`, `isContext`, `measureMemory`, `constants`, …) is the real thing, passed
 * through — see the module doc comment for why those are out of scope for this gate.
 */
export function createVmShim(ctx: ShimContext): typeof import("node:vm") {
  function check(): void {
    guard(ctx, { kind: "vm" });
  }

  function wrapFn(orig: AnyFn): AnyFn {
    const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
      check(); // throws on enforce-deny, before the real call runs
      return orig.apply(this, args);
    };
    Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
    return harden(ctx, wrapped);
  }

  /**
   * Wrap a `vm` class (`Script`, `SourceTextModule`, `SyntheticModule`) so `new Vm.X(...)`
   * is gated at construction. Uses a construct-trap Proxy so `instanceof` and class identity
   * are preserved — identical approach to `fs.ts`'s `wrapPathClass`.
   *
   * NOT hardened even under hardened mode: `Object.freeze` on a Proxy forwards to its TARGET,
   * so freezing this would freeze the real `vm.Script` class process-wide (see harden.ts).
   */
  function wrapClass<T extends CtorClass>(RealClass: T): T {
    return new Proxy(RealClass, {
      construct(target, argArray, newTarget) {
        check(); // throws on enforce-deny, before the instance exists
        return Reflect.construct(target, argArray as never[], newTarget);
      },
    });
  }

  const realRecord = realVm as unknown as Record<string, unknown>;
  const shim: Record<string, unknown> = {};

  // Copy every real export, then override the ones we gate — same pattern as `fs.ts`.
  for (const key of Object.keys(realVm)) {
    shim[key] = realRecord[key];
  }

  for (const name of GATED_FUNCTIONS) {
    const orig = realRecord[name];
    if (typeof orig === "function") shim[name] = wrapFn(orig as AnyFn);
  }

  for (const name of GATED_CLASSES) {
    const RealClass = realRecord[name];
    if (typeof RealClass === "function") {
      shim[name] = wrapClass(RealClass as CtorClass);
    }
  }

  return harden(ctx, shim) as typeof import("node:vm");
}

/** Register the vm shim's specifiers (`vm`, `node:vm`) into the loader registry. */
export function registerVmShim(reg: ShimRegistry, ctx: ShimContext): void {
  const shim = createVmShim(ctx);
  reg.set("vm", shim);
  reg.set("node:vm", shim);
}
