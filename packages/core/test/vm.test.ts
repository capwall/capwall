/**
 * Tests for the `vm` capability shim (roadmap M4, issue #9).
 *
 * Unlike `fs-slice.test.ts`, these tests do NOT go through `install()`/`require()`
 * interception — the shim registry isn't wired into `shims/index.ts` yet (that's a separate
 * step). Instead the shim is built directly via `createVmShim(ctx)` against a fake
 * `ShimContext`, matching how `buildShimRegistry` will eventually construct it.
 *
 * Attribution note: every call below happens directly in THIS test file, which lives outside
 * any `node_modules` tree, so `attributeCaller()` resolves the caller to `<app>` (APP_ROOT),
 * not to a package name. Grants below are therefore made under `default` (which `<app>`
 * falls back to, since it has no explicit `policy.packages["<app>"]` entry).
 */
import * as realVm from "node:vm";
import { describe, expect, it } from "vitest";
import { loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";
import { createVmShim } from "../src/shims/vm.js";
import type { ShimContext } from "../src/shims/runtime.js";

type Recorded = { pkg: string; decision: Decision };

/** Build a fake ShimContext with a decision collector, for direct (non-require) shim tests. */
function makeCtx(policy: Policy, mode: "observe" | "enforce"): { ctx: ShimContext; decisions: Recorded[] } {
  const decisions: Recorded[] = [];
  const ctx: ShimContext = {
    policy,
    mode,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
  };
  return { ctx, decisions };
}

const emptyEnforcePolicy = (): Policy => loadPolicyFromObject({ version: 1, mode: "enforce" });

const grantedEnforcePolicy = (): Policy =>
  loadPolicyFromObject({ version: 1, mode: "enforce", default: { vm: true } });

const emptyObservePolicy = (): Policy => loadPolicyFromObject({ version: 1, mode: "observe" });

describe("vm shim — enforce mode denies by default", () => {
  it("denies runInNewContext with no policy entry (CapabilityError)", () => {
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const vmShim = createVmShim(ctx);
    expect(() => vmShim.runInNewContext("1+1")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.pkg).toBe("<app>");
    expect(decisions[0]!.decision.allowed).toBe(false);
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "vm" });
  });

  it("denies `new Script(...)` with no policy entry (CapabilityError, before construction)", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const vmShim = createVmShim(ctx);
    expect(() => new vmShim.Script("1+1")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });

  it("also denies runInThisContext, runInContext, and compileFunction", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const vmShim = createVmShim(ctx);
    expect(() => vmShim.runInThisContext("1+1")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    const context = vmShim.createContext({});
    expect(() => vmShim.runInContext("1+1", context)).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(() => vmShim.compileFunction("return 1")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });
});

describe("vm shim — enforce mode, granted", () => {
  it("runInNewContext executes and returns the real result once granted", () => {
    const { ctx, decisions } = makeCtx(grantedEnforcePolicy(), "enforce");
    const vmShim = createVmShim(ctx);
    expect(vmShim.runInNewContext("1+1")).toBe(2);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(true);
  });

  it("`new Script(...)` constructs (and runs) once granted", () => {
    const { ctx } = makeCtx(grantedEnforcePolicy(), "enforce");
    const vmShim = createVmShim(ctx);
    const script = new vmShim.Script("1+1");
    expect(script).toBeInstanceOf(vmShim.Script);
    expect(script).toBeInstanceOf(realVm.Script); // guarded subclass keeps the real chain
    expect(script.runInThisContext()).toBe(2);
  });

  it("a further subclass of Script still works and is still gated", () => {
    const granted = makeCtx(grantedEnforcePolicy(), "enforce");
    const grantedShim = createVmShim(granted.ctx);
    class MyScript extends grantedShim.Script {}
    const mine = new MyScript("1+1");
    expect(mine).toBeInstanceOf(MyScript);
    expect(mine).toBeInstanceOf(grantedShim.Script);
    expect(mine.runInThisContext()).toBe(2);
    // An unrelated real Script must NOT satisfy `instanceof MyScript` — the guarded class's
    // `Symbol.hasInstance` is inherited down the static chain, so it has to fall back to
    // ordinary prototype-chain semantics for any receiver other than itself.
    expect(new realVm.Script("1+1") instanceof MyScript).toBe(false);

    const denied = makeCtx(emptyEnforcePolicy(), "enforce");
    const deniedShim = createVmShim(denied.ctx);
    class MyDeniedScript extends deniedShim.Script {}
    expect(() => new MyDeniedScript("1+1")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });
});

describe("vm shim — class escape surfaces (#64)", () => {
  it("`Script.prototype.constructor` is the guarded class, not the real one", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const vmShim = createVmShim(ctx);
    expect(vmShim.Script).not.toBe(realVm.Script);
    expect(vmShim.Script.prototype.constructor).toBe(vmShim.Script);
    expect(vmShim.Script.name).toBe("Script");
    // The escape that motivated #64: with a construct-trap Proxy this compiled and ran code
    // with the guard never firing.
    // Cast is typing-only: `.prototype.constructor` is declared as `Function`.
    const Escaped = vmShim.Script.prototype.constructor as new (code: string) => unknown;
    expect(() => new Escaped("1+1")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });

  /*
   * `vm.SourceTextModule` / `vm.SyntheticModule` live behind `--experimental-vm-modules`, and
   * vitest is never handed that flag (`packages/core/vitest.config.ts` sets only
   * `esbuild.include`; `.github/workflows/ci.yml` runs plain `pnpm test`). So they are
   * `undefined` on Node 20, 22 AND 24 as this suite runs.
   *
   * This used to be ONE test whose title claimed both halves — "gated when present, and absent
   * ones don't throw" — with the present-half behind a `continue` that has never executed on any
   * supported runtime (#112). Splitting it makes the state of affairs legible in the reporter: a
   * row that runs everywhere, and a row that visibly SKIPS everywhere. And the present-half now
   * asserts the gate BEHAVIORALLY (a `CapabilityError`), not just that the class was replaced —
   * `Cls !== real[name]` would hold for any substitute, guarded or not.
   */
  const VM_MODULE_CLASSES = ["SourceTextModule", "SyntheticModule"] as const;
  const realVmRecord = realVm as unknown as Record<string, unknown>;
  const HAS_VM_MODULES = VM_MODULE_CLASSES.every(
    (n) => typeof realVmRecord[n] === "function",
  );

  it("omits SourceTextModule/SyntheticModule when the runtime does not have them", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const vmShim = createVmShim(ctx) as unknown as Record<string, unknown>;
    for (const name of VM_MODULE_CLASSES) {
      // Mirrors the real module either way, so this row asserts something on both kinds of
      // runtime instead of silently doing nothing on one of them.
      expect({ name, shimmed: vmShim[name] === undefined }).toEqual({
        name,
        shimmed: typeof realVmRecord[name] !== "function",
      });
    }
  });

  it.skipIf(!HAS_VM_MODULES)(
    "gates SourceTextModule/SyntheticModule when the runtime has them (--experimental-vm-modules)",
    () => {
      const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
      const vmShim = createVmShim(ctx) as unknown as Record<string, unknown>;
      for (const name of VM_MODULE_CLASSES) {
        const Cls = vmShim[name] as new (...a: never[]) => unknown;
        expect(Cls).not.toBe(realVmRecord[name]);
        expect((Cls as { prototype: Record<string, unknown> }).prototype["constructor"]).toBe(Cls);
        // The load-bearing half: a guarded class that does not DENY is not a gate.
        expect(() => new Cls(...(["export default 1;"] as never[]))).toThrowError(
          expect.objectContaining({ name: "CapabilityError" }),
        );
      }
    },
  );
});

describe("vm shim — observe mode never blocks", () => {
  it("runInNewContext runs and records an observed { kind: 'vm' } request", () => {
    const { ctx, decisions } = makeCtx(emptyObservePolicy(), "observe");
    const vmShim = createVmShim(ctx);
    expect(vmShim.runInNewContext("1+1")).toBe(2);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.pkg).toBe("<app>");
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "vm" });
  });

  it("`new Script(...)` never throws in observe mode", () => {
    const { ctx, decisions } = makeCtx(emptyObservePolicy(), "observe");
    const vmShim = createVmShim(ctx);
    expect(() => new vmShim.Script("1+1")).not.toThrow();
    expect(decisions.some((d) => d.decision.observed.kind === "vm")).toBe(true);
  });
});

describe("vm shim — pass-through surface", () => {
  it("createContext/isContext/constants are the real, ungated implementations", () => {
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const vmShim = createVmShim(ctx);
    const context = vmShim.createContext({ x: 1 });
    expect(vmShim.isContext(context)).toBe(true);
    expect(vmShim.constants).toBeDefined();
    // Pass-through surface never guards, so no decisions are recorded for it.
    expect(decisions).toHaveLength(0);
  });
});
