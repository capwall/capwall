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
import { describe, expect, it } from "vitest";
import { loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";
import { createVmShim, type ShimContext } from "../src/shims/vm.js";

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
    expect(script.runInThisContext()).toBe(2);
  });
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
