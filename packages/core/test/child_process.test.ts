/**
 * `child_process` shim tests (roadmap M4, issue #6).
 *
 * Builds the shim directly via its factory with a fake ShimContext (the loader registry
 * isn't wired for these two shims yet, so no `require()` interception here). Covers:
 * enforce+deny-by-default throws CapabilityError before any process starts, enforce+granted
 * forwards to the real implementation, and observe never throws but records the decision.
 */
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";
import { createChildProcessShim } from "../src/shims/child_process.js";
import type { ShimContext } from "../src/shims/runtime.js";

const here = path.dirname(fileURLToPath(import.meta.url));

type Recorded = { pkg: string; decision: Decision };

function makeCtx(policy: Policy, mode: "observe" | "enforce"): { ctx: ShimContext; decisions: Recorded[] } {
  const decisions: Recorded[] = [];
  const ctx: ShimContext = {
    policy,
    mode,
    projectRoot: here,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
  };
  return { ctx, decisions };
}

const emptyEnforcePolicy = (): Policy =>
  loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: here });

const emptyObservePolicy = (): Policy =>
  loadPolicyFromObject({ version: 1, mode: "observe" }, { projectRoot: here });

// A unit-test call site is not under node_modules, so it attributes to "<app>".
const grantedEnforcePolicy = (): Policy =>
  loadPolicyFromObject(
    { version: 1, mode: "enforce", packages: { "<app>": { child_process: true } } },
    { projectRoot: here },
  );

describe("child_process shim — enforce mode denies by default", () => {
  it("spawn throws CapabilityError before starting a process", () => {
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const shim = createChildProcessShim(ctx);
    expect(() => shim.spawn("echo", ["hi"])).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.pkg).toBe("<app>");
    expect(decisions[0]!.decision.allowed).toBe(false);
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "child_process" });
  });

  it("execSync throws CapabilityError (sync surface)", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const shim = createChildProcessShim(ctx);
    expect(() => shim.execSync("echo hi")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });

  it("fork throws CapabilityError", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const shim = createChildProcessShim(ctx);
    expect(() => shim.fork(path.join(here, "does-not-matter.js"))).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });
});

describe("child_process shim — enforce mode with a grant", () => {
  it("spawnSync of a trivial no-op is allowed through (no CapabilityError)", () => {
    const { ctx, decisions } = makeCtx(grantedEnforcePolicy(), "enforce");
    const shim = createChildProcessShim(ctx);
    const result = shim.spawnSync(process.execPath, ["-e", ""]);
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(true);
  });

  it("execFileSync of a trivial no-op is allowed through", () => {
    const { ctx } = makeCtx(grantedEnforcePolicy(), "enforce");
    const shim = createChildProcessShim(ctx);
    expect(() => shim.execFileSync(process.execPath, ["-e", ""])).not.toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });
});

describe("child_process shim — observe mode never blocks", () => {
  it("spawnSync is never denied, but the decision is recorded", () => {
    const { ctx, decisions } = makeCtx(emptyObservePolicy(), "observe");
    const shim = createChildProcessShim(ctx);
    const result = shim.spawnSync(process.execPath, ["-e", ""]);
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.pkg).toBe("<app>");
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "child_process" });
  });
});

describe("child_process shim — passthrough", () => {
  it("exposes the real ChildProcess class unmodified", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const shim = createChildProcessShim(ctx);
    expect(typeof shim.ChildProcess).toBe("function");
  });
});
