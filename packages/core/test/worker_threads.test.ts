/**
 * `worker_threads` shim tests (roadmap M4, issue #7).
 *
 * Builds the shim directly via its factory with a fake ShimContext (the loader registry
 * isn't wired for these two shims yet, so no `require()` interception here). Constructing a
 * real, successfully-running worker is heavy for a unit test, so the "granted" case instead
 * constructs with an intentionally bad module path: if the guard denies, the Proxy throws
 * CapabilityError synchronously and no OS thread is ever created; if the guard allows, Node's
 * own `Reflect.construct` runs and the worker fails to LOAD (MODULE_NOT_FOUND) asynchronously
 * — proving the guard was passed without needing a real, working worker script.
 */
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as realWorkerThreads from "node:worker_threads";
import { describe, expect, it } from "vitest";
import { loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";
import { createWorkerThreadsShim } from "../src/shims/worker_threads.js";
import type { ShimContext } from "../src/shims/runtime.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const BAD_MODULE = path.join(here, "definitely-does-not-exist.js");

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
    { version: 1, mode: "enforce", packages: { "<app>": { worker_threads: true } } },
    { projectRoot: here },
  );

/**
 * Wait for the worker's 'error' event (Node's own load failure), then terminate it.
 * Note: 'online' fires once the worker's JS environment is up, which happens BEFORE module
 * resolution runs — so it is expected here too and is not itself a sign anything is wrong.
 */
async function waitForLoadError(worker: import("node:worker_threads").Worker): Promise<unknown> {
  try {
    return await new Promise((resolve) => {
      worker.once("error", resolve);
    });
  } finally {
    await worker.terminate();
  }
}

describe("worker_threads shim — enforce mode denies by default", () => {
  it("new Worker(...) throws CapabilityError before any thread is created", () => {
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const shim = createWorkerThreadsShim(ctx);
    expect(() => new shim.Worker(BAD_MODULE)).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.pkg).toBe("<app>");
    expect(decisions[0]!.decision.allowed).toBe(false);
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "worker_threads" });
  });
});

describe("worker_threads shim — enforce mode with a grant", () => {
  it("construction is attempted past the guard (Node's own error surfaces, not CapabilityError)", async () => {
    const { ctx, decisions } = makeCtx(grantedEnforcePolicy(), "enforce");
    const shim = createWorkerThreadsShim(ctx);
    let worker!: import("node:worker_threads").Worker;
    expect(() => {
      worker = new shim.Worker(BAD_MODULE);
    }).not.toThrow();
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(true);

    const err = await waitForLoadError(worker);
    expect(err).not.toMatchObject({ name: "CapabilityError" });
    expect((err as { code?: string }).code).toBe("MODULE_NOT_FOUND");
  }, 10_000);

  it("preserves instanceof / class identity through the construct-trap Proxy", () => {
    const { ctx } = makeCtx(grantedEnforcePolicy(), "enforce");
    const shim = createWorkerThreadsShim(ctx);
    const worker = new shim.Worker(BAD_MODULE);
    try {
      expect(worker).toBeInstanceOf(realWorkerThreads.Worker);
    } finally {
      void worker.terminate();
    }
  });
});

describe("worker_threads shim — observe mode never blocks", () => {
  it("construction never throws, but the decision is recorded", async () => {
    const { ctx, decisions } = makeCtx(emptyObservePolicy(), "observe");
    const shim = createWorkerThreadsShim(ctx);
    let worker!: import("node:worker_threads").Worker;
    expect(() => {
      worker = new shim.Worker(BAD_MODULE);
    }).not.toThrow();
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.pkg).toBe("<app>");
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "worker_threads" });

    await waitForLoadError(worker);
  }, 10_000);
});

describe("worker_threads shim — passthrough", () => {
  it("exposes non-Worker exports unmodified", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const shim = createWorkerThreadsShim(ctx);
    expect(typeof shim.isMainThread).toBe("boolean");
    expect(typeof shim.MessageChannel).toBe("function");
    expect(shim.SHARE_ENV).toBeDefined();
  });
});
