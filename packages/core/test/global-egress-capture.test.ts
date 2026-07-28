/**
 * WHEN capwall CAPTURES `Request.prototype.url`, AND WHAT THE OFF SWITCH REFUNDS (issue #170).
 *
 * `shims/global-egress.ts` captures the real `Request.prototype.url` getter as early as capwall
 * itself loads. That capture is what closes #26/#56 for the `Request` input shape, and reading
 * `globalThis.Request` to take it materializes undici — ~21 ms of every mediated process's
 * startup, the largest single line in `scripts/bench/README.md` § Startup.
 *
 * Until #170 it was an unconditional module-scope IIFE, so `CAPWALL_GLOBAL_EGRESS=0` removed the
 * control and kept the cost: 188.98 vs 187.78 ms on Node 22, 148.76 vs 159.36 on 26. An escape
 * hatch that disables a guard without refunding its price is the opposite of an escape hatch.
 *
 * Two claims, and they pull in opposite directions, which is why they are tested together:
 *
 *  1. **The capture still precedes anything that could tamper.** The first `describe` is the
 *     `#170` mutant's target. It replaces `Request.prototype.url` BEFORE `install()` — the
 *     embedder shape, `import @capwall/core` … dependency … `install()` — and asserts capwall
 *     guards the URL undici will really dial rather than the one the getter now claims. Deleting
 *     the eager capture (deferring it to install time for everyone) makes this go red, which is
 *     the whole reason #170 could not be closed by moving the capture into
 *     `installGlobalEgressGuard()`.
 *
 *     This file is deliberately the only place in the suite that installs before the tamper, and
 *     the tamper test is deliberately FIRST: `ensureRequestUrlCapture()` runs once per process,
 *     so an earlier `install()` in the same worker would take the deferred capture on clean
 *     state and the mutant would survive.
 *
 *  2. **The switch now refunds the cost.** The second `describe` asserts on
 *     `process.moduleLoadList` rather than on a clock. `internal/deps/undici/undici` enters that
 *     list at the instant anything reads `globalThis.Request` and not before — reading
 *     `globalThis.fetch` alone does NOT load it (measured on 22.22.3 / 24.18.0 / 26.5.0). So its
 *     presence is a machine-independent, contention-proof proxy for "this process paid the
 *     undici materialization", where AGENTS.md § 7 forbids a wall-clock threshold.
 *
 * The third `describe` covers the one self-contradictory configuration — `CAPWALL_GLOBAL_EGRESS=0`
 * in the environment AND an embedder that asks `install()` for the guard anyway — in BOTH
 * directions: capwall takes the capture late and the guard works, silently when nothing could
 * have tampered and with a warning when something could have.
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { install, loadPolicyFromObject, type Decision } from "../src/index.js";
import {
  assertPreloadBuilt,
  PRELOAD_IMPORT_FLAG,
  runNode,
  type NodeRunResult,
} from "./helpers/subprocess.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");
const UNDICI_APP = path.join(here, "fixtures", "undici-materialization-app.cjs");
const EMBEDDER_APP = path.join(here, "fixtures", "egress-capture-embedder.mjs");

interface FixtureDep {
  fetchViaRequest(url: string, init?: unknown): Promise<{ status: number; body: string }>;
}

/** The un-tampered descriptor, so the process is left exactly as it was found. */
let originalUrlDescriptor: PropertyDescriptor | undefined;

beforeAll(() => {
  assertPreloadBuilt();
  originalUrlDescriptor = Object.getOwnPropertyDescriptor(Request.prototype, "url");
  expect(
    typeof originalUrlDescriptor?.get,
    "Request.prototype.url must be an accessor for this file to mean anything",
  ).toBe("function");
});

afterAll(() => {
  if (originalUrlDescriptor !== undefined) {
    Object.defineProperty(Request.prototype, "url", originalUrlDescriptor);
  }
});

describe("#170 — the capture precedes anything that could tamper", () => {
  it("guards the URL undici will dial when the PROTOTYPE getter was replaced before install()", async () => {
    // A dependency `require`d between `import @capwall/core` and `install()` needs one line to
    // make every later `Request` lie about where it is going, and undici keeps dialing the real
    // internal URL regardless (measured on 22.22.3 and 26.5.0). capwall is only immune because it
    // captured the getter when its own module was evaluated — before this ran.
    Object.defineProperty(Request.prototype, "url", {
      configurable: true,
      enumerable: originalUrlDescriptor?.enumerable ?? false,
      get: () => "https://granted.example/",
    });
    expect(new Request("http://127.0.0.1:1/real").url).toBe("https://granted.example/");

    const decisions: Array<{ pkg: string; decision: Decision }> = [];
    const handle = install(
      loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: here }),
      "enforce",
      { projectRoot: here, env: false, onDecision: (pkg, decision) => decisions.push({ pkg, decision }) },
    );
    try {
      const resolved = requireCjs.resolve(FIXTURE);
      delete requireCjs.cache[resolved];
      const dep = requireCjs(FIXTURE) as FixtureDep;
      await expect(dep.fetchViaRequest("http://127.0.0.1:1/real")).rejects.toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    } finally {
      handle.uninstall();
      if (originalUrlDescriptor !== undefined) {
        Object.defineProperty(Request.prototype, "url", originalUrlDescriptor);
      }
    }

    // THE assertion. A capture taken after the tamper reports `granted.example:443` here, which
    // is a decision about a request that never happened — the #26/#56 failure, reopened.
    expect(decisions).toHaveLength(1);
    expect(decisions[0]?.pkg).toBe("fixture-dep");
    expect(decisions[0]?.decision.observed).toEqual({ kind: "net", host: "127.0.0.1", port: 1 });
  });
});

describe("#170 — CAPWALL_GLOBAL_EGRESS=0 refunds the undici materialization", () => {
  /** One mediated child that reports whether capwall made it materialize undici. */
  function runMediated(env: Record<string, string | undefined>): Promise<NodeRunResult> {
    return runNode([PRELOAD_IMPORT_FLAG, UNDICI_APP], {
      cwd: path.dirname(UNDICI_APP),
      env: { CAPWALL_MODE: "enforce", CAPWALL_PROJECT_ROOT: path.dirname(UNDICI_APP), ...env },
    });
  }

  it("pays it with the guard on — the control that makes the next assertion mean something", async () => {
    const r = await runMediated({ CAPWALL_GLOBAL_EGRESS: undefined });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("undici-materialized:true");
  });

  it("does not pay it with the guard off", async () => {
    const r = await runMediated({ CAPWALL_GLOBAL_EGRESS: "0" });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("undici-materialized:false");
  });
});

describe("#170 — the contradictory configuration: the variable off, the option on", () => {
  /**
   * `CAPWALL_GLOBAL_EGRESS` is the preload's switch; `install()`'s `globalEgress` option is a
   * code-level default the variable does not reach. An embedder can therefore set the variable
   * and still get the guard, which is the one path where the capture is taken late. capwall does
   * not silently pick a side there: the guard still works, and capwall says so when it cannot
   * prove the getter is still Node's own.
   */
  function runEmbedder(mode: "clean" | "materialize"): Promise<NodeRunResult> {
    return runNode([EMBEDDER_APP, mode], {
      cwd: path.dirname(EMBEDDER_APP),
      env: { CAPWALL_GLOBAL_EGRESS: "0", CAPWALL_MODE: undefined, CAPWALL_POLICY_FILE: undefined },
    });
  }

  it("takes the capture late and guards both input shapes, silently, when nothing could have tampered", async () => {
    const r = await runEmbedder("clean");
    expect(r.code).toBe(0);
    // Both shapes denied => the late capture produced a working guard, not merely a quiet one.
    expect(r.stdout).toContain("string-input:DENIED");
    expect(r.stdout).toContain("request-input:DENIED");
    // Nothing had materialized undici between capwall's module evaluation and install(), so no
    // `Request` existed to tamper with and there is nothing to warn about.
    expect(r.stderr).not.toContain("CAPWALL_GLOBAL_EGRESS=0 is set");
  });

  it("warns when undici was already materialized, and still guards both input shapes", async () => {
    const r = await runEmbedder("materialize");
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("string-input:DENIED");
    expect(r.stdout).toContain("request-input:DENIED");
    expect(r.stderr).toContain("CAPWALL_GLOBAL_EGRESS=0 is set");
    expect(r.stderr).toContain("cannot prove the getter it captured is Node's own");
  });
});
