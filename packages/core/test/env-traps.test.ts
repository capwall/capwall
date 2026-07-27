/**
 * Regression tests for the `process.env` Proxy TRAPS, as opposed to the read policy itself
 * (that lives in env.test.ts).
 *
 * #66 — with no `set` trap, `proxy.K = v` on a key the target ALREADY has completes as
 * `receiver.[[DefineOwnProperty]](K, {[[Value]]: v})`, a partial descriptor that Node's
 * `process.env` handler rejects with `ERR_INVALID_OBJECT_DEFINE_PROPERTY`. Any dependency
 * writing to an already-set env var crashed the host app. These tests fail on `main`.
 *
 * Method: every assertion that should agree with plain Node is checked against the SAME fixture
 * code run OUTSIDE the capwall window (`unshimmed()`), so the baseline is real `process.env`
 * behavior rather than a hand-written expectation.
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { install, loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");

/** The subset of fixture-dep exercised here (see fixtures/.../index.js for each helper). */
interface EnvFixture {
  readEnv(key: string): string | undefined;
  readEnvDescriptor(key: string): PropertyDescriptor | undefined;
  setEnv(key: string, value: unknown): void;
  assignEnv(key: string, value: unknown): void;
  appendEnv(key: string, suffix: string): void;
  setEnvSymbol(): void;
  deleteEnv(key: string): boolean;
  defineEnv(key: string, value: string): void;
  definePartialEnv(key: string, value: string): void;
  hasEnv(key: string): boolean;
}

function loadFixtureFresh(): EnvFixture {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as unknown as EnvFixture;
}

type Recorded = { pkg: string; decision: Decision };

/** Run `fn` with capwall installed (env gate on), always uninstalling afterwards. */
function withCapwall<T>(
  policy: Policy,
  mode: "observe" | "enforce",
  fn: (dep: EnvFixture) => T,
): { result: T; decisions: Recorded[] } {
  const decisions: Recorded[] = [];
  const handle = install(policy, mode, {
    projectRoot: here,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
  });
  try {
    return { result: fn(loadFixtureFresh()), decisions };
  } finally {
    handle.uninstall();
  }
}

/** The same fixture code against the REAL `process.env` — the un-shimmed Node baseline. */
function unshimmed<T>(fn: (dep: EnvFixture) => T): T {
  return fn(loadFixtureFresh());
}

/** Env keys the shim reported for the dependency, sorted — the trace/gen-policy input. */
function recordedEnvKeys(decisions: Recorded[]): string[] {
  return decisions
    .filter((d) => d.pkg === "fixture-dep" && d.decision.observed.kind === "env")
    .map((d) => (d.decision.observed as { kind: "env"; key: string }).key)
    .sort();
}

const EXISTING = "FIXTURE_TRAPS_EXISTING";
const SECRET = "FIXTURE_TRAPS_SECRET";
const FRESH = "FIXTURE_TRAPS_FRESH";
const ALL_KEYS = [EXISTING, SECRET, FRESH];

beforeEach(() => {
  process.env[EXISTING] = "orig";
  process.env[SECRET] = "s3cr3t";
  delete process.env[FRESH];
});

afterEach(() => {
  // Guard: process.env must be the real object again (a leaked proxy would poison later tests).
  expect(process.env[SECRET]).toBe("s3cr3t");
  for (const k of ALL_KEYS) delete process.env[k];
});

/** Deny-by-default enforce policy, optionally granting `env` keys to fixture-dep. */
const enforce = (env: string[] = []): Policy =>
  loadPolicyFromObject(
    { version: 1, mode: "enforce", packages: { "fixture-dep": { env } } },
    { projectRoot: here },
  );

describe("env shim — writes reach the real environment (#66)", () => {
  it("assigns to an ALREADY-SET key without throwing", () => {
    // The bug: this threw ERR_INVALID_OBJECT_DEFINE_PROPERTY before the `set` trap existed.
    withCapwall(enforce([]), "enforce", (dep) => dep.setEnv(EXISTING, "changed"));
    expect(process.env[EXISTING]).toBe("changed"); // landed on the REAL env, not a proxy copy
  });

  it("assigns to a NEW key (the path that always worked — kept as a control)", () => {
    withCapwall(enforce([]), "enforce", (dep) => dep.setEnv(FRESH, "created"));
    expect(process.env[FRESH]).toBe("created");
  });

  it("accepts Object.assign onto an already-set key", () => {
    withCapwall(enforce([]), "enforce", (dep) => dep.assignEnv(EXISTING, "via-assign"));
    expect(process.env[EXISTING]).toBe("via-assign");
  });

  it("supports compound assignment (get+set) on a granted key", () => {
    withCapwall(enforce([EXISTING]), "enforce", (dep) => dep.appendEnv(EXISTING, "-x"));
    expect(process.env[EXISTING]).toBe("orig-x");
  });

  it("composes with soft deny: += on a DENIED key writes the hidden read back, never throws", () => {
    // Documented consequence of soft deny (read yields undefined), not a separate bug: the
    // point is that it does not crash, and the write still reaches the real environment.
    withCapwall(enforce([]), "enforce", (dep) => dep.appendEnv(EXISTING, "-x"));
    expect(process.env[EXISTING]).toBe("undefined-x");
  });

  it("coerces non-string values exactly like un-shimmed process.env", () => {
    withCapwall(enforce([]), "enforce", (dep) => dep.setEnv(FRESH, 5));
    const shimmed = process.env[FRESH];
    delete process.env[FRESH];
    unshimmed((dep) => dep.setEnv(FRESH, 5));
    expect(shimmed).toBe(process.env[FRESH]);
    expect(shimmed).toBe("5");
  });

  it("throws the same TypeError as un-shimmed process.env for a symbol key", () => {
    const baseline = (() => {
      try {
        unshimmed((dep) => dep.setEnvSymbol());
        return null;
      } catch (err) {
        return (err as Error).message;
      }
    })();
    expect(baseline).toMatch(/Symbol/);
    expect(() => withCapwall(enforce([]), "enforce", (dep) => dep.setEnvSymbol())).toThrow(
      baseline as string,
    );
  });

  it("does NOT gate or record writes — the policy is a READ allowlist", () => {
    // Deny-by-default: the write still succeeds, and nothing lands in the trace. Recording it
    // would be actively harmful — gen-policy merges every observed {kind:"env"} into the
    // package's READ allowlist, so an observed write would silently widen read access.
    const { decisions } = withCapwall(enforce([]), "enforce", (dep) => {
      dep.setEnv(FRESH, "written-by-a-denied-dep");
    });
    expect(process.env[FRESH]).toBe("written-by-a-denied-dep");
    expect(recordedEnvKeys(decisions)).toEqual([]);
  });

  it("still lets app code (<app>) write through the proxy", () => {
    withCapwall(enforce([]), "enforce", () => {
      process.env[EXISTING] = "by-the-app";
      expect(process.env[EXISTING]).toBe("by-the-app");
    });
  });
});

describe("env shim — the other traps match un-shimmed process.env", () => {
  it("delete removes the key and returns true, like un-shimmed", () => {
    const shimmed = withCapwall(enforce([]), "enforce", (dep) => dep.deleteEnv(EXISTING));
    expect(shimmed.result).toBe(true);
    expect(process.env[EXISTING]).toBeUndefined();

    process.env[EXISTING] = "orig";
    expect(unshimmed((dep) => dep.deleteEnv(EXISTING))).toBe(true);
    expect(process.env[EXISTING]).toBeUndefined();
  });

  it("Object.defineProperty with a full data descriptor works", () => {
    withCapwall(enforce([]), "enforce", (dep) => dep.defineEnv(FRESH, "defined"));
    expect(process.env[FRESH]).toBe("defined");
  });

  it("Object.defineProperty with a PARTIAL descriptor throws — un-shimmed does too", () => {
    // Parity check, not a capwall rule: real process.env rejects partial descriptors, so the
    // proxy must too. This is the same rejection that #66's missing `set` trap tripped into.
    expect(() => unshimmed((dep) => dep.definePartialEnv(FRESH, "x"))).toThrow(
      /configurable, writable, and enumerable/,
    );
    expect(() =>
      withCapwall(enforce([]), "enforce", (dep) => dep.definePartialEnv(FRESH, "x")),
    ).toThrow(/configurable, writable, and enumerable/);
  });

  it("`in` reports a denied key as present and records nothing (names are not the secret)", () => {
    const { result, decisions } = withCapwall(enforce([]), "enforce", (dep) => dep.hasEnv(SECRET));
    expect(result).toBe(true);
    expect(result).toBe(unshimmed((dep) => dep.hasEnv(SECRET)));
    expect(recordedEnvKeys(decisions)).toEqual([]);
  });

  it("getOwnPropertyDescriptor still hides a denied value (unchanged by this fix)", () => {
    const { result } = withCapwall(enforce([]), "enforce", (dep) => dep.readEnvDescriptor(SECRET));
    expect(result?.value).toBeUndefined();
    expect(unshimmed((dep) => dep.readEnvDescriptor(SECRET))?.value).toBe("s3cr3t");
  });
});
