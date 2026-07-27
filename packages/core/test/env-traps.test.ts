/**
 * Regression tests for the `process.env` Proxy TRAPS, as opposed to the read policy itself
 * (that lives in env.test.ts). Two bugs, both proxy-semantics rather than policy:
 *
 *  - #66 — with no `set` trap, `proxy.K = v` on a key the target ALREADY has completes as
 *    `receiver.[[DefineOwnProperty]](K, {[[Value]]: v})`, a partial descriptor that Node's
 *    `process.env` handler rejects with `ERR_INVALID_OBJECT_DEFINE_PROPERTY`. Any dependency
 *    writing to an already-set env var crashed the host app. These tests fail on `main`.
 *
 *  - #67 — `Object.keys` / `for..in` call `[[GetOwnProperty]]` once per key (to read
 *    `[[Enumerable]]`), so the gated `getOwnPropertyDescriptor` trap recorded enumeration as a
 *    value read of EVERY key in the environment. These tests pin the fix: enumeration records
 *    nothing, value reads still record, and the descriptor hole stays shut.
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
  envKeys(): string[];
  envForInKeys(): string[];
  envOwnPropertyNames(): string[];
  envJson(): string;
  envSpread(): Record<string, string | undefined>;
  envEntries(): Array<[string, string | undefined]>;
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
const ALL_KEYS = [EXISTING, SECRET, FRESH, "FIXTURE_TRAPS_HOST_A", "FIXTURE_TRAPS_HOST_B"];

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
});

describe("env shim — enumeration is a NAME-level operation: ungated, unrecorded (#67)", () => {
  it("Object.keys returns the un-shimmed key set and records NOTHING", () => {
    const baseline = unshimmed((dep) => dep.envKeys()).sort();
    const { result, decisions } = withCapwall(enforce([]), "enforce", (dep) => dep.envKeys());
    expect(result.sort()).toEqual(baseline);
    expect(result).toContain(SECRET); // the NAME is still visible — documented behavior
    expect(recordedEnvKeys(decisions)).toEqual([]); // ...but it is not a recorded value read
  });

  it("for..in returns the un-shimmed key set and records NOTHING", () => {
    const baseline = unshimmed((dep) => dep.envForInKeys()).sort();
    const { result, decisions } = withCapwall(enforce([]), "enforce", (dep) => dep.envForInKeys());
    expect(result.sort()).toEqual(baseline);
    expect(recordedEnvKeys(decisions)).toEqual([]);
  });

  it("Object.getOwnPropertyNames returns the un-shimmed key set and records NOTHING", () => {
    const baseline = unshimmed((dep) => dep.envOwnPropertyNames()).sort();
    const { result, decisions } = withCapwall(enforce([]), "enforce", (dep) =>
      dep.envOwnPropertyNames(),
    );
    expect(result.sort()).toEqual(baseline);
    expect(recordedEnvKeys(decisions)).toEqual([]);
  });

  it("what observe records is a property of the PACKAGE, not of the host environment", () => {
    // The #67 headline: the same enumerating package on two machines must produce the same
    // policy. Before the fix this recorded every key the host happened to export.
    const enumerateWith = (extraKey: string): string[] => {
      process.env[extraKey] = "host-specific";
      try {
        const { decisions } = withCapwall(enforce([]), "observe", (dep) => dep.envKeys());
        return recordedEnvKeys(decisions);
      } finally {
        delete process.env[extraKey];
      }
    };
    expect(enumerateWith("FIXTURE_TRAPS_HOST_A")).toEqual(enumerateWith("FIXTURE_TRAPS_HOST_B"));
    expect(enumerateWith("FIXTURE_TRAPS_HOST_A")).toEqual([]);
  });
});

describe("env shim — value reads stay gated AND recorded (#67 must not weaken the gate)", () => {
  it("JSON.stringify omits denied values and records every key it actually read", () => {
    const { result, decisions } = withCapwall(enforce([]), "enforce", (dep) => dep.envJson());
    const parsed = JSON.parse(result) as Record<string, unknown>;
    // Denied values come back undefined, and JSON.stringify drops undefined-valued properties.
    expect(Object.hasOwn(parsed, SECRET)).toBe(false);
    expect(recordedEnvKeys(decisions)).toContain(SECRET); // a real value read — correctly logged

    const baseline = JSON.parse(unshimmed((dep) => dep.envJson())) as Record<string, unknown>;
    expect(baseline[SECRET]).toBe("s3cr3t"); // un-shimmed would have leaked it
  });

  it("JSON.stringify passes through values the dependency IS granted", () => {
    const { result } = withCapwall(enforce([SECRET]), "enforce", (dep) => dep.envJson());
    expect((JSON.parse(result) as Record<string, unknown>)[SECRET]).toBe("s3cr3t");
  });

  it("spread keeps the key but hides the denied value, and records it", () => {
    const { result, decisions } = withCapwall(enforce([]), "enforce", (dep) => dep.envSpread());
    expect(Object.hasOwn(result, SECRET)).toBe(true); // CopyDataProperties creates the property
    expect(result[SECRET]).toBeUndefined();
    expect(recordedEnvKeys(decisions)).toContain(SECRET);
    expect(unshimmed((dep) => dep.envSpread())[SECRET]).toBe("s3cr3t");
  });

  it("Object.entries hides the denied value and records it", () => {
    const { result, decisions } = withCapwall(enforce([]), "enforce", (dep) => dep.envEntries());
    expect(result.find(([k]) => k === SECRET)?.[1]).toBeUndefined();
    expect(recordedEnvKeys(decisions)).toContain(SECRET);
  });

  it("getOwnPropertyDescriptor STILL hides the value — the exfiltration hole stays shut", () => {
    // The reason the descriptor trap is gated at all. #67 dropped its RECORDING, never its
    // hiding: this must keep failing for an attacker.
    const { result } = withCapwall(enforce([]), "enforce", (dep) => dep.readEnvDescriptor(SECRET));
    expect(result?.value).toBeUndefined();
    expect(unshimmed((dep) => dep.readEnvDescriptor(SECRET))?.value).toBe("s3cr3t");
  });

  it("the hidden descriptor stays enumerable, so Object.keys still lists the key", () => {
    const { result } = withCapwall(enforce([]), "enforce", (dep) => dep.readEnvDescriptor(SECRET));
    expect(result?.enumerable).toBe(true);
    expect(result?.configurable).toBe(true);
  });

  it("getOwnPropertyDescriptor of a GRANTED key matches un-shimmed exactly", () => {
    const { result } = withCapwall(enforce([SECRET]), "enforce", (dep) =>
      dep.readEnvDescriptor(SECRET),
    );
    expect(result).toEqual(unshimmed((dep) => dep.readEnvDescriptor(SECRET)));
  });

  it("a direct read is still denied and still recorded", () => {
    const { result, decisions } = withCapwall(enforce([]), "enforce", (dep) => dep.readEnv(SECRET));
    expect(result).toBeUndefined();
    expect(recordedEnvKeys(decisions)).toEqual([SECRET]);
  });
});
