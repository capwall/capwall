/**
 * Tests for the process.env read shim (roadmap M4, issue #8): the anti-exfiltration control.
 *
 * install() replaces process.env with a read-gating Proxy. A dependency (attributed to
 * "fixture-dep") reading a non-granted env key is denied in enforce / logged in observe;
 * app-and-internal reads (attributed to <app>) pass through ungated by design.
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { install, loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");

interface FixtureDep {
  readEnv(key: string): string | undefined;
}

function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

type Recorded = { pkg: string; decision: Decision };

/** Install with env gating, run fn, always uninstall (restore process.env). */
function withCapwall<T>(
  policy: Policy,
  mode: "observe" | "enforce",
  fn: (dep: FixtureDep) => T,
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

const SECRET = "FIXTURE_SECRET_XYZ";
process.env[SECRET] = "s3cr3t";
process.env["FIXTURE_OK"] = "fine";

afterEach(() => {
  // Guard: process.env must be restored to the real object after each test.
  expect(typeof process.env[SECRET]).toBe("string");
});

const enforce = (env: string[] = []): Policy =>
  loadPolicyFromObject(
    { version: 1, mode: "enforce", packages: { "fixture-dep": { env } } },
    { projectRoot: here },
  );

describe("env shim — enforce (soft deny: hide value, never throw)", () => {
  it("hides an env key a dependency was not granted (returns undefined, no throw)", () => {
    const { decisions } = withCapwall(enforce([]), "enforce", (dep) => {
      expect(dep.readEnv(SECRET)).toBeUndefined();
    });
    const rec = decisions.find((d) => d.pkg === "fixture-dep");
    expect(rec?.decision.allowed).toBe(false); // the denial is still recorded/logged
  });

  it("allows a granted key and hides a different one", () => {
    const { decisions } = withCapwall(enforce(["FIXTURE_OK"]), "enforce", (dep) => {
      expect(dep.readEnv("FIXTURE_OK")).toBe("fine");
      expect(dep.readEnv(SECRET)).toBeUndefined();
    });
    expect(decisions.some((d) => d.decision.allowed)).toBe(true);
    expect(decisions.some((d) => !d.decision.allowed)).toBe(true);
  });

  it("honors the '*' wildcard grant", () => {
    withCapwall(enforce(["*"]), "enforce", (dep) => {
      expect(dep.readEnv(SECRET)).toBe("s3cr3t");
    });
  });

  it("does NOT gate app/internal reads (attributed to <app>)", () => {
    // Deny-by-default policy, but a read from THIS test file attributes to <app>.
    withCapwall(enforce([]), "enforce", () => {
      expect(process.env[SECRET]).toBe("s3cr3t"); // not gated, not thrown
    });
  });

  it("closes the getOwnPropertyDescriptor(...).value exfiltration path", () => {
    withCapwall(enforce([]), "enforce", (dep) => {
      const dep2 = dep as unknown as { readEnvDescriptor(k: string): PropertyDescriptor | undefined };
      const desc = dep2.readEnvDescriptor(SECRET);
      expect(desc?.value).toBeUndefined(); // value hidden, not leaked
    });
  });

  it("never gates or records CAPWALL_* plumbing keys", () => {
    process.env["CAPWALL_FAKE_PLUMBING"] = "internal";
    const { decisions } = withCapwall(enforce([]), "enforce", (dep) => {
      expect(dep.readEnv("CAPWALL_FAKE_PLUMBING")).toBe("internal"); // passed through
    });
    expect(decisions.some((d) => d.decision.observed.kind === "env")).toBe(false);
    delete process.env["CAPWALL_FAKE_PLUMBING"];
  });
});

describe("env shim — observe never blocks", () => {
  it("allows the read but records the attributed env request", () => {
    const { result, decisions } = withCapwall(enforce([]), "observe", (dep) =>
      dep.readEnv(SECRET),
    );
    expect(result).toBe("s3cr3t");
    const rec = decisions.find((d) => d.pkg === "fixture-dep");
    expect(rec?.decision.observed).toMatchObject({ kind: "env", key: SECRET });
  });
});

describe("env shim — uninstall restores process.env", () => {
  it("after uninstall, a dependency read is no longer gated", () => {
    withCapwall(enforce([]), "enforce", () => undefined);
    const dep = loadFixtureFresh();
    expect(dep.readEnv(SECRET)).toBe("s3cr3t"); // would throw if proxy still installed
  });
});
