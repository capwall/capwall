/**
 * End-to-end tests for the fs vertical slice: require patch → attribution → fs shim →
 * evaluate. Uses a vendored fixture "dependency" (test/fixtures/node_modules/fixture-dep)
 * so attribution resolves a real node_modules path.
 *
 * Includes the REQUIRED regression from AGENTS.md § 7: a package NOT in the policy is
 * denied fs access in enforce mode (deny-by-default) and merely logged in observe mode.
 *
 * Patched windows are kept tight and synchronous (install → require fresh → call →
 * uninstall) so the loader patch never affects vitest's own machinery.
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  install,
  loadPolicyFromObject,
  type Decision,
  type Policy,
} from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");

interface FixtureDep {
  readData(): string;
  readDataAsync(): Promise<string>;
  writeFile(target: string): void;
  readViaStreamClass(): Promise<string>;
  probeExists(): boolean;
}

/** Require the fixture fresh (cache cleared) so its top-level require("fs") re-runs. */
function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

const emptyEnforcePolicy = (): Policy =>
  loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: here });

type Recorded = { pkg: string; decision: Decision };

/** Run `fn` inside a tight install window, collecting every decision. */
function withCapwall<T>(policy: Policy, mode: "observe" | "enforce", fn: (dep: FixtureDep) => T): { result: T; decisions: Recorded[] } {
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

describe("fs slice — enforce mode denies by default", () => {
  it("denies fs read to a package with no policy entry (REQUIRED regression)", () => {
    const { decisions } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) => {
      expect(() => dep.readData()).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.pkg).toBe("fixture-dep");
    expect(decisions[0]!.decision.allowed).toBe(false);
    expect(decisions[0]!.decision.reason).toMatch(/deny-by-default/);
  });

  it("rejects (not throws) on the fs/promises surface", async () => {
    const { result } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) =>
      dep.readDataAsync(),
    );
    await expect(result).rejects.toMatchObject({ name: "CapabilityError" });
  });

  it("denies app-root code too when '<app>' has no grant", () => {
    withCapwall(emptyEnforcePolicy(), "enforce", () => {
      const shimmedFs = requireCjs("fs") as typeof import("node:fs");
      expect(() => shimmedFs.readFileSync(path.join(FIXTURE, "data.txt"))).toThrowError(
        expect.objectContaining({ name: "CapabilityError", pkg: "<app>" }),
      );
    });
  });

  it("allows a granted read and still denies writes", () => {
    const policy = loadPolicyFromObject(
      {
        version: 1,
        mode: "enforce",
        packages: { "fixture-dep": { fs: { read: ["./fixtures/**"], write: [] } } },
      },
      { projectRoot: here },
    );
    const { result, decisions } = withCapwall(policy, "enforce", (dep) => {
      const data = dep.readData();
      expect(() => dep.writeFile(path.join(here, "fixtures", "nope.txt"))).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
      return data;
    });
    expect(result).toBe("fixture data\n");
    expect(decisions.map((d) => d.decision.allowed)).toEqual([true, false]);
  });
});

describe("fs slice — observe mode never blocks", () => {
  it("allows an ungranted read, but records the decision (attributed)", () => {
    const { result, decisions } = withCapwall(emptyEnforcePolicy(), "observe", (dep) =>
      dep.readData(),
    );
    expect(result).toBe("fixture data\n");
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.pkg).toBe("fixture-dep");
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(decisions[0]!.decision.observed).toMatchObject({
      kind: "fs",
      access: "read",
    });
  });
});

describe("fs slice — stream-class + existence-probe surfaces (review findings)", () => {
  it("mediates `new fs.ReadStream(path)` (not just createReadStream) in enforce", async () => {
    // Regression: the stream CONSTRUCTOR was a full read bypass — it must be denied too.
    const { result } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) =>
      dep.readViaStreamClass(),
    );
    await expect(result).rejects.toMatchObject({ name: "CapabilityError" });
  });

  it("allows `new fs.ReadStream(path)` when the read is granted", async () => {
    const policy = loadPolicyFromObject(
      {
        version: 1,
        mode: "enforce",
        packages: { "fixture-dep": { fs: { read: ["./fixtures/**"], write: [] } } },
      },
      { projectRoot: here },
    );
    const { result } = withCapwall(policy, "enforce", (dep) => dep.readViaStreamClass());
    await expect(result).resolves.toBe("fixture data\n");
  });

  it("also mediates the deprecated FileReadStream alias (same bypass class)", () => {
    withCapwall(emptyEnforcePolicy(), "enforce", () => {
      const fs = requireCjs("fs") as typeof import("node:fs") & {
        FileReadStream?: new (p: string) => unknown;
      };
      if (typeof fs.FileReadStream !== "function") return; // alias not present on this Node
      expect(() => new fs.FileReadStream!(path.join(FIXTURE, "data.txt"))).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("existsSync returns false (never throws) for a denied probe in enforce", () => {
    // Regression: existsSync is contractually non-throwing; a denial must return false.
    const { result, decisions } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) =>
      dep.probeExists(),
    );
    expect(result).toBe(false);
    expect(decisions[0]!.decision.allowed).toBe(false); // still recorded as a denial
  });

  it("existsSync returns the real answer when granted", () => {
    const policy = loadPolicyFromObject(
      {
        version: 1,
        mode: "enforce",
        packages: { "fixture-dep": { fs: { read: ["./fixtures/**"], write: [] } } },
      },
      { projectRoot: here },
    );
    const { result } = withCapwall(policy, "enforce", (dep) => dep.probeExists());
    expect(result).toBe(true);
  });
});

describe("fs slice — uninstall restores the loader", () => {
  it("a fresh require after uninstall gets the real fs (no denials)", () => {
    withCapwall(emptyEnforcePolicy(), "enforce", () => undefined); // install + uninstall
    const dep = loadFixtureFresh();
    expect(dep.readData()).toBe("fixture data\n"); // would throw if still shimmed+enforced
  });
});
