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
import * as nodeFs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  install,
  loadPolicyFromObject,
  type Decision,
  type Policy,
} from "../src/index.js";
import { createFsShim } from "../src/shims/fs.js";

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

/** Build a shim directly against `createFsShim`, bypassing the require loader entirely. */
function directShim(
  policy: Policy,
  mode: "observe" | "enforce",
): { shim: ReturnType<typeof createFsShim>; decisions: Recorded[] } {
  const decisions: Recorded[] = [];
  const shim = createFsShim({
    policy,
    mode,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
    projectRoot: here,
  });
  return { shim, decisions };
}

describe("fs slice — denial delivery matches the real API's error channel (#16)", () => {
  it("a denied callback-style method (readFile) delivers CapabilityError via the callback, not a synchronous throw", async () => {
    const { shim } = directShim(emptyEnforcePolicy(), "enforce");
    const target = path.join(FIXTURE, "data.txt");
    let calledSync = false;
    const errPromise = new Promise((resolve) => {
      expect(() => {
        shim.readFile(target, "utf8", (err: unknown) => {
          calledSync = true;
          resolve(err);
        });
      }).not.toThrow();
    });
    // Must not have fired before this synchronous call returns — it's process.nextTick'd.
    expect(calledSync).toBe(false);
    const err = await errPromise;
    expect(err).toMatchObject({ name: "CapabilityError" });
  });

  it("falls back to a synchronous throw for a callback-style mis-call (no callback arg) — matches real Node", () => {
    const { shim } = directShim(emptyEnforcePolicy(), "enforce");
    const target = path.join(FIXTURE, "data.txt");
    expect(() => (shim.readFile as unknown as (p: string, enc: string) => void)(target, "utf8")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });

  it("a denied createReadStream emits 'error' asynchronously, not a synchronous throw", async () => {
    const { shim } = directShim(emptyEnforcePolicy(), "enforce");
    const target = path.join(FIXTURE, "data.txt");
    let stream: nodeFs.ReadStream | undefined;
    expect(() => {
      stream = shim.createReadStream(target);
    }).not.toThrow();
    const err = await new Promise((resolve, reject) => {
      stream!.on("data", () => reject(new Error("should not emit data on a denied stream")));
      stream!.on("error", resolve);
    });
    expect(err).toMatchObject({ name: "CapabilityError" });
  });

  it("a denied createWriteStream emits 'error' asynchronously, not a synchronous throw", async () => {
    const { shim } = directShim(emptyEnforcePolicy(), "enforce");
    const target = path.join(here, "fixtures", "nope-write.txt");
    let stream: nodeFs.WriteStream | undefined;
    expect(() => {
      stream = shim.createWriteStream(target);
    }).not.toThrow();
    const err = await new Promise((resolve, reject) => {
      stream!.on("finish", () => reject(new Error("should not finish a denied stream")));
      stream!.on("error", resolve);
    });
    expect(err).toMatchObject({ name: "CapabilityError" });
    expect(nodeFs.existsSync(target)).toBe(false); // nothing was actually written
  });

  it("*Sync methods still throw synchronously on denial (unchanged)", () => {
    const { shim } = directShim(emptyEnforcePolicy(), "enforce");
    expect(() => shim.readFileSync(path.join(FIXTURE, "data.txt"))).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });

  it("fs.promises methods still reject on denial (unchanged)", async () => {
    const { shim } = directShim(emptyEnforcePolicy(), "enforce");
    await expect(shim.promises.readFile(path.join(FIXTURE, "data.txt"))).rejects.toMatchObject({
      name: "CapabilityError",
    });
  });
});

/** Attach-timing strategies for the #40 catch-window matrix: sync/microtask/macrotasks. */
type Schedule = (attach: () => void) => void;
const attachTimings: Array<[string, Schedule]> = [
  ["synchronously", (attach: () => void): void => attach()],
  ["on a microtask", (attach: () => void): void => void Promise.resolve().then(attach)],
  ["on setImmediate", (attach: () => void): void => void setImmediate(attach)],
  ["on setTimeout(0)", (attach: () => void): void => void setTimeout(attach, 0)],
];

describe("fs slice — deny-stream 'error' delivered whenever a handler attaches, not on a fixed timer (#40)", () => {
  // The old fixed `setImmediate` delivery had a bounded catch window: a handler attached on
  // a LATER macrotask (e.g. setTimeout(0)) could register after the timer already fired,
  // missing the event → uncaught 'error' crash. The fix holds the error until a handler
  // attaches (any time), so every attach timing below must catch it.
  it.each(attachTimings)("createReadStream: a handler attached %s still catches the CapabilityError", async (_label, schedule) => {
    const { shim } = directShim(emptyEnforcePolicy(), "enforce");
    const target = path.join(FIXTURE, "data.txt");
    const stream = shim.createReadStream(target);
    const err = await new Promise((resolve) => {
      schedule(() => stream.on("error", resolve));
    });
    expect(err).toMatchObject({ name: "CapabilityError" });
    expect((stream as unknown as { path: string }).path).toBe(target); // stream.path preserved
  });

  it.each(attachTimings)("createWriteStream: a handler attached %s still catches the CapabilityError", async (_label, schedule) => {
    const { shim } = directShim(emptyEnforcePolicy(), "enforce");
    const target = path.join(here, "fixtures", "nope-write-40.txt");
    const stream = shim.createWriteStream(target);
    const err = await new Promise((resolve) => {
      schedule(() => stream.on("error", resolve));
    });
    expect(err).toMatchObject({ name: "CapabilityError" });
    expect((stream as unknown as { path: string }).path).toBe(target); // stream.path preserved
    expect(nodeFs.existsSync(target)).toBe(false); // still fail-closed — nothing written
  });

  it("delivers exactly once even with multiple 'error' listeners attached (no duplicate delivery)", async () => {
    const { shim } = directShim(emptyEnforcePolicy(), "enforce");
    const target = path.join(FIXTURE, "data.txt");
    const stream = shim.createReadStream(target);
    let fireCount1 = 0;
    let fireCount2 = 0;
    const [err1, err2] = await Promise.all([
      new Promise((resolve) => stream.on("error", (e) => (fireCount1++, resolve(e)))),
      new Promise((resolve) => stream.on("error", (e) => (fireCount2++, resolve(e)))),
    ]);
    expect(err1).toMatchObject({ name: "CapabilityError" });
    expect(err2).toMatchObject({ name: "CapabilityError" });
    // Give any stray extra emission a chance to land before asserting exactly-once.
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(fireCount1).toBe(1);
    expect(fireCount2).toBe(1);
  });

  it("still surfaces (crashes) an unhandled denial when NO 'error' listener is ever attached — not silently swallowed", async () => {
    const { shim } = directShim(emptyEnforcePolicy(), "enforce");
    const target = path.join(FIXTURE, "data.txt");
    const caught = await new Promise((resolve) => {
      process.once("uncaughtException", resolve);
      shim.createReadStream(target); // never attach an 'error' listener
    });
    expect(caught).toMatchObject({ name: "CapabilityError" });
  });
});

describe("fs slice — Buffer path fidelity (#19)", () => {
  it("decodes a non-UTF-8 Buffer path losslessly (latin1) for the policy check", () => {
    const { shim, decisions } = directShim(emptyEnforcePolicy(), "observe");
    // 0xFF is not a valid standalone UTF-8 byte; a "utf8" decode would collapse it to U+FFFD,
    // making the checked path diverge from the bytes actually forwarded to real fs.
    const weird = Buffer.from([0x2f, 0x66, 0x6f, 0x6f, 0xff, 0x2e, 0x74, 0x78, 0x74]); // "/foo\xFF.txt"
    try {
      shim.readFileSync(weird as unknown as string);
    } catch {
      // A real ENOENT from real fs is expected and irrelevant — observe mode never denies.
    }
    expect(decisions).toHaveLength(1);
    const expected = path.resolve(weird.toString("latin1")).split(path.sep).join("/");
    const observed = decisions[0]!.decision.observed as { kind: string; path: string };
    expect(observed).toMatchObject({ kind: "fs", path: expected });
    // The exact byte round-tripped — a lossy utf8 decode would have produced U+FFFD instead.
    expect(observed.path).toContain("ÿ");
    expect(observed.path).not.toContain("�");
  });
});

describe("fs slice — fs.access W_OK classification (#20)", () => {
  it("classifies a W_OK probe as write: denied by a read-only grant, allowed by a write grant", () => {
    const target = path.join(FIXTURE, "data.txt");
    const readOnly = loadPolicyFromObject(
      {
        version: 1,
        mode: "enforce",
        packages: { "<app>": { fs: { read: ["./fixtures/**"], write: [] } } },
      },
      { projectRoot: here },
    );
    const { shim: shimReadOnly, decisions } = directShim(readOnly, "enforce");
    expect(() => shimReadOnly.accessSync(target, nodeFs.constants.W_OK)).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "fs", access: "write" });

    const withWrite = loadPolicyFromObject(
      {
        version: 1,
        mode: "enforce",
        packages: { "<app>": { fs: { read: [], write: ["./fixtures/**"] } } },
      },
      { projectRoot: here },
    );
    const { shim: shimWrite } = directShim(withWrite, "enforce");
    expect(() => shimWrite.accessSync(target, nodeFs.constants.W_OK)).not.toThrow();
  });

  it("a plain existence probe (no mode arg) still classifies as read", () => {
    const target = path.join(FIXTURE, "data.txt");
    const readOnly = loadPolicyFromObject(
      {
        version: 1,
        mode: "enforce",
        packages: { "<app>": { fs: { read: ["./fixtures/**"], write: [] } } },
      },
      { projectRoot: here },
    );
    const { shim, decisions } = directShim(readOnly, "enforce");
    expect(() => shim.accessSync(target)).not.toThrow();
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "fs", access: "read" });
  });
});
