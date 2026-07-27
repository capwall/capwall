/**
 * Table-driven fs-shim method coverage (issue #23). Complements fs-slice.test.ts, which
 * covers the core loop + denial-delivery channels in depth for a handful of methods. This
 * file broadens the SURFACE covered: for each wrapped method it asserts the shim attributes
 * + evaluates the RIGHT access ("read" vs "write") on the RIGHT path argument — deny-by-
 * default denies it in enforce, and a matching grant allows it (or, where performing the
 * real operation would require extra fixture setup with little added signal, at minimum
 * that the decision records the expected `{access, path}` via the onDecision sink, per the
 * issue's stated bar).
 *
 * Uses the same vendored fixture-dep pattern as fs-slice.test.ts (a real node_modules
 * "dependency" so attribution resolves to "fixture-dep", not "<app>").
 */
import { createRequire } from "node:module";
import * as nodeFs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  install,
  loadPolicyFromObject,
  type Decision,
  type Policy,
} from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");
const DATA = path.join(FIXTURE, "data.txt");
const SCRATCH = path.join(here, "fixtures", "scratch");

interface FixtureDep {
  mkdtempSync(prefix: string): string;
  cpSync(src: string, dest: string): void;
  copyFileSync(src: string, dest: string): void;
  renameSync(oldPath: string, newPath: string): void;
  linkSync(existingPath: string, newPath: string): void;
  symlinkSync(target: string, linkPath: string): void;
  openSync(target: string, flags: string | number): boolean;
  watchDir(dir: string): boolean;
  readdirSync(dir: string): string[];
  realpathSync(target: string): string;
  statSync(target: string): unknown;
  statSyncBuffer(target: string): unknown;
  statSyncUrl(target: string): unknown;
}

function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

const emptyEnforcePolicy = (): Policy =>
  loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: here });

const grantPolicy = (read: string[], write: string[]): Policy =>
  loadPolicyFromObject(
    { version: 1, mode: "enforce", packages: { "fixture-dep": { fs: { read, write } } } },
    { projectRoot: here },
  );

type Recorded = { pkg: string; decision: Decision };

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

function expectDenied(decisions: Recorded[], index: number, access: "read" | "write"): void {
  expect(decisions[index]!.pkg).toBe("fixture-dep");
  expect(decisions[index]!.decision.allowed).toBe(false);
  expect(decisions[index]!.decision.observed).toMatchObject({ kind: "fs", access });
}

function expectAllowed(decisions: Recorded[], index: number, access: "read" | "write"): void {
  expect(decisions[index]!.pkg).toBe("fixture-dep");
  expect(decisions[index]!.decision.allowed).toBe(true);
  expect(decisions[index]!.decision.observed).toMatchObject({ kind: "fs", access });
}

beforeEach(() => {
  nodeFs.mkdirSync(SCRATCH, { recursive: true });
});
afterEach(() => {
  nodeFs.rmSync(SCRATCH, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------------------
// Simple single-path "read" methods: readdir, realpath, stat, watch (#23 thin coverage).
// ---------------------------------------------------------------------------------------
const simpleReadCases: Array<{ name: string; run: (dep: FixtureDep) => unknown }> = [
  { name: "readdirSync", run: (dep) => dep.readdirSync(FIXTURE) },
  { name: "realpathSync", run: (dep) => dep.realpathSync(DATA) },
  { name: "statSync", run: (dep) => dep.statSync(DATA) },
  { name: "watchDir (fs.watch)", run: (dep) => dep.watchDir(FIXTURE) },
];

// `$name` in the title is interpolated by vitest from the case object, so only `run` is bound.
describe.each(simpleReadCases)("fs method coverage — $name (#23)", ({ run }) => {
  it(`denies by default and records a single read decision`, () => {
    const { decisions } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) => {
      expect(() => run(dep)).toThrowError(expect.objectContaining({ name: "CapabilityError" }));
    });
    expect(decisions).toHaveLength(1);
    expectDenied(decisions, 0, "read");
  });

  it(`allows when read is granted`, () => {
    const policy = grantPolicy(["./fixtures/**"], []);
    const { decisions } = withCapwall(policy, "enforce", (dep) => {
      expect(() => run(dep)).not.toThrow();
    });
    expectAllowed(decisions, 0, "read");
  });
});

// ---------------------------------------------------------------------------------------
// mkdtemp / mkdtempSync — write access on the prefix argument (#23).
// ---------------------------------------------------------------------------------------
describe("fs method coverage — mkdtempSync (#23)", () => {
  it("denies by default and records a write decision on the prefix", () => {
    const prefix = path.join(SCRATCH, "mkd-");
    const { decisions } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) => {
      expect(() => dep.mkdtempSync(prefix)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expect(decisions).toHaveLength(1);
    expectDenied(decisions, 0, "write");
  });

  it("allows and actually creates a directory when write is granted", () => {
    const prefix = path.join(SCRATCH, "mkd-");
    const policy = grantPolicy([], ["./fixtures/**"]);
    const { result, decisions } = withCapwall(policy, "enforce", (dep) => dep.mkdtempSync(prefix));
    expectAllowed(decisions, 0, "write");
    expect(nodeFs.existsSync(result)).toBe(true);
    expect(nodeFs.statSync(result).isDirectory()).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------
// cp/cpSync and copyFile/copyFileSync — COPY spec: index 0 read (src), index 1 write (dest).
// ---------------------------------------------------------------------------------------
for (const method of ["cpSync", "copyFileSync"] as const) {
  describe(`fs method coverage — ${method} (COPY spec, #23)`, () => {
    it("denies with no grants (fails on the read check first)", () => {
      const dest = path.join(SCRATCH, "out.txt");
      const { decisions } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) => {
        expect(() => dep[method](DATA, dest)).toThrowError(
          expect.objectContaining({ name: "CapabilityError" }),
        );
      });
      expect(decisions).toHaveLength(1);
      expectDenied(decisions, 0, "read");
    });

    it("allows the read but denies the write when only read is granted", () => {
      const dest = path.join(SCRATCH, "out.txt");
      const policy = grantPolicy(["./fixtures/**"], []);
      const { decisions } = withCapwall(policy, "enforce", (dep) => {
        expect(() => dep[method](DATA, dest)).toThrowError(
          expect.objectContaining({ name: "CapabilityError" }),
        );
      });
      expect(decisions).toHaveLength(2);
      expectAllowed(decisions, 0, "read");
      expectDenied(decisions, 1, "write");
      expect(nodeFs.existsSync(dest)).toBe(false); // fail-closed — nothing copied
    });

    it("succeeds when both read (src) and write (dest) are granted", () => {
      const dest = path.join(SCRATCH, "out.txt");
      const policy = grantPolicy(["./fixtures/**"], ["./fixtures/**"]);
      const { decisions } = withCapwall(policy, "enforce", (dep) => {
        expect(() => dep[method](DATA, dest)).not.toThrow();
      });
      expect(decisions).toHaveLength(2);
      expectAllowed(decisions, 0, "read");
      expectAllowed(decisions, 1, "write");
      expect(nodeFs.readFileSync(dest, "utf8")).toBe("fixture data\n");
    });
  });
}

// ---------------------------------------------------------------------------------------
// rename/renameSync — RENAME spec: BOTH index 0 and index 1 require WRITE (neither is a
// read check) — a common misclassification bug would be treating oldPath as "read".
// ---------------------------------------------------------------------------------------
describe("fs method coverage — renameSync (RENAME spec, #23)", () => {
  it("denies with only a read grant (oldPath needs write, not read)", () => {
    const src = path.join(SCRATCH, "src.txt");
    const dest = path.join(SCRATCH, "dst.txt");
    nodeFs.writeFileSync(src, "x");
    const policy = grantPolicy(["./fixtures/**"], []); // read-only grant
    const { decisions } = withCapwall(policy, "enforce", (dep) => {
      expect(() => dep.renameSync(src, dest)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expect(decisions).toHaveLength(1);
    expectDenied(decisions, 0, "write"); // NOT "read" — this is the bug this test guards.
  });

  it("succeeds with a write-only grant covering both paths", () => {
    const src = path.join(SCRATCH, "src.txt");
    const dest = path.join(SCRATCH, "dst.txt");
    nodeFs.writeFileSync(src, "x");
    const policy = grantPolicy([], ["./fixtures/**"]); // write-only grant, no read at all
    const { decisions } = withCapwall(policy, "enforce", (dep) => {
      expect(() => dep.renameSync(src, dest)).not.toThrow();
    });
    expect(decisions).toHaveLength(2);
    expectAllowed(decisions, 0, "write");
    expectAllowed(decisions, 1, "write");
    expect(nodeFs.existsSync(dest)).toBe(true);
    expect(nodeFs.existsSync(src)).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------
// link/linkSync — COPY spec: index 0 read (existing), index 1 write (new link).
// ---------------------------------------------------------------------------------------
describe("fs method coverage — linkSync (COPY spec, #23)", () => {
  it("denies with no grants (fails on the read check first)", () => {
    const dest = path.join(SCRATCH, "hardlink.txt");
    const { decisions } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) => {
      expect(() => dep.linkSync(DATA, dest)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expect(decisions).toHaveLength(1);
    expectDenied(decisions, 0, "read");
  });

  it("succeeds when both read (existing) and write (new) are granted", () => {
    const dest = path.join(SCRATCH, "hardlink.txt");
    const policy = grantPolicy(["./fixtures/**"], ["./fixtures/**"]);
    const { decisions } = withCapwall(policy, "enforce", (dep) => {
      expect(() => dep.linkSync(DATA, dest)).not.toThrow();
    });
    expectAllowed(decisions, 0, "read");
    expectAllowed(decisions, 1, "write");
    expect(nodeFs.readFileSync(dest, "utf8")).toBe("fixture data\n");
  });
});

// ---------------------------------------------------------------------------------------
// symlink/symlinkSync — SYMLINK spec: ONLY index 1 (the new link path) is checked; index 0
// (the target string) is arbitrary and not itself resolved/checked.
// ---------------------------------------------------------------------------------------
describe("fs method coverage — symlinkSync (SYMLINK spec, #23)", () => {
  it("denies on the link path only — the target argument is never checked", () => {
    const dest = path.join(SCRATCH, "symlink.txt");
    const { decisions } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) => {
      // target need not exist/resolve — symlink doesn't require it to.
      expect(() => dep.symlinkSync("/nonexistent/wherever/it/points", dest)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expect(decisions).toHaveLength(1); // ONE decision — proves index 0 is not checked at all.
    expectDenied(decisions, 0, "write");
    expect(decisions[0]!.decision.observed).toMatchObject({
      path: expect.stringContaining("symlink.txt"),
    });
  });

  it("succeeds when write is granted for the link path", () => {
    const dest = path.join(SCRATCH, "symlink.txt");
    const policy = grantPolicy([], ["./fixtures/**"]);
    const { decisions } = withCapwall(policy, "enforce", (dep) => {
      expect(() => dep.symlinkSync(DATA, dest)).not.toThrow();
    });
    expect(decisions).toHaveLength(1);
    expectAllowed(decisions, 0, "write");
    expect(nodeFs.readFileSync(dest, "utf8")).toBe("fixture data\n");
  });
});

// ---------------------------------------------------------------------------------------
// open/openSync — flag-derived access (#23): 'r' → read; 'w'/'a'/'+' → write; numeric
// O_* flags → write iff O_WRONLY|O_RDWR|O_APPEND|O_CREAT is set, else read.
// ---------------------------------------------------------------------------------------
const openFlagCases: Array<{ label: string; flags: string | number; access: "read" | "write" }> = [
  { label: "'r' (explicit)", flags: "r", access: "read" },
  { label: "'w'", flags: "w", access: "write" },
  { label: "'a'", flags: "a", access: "write" },
  { label: "'r+'", flags: "r+", access: "write" },
  { label: "O_RDONLY (numeric)", flags: nodeFs.constants.O_RDONLY, access: "read" },
  { label: "O_WRONLY (numeric)", flags: nodeFs.constants.O_WRONLY, access: "write" },
  {
    label: "O_RDONLY|O_CREAT (numeric)",
    flags: nodeFs.constants.O_RDONLY | nodeFs.constants.O_CREAT,
    access: "write",
  },
];

describe.each(openFlagCases)("fs method coverage — openSync flags $label (#23)", ({ flags, access }) => {
  it(`derives "${access}" access and denies by default`, () => {
    const target = path.join(SCRATCH, "open-target.txt");
    const { decisions } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) => {
      expect(() => dep.openSync(target, flags)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expect(decisions).toHaveLength(1);
    expectDenied(decisions, 0, access);
  });
});

describe("fs method coverage — openSync flags, granted end-to-end (#23)", () => {
  it("a read-flagged open succeeds against a real file with only a read grant", () => {
    const policy = grantPolicy(["./fixtures/**"], []);
    const { decisions } = withCapwall(policy, "enforce", (dep) => {
      expect(() => dep.openSync(DATA, "r")).not.toThrow();
    });
    expectAllowed(decisions, 0, "read");
  });

  it("a write-flagged open succeeds with only a write grant (and creates the file)", () => {
    const target = path.join(SCRATCH, "open-w.txt");
    const policy = grantPolicy([], ["./fixtures/**"]);
    const { decisions } = withCapwall(policy, "enforce", (dep) => {
      expect(() => dep.openSync(target, "w")).not.toThrow();
    });
    expectAllowed(decisions, 0, "write");
    expect(nodeFs.existsSync(target)).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------
// Buffer path arguments (#23) — same latin1 coercion as fs-slice.test.ts's dedicated
// Buffer-fidelity test (#19), exercised here through a DIFFERENT wrapped method (statSync)
// to confirm the coercion is applied uniformly across the method table, not special-cased.
// ---------------------------------------------------------------------------------------
describe("fs method coverage — Buffer path argument (#23)", () => {
  it("denies by default and records the decoded path", () => {
    const { decisions } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) => {
      expect(() => dep.statSyncBuffer(DATA)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expect(decisions).toHaveLength(1);
    expectDenied(decisions, 0, "read");
    const expected = path.resolve(DATA).split(path.sep).join("/");
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "fs", path: expected });
  });

  it("allows when read is granted", () => {
    const policy = grantPolicy(["./fixtures/**"], []);
    const { decisions } = withCapwall(policy, "enforce", (dep) => {
      expect(() => dep.statSyncBuffer(DATA)).not.toThrow();
    });
    expectAllowed(decisions, 0, "read");
  });
});

// ---------------------------------------------------------------------------------------
// URL path arguments (#23) — coercePath's `arg instanceof URL` branch (fileURLToPath) was
// previously untested by any method in the suite.
// ---------------------------------------------------------------------------------------
describe("fs method coverage — URL path argument (#23)", () => {
  it("denies by default and records the file:// URL's resolved path", () => {
    const { decisions } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) => {
      expect(() => dep.statSyncUrl(DATA)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expect(decisions).toHaveLength(1);
    expectDenied(decisions, 0, "read");
    const expected = path.resolve(DATA).split(path.sep).join("/");
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "fs", path: expected });
  });

  it("allows when read is granted", () => {
    const policy = grantPolicy(["./fixtures/**"], []);
    const { decisions } = withCapwall(policy, "enforce", (dep) => {
      expect(() => dep.statSyncUrl(DATA)).not.toThrow();
    });
    expectAllowed(decisions, 0, "read");
  });
});
