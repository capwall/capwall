/**
 * `fs.glob` / `fs.globSync` / `fs.promises.glob` — the Node ≥22 enumeration family (issue #106).
 *
 * Until this file, all three were absent from the fs shim's method tables: a dependency could
 * list any directory on the machine under a deny-all `enforce` policy with **no decision
 * recorded and nothing denied**. They are now gated as ONE `fs.read` decision per pattern, on the
 * directory that pattern's walk is rooted at — the same shape `readdir` already had.
 *
 * The file is organized around the three things that can go wrong with that:
 *  1. delivery — a denial has to arrive through the channel each of the three forms uses;
 *  2. base derivation — the guarded directory has to be one the walk genuinely cannot escape,
 *     which the "escape evidence" block below establishes against real Node rather than assuming;
 *  3. `cwd` — a caller-controlled option that decides the base, so it obeys the same single-read
 *     pinning rule as every other capability-relevant option (#26/#56/#89).
 *
 * NODE 20 has none of this family. That is asserted (`describe("Node version matrix")`), not
 * skipped past: the shim must expose exactly what the runtime does and invent nothing.
 */
import { createRequire } from "node:module";
import * as nodeFs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { install, loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");
const SCRATCH = path.join(here, "fixtures", "scratch-glob");
const DATA = path.join(SCRATCH, "data");
const SUB = path.join(DATA, "sub");
const SECRETS = path.join(SCRATCH, "secrets");

/**
 * The REAL, un-shimmed `globSync` — Node ≥22 only, and typed by hand because `@types/node` is
 * pinned to v20 and does not declare the family at all. Reading it off the real `fs` is what lets
 * the matrix below compare what the RUNTIME has against what the SHIM exposes.
 */
const realGlobSync = (nodeFs as unknown as { globSync?: (p: string, o?: unknown) => unknown[] })
  .globSync;
const HAS_GLOB = typeof realGlobSync === "function";

interface FixtureDep {
  globSurface(): { glob: string; globSync: string; promisesGlob: string };
  globSync(pattern: unknown, options?: unknown): string[];
  globCallback(
    pattern: unknown,
    options?: unknown,
  ): Promise<{ err: (Error & { name: string }) | null; matches?: string[] }>;
  globPromises(
    pattern: unknown,
    options?: unknown,
  ): Promise<{ ok: boolean; matches?: string[]; error?: string }>;
  globPromisesIsAsyncIterator(pattern: unknown, options?: unknown): boolean;
  globSyncFlipFloppingCwd(
    pattern: string,
    first: string,
    second: string,
  ): { matches: string[]; reads: number };
  globSyncUrlCwd(pattern: string, dir: string): string[];
  globSyncMany(patterns: unknown[], options?: unknown): string[];
}

function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

const emptyEnforcePolicy = (): Policy =>
  loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: here });

const readGrant = (read: string[]): Policy =>
  loadPolicyFromObject(
    { version: 1, mode: "enforce", packages: { "fixture-dep": { fs: { read, write: [] } } } },
    { projectRoot: here },
  );

/** Read grant covering the whole `data` subtree and nothing else — the policy most of the
 * base-derivation table is written against. `secrets` is deliberately a sibling. */
const DATA_GRANT = (): Policy => readGrant(["./fixtures/scratch-glob/data/**"]);

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

async function withCapwallAsync<T>(
  policy: Policy,
  mode: "observe" | "enforce",
  fn: (dep: FixtureDep) => Promise<T>,
): Promise<{ result: T; decisions: Recorded[] }> {
  const decisions: Recorded[] = [];
  const handle = install(policy, mode, {
    projectRoot: here,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
  });
  try {
    return { result: await fn(loadFixtureFresh()), decisions };
  } finally {
    handle.uninstall();
  }
}

/** The single fs:read decision a glob call must produce, and the directory it names. */
function expectOneDecision(decisions: Recorded[], allowed: boolean, base: string): void {
  expect(decisions).toHaveLength(1);
  expect(decisions[0]!.pkg).toBe("fixture-dep");
  expect(decisions[0]!.decision.allowed).toBe(allowed);
  expect(decisions[0]!.decision.observed).toEqual({ kind: "fs", access: "read", path: base });
}

beforeEach(() => {
  nodeFs.mkdirSync(SUB, { recursive: true });
  nodeFs.mkdirSync(SECRETS, { recursive: true });
  nodeFs.writeFileSync(path.join(DATA, "a.txt"), "a");
  nodeFs.writeFileSync(path.join(DATA, "b.txt"), "b");
  nodeFs.writeFileSync(path.join(SUB, "c.txt"), "c");
  nodeFs.writeFileSync(path.join(SECRETS, "key.txt"), "SECRET");
});
afterEach(() => {
  nodeFs.rmSync(SCRATCH, { recursive: true, force: true });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// The Node version matrix. Runs on BOTH supported majors and asserts the right thing on each,
// which is the point: a `skip` on Node 20 would prove nothing about the no-op.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("fs.glob — Node version matrix (#106)", () => {
  it("the shim exposes exactly what the runtime does: present on ≥22, absent on 20", () => {
    const expected = HAS_GLOB ? "function" : "undefined";
    const { result } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) => dep.globSurface());
    expect(result).toEqual({
      glob: expected,
      globSync: expected,
      promisesGlob: expected,
    });
  });

  it("wrapping the family never breaks the rest of the surface on a runtime without it", () => {
    // The Node-20 no-op in one assertion: an unrelated, always-present method still works, so a
    // table entry for a name the runtime does not define costs nothing.
    const { decisions } = withCapwall(readGrant(["./fixtures/**"]), "enforce", (dep) => {
      expect(dep.globSurface()).toBeTruthy();
      expect(nodeFs.existsSync(path.join(DATA, "a.txt"))).toBe(true);
    });
    expect(decisions).toHaveLength(0);
  });
});

// From here on the API has to exist. `skipIf` rather than a silent no-op assertion, because the
// version matrix above already carries the Node-20 claim.
describe.skipIf(!HAS_GLOB)("fs.glob — deny by default, allow when granted (#106)", () => {
  it("does not charge Node's own lazy minimatch env read to the calling package", () => {
    // Node `require`s its vendored minimatch from inside the FIRST glob in the process, and that
    // module reads `__MINIMATCH_TESTING_PLATFORM__` at module scope — on the stack of whoever
    // globbed first. Left alone it puts a spurious `env` grant in every observe trace and a
    // `DENY '<pkg>' env:…` line in every enforce log. Necessarily the FIRST glob-touching test in
    // this file: the load happens once per process, so nothing later can observe the leak.
    const { decisions } = withCapwall(DATA_GRANT(), "enforce", (dep) =>
      dep.globSync("*.txt", { cwd: DATA }),
    );
    expect(decisions.map((d) => d.decision.observed.kind)).toEqual(["fs"]);
  });

  it("globSync denies by default and records one fs:read on the walk's base directory", () => {
    const { decisions } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) => {
      expect(() => dep.globSync("*.txt", { cwd: DATA })).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expectOneDecision(decisions, false, DATA);
  });

  it("globSync enumerates when the base directory is granted", () => {
    const { result, decisions } = withCapwall(DATA_GRANT(), "enforce", (dep) =>
      dep.globSync("*.txt", { cwd: DATA }),
    );
    expect([...result].sort()).toEqual(["a.txt", "b.txt"]);
    expectOneDecision(decisions, true, DATA);
  });

  it("a denied fs.glob reports through its CALLBACK, not as a synchronous throw", async () => {
    // Real `fs.glob` never throws synchronously (verified on Node 22), so idiomatic
    // try/catch-free callback code must not be crashed by a denial — same rule as #16.
    const { result, decisions } = await withCapwallAsync(
      emptyEnforcePolicy(),
      "enforce",
      (dep) => dep.globCallback("*.txt", { cwd: DATA }),
    );
    expect(result.err?.name).toBe("CapabilityError");
    expect(result.matches).toBeUndefined();
    expectOneDecision(decisions, false, DATA);
  });

  it("a granted fs.glob delivers matches through the same callback", async () => {
    const { result, decisions } = await withCapwallAsync(DATA_GRANT(), "enforce", (dep) =>
      dep.globCallback("*.txt", { cwd: DATA }),
    );
    expect(result.err).toBeNull();
    expect([...(result.matches ?? [])].sort()).toEqual(["a.txt", "b.txt"]);
    expectOneDecision(decisions, true, DATA);
  });

  it("a denied fs.promises.glob still RETURNS an async iterator and rejects at iteration", async () => {
    // `fsPromises.glob` is the one method on that surface that does not return a promise. A
    // `Promise.reject` here would make `for await` fail with a TypeError naming the wrong
    // problem; real Node reports even ERR_INVALID_ARG_TYPE at the first next().
    const { result, decisions } = await withCapwallAsync(
      emptyEnforcePolicy(),
      "enforce",
      async (dep) => ({
        shape: dep.globPromisesIsAsyncIterator("*.txt", { cwd: DATA }),
        outcome: await dep.globPromises("*.txt", { cwd: DATA }),
      }),
    );
    expect(result.shape).toBe(true);
    expect(result.outcome.ok).toBe(false);
    expect(result.outcome.error).toBe("CapabilityError");
    // Two calls above → two decisions; both denied on the same base.
    expect(decisions).toHaveLength(2);
    expect(decisions.every((d) => !d.decision.allowed)).toBe(true);
    expect(decisions[0]!.decision.observed).toEqual({ kind: "fs", access: "read", path: DATA });
  });

  it("a granted fs.promises.glob iterates normally", async () => {
    const { result, decisions } = await withCapwallAsync(DATA_GRANT(), "enforce", (dep) =>
      dep.globPromises("*.txt", { cwd: DATA }),
    );
    expect(result.ok).toBe(true);
    expect([...(result.matches ?? [])].sort()).toEqual(["a.txt", "b.txt"]);
    expectOneDecision(decisions, true, DATA);
  });

  it("observe records the enumeration and blocks nothing", () => {
    const { result, decisions } = withCapwall(emptyEnforcePolicy(), "observe", (dep) =>
      dep.globSync("*.txt", { cwd: DATA }),
    );
    expect([...result].sort()).toEqual(["a.txt", "b.txt"]);
    expectOneDecision(decisions, true, DATA);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// ESCAPE EVIDENCE. #106's own suggestion was to gate the pattern's non-magic prefix. These
// three shapes are why that would have been fail-open: measured against the REAL, un-shimmed
// `fs.globSync`, each one reaches outside the directory its literal prefix names.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe.skipIf(!HAS_GLOB)("fs.glob — patterns really do escape their literal prefix", () => {
  const escaping: Array<[name: string, pattern: string]> = [
    ["`**` then `..` (** matches zero segments)", "**/../secrets/*.txt"],
    ["a brace group containing `..`", "{.,..}/secrets/*.txt"],
    ["a brace group with ABSOLUTE alternatives", `{${SECRETS},${DATA}}/*.txt`],
  ];
  for (const [name, pattern] of escaping) {
    it(`un-shimmed, ${name} reaches SECRETS from a cwd of DATA`, () => {
      const reached = realGlobSync!(pattern, { cwd: DATA }).map((m) =>
        path.resolve(DATA, m as string),
      );
      expect(reached).toContain(path.join(SECRETS, "key.txt"));
    });

    it(`shimmed, ${name} is gated on the filesystem root and denied`, () => {
      const { decisions } = withCapwall(DATA_GRANT(), "enforce", (dep) => {
        expect(() => dep.globSync(pattern, { cwd: DATA })).toThrowError(
          expect.objectContaining({ name: "CapabilityError" }),
        );
      });
      expectOneDecision(decisions, false, path.parse(DATA).root.split(path.sep).join("/"));
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// BASE DERIVATION. One policy (`./fixtures/scratch-glob/data/**`), many patterns; what changes is
// only which directory the walk is rooted at.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe.skipIf(!HAS_GLOB)("fs.glob — which directory each pattern is gated on (#106)", () => {
  const cases: Array<{ name: string; pattern: string; cwd?: string; base: string }> = [
    { name: "`**` is rooted at the cwd", pattern: "**", cwd: DATA, base: DATA },
    { name: "a literal prefix descends", pattern: "sub/*.txt", cwd: DATA, base: SUB },
    {
      name: "segment-local braces do not move the root",
      pattern: "{a,b}*.txt",
      cwd: DATA,
      base: DATA,
    },
    { name: "a leading `..` is exact, not unbounded", pattern: "../secrets/*", cwd: DATA, base: SECRETS },
    { name: "an absolute pattern ignores the cwd", pattern: `${SECRETS}/*`, cwd: DATA, base: SECRETS },
    { name: "an absolute pattern rooted in the grant", pattern: `${DATA}/*`, cwd: SECRETS, base: DATA },
  ];
  for (const { name, pattern, cwd, base } of cases) {
    it(`${name} (${pattern})`, () => {
      const { decisions } = withCapwall(DATA_GRANT(), "enforce", (dep) => {
        try {
          dep.globSync(pattern, cwd === undefined ? undefined : { cwd });
        } catch (err) {
          expect((err as Error).name).toBe("CapabilityError");
        }
      });
      // Whether it was allowed follows entirely from whether the base is inside the grant.
      const granted = base === DATA || base.startsWith(DATA + path.sep);
      expectOneDecision(decisions, granted, base);
    });
  }

  it("with no options at all, the base is the process cwd", () => {
    const { decisions } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) => {
      expect(() => dep.globSync("*.txt")).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expectOneDecision(decisions, false, process.cwd().split(path.sep).join("/"));
  });

  it("a pattern shape Node itself rejects is gated as unbounded, never skipped", () => {
    // #99's lesson: an unrecognized argument shape must not mean "no gate". A non-string pattern
    // is denied on the root rather than passed through un-decided.
    const { decisions } = withCapwall(DATA_GRANT(), "enforce", (dep) => {
      expect(() => dep.globSync(123, { cwd: DATA })).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expectOneDecision(decisions, false, path.parse(DATA).root.split(path.sep).join("/"));
  });

  it("a cwd shape capwall cannot resolve is gated as unbounded too", () => {
    const { decisions } = withCapwall(DATA_GRANT(), "enforce", (dep) => {
      // Node rejects a Buffer cwd; the gate must have run and failed closed before that.
      expect(() => dep.globSync("*.txt", { cwd: Buffer.from(DATA) })).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expectOneDecision(decisions, false, path.parse(DATA).root.split(path.sep).join("/"));
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// PATTERN ARRAYS — one enumeration per pattern, so one decision per pattern.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe.skipIf(!HAS_GLOB)("fs.glob — an array of patterns (#106)", () => {
  it("records one decision per pattern", () => {
    const { result, decisions } = withCapwall(DATA_GRANT(), "enforce", (dep) =>
      dep.globSyncMany(["*.txt", "sub/*.txt"], { cwd: DATA }),
    );
    expect([...result].sort()).toEqual(["a.txt", "b.txt", path.join("sub", "c.txt")]);
    expect(decisions).toHaveLength(2);
    expect(decisions.map((d) => (d.decision.observed as { path: string }).path)).toEqual([
      DATA,
      SUB,
    ]);
  });

  it("denies the whole call on the first pattern that is not granted, and enumerates nothing", () => {
    const { decisions } = withCapwall(DATA_GRANT(), "enforce", (dep) => {
      expect(() => dep.globSyncMany(["*.txt", "../secrets/*"], { cwd: DATA })).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expect(decisions).toHaveLength(2);
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(decisions[1]!.decision.allowed).toBe(false);
    expect(decisions[1]!.decision.observed).toEqual({
      kind: "fs",
      access: "read",
      path: SECRETS,
    });
  });

  it("an empty pattern array enumerates nothing and records nothing", () => {
    const { result, decisions } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) =>
      dep.globSyncMany([], { cwd: DATA }),
    );
    expect(result).toEqual([]);
    expect(decisions).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// `options.cwd` PINNING (#26/#56/#89, glob flavor). `cwd` decides the base, so it is
// capability-relevant, so it is read exactly once and the single answer is what Node receives.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe.skipIf(!HAS_GLOB)("fs.glob — options.cwd is pinned (#106)", () => {
  it("a cwd accessor runs ONCE, and Node walks the directory capwall guarded", () => {
    const { result, decisions } = withCapwall(DATA_GRANT(), "enforce", (dep) =>
      dep.globSyncFlipFloppingCwd("*.txt", DATA, SECRETS),
    );
    // Un-pinned, capwall would guard DATA (allowed) and Node would re-read and walk SECRETS.
    expect(result.reads).toBe(1);
    expect([...result.matches].sort()).toEqual(["a.txt", "b.txt"]);
    expect(result.matches).not.toContain("key.txt");
    expectOneDecision(decisions, true, DATA);
  });

  it("a file-URL cwd is converted once and gated on the converted path", () => {
    const { result, decisions } = withCapwall(DATA_GRANT(), "enforce", (dep) =>
      dep.globSyncUrlCwd("*.txt", DATA),
    );
    expect([...result].sort()).toEqual(["a.txt", "b.txt"]);
    expectOneDecision(decisions, true, DATA);
  });
});
