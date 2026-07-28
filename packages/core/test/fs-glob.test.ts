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
 * The family is present on every supported runtime now that the floor is Node ≥22.15 — this file
 * used to open with a Node-20 caveat and carry a `HAS_GLOB` predicate through seven `describe`
 * blocks. What survives that removal is the claim that was never about the version: the shim must
 * expose exactly what the runtime does and invent nothing, asserted against the real `fs` rather
 * than against a hardcoded expectation.
 */
import { createRequire } from "node:module";
import * as nodeFs from "node:fs";
import * as nodeOs from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { install, loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";
import { nodeGlobBase } from "../src/policy/glob.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");
const SCRATCH = path.join(here, "fixtures", "scratch-glob");
const DATA = path.join(SCRATCH, "data");
const SUB = path.join(DATA, "sub");
const SECRETS = path.join(SCRATCH, "secrets");

/**
 * The REAL, un-shimmed `globSync`. The `fs.glob` family is Node ≥22 and the supported floor is
 * ≥22.15, so it is now present on every runtime this suite runs on — it used to be read through
 * a hand-written type because `@types/node` was pinned to v20 and did not declare the family at
 * all, and both that cast and the `HAS_GLOB` skip guard went away with the Node 20 leg.
 *
 * Still read off the real `fs` rather than assumed, because the matrix row below compares what
 * the RUNTIME has against what the SHIM exposes; that comparison is the point.
 */
const realGlobSync = nodeFs.globSync;

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
// The shim mirrors the runtime. This block used to be the Node version matrix, asserting
// "present on ≥22, absent on 20" from a `HAS_GLOB` predicate; with the floor at ≥22.15 the
// absent arm is unreachable, so it now states the claim directly rather than deriving it from
// a condition that can only be true. The claim is still worth an assertion: `wrapSurface`
// builds the shim from a table of NAMES, and a name the runtime does not define is skipped —
// so "the shim exposes the family" is a fact about the wrapping, not about the Node version.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("fs.glob — the shim exposes exactly what the runtime does (#106)", () => {
  it("exposes the whole glob family, because this runtime has it", () => {
    // Cross-checked against the REAL fs rather than hardcoded to "function": if a future Node
    // ever drops or renames one of these, this fails as a mismatch instead of quietly passing
    // against a constant nobody re-derived.
    expect(typeof realGlobSync).toBe("function");
    const { result } = withCapwall(emptyEnforcePolicy(), "enforce", (dep) => dep.globSurface());
    expect(result).toEqual({
      glob: "function",
      globSync: "function",
      promisesGlob: "function",
    });
  });

  it("wrapping the family leaves the rest of the surface alone", () => {
    const { decisions } = withCapwall(readGrant(["./fixtures/**"]), "enforce", (dep) => {
      // The exact surface, not `toBeTruthy()` — which accepts any non-empty object and would
      // hold with the glob table emptied entirely (#112). Same expectation as the row above,
      // asserted here under a GRANTING policy so the two differ only in the policy.
      expect(dep.globSurface()).toEqual({
        glob: "function",
        globSync: "function",
        promisesGlob: "function",
      });
      expect(nodeFs.existsSync(path.join(DATA, "a.txt"))).toBe(true);
    });
    expect(decisions).toHaveLength(0);
  });
});

describe("fs.glob — deny by default, allow when granted (#106)", () => {
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

/** `/`-separated absolute form, the shape a decision's `path` carries. */
const asPolicyPath = (nativePath: string): string => nativePath.split(path.sep).join("/");
const FS_ROOT = asPolicyPath(path.parse(SCRATCH).root);

// ═══════════════════════════════════════════════════════════════════════════════════════════
// ESCAPE EVIDENCE. #106's own suggestion was to gate the pattern's non-magic prefix. These
// three shapes are why that would have been fail-open: measured against the REAL, un-shimmed
// `fs.globSync`, each one reaches outside the directory its literal prefix names.
//
// Since #120 the guarded directory for a BRACED pattern is the common ancestor of its
// alternatives rather than the filesystem root — tighter, and still outside the grant, because
// the expansion is now performed instead of being pattern-matched for a `/` or a `..`.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("fs.glob — patterns really do escape their literal prefix", () => {
  const escaping: Array<[name: string, pattern: string, base: string]> = [
    ["`**` then `..` (** matches zero segments)", "**/../secrets/*.txt", FS_ROOT],
    ["a brace group containing `..`", "{.,..}/secrets/*.txt", asPolicyPath(SCRATCH)],
    [
      "a brace group with ABSOLUTE alternatives",
      `{${SECRETS},${DATA}}/*.txt`,
      asPolicyPath(SCRATCH),
    ],
  ];
  for (const [name, pattern, base] of escaping) {
    it(`un-shimmed, ${name} reaches SECRETS from a cwd of DATA`, () => {
      const reached = realGlobSync(pattern, { cwd: DATA }).map((m) =>
        path.resolve(DATA, m as string),
      );
      expect(reached).toContain(path.join(SECRETS, "key.txt"));
    });

    it(`shimmed, ${name} is gated outside the grant and denied`, () => {
      const { decisions } = withCapwall(DATA_GRANT(), "enforce", (dep) => {
        expect(() => dep.globSync(pattern, { cwd: DATA })).toThrowError(
          expect.objectContaining({ name: "CapabilityError" }),
        );
      });
      expectOneDecision(decisions, false, base);
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// #120 — a `..` SPELLED AS A GLOB EXPANSION.
//
// The pre-#120 resolver asked a STRING question ("is this segment literally `..`?", "does this
// brace group contain a `/` or a `..`?") of a pattern language whose consumer is a MATCHER. Each
// spelling below walks to the parent of `cwd` while capwall predicted the walk could not leave
// `cwd` at all — so the only decision recorded was an ALLOWED read of the package's own granted
// directory, and `enforce` printed nothing.
//
// This block is the PoC, end to end, under the most ordinary grant there is: the package may read
// its own directory and nothing else. It is EVIDENCE, not the mechanism — the property test below
// is what checks capwall against real `fs.globSync` over patterns nobody wrote down.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("fs.glob — a `..` written as an expansion cannot escape (#120)", () => {
  /** #120's table, plus the two spellings its "same shape from the other side" note describes. */
  const spellings = [
    "[.][.]",
    "[.].",
    ".[.]",
    "[.-.][.-.]",
    "..{,}",
    ".{.,.}",
    "{a,[.][.]}",
    "[.][.]{,}",
  ];

  for (const token of spellings) {
    it(`un-shimmed, '${token}' really does reach the parent of the cwd`, () => {
      const reached = realGlobSync(`${token}/*.txt`, { cwd: SUB }).map((m) =>
        path.resolve(SUB, m as string),
      );
      expect(reached).toContain(path.join(DATA, "a.txt"));
    });

    it(`shimmed, '${token}' is denied — the walk's real root is what gets decided`, () => {
      // The grant covers `sub` and nothing above it, which is exactly the shape of #120's PoC
      // ("a read grant on its own directory and nothing else").
      const policy = readGrant(["./fixtures/scratch-glob/data/sub/**"]);
      const { decisions } = withCapwall(policy, "enforce", (dep) => {
        expect(() => dep.globSync(`${token}/*.txt`, { cwd: SUB })).toThrowError(
          expect.objectContaining({ name: "CapabilityError" }),
        );
      });
      expect(decisions).toHaveLength(1);
      expect(decisions[0]!.decision.allowed).toBe(false);
      // Either the exact parent (when the expansion resolves to a literal `..` capwall can
      // resolve) or the filesystem root (when capwall refuses to prove the segment bounded).
      // What must NEVER happen is a decision on `sub` itself, which is what shipped before #120.
      const decided = (decisions[0]!.decision.observed as { path: string }).path;
      expect([asPolicyPath(DATA), FS_ROOT]).toContain(decided);
    });
  }

  it("chaining the spelling four deep is still denied", () => {
    const pattern = ["[.][.]", "[.][.]", "[.][.]", "[.][.]", "**"].join("/");
    const policy = readGrant(["./fixtures/scratch-glob/data/sub/**"]);
    const { decisions } = withCapwall(policy, "enforce", (dep) => {
      expect(() => dep.globSync(pattern, { cwd: SUB })).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expectOneDecision(decisions, false, FS_ROOT);
  });

  it("does NOT over-deny a segment that stays a matcher", () => {
    // `.*`, `*.*`, `[.]*` and `..*` all contain a `*`, so nothing in the grammar can reduce them
    // to a literal path component; they match directory entries, and `readdir` never yields `.`
    // or `..`. Denying these would have been the cheap way to close #120 and would have broken
    // every dotfile glob in the ecosystem.
    for (const pattern of [".*", "*.*", "[.]*", "..*", "?.txt"]) {
      const policy = readGrant(["./fixtures/scratch-glob/data/sub/**"]);
      const { decisions } = withCapwall(policy, "enforce", (dep) =>
        dep.globSync(pattern, { cwd: SUB }),
      );
      expectOneDecision(decisions, true, SUB);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// THE PROPERTY, over GENERATED patterns (#120).
//
// #84, #95 and #120 are the same failure three times: a parser deciding a security boundary while
// modelling a narrower grammar than its consumer accepts. Three more hand-picked cases in the
// table above would be the fourth. So the divergence itself is the test:
//
//     for every generated pattern p,
//       every entry real fs.globSync(p, {cwd}) returns
//       resolves INSIDE the directory nodeGlobBase(p, cwd) names.
//
// If minimatch grows a new way to spell `..` — or capwall's expansion ever disagrees with the
// real one — this fails, whether or not anybody thought to write that spelling down.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("fs.glob — capwall's base bounds where Node really walks (#120)", () => {
  /**
   * A DEEP, TINY sandbox, and both adjectives are load-bearing.
   *
   * Deep: the generator composes at most three upward tokens, so four padding levels above the
   * walk's cwd mean even a fully-escaping pattern stays inside the sandbox. Tiny: a `**` that
   * escapes into a real source tree turns this test into a filesystem crawl (measured: minutes),
   * and a slow property test is a property test somebody deletes.
   */
  const PROP_ROOT = nodeFs.realpathSync(
    nodeFs.mkdtempSync(path.join(nodeOs.tmpdir(), "capwall-globprop-")),
  );
  const LEVELS = ["p1", "p2", "p3", "p4"];
  const WALK_CWD = path.join(PROP_ROOT, ...LEVELS, "cwd");

  beforeEach(() => {
    nodeFs.mkdirSync(path.join(WALK_CWD, "sub"), { recursive: true });
    // One marker file per level, so a walk that escapes N levels RETURNS something and the
    // property has an entry to judge. A silent escape that matched nothing would pass vacuously.
    nodeFs.writeFileSync(path.join(PROP_ROOT, "up5.txt"), "5");
    for (let i = 0; i < LEVELS.length; i++) {
      nodeFs.writeFileSync(
        path.join(PROP_ROOT, ...LEVELS.slice(0, i + 1), `up${LEVELS.length - i}.txt`),
        String(i),
      );
    }
    nodeFs.writeFileSync(path.join(WALK_CWD, "here.txt"), "0");
    nodeFs.writeFileSync(path.join(WALK_CWD, ".dot.txt"), "d");
    nodeFs.writeFileSync(path.join(WALK_CWD, "sub", "deep.txt"), "s");
  });
  afterEach(() => {
    nodeFs.rmSync(path.join(PROP_ROOT, LEVELS[0]!), { recursive: true, force: true });
  });

  /**
   * Segment-shaped tokens the generator composes. Deliberately weighted towards dots and
   * punctuation — the region of the grammar where "is this a `..`?" stops being a string
   * question — with ordinary segments and plain wildcards mixed in so the corpus also proves the
   * analysis does not simply answer "unbounded" to everything.
   */
  const TOKENS = [
    "..", ".", "...", "[.]", "[.].", ".[.]", "[.][.]", "[.-.][.-.]", "[..]",
    "..{,}", ".{.,.}", "{.,..}", "{a,[.][.]}", "[.][.]{,}", "{,..}", "{..,.}",
    "@(..)", "+(.)", "!(x)", "[!q][!q]", "?.", ".?", "*.", ".*", "*.*", "[.]*",
    "..*", "*", "**", "?", "sub", "p4", "{sub,p4}", "[sp]*", "s?b",
  ];
  const TAILS = ["*", "*.txt", "**"];

  /** Deterministic 32-bit PRNG — a fixed seed, so a failure is reproducible from the message. */
  function makeRandom(seed: number): () => number {
    let state = seed >>> 0;
    return () => {
      state = (state * 1664525 + 1013904223) >>> 0;
      return state / 0x100000000;
    };
  }

  function generatePatterns(): string[] {
    const patterns = new Set<string>();
    // Exhaustive over PAIRS of tokens: 2 levels of escape is enough to leave the sandbox, and
    // every spelling gets composed with every other one.
    for (const a of TOKENS) {
      for (const b of TOKENS) patterns.add(`${a}/${b}/*`);
      for (const tail of TAILS) patterns.add(`${a}/${tail}`);
    }
    // Plus a seeded random pass over 1–3 tokens and a random tail, so the corpus is not only the
    // shapes the cross-product happens to produce.
    const random = makeRandom(0x120c0de);
    const pick = <T>(xs: readonly T[]): T => xs[Math.floor(random() * xs.length)]!;
    for (let i = 0; i < 400; i++) {
      const depth = 1 + Math.floor(random() * 3);
      const segments: string[] = [];
      for (let d = 0; d < depth; d++) segments.push(pick(TOKENS));
      segments.push(pick(TAILS));
      patterns.add(segments.join("/"));
    }
    return [...patterns];
  }

  it("every entry Node returns is inside the directory capwall decided about", () => {
    const cwdPolicy = asPolicyPath(WALK_CWD);
    const violations: string[] = [];
    let withResults = 0;
    let escapedCwd = 0;

    const fsRoot = asPolicyPath(path.parse(WALK_CWD).root);
    for (const pattern of generatePatterns()) {
      const base = nodeGlobBase(pattern, WALK_CWD);
      // Nothing to check, and nothing to learn: when capwall already answers "the filesystem
      // root" the property holds for any result whatsoever, so running the walk only costs time
      // — and some of these really are rooted at `/` (`{,..}/**` expands to `/**`, which crawls
      // the whole machine). The complementary risk, an implementation that answers `/` to
      // EVERYTHING and passes vacuously, is what the next test rules out.
      if (base === fsRoot) continue;
      let matches: unknown[];
      try {
        matches = realGlobSync(pattern, { cwd: WALK_CWD });
      } catch {
        // Node itself rejected the pattern — no walk, so nothing was disclosed.
        continue;
      }
      if (matches.length === 0) continue;
      withResults++;
      let escaped = false;
      for (const match of matches) {
        const resolved = asPolicyPath(path.resolve(WALK_CWD, match as string));
        if (!(resolved === base || resolved.startsWith(base.endsWith("/") ? base : base + "/"))) {
          violations.push(`${JSON.stringify(pattern)} -> ${resolved} escapes base ${base}`);
        }
        if (!(resolved === cwdPolicy || resolved.startsWith(cwdPolicy + "/"))) escaped = true;
      }
      if (escaped) escapedCwd++;
    }

    expect(violations.slice(0, 10).join("\n")).toBe("");
    // The corpus has to be doing work: patterns that match nothing prove nothing, and patterns
    // that never leave the cwd would not have caught #120 in the first place.
    expect(withResults).toBeGreaterThan(100);
    expect(escapedCwd).toBeGreaterThan(20);
  }, 120_000);

  it("does not answer `unbounded` to everything — ordinary patterns still name a real base", () => {
    // The trivially "safe" implementation returns the filesystem root for every pattern and
    // passes the property above while making `fs.glob` unusable. These assertions are what stops
    // that from being an acceptable fix.
    const root = asPolicyPath(path.parse(WALK_CWD).root);
    for (const pattern of ["**", "*.txt", "sub/*", ".*", "*.*", "{a,b}*.txt", "[sl]*/*"]) {
      expect(nodeGlobBase(pattern, WALK_CWD), pattern).not.toBe(root);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// BASE DERIVATION. One policy (`./fixtures/scratch-glob/data/**`), many patterns; what changes is
// only which directory the walk is rooted at.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("fs.glob — which directory each pattern is gated on (#106)", () => {
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
describe("fs.glob — an array of patterns (#106)", () => {
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
describe("fs.glob — options.cwd is pinned (#106)", () => {
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
