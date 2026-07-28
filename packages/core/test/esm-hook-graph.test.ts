/**
 * THE ESM LOADER THREAD'S GRAPH IS MINIMAL, AND STAYS MINIMAL (issue #150).
 *
 * ── WHY THIS IS A GUARD RATHER THAN A PREFERENCE ────────────────────────────────────────────
 * `module.register()` starts Node's module-customization thread and BLOCKS the main thread until
 * that thread has resolved, compiled and evaluated the hook module's entire import graph. So every
 * module reachable from `loader/esm-hooks.ts` is paid for SERIALLY, at startup, on every process
 * capwall mediates — a CLI that shells out, a test runner spawning workers, a serverless cold
 * start. Measured on Node 22 (see `scripts/bench/README.md` § Startup): `registerEsmHook()` was
 * ~93 ms, of which ~40 ms was capwall's own graph on that thread and the rest was Node's worker
 * bootstrap.
 *
 * Two things were on that graph for no reason, and both were invisible in review because both
 * arrived through a barrel import three modules away:
 *
 *  1. **`zod`**, via `@capwall/policy-schema`'s barrel, which builds the whole schema tree at
 *     module scope. The loader thread never parses a policy — it is handed an already-parsed one
 *     in an {@link EsmGateSnapshot} — so it needed the grammar helpers and nothing else. Fixed by
 *     importing `@capwall/policy-schema/host` and `/package-key` directly.
 *  2. **Ten builtins it never uses**, via `real-builtins.cts`, whose whole purpose is to capture all
 *     twelve. The loader thread needs exactly two: `fs` (attribution reads package.json) and
 *     `worker_threads` (the #123 gate's synchronous port drain). Fixed by the narrow captures under
 *     `src/real-builtins/` — see `src/real-builtins/fs.cts` for why that narrowing takes nothing
 *     away from #78.
 *
 * Together: ~93 ms → ~70 ms at the minimum, ~112 ms → ~85 ms at p50.
 *
 * ── WHY IT NEEDS A TEST AT ALL ──────────────────────────────────────────────────────────────
 * Because the regression is a ONE-CHARACTER edit in a file nobody is thinking about the loader
 * thread while editing. Changing `@capwall/policy-schema/host` back to `@capwall/policy-schema` in
 * `policy/evaluate.ts` is the most natural import in the repo, breaks nothing, fails nothing, and
 * silently puts zod back on the blocking startup path of every mediated process. Same for
 * `../real-builtins.cjs` in `attribution/index.ts`. This is the same class of property as #78's own
 * capture rule and #107's process-patch rule, and it gets the same treatment: a scan that fails by
 * name, plus a runtime check that the scan is describing something real.
 *
 * ── THE TWO HALVES ──────────────────────────────────────────────────────────────────────────
 *  - **The static scan** walks the transitive import graph of `src/loader/esm-hooks.ts` over `src`
 *    and fails on any module in it that value-imports the policy-schema barrel or the twelve-wide
 *    capture. It runs on SOURCE, so it fails on the edit rather than on the build.
 *  - **The runtime check** imports the BUILT `dist/loader/esm-hooks.js` in a clean child and asks
 *    Node what it actually loaded, with the aggregate capture as a positive control in the same
 *    child — because a `moduleLoadList` probe that reports "nothing extra" is indistinguishable
 *    from a probe that stopped working.
 */
import * as path from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { blankNonCode } from "./helpers/source-scan.js";
import { assertPreloadBuilt, runNode } from "./helpers/subprocess.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const SRC_ROOT = path.join(here, "..", "src");

/** The hook module Node's loader thread evaluates — the root of the graph under test. */
const HOOK_ENTRY = path.join(SRC_ROOT, "loader", "esm-hooks.ts");

/**
 * Specifiers a module on that thread must not import for a VALUE.
 *
 * `import type` forms are fine and are used freely — `module-read.ts` takes `Mode`/`Policy` from
 * the barrel and `tsc` erases both, loading nothing.
 */
const BANNED = [
  {
    specifier: "@capwall/policy-schema",
    why: "the barrel builds the whole Zod schema tree at module scope; take the grammar from '@capwall/policy-schema/host' or '/package-key', or the type from an `import type`",
  },
  {
    specifier: "../real-builtins.cjs",
    why: "the twelve-wide aggregate; take the one builtin this realm needs from src/real-builtins/ (see its fs.cts header)",
  },
];

/**
 * Resolve a relative specifier as written in `src` (`.js`/`.cjs`, per the ESM extension rule) back
 * to the TypeScript file it came from. Returns `null` for a bare specifier or a `node:` builtin —
 * neither is part of capwall's own graph.
 */
function resolveToSource(fromFile: string, specifier: string): string | null {
  if (!specifier.startsWith(".")) return null;
  const abs = path.resolve(path.dirname(fromFile), specifier);
  const candidates = abs.endsWith(".cjs")
    ? [abs.replace(/\.cjs$/, ".cts")]
    : abs.endsWith(".mjs")
      ? [abs.replace(/\.mjs$/, ".mts")]
      : [abs.replace(/\.js$/, ".ts"), `${abs}.ts`];
  for (const c of candidates) {
    try {
      readFileSync(c);
      return c;
    } catch {
      /* try the next spelling */
    }
  }
  return null;
}

/** Every `from "…"` / bare `import "…"` specifier in `code`, EXCLUDING erased `import type`. */
function valueImportSpecifiers(code: string): string[] {
  const out: string[] = [];
  for (const m of code.matchAll(/\bimport\s+(?!type\b)[^;]*?\bfrom\s*["']([^"']+)["']/g)) {
    out.push(m[1] ?? "");
  }
  for (const m of code.matchAll(/\bimport\s*["']([^"']+)["']/g)) out.push(m[1] ?? "");
  for (const m of code.matchAll(/\bexport\s+(?!type\b)[^;]*?\bfrom\s*["']([^"']+)["']/g)) {
    out.push(m[1] ?? "");
  }
  return out;
}

interface GraphEdge {
  /** `src`-relative file doing the importing. */
  from: string;
  specifier: string;
}

/** The transitive value-import graph rooted at `entry`, as `file → its specifiers`. */
function graphFrom(entry: string): { files: Set<string>; edges: GraphEdge[] } {
  const files = new Set<string>();
  const edges: GraphEdge[] = [];
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop()!;
    if (files.has(file)) continue;
    files.add(file);
    const code = blankNonCode(readFileSync(file, "utf8"), { strings: false });
    for (const specifier of valueImportSpecifiers(code)) {
      edges.push({ from: path.relative(SRC_ROOT, file), specifier });
      const next = resolveToSource(file, specifier);
      if (next !== null) queue.push(next);
    }
  }
  return { files, edges };
}

describe("#150 — the ESM hook's graph carries nothing the loader thread does not use", () => {
  it("value-imports neither the policy-schema barrel nor the twelve-wide capture", () => {
    const { edges } = graphFrom(HOOK_ENTRY);
    const offenders = edges.filter((e) => BANNED.some((b) => b.specifier === e.specifier));
    expect(
      offenders,
      `A module on the ESM loader thread's graph imports something that realm does not use. ` +
        `module.register() BLOCKS the main thread while that graph is resolved, compiled and ` +
        `evaluated, so this is serial startup cost on every mediated process (#150). Offenders:\n` +
        offenders
          .map(
            (o) =>
              `  ${o.from} imports ${o.specifier}\n      ${BANNED.find((b) => b.specifier === o.specifier)?.why}`,
          )
          .join("\n"),
    ).toEqual([]);
  });

  it("is a scan that actually fires — and does not fire on an erased type import", () => {
    // Worth nothing unless it catches the exact edits it forbids. Both offenders are the shape a
    // reviewer would wave through, which is the whole reason the scan exists.
    const guilty = `
      import { ANY_HOST } from "@capwall/policy-schema";
      import { realFs } from "../real-builtins.cjs";
    `;
    const banned = new Set(BANNED.map((b) => b.specifier));
    expect(valueImportSpecifiers(guilty).filter((s) => banned.has(s))).toEqual([
      "@capwall/policy-schema",
      "../real-builtins.cjs",
    ]);

    const innocent = `
      import type { Mode, Policy } from "@capwall/policy-schema";
      import { ANY_HOST } from "@capwall/policy-schema/host";
      import { realFs } from "../real-builtins/fs.cjs";
      /** Not this: import { z } from "@capwall/policy-schema"; */
    `;
    const code = blankNonCode(innocent, { strings: false });
    expect(valueImportSpecifiers(code).filter((s) => banned.has(s))).toEqual([]);
  });

  it("reaches the modules it claims to — the graph walk is not silently empty", () => {
    // A walk that resolved nothing would pass the check above for the worst possible reason.
    const { files } = graphFrom(HOOK_ENTRY);
    const rel = [...files].map((f) => path.relative(SRC_ROOT, f).split(path.sep).join("/")).sort();
    expect(rel).toContain("loader/module-read.ts");
    expect(rel).toContain("policy/evaluate.ts");
    expect(rel).toContain("attribution/index.ts");
    expect(rel).toContain("attribution/link-map.ts");
    expect(rel).toContain("shims/runtime.ts");
    expect(rel).toContain("real-builtins/worker_threads.cts");
    expect(rel).toContain("real-builtins/fs.cts");
  });
});

/**
 * The runtime half. One child, shared between the two claims it supports: the probe is a pure
 * function of (argv, cwd, env), so `share: true` is sound here — see helpers/subprocess.ts.
 */
const PROBE = path.join(here, "fixtures", "loader-thread-graph.mjs");
const probe = (): Promise<{ code: number; stdout: string; stderr: string }> =>
  runNode([PROBE], { cwd: here, share: true });

/**
 * DEP0205 — **Node 26 deprecated `module.register()` in favour of `module.registerHooks()`**, so
 * capwall's own ESM install now prints a runtime DeprecationWarning on the 26 leg of the matrix.
 * It is capwall's warning, about capwall's call, and it is correct: the fix is issue #152
 * (switch the ESM perimeter to the synchronous same-thread hooks), which is deliberately NOT
 * done here — that perimeter is where #59, #61 and #62 lived and it needs its own PR with the
 * laundering-vector suite run against it.
 *
 * Subtracted by EXACT match rather than by loosening the assertion to `not.toContain`. The claim
 * this test makes is "the probe writes nothing to stderr" — that is how a loader-thread crash or
 * an unexpected experimental warning shows up — and a substring check would keep passing through
 * any future warning that happened to arrive alongside this one. When #152 lands, these lines
 * simply stop appearing and the filter becomes a no-op; it does not need removing to stay
 * correct, and leaving it does not hide anything, because ANY other stderr still fails.
 */
function stderrWithoutKnownDeprecations(stderr: string): string {
  const IGNORE = [
    /^\(node:\d+\) \[DEP0205\] DeprecationWarning: `module\.register\(\)` is deprecated\. Use `module\.registerHooks\(\)` instead\.$/,
    /^\(Use `node --trace-deprecation \.\.\.` to show where the warning was created\)$/,
  ];
  return stderr
    .split("\n")
    .filter((line) => line.trim() !== "" && !IGNORE.some((re) => re.test(line)))
    .join("\n");
}

describe("#150 — what the built hook module actually loads, measured in a clean process", () => {
  beforeAll(() => {
    assertPreloadBuilt();
  });

  it("pulls in no mediated builtin beyond fs and worker_threads", async () => {
    const r = await probe();
    const unexpected = stderrWithoutKnownDeprecations(r.stderr);
    expect(unexpected, r.stderr).toBe("");
    const out = JSON.parse(r.stdout) as { hook: string[]; aggregate: string[] };
    // `fs` is already resident from Node's own bootstrap in most builds, so it is allowed rather
    // than required; `worker_threads` is the one the hook genuinely brings in.
    expect(out.hook.filter((m) => m !== "fs" && m !== "worker_threads")).toEqual([]);
  });

  it("has a working probe — the aggregate capture DOES pull the rest in", async () => {
    // The positive control. Without it, "the hook loaded nothing extra" and "moduleLoadList stopped
    // reporting" are the same green.
    //
    // `net` and `http` are deliberately NOT in this list: whether they are already resident before
    // any user code runs depends on how the child's stdio was set up (a piped stdio loads `net`
    // during bootstrap, which is exactly how this test is run), and a control that flakes on the
    // harness's own plumbing is worse than a narrower one. The four below have no such route.
    const r = await probe();
    const out = JSON.parse(r.stdout) as { hook: string[]; aggregate: string[] };
    for (const m of ["tls", "http2", "dgram", "child_process", "vm"]) {
      expect(out.aggregate, `${m} should appear once the aggregate capture is loaded`).toContain(m);
    }
  });

  it("keeps zod off the loader thread's graph entirely", async () => {
    const r = await probe();
    const out = JSON.parse(r.stdout) as { zodAfterHook: number; zodAfterPolicyLoad: number };
    expect(out.zodAfterHook, "zod must not be reachable from the ESM hook module").toBe(0);
    // Control again: zod is not gone from the product, it is off ONE graph. `policy/load.ts` still
    // needs it, on the main thread, where a policy is actually parsed.
    expect(out.zodAfterPolicyLoad, "policy/load.ts still parses with zod").toBeGreaterThan(0);
  });
});

/**
 * THE MAIN THREAD'S STARTUP GRAPH HAS A CEILING TOO (issue #167).
 *
 * ── WHY THIS EXISTS ─────────────────────────────────────────────────────────────────────────
 * zod 3 -> 4 (#161) added **~58 ms** to every mediated process's startup, and **not one gate in
 * this repo noticed**: `pnpm test` green, `bench:gate` green with all 21 self-checks,
 * `mutation:gate` 17/17, `ci:local` green on 22, 24 and 26. It was found by building a one-off
 * harness on purpose. That is the same shape as the inverted vite override #158 found after
 * months, and the same shape as the two imports #150 found — a cost that is real, permanent, paid
 * by every user, and invisible to everything that runs automatically.
 *
 * The blocking `module.register()` graph got a guard in #150. This is the other half: the graph
 * the MAIN thread evaluates before the target's entry point, where the policy is parsed.
 *
 * ── WHY A COUNT AND NOT A TIME ──────────────────────────────────────────────────────────────
 * AGENTS.md § 7: never gate on a wall-clock figure. A descheduled process accumulates elapsed
 * time it did not spend running, so any millisecond threshold that still catches a regression
 * goes red on a busy machine — and the suite already spawns ~190 children (#145). `bench.mjs`
 * solves that for per-call latency with a co-sampled ratio; startup has no equivalent reference,
 * because "how long does Node take to evaluate 80 ES modules" has nothing to co-sample against.
 *
 * So this gates the thing the milliseconds are made of instead. **Module count is immune to
 * machine speed by construction**, and it is what actually moved: zod's graph went from **19
 * resolves to 180** across that upgrade — 9.5x, which is where the 58 ms came from. Measured
 * identical (180) on Node 22, 24 and 26, and byte-stable across repeated runs on each.
 *
 * ── WHY A CEILING WITH HEADROOM, AND WHERE THE HEADROOM COMES FROM ──────────────────────────
 * `ci.yml` installs with `--frozen-lockfile=false`, so pinning this to today's exact 180 would
 * turn CI red the day zod ships a patch that adds a file, with no human having done anything. A
 * gate that goes red on its own is a gate that gets deleted.
 *
 * So the budget is a ceiling — but the headroom is DERIVED rather than picked. § zod 4 measures
 * zod 4's graph at ~62 ms over 180 resolves, i.e. **~0.34 ms per resolve**. Choose the number of
 * milliseconds worth being interrupted for, divide, and that is the headroom. At 15 ms that is
 * ~44 resolves, giving a budget of ~224. Ordinary churn passes; anything that costs more than a
 * blink does not.
 *
 * Note what this gate can and cannot do, because the first draft of it got this wrong and the
 * self-check below caught it: **a ceiling never catches a regression that has already landed.**
 * 180 is today's number, so no budget at-or-above 180 would have failed on zod 4. This is a
 * forward gate on the NEXT widening, and the self-check's job is to keep the ceiling close enough
 * to the floor that the next one has to be small to slip through.
 *
 * If you are here because this failed: read `scripts/bench/README.md` § zod 4 first. It has the
 * breakdown, the harness, and the entry points that were already tried and rejected. Then move
 * the number WITH a measurement, the way that section did — do not raise it to clear the red.
 *
 * `zod` is named here because it is capwall's only runtime dependency and therefore the entire
 * third-party graph on this path. If it is ever replaced, this gate moves to whatever replaces
 * it; the property being defended is "the startup graph does not silently widen", not "zod".
 */
describe("#167 — the main thread's startup graph does not silently widen", () => {
  /** Resolve calls under `zod/` after `policy/load.js` is imported, measured on 22, 24 and 26. */
  const OBSERVED = 180;
  /** ~62 ms over those 180 resolves — `scripts/bench/README.md` § zod 4. */
  const MS_PER_RESOLVE = 62 / OBSERVED;
  /** How much added startup may arrive without anyone being told. A judgement, stated once. */
  const HEADROOM_MS = 15;

  const ZOD_RESOLVE_BUDGET = Math.round(OBSERVED + HEADROOM_MS / MS_PER_RESOLVE);

  beforeAll(() => {
    assertPreloadBuilt();
  });

  it("keeps capwall's runtime dependency graph inside its startup budget", async () => {
    const r = await probe();
    const out = JSON.parse(r.stdout) as { zodAfterPolicyLoad: number };
    expect(
      out.zodAfterPolicyLoad,
      `The policy validator's module graph is now ${out.zodAfterPolicyLoad} resolves, over the ` +
        `${ZOD_RESOLVE_BUDGET} budget — roughly ` +
        `+${Math.round((out.zodAfterPolicyLoad - OBSERVED) * MS_PER_RESOLVE)} ms of startup. ` +
        `module.register() is not involved: this is the MAIN thread, before the target's entry ` +
        `point, on every mediated process. The last time this number moved (19 -> 180, zod 3 -> ` +
        `4) it cost ~58 ms and no gate in this repo caught it, which is why this one exists ` +
        `(#161, #167). Read scripts/bench/README.md § zod 4 before raising the budget, and raise ` +
        `it with a measurement rather than to clear the red.`,
    ).toBeLessThanOrEqual(ZOD_RESOLVE_BUDGET);
  });

  it("has a budget that constrains — the ceiling sits within one headroom of the floor", async () => {
    // The self-check #112 asks for. A budget set so high that no plausible change trips it is
    // indistinguishable from no budget, and reads green either way. This is the claim that makes
    // raising `ZOD_RESOLVE_BUDGET` on its own fail: the ceiling is pinned to the OBSERVED floor
    // by the stated millisecond headroom, so moving one without the other is an error, and the
    // first draft of this block — a hand-picked 220 with no derivation — is exactly what it
    // rejects.
    expect(
      ZOD_RESOLVE_BUDGET - OBSERVED,
      "the budget has drifted away from its stated millisecond headroom",
    ).toBeLessThanOrEqual(Math.ceil(HEADROOM_MS / MS_PER_RESOLVE));
    expect(HEADROOM_MS, "15 ms is the most this may absorb silently").toBeLessThanOrEqual(15);

    // …and that the floor it is pinned to is still the real number. Without this the pair above
    // is arithmetic about two constants and would pass with the product deleted.
    //
    // A LOWER bound, deliberately, and not `toBe(OBSERVED)`: pinning exactly would reintroduce
    // the "CI goes red the day zod ships a patch" failure the ceiling exists to avoid. The upper
    // side is already the gate above. What this catches is the other kind of staleness — the
    // graph got much SMALLER (a cheaper validator, a narrower import) and nobody re-derived, so
    // the budget silently became decorative.
    const r = await probe();
    const out = JSON.parse(r.stdout) as { zodAfterPolicyLoad: number };
    expect(
      out.zodAfterPolicyLoad,
      `OBSERVED (${OBSERVED}) is stale: the graph now resolves only ${out.zodAfterPolicyLoad}, ` +
        `so the budget above no longer constrains anything. Re-derive it from the new floor.`,
    ).toBeGreaterThan(OBSERVED - Math.ceil(HEADROOM_MS / MS_PER_RESOLVE));
  });
});
