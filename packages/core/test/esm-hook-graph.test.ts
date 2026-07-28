/**
 * WHAT `install({ esm: true })` COSTS A PROCESS BEFORE IT RUNS (#150, re-aimed by #152/#153).
 *
 * ── WHAT #152 CHANGED ABOUT THIS FILE, STATED FIRST ─────────────────────────────────────────
 * #150 wrote this file about **Node's ESM loader thread**. `module.register()` started a separate
 * module-customization thread and BLOCKED the main thread until that thread had resolved, compiled
 * and evaluated the hook module's entire import graph, so every module reachable from
 * `loader/esm-hooks.ts` was serial startup cost on every mediated process. Two things were on that
 * graph for no reason — `zod` via `@capwall/policy-schema`'s barrel, and ten of the twelve builtins
 * via the aggregate capture — and this file's two static scans kept both off it.
 *
 * **`module.registerHooks()` does not start that thread**, so the realm those scans were about no
 * longer exists, and both of them are now vacuous rather than merely smaller:
 *
 *  - the **narrow per-builtin captures** (`src/real-builtins/`) existed so a module on the loader
 *    thread could reach `node:fs` without dragging in the other eleven. On this thread the
 *    aggregate is loaded unconditionally anyway (`index.ts` → `loader/require.ts` →
 *    `real-builtins.cjs`), so the narrowing now buys nothing at all. It has been removed, with its
 *    mutant.
 *  - the **zod ban** was never really a loader-thread-only fact in principle, but it is one in
 *    practice: `src/index.ts` re-exports `loadPolicyFromObject` from `policy/load.ts`, so zod is
 *    on `@capwall/core`'s entry graph regardless and the preload parses a real policy on every
 *    run. Re-rooting the scan at `index.ts` would have made it fail on the very first run for a
 *    reason that is not a defect. It has been removed too. `policy/evaluate.ts` still takes the
 *    grammar from `@capwall/policy-schema/host` — that is correct and free, it is simply no longer
 *    a claim worth a guard.
 *
 * Deleting a guard is not free either, so this file keeps the SHAPE #150 established — a
 * measurement in a clean child, plus a positive control in the same child, because a probe that
 * reports "nothing extra" is indistinguishable from a probe that stopped working — and points it
 * at the property #152 actually bought:
 *
 *  1. **capwall's ESM install starts no module-customization thread.** That is the ~53 ms, and it
 *     is the difference between the two registration APIs rather than anything about capwall's
 *     own graph. Measured through `process.moduleLoadList`, which on 22/24/26 alike gains
 *     `NativeModule internal/modules/esm/hooks` (and four `internal/worker*` entries) for
 *     `module.register()` and nothing at all for `module.registerHooks()`. Only the first of those
 *     is usable as a signal here — capwall captures `node:worker_threads` unconditionally (#78),
 *     so the `internal/worker*` entries are resident either way; see the fixture.
 *  2. **a mediated process starts silently.** #153's acceptance criterion: on Node 26
 *     `module.register()` printed `[DEP0205] DeprecationWarning` on every run, on the channel
 *     capwall's own `DENY` lines live on.
 */
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { assertPreloadBuilt, runNode } from "./helpers/subprocess.js";

const here = path.dirname(fileURLToPath(import.meta.url));

/**
 * One child, shared between every claim it supports: the probe is a pure function of
 * (argv, cwd, env), so `share: true` is sound here — see helpers/subprocess.ts.
 */
const PROBE = path.join(here, "fixtures", "startup-graph.mjs");
const probe = (): Promise<{ code: number; stdout: string; stderr: string }> =>
  runNode([PROBE], { cwd: here, share: true });

interface ProbeResult {
  /** Loader-thread internals resident after `install({ esm: true })`. Must be empty. */
  afterInstall: string[];
  /** The same list after a bare `module.register()` in the same child. The positive control. */
  afterRegister: string[];
  /** Resolve calls under `zod/` once `policy/load.js` is in. #167's subject, below. */
  zodAfterPolicyLoad: number;
}

describe("#152 — install({ esm: true }) starts no module-customization thread", () => {
  beforeAll(() => {
    assertPreloadBuilt();
  });

  it("loads none of Node's loader-thread internals", async () => {
    // ~53 ms of the old ~93 ms `registerEsmHook()` was Node bootstrapping this thread, measured
    // with a NO-OP hook module — so it was Node's cost, not capwall's graph, and no amount of
    // narrowing that graph (#150) could reach it. Only not asking for the thread does.
    const r = await probe();
    const out = JSON.parse(r.stdout) as ProbeResult;
    expect(
      out.afterInstall,
      `capwall's ESM install pulled in Node's module-customization thread. That is the ~53 ms ` +
        `#152 removed, and the only way to spend it again is to go back to module.register() — ` +
        `which is also DEP0205-deprecated with removal announced (#153).`,
    ).toEqual([]);
  });

  it("has a working probe — module.register() DOES pull them in", async () => {
    // The positive control. Without it, "capwall started no thread" and "moduleLoadList stopped
    // reporting" are the same green — the exact failure #150's own probe was built to exclude.
    const r = await probe();
    const out = JSON.parse(r.stdout) as ProbeResult;
    expect(out.afterRegister).toEqual(["NativeModule internal/modules/esm/hooks"]);
  });
});

describe("#153 — a mediated process starts silently (DEP0205)", () => {
  beforeAll(() => {
    assertPreloadBuilt();
  });

  it("writes NOTHING to stderr while registering capwall's hooks", async () => {
    // Asserted as an EXACT emptiness rather than a `not.toContain("DEP0205")`. On Node 26,
    //
    //   (node:…) [DEP0205] DeprecationWarning: `module.register()` is deprecated.
    //                      Use `module.registerHooks()` instead.
    //
    // appeared here on every run, and this file used to carry a two-line regex subtracting it by
    // exact match with a comment pointing at #152. That filter is gone because the warning is.
    // Emptiness is also how a loader crash or a new experimental warning shows up, which a
    // substring check would let through.
    //
    // The probe deliberately samples stderr BEFORE its own `module.register()` control, which on
    // Node 26 does still warn — see the fixture.
    const r = await probe();
    expect(r.stderr, "a mediated process must start silently").toBe("");
    expect(r.code).toBe(0);
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
 * the MAIN thread evaluates before the target's entry point, where the policy is parsed. #152
 * since retired the first half — `module.registerHooks()` runs the hooks in this realm, so there
 * is no second graph to guard and the one above is the only one — which makes this gate the whole
 * of the startup-graph coverage rather than half of it.
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
