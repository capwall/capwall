/**
 * INSTALL LIFECYCLE on the CJS require path — issue #87, the twin of #62/#74.
 *
 * The bug: `loader/require.ts` built a fresh `ShimContext` per `install()` and never re-pointed
 * the old one, so a module that captured `fs` under a loose policy kept enforcing THAT policy
 * after `uninstall()` and after `install(tighter)`, while a freshly-required `fs` correctly
 * denied — one process, two live policies, disagreeing. `process.env` rebuilt its proxy per
 * install and so DID tighten, which made env and fs disagree too, and `onDecision` kept firing
 * into the torn-down install's sink.
 *
 * Every case below turns on ONE variable: WHEN the dependency captured its reference.
 * `fixture-dep.readData()` uses the `fs` captured at load; `readDataFreshRequire()` re-requires
 * per call; `readEnv()` reads the live `process.env`; `readCapturedEnv()` uses the object captured
 * at load. The invariant this file pins is that all four answer the same question the same way.
 *
 * THE SEMANTICS ASSERTED HERE, stated once (see also `InstallHandle.uninstall`'s doc):
 *   - under `install(tighter)`, an ALREADY-CAPTURED shim enforces the NEW policy. That is the fix;
 *   - after the LAST `uninstall()`, an already-captured shim FAILS CLOSED (deny-all `enforce`) and
 *     records nothing, matching what #74 chose for ESM. A capture cannot be revoked, so "capwall
 *     is off again" is not available for it; the choice is between the dead policy's grants and
 *     no grants, and serving revoked grants is the fail-open one;
 *   - after the last `uninstall()`, a FRESH access is genuinely un-mediated, because the
 *     interception POINTS (`Module._load`, `process.env`) really are restored. Fail-closed
 *     applies to stale captures, not to a torn-down process;
 *   - installs NEST. `uninstall()` deactivates one install and re-exposes the one below it —
 *     including for already-captured shims — in any order, not just LIFO.
 */
import { readFileSync as fsReadFileSync } from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  install,
  loadPolicyFromObject,
  type Decision,
  type InstallHandle,
  type Policy,
} from "../src/index.js";
import { liveCtx, popInstall, pushInstall } from "../src/loader/live-context.js";
import type { ShimContext } from "../src/shims/runtime.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");
const DATA = "fixture data\n";
/** Deliberately NOT a `CAPWALL_*` name — those are exempt from env gating (see shims/env.ts). */
const SECRET_KEY = "LIFECYCLE_TEST_SECRET";
const SECRET_VALUE = "s3cr3t";

interface FixtureDep {
  readData(): string;
  readDataFreshRequire(): string;
  readEnv(key: string): string | undefined;
  readCapturedEnv(key: string): string | undefined;
}

/** Require the fixture fresh (cache cleared) so its load-time captures re-run in this window. */
function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

/** Grants fixture-dep everything the fixture touches. */
const loose = (): Policy =>
  loadPolicyFromObject(
    {
      version: 1,
      mode: "enforce",
      packages: { "fixture-dep": { fs: { read: ["./**"] }, env: [SECRET_KEY] } },
    },
    { projectRoot: here },
  );

/** Grants nothing at all — deny-by-default for every package. */
const tight = (): Policy =>
  loadPolicyFromObject({ version: 1, mode: "enforce", packages: {} }, { projectRoot: here });

// `env` stays ON (it is half of the consistency question this file exists to pin); global egress
// is off because none of these cases touch it and it writes to `globalThis`.
const OPTS = { projectRoot: here, globalEgress: false } as const;

type Recorded = { pkg: string; decision: Decision };

/** Everything installed by a test, torn down in reverse even if an assertion threw. */
const open: InstallHandle[] = [];
function track(handle: InstallHandle): InstallHandle {
  open.push(handle);
  return handle;
}
afterEach(() => {
  while (open.length > 0) open.pop()?.uninstall();
});

/* ── the co-sampled reference for the ratio backstop at the bottom of this file (#145) ────── */

/**
 * The UNMEDIATED form of the exact call the backstop measures: the same `readFileSync`, on the
 * same file, reached through this test file's own `node:fs` binding rather than through the
 * fixture's captured shim.
 *
 * `scripts/bench/bench.mjs` gates on a ratio against a co-sampled CPU calibration for the same
 * reason this does — an absolute microsecond figure is a statement about the machine, not about
 * the code. Here the reference can be stronger than a synthetic CPU loop: capwall's overhead on
 * `readFileSync` is a MULTIPLIER on `readFileSync`, so dividing by the raw call cancels CPU
 * speed AND filesystem contention, which a pure-CPU calibration does not. That mattered
 * empirically: a CPU-only reference put the gate's own margin at 4.8 during a parallel suite
 * run, because the mediated arm does real I/O and the reference arm did not.
 *
 * Imported at module scope, before any `install()` in this file, so it is the real builtin.
 */
const rawReadFileSync = fsReadFileSync;
const DATA_FILE = path.join(FIXTURE, "data.txt");
/** Kept live so V8 cannot eliminate the reference loop as dead code. */
let SINK: unknown = null;

/**
 * MEASURED, then given ~2x headroom. The gated figure — the MINIMUM per-block ratio of mediated ÷
 * raw `readFileSync` — observed on this tree, Node 22 (#145):
 *
 *   | condition                                              | min per-block ratio |
 *   |--------------------------------------------------------|---------------------|
 *   | this file alone, 16-core host                           |         7.0 – 8.9   |
 *   | inside a full parallel `vitest run`, 16-core host       |         2.9 – 6.8   |
 *   | inside a full parallel run at ~4x CPU oversubscription  |         3.1 – 3.4   |
 *   | inside a full parallel run in `docker run --cpus=2`     |               5.4   |
 *
 * Note which direction contention moves it: DOWN, because the reference arm is slowed too. The
 * binding case for the limit is the quiet machine, not the busy one — the opposite of the
 * wall-clock assertion this replaced, and the reason it is a usable gate.
 *
 * 18 is ~2x the widest of those. It is not tuned until the run goes green: a per-call proxy or a
 * per-call registry rebuild — the regressions this exists to catch — multiplies the mediated arm
 * again, landing far outside it.
 */
const RATIO_LIMIT = 18;

const isDenied = (fn: () => unknown): boolean => {
  try {
    fn();
    return false;
  } catch (err) {
    return (err as { name?: string }).name === "CapabilityError";
  }
};

beforeAll(() => {
  // Set on the REAL environment, before any proxy is in place.
  process.env[SECRET_KEY] = SECRET_VALUE;
});

describe("#87 — a runtime policy swap reaches an already-captured CJS shim", () => {
  it("applies a TIGHTER policy to the fs a dependency captured under a looser one", () => {
    const first = track(install(loose(), "enforce", OPTS));
    const dep = loadFixtureFresh(); // captures the shimmed `fs` while `loose` is in force
    expect(dep.readData()).toBe(DATA);

    first.uninstall();
    track(install(tight(), "enforce", OPTS));

    // THE FINDING. Pre-fix this returned the file contents: the captured shim closed over the
    // first install's context object, which nothing ever re-pointed.
    expect(() => dep.readData()).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });

  it("applies it to a freshly-required fs too, so the two forms never disagree", () => {
    const first = track(install(loose(), "enforce", OPTS));
    const dep = loadFixtureFresh();
    expect(dep.readDataFreshRequire()).toBe(DATA);

    first.uninstall();
    track(install(tight(), "enforce", OPTS));

    // This half already worked before the fix — it is pinned so the two can never drift apart
    // again. A process where the answer depends on when `require("fs")` happened to run is the
    // actual defect; either behaviour applied consistently would be defensible.
    expect(() => dep.readDataFreshRequire()).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });

  it("keeps the captured and the freshly-required shim in agreement at every step", () => {
    const first = track(install(loose(), "enforce", OPTS));
    const dep = loadFixtureFresh();
    const step = (): [boolean, boolean] => [
      isDenied(() => dep.readData()),
      isDenied(() => dep.readDataFreshRequire()),
    ];

    expect(step()).toEqual([false, false]);
    const second = track(install(tight(), "enforce", OPTS));
    expect(step()).toEqual([true, true]);
    second.uninstall();
    // Loosening applies as well — this is a live policy, not a one-way ratchet.
    expect(step()).toEqual([false, false]);
    first.uninstall();
    // Torn down: the CAPTURE fails closed, while a FRESH require reaches the real, un-shimmed
    // fs because `Module._load` genuinely is restored. Asymmetric on purpose — see the header.
    expect(step()).toEqual([true, false]);
  });

  it("keeps process.env and fs in agreement across the swap (the named inconsistency)", () => {
    const first = track(install(loose(), "enforce", OPTS));
    const dep = loadFixtureFresh();
    expect(dep.readEnv(SECRET_KEY)).toBe(SECRET_VALUE);
    expect(dep.readCapturedEnv(SECRET_KEY)).toBe(SECRET_VALUE);
    expect(isDenied(() => dep.readData())).toBe(false);

    first.uninstall();
    track(install(tight(), "enforce", OPTS));

    // env soft-denies (returns undefined) and fs throws — different DELIVERY, same DECISION.
    // Before the fix env tightened here and fs did not, which is what #87 called "two
    // capabilities in one process disagreeing about which policy is in force".
    expect(dep.readEnv(SECRET_KEY)).toBeUndefined();
    expect(dep.readCapturedEnv(SECRET_KEY)).toBeUndefined();
    expect(isDenied(() => dep.readData())).toBe(true);
  });
});

describe("#87 — post-uninstall() behaviour, asserted explicitly", () => {
  it("fails an already-captured shim CLOSED once the last install is gone", () => {
    const handle = track(install(loose(), "enforce", OPTS));
    const dep = loadFixtureFresh();
    expect(dep.readData()).toBe(DATA);

    handle.uninstall();

    // Not "pass through to the real fs" and not "keep enforcing the last policy" — deny.
    expect(() => dep.readData()).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    // Same answer for the env proxy the dependency captured, so the two agree here too.
    expect(dep.readCapturedEnv(SECRET_KEY)).toBeUndefined();
  });

  it("restores the interception points, so a FRESH access is un-mediated", () => {
    const handle = track(install(loose(), "enforce", OPTS));
    loadFixtureFresh();
    handle.uninstall();

    // `Module._load` is really unpatched and `process.env` is really the original object, so a
    // module loaded after teardown gets the raw builtins. Fail-closed is about stale captures,
    // not about turning a torn-down process into a deny-all one.
    const after = loadFixtureFresh();
    expect(after.readData()).toBe(DATA);
    expect(after.readEnv(SECRET_KEY)).toBe(SECRET_VALUE);
    expect(after.readCapturedEnv(SECRET_KEY)).toBe(SECRET_VALUE);
  });

  it("stops reporting into the torn-down install's decision sink", () => {
    const decisions: Recorded[] = [];
    const handle = track(
      install(loose(), "enforce", {
        ...OPTS,
        onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
      }),
    );
    const dep = loadFixtureFresh();
    dep.readData();
    dep.readEnv(SECRET_KEY);
    expect(decisions.length).toBeGreaterThan(0);

    handle.uninstall();
    const settled = decisions.length;

    // The captured shim still runs — and still denies — but the embedder's collector (or the
    // CLI's trace file) belongs to an install that no longer exists. Writing a decision into it
    // is a use-after-free of someone else's state, so the sink is dropped with its install.
    // The denial itself stays visible: it throws.
    expect(() => dep.readData()).toThrow();
    expect(dep.readCapturedEnv(SECRET_KEY)).toBeUndefined();
    expect(decisions.length).toBe(settled);
  });
});

describe("#87 — nested installs", () => {
  it("innermost wins, and unwinding re-exposes the one below it", () => {
    const outer = track(install(loose(), "enforce", OPTS));
    const dep = loadFixtureFresh();
    expect(isDenied(() => dep.readData())).toBe(false);

    const inner = track(install(tight(), "enforce", OPTS));
    expect(isDenied(() => dep.readData())).toBe(true);

    inner.uninstall();
    expect(isDenied(() => dep.readData())).toBe(false); // outer is live again

    outer.uninstall();
    expect(isDenied(() => dep.readData())).toBe(true); // nothing installed → fail closed
  });

  it("survives an out-of-LIFO-order uninstall (mirrors the _load chain's #22 contract)", () => {
    const outer = track(install(loose(), "enforce", OPTS));
    const dep = loadFixtureFresh();
    const inner = track(install(tight(), "enforce", OPTS));

    // Remove the OUTER install first. It is not on top, so the live policy must not change.
    outer.uninstall();
    expect(isDenied(() => dep.readData())).toBe(true);

    // Idempotent: a second uninstall of an already-removed install must not pop the survivor.
    outer.uninstall();
    expect(isDenied(() => dep.readData())).toBe(true);

    inner.uninstall();
    expect(isDenied(() => dep.readData())).toBe(true); // torn down, so still denied
    expect(loadFixtureFresh().readData()).toBe(DATA); // …but the loader is restored
  });
});

describe("#87 — the live context mirrors the whole install", () => {
  /**
   * The failure mode this guards is "a field was added to `ShimContext` and nobody mirrored it
   * onto the live box", which silently leaves that field at the PREVIOUS install's value — the
   * #62/#87 bug in miniature, one field at a time. It is not hypothetical: `hardened` was
   * exactly this. #74 built the ESM registry from the live box but never copied `hardened` onto
   * it, so `install(policy, mode, { hardened: true, esm: true })` produced UNFROZEN ESM shims —
   * hardened mode was inert on the import path, silently, with no test that would have said so.
   *
   * `Required<ShimContext>` is what makes this exhaustive: a new optional field breaks the
   * literal below until it is listed, and the loop then checks it survived the round trip.
   */
  it("copies every ShimContext field onto the live box, and clears them all on teardown", () => {
    const probe: Required<ShimContext> = {
      policy: tight(),
      mode: "observe",
      onDecision: () => {},
      projectRoot: "/probe/root",
      maxFrames: 7,
      hardened: true,
    };
    const live = liveCtx as unknown as Record<string, unknown>;
    pushInstall(probe);
    try {
      for (const key of Object.keys(probe)) {
        expect([key, live[key]]).toEqual([key, (probe as unknown as Record<string, unknown>)[key]]);
      }
    } finally {
      popInstall(probe);
    }

    // Torn down: deny-all `enforce`, a dropped sink, and every optional field cleared. Leaving
    // `projectRoot` behind would attribute post-teardown calls against a stale root.
    expect(liveCtx.mode).toBe("enforce");
    expect(liveCtx.policy.packages).toEqual({});
    expect(liveCtx.policy.default).toEqual({});
    expect(liveCtx.projectRoot).toBeUndefined();
    expect(liveCtx.maxFrames).toBeUndefined();
    expect(liveCtx.hardened).toBeUndefined();
  });
});

describe("#87 — the fix adds no per-call work to the hot path", () => {
  /**
   * The whole point of re-pointing a long-lived context's FIELDS (rather than wrapping exports
   * in forwarders) is that nothing is inserted between the caller and the guard. This asserts
   * that structurally, which is stronger and far less flaky than a wall-clock threshold: if a
   * policy swap were implemented with a proxy or a per-install forwarder, these identities
   * would have to change.
   */
  it("hands out the SAME shim objects and functions across a policy swap — no forwarder", () => {
    const first = track(install(loose(), "enforce", OPTS));
    const fsBefore = requireCjs("fs") as Record<string, unknown>;
    const readBefore = fsBefore["readFileSync"];

    first.uninstall();
    track(install(tight(), "enforce", OPTS));

    const fsAfter = requireCjs("fs") as Record<string, unknown>;
    expect(fsAfter).toBe(fsBefore);
    expect(fsAfter["readFileSync"]).toBe(readBefore);
    // …and the shim is still a plain, patchable object, which is the compatibility half of that
    // decision (graceful-fs et al. — see shims/harden.ts).
    expect(Object.isFrozen(fsAfter)).toBe(false);
  });

  /**
   * A backstop for the same claim, stated as a RATIO rather than a wall clock (#145).
   *
   * This used to assert `perCallUs < 500` against a measured single-digit µs — a ~100x margin,
   * which still went red on a loaded box. A per-call wall clock cannot be made
   * contention-proof by widening it: the loop measures elapsed time, and a descheduled process
   * accumulates elapsed time it did not spend running. 200 ms of scheduler stall spread over
   * 2000 iterations reads as +100 µs per call, and no bound that still catches a real
   * regression survives that.
   *
   * So it is measured the way `scripts/bench/bench.mjs` gates the perf budget: divided by a
   * reference CO-SAMPLED in the same interleaved loop, with the gate taking the MINIMUM
   * per-block ratio. Both arms are descheduled together, so a stall that inflates one inflates
   * the other and mostly cancels, and the minimum block is the least-disturbed sample. The
   * reference here is the SAME `readFileSync` on the SAME file, unmediated — so the number is
   * literally "what capwall multiplies this call by", and it says the same thing on a 2-core
   * runner, on a 16-core box, and on either at 4x oversubscription.
   *
   * It is still a coarse backstop, not a benchmark: it exists to catch an accidental
   * order-of-magnitude regression (a per-call proxy, a per-call registry rebuild), and
   * {@link RATIO_LIMIT} is set from a measurement rather than nudged until green. The real
   * per-call budget lives in the bench harness, which controls its own environment.
   */
  it("costs a bounded multiple of the same unmediated call, per mediated call", () => {
    track(install(loose(), "enforce", OPTS));
    const dep = loadFixtureFresh();
    // Warm both arms: JIT, the page cache, and each call site's own inline caches.
    for (let i = 0; i < 300; i++) dep.readData();
    for (let i = 0; i < 300; i++) SINK = rawReadFileSync(DATA_FILE, "utf8");

    // Interleave at ~50 µs granularity: a scheduler stall long enough to matter then lands on
    // both arms in roughly the proportion they occupy, instead of on whichever one it
    // interrupted. Coarser interleaving (a whole arm, then the other) measurably widened the
    // spread when this was written.
    const BLOCKS = 15;
    const CHUNKS = 30;
    const PER_CHUNK = 10;
    const ratios: number[] = [];
    for (let b = 0; b < BLOCKS; b++) {
      let mediatedNs = 0;
      let rawNs = 0;
      for (let c = 0; c < CHUNKS; c++) {
        const t0 = process.hrtime.bigint();
        for (let i = 0; i < PER_CHUNK; i++) SINK = dep.readData();
        const t1 = process.hrtime.bigint();
        for (let i = 0; i < PER_CHUNK; i++) SINK = rawReadFileSync(DATA_FILE, "utf8");
        const t2 = process.hrtime.bigint();
        mediatedNs += Number(t1 - t0);
        rawNs += Number(t2 - t1);
      }
      ratios.push(mediatedNs / rawNs);
    }
    // Both arms must really have read the file — a mediated read that started returning a
    // constant, or a reference arm optimised away, would make the ratio meaningless.
    expect(SINK, "the last co-sampled reference read did not return the fixture's bytes").toBe(
      DATA,
    );
    const best = Math.min(...ratios);
    expect(
      best,
      `mediated ÷ co-sampled unmediated readFileSync, per block: ` +
        `${ratios.map((r) => r.toFixed(2)).join(", ")} (gate takes the minimum, limit ${RATIO_LIMIT})`,
    ).toBeLessThan(RATIO_LIMIT);
  });
});
