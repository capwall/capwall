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
   * A crude wall-clock backstop for the same claim. The bound is deliberately enormous relative
   * to the measured cost (single-digit µs per mediated call) — it exists to catch an accidental
   * order-of-magnitude regression such as a per-call proxy or a per-call registry rebuild, not
   * to benchmark. Tightening it would buy nothing and would flake on a loaded CI box.
   */
  it("stays in the microsecond range per mediated call", () => {
    track(install(loose(), "enforce", OPTS));
    const dep = loadFixtureFresh();
    for (let i = 0; i < 200; i++) dep.readData(); // warm up JIT + fs cache
    const N = 2000;
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < N; i++) dep.readData();
    const perCallUs = Number(process.hrtime.bigint() - t0) / 1000 / N;
    expect(perCallUs).toBeLessThan(500);
  });
});
