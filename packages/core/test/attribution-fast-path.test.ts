/**
 * Issue #133 — the enumeration fast path, and the attacks it must not create.
 *
 * WHAT CHANGED. `{...process.env}` is two gated Proxy traps per environment variable, and each
 * of them attributed the caller by materializing up to `maxFrames` (25) V8 CallSites. That is
 * ~160 stack walks and MILLISECONDS for a single JS call — the shape `dotenv` and every config
 * loader has. The traps now hand themselves to `attributeCallerVia`, which starts the capture
 * directly below the trap frame and materializes only {@link FAST_PATH_FRAMES}, falling back to
 * the full walk whenever that prefix does not reach a frame it may believe.
 *
 * WHY THIS FILE EXISTS. "Make the repeated case cheap" is the exact shape of the bugs this
 * project keeps finding: #84 was a cache-shaped trust decision that fell to a one-line forgery,
 * #92 was an identity derived from a name an attacker could choose, #89 was a privileged window
 * one package opened and every other package could read through. So the change is deliberately
 * NOT a cache — nothing survives a call — and these tests are the adversary's side of that
 * claim. Two properties, tested separately:
 *
 *   1. EQUIVALENCE. For every stack shape, the fast path answers exactly what the full walk
 *      answers, or declines and lets the full walk answer. It is a cheaper computation of the
 *      same function, not an approximation of it.
 *   2. NO REUSE. A package with no grants cannot acquire another principal's answer by reading
 *      next to it, right after it, in the same tick or the next one, however it shapes the
 *      frames between itself and the trap.
 *
 * The reader here is `fixture-envpeek`, which is granted NOTHING in every policy below, and the
 * secret is granted to `fixture-dep` only. Any assertion that comes back `fixture-dep`, `<app>`
 * or `allowed: true` for an envpeek read is a live exfiltration hole, not a stale expectation.
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  APP_ROOT,
  UNATTRIBUTED,
  attributeCaller,
  attributeCallerVia,
  install,
  loadPolicyFromObject,
  type Decision,
  type Policy,
} from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURES = path.join(here, "fixtures");
const DEP = path.join(FIXTURES, "node_modules", "fixture-dep");
const PEEK = path.join(FIXTURES, "node_modules", "fixture-envpeek");

/**
 * Granted to `fixture-dep` and to nobody else.
 *
 * Deliberately NOT `CAPWALL_`-prefixed: the env shim exempts its own plumbing keys by prefix
 * before it attributes anything, so a key named that way would test the exemption's `startsWith`
 * and nothing else — and would do it by passing.
 */
const SECRET = "FASTPATH_SECRET_133";
const SECRET_VALUE = "fixture-placeholder-not-a-real-secret";

interface Dep {
  readEnv(key: string): string | undefined;
  readEnvDescriptor(key: string): PropertyDescriptor | undefined;
  envSpread(): Record<string, string | undefined>;
  envKeys(): string[];
}
interface Peek {
  read(key: string): string | undefined;
  readAll(): Record<string, string | undefined>;
  readThroughBuiltin(key: string): string | undefined;
  readThroughBuiltins(key: string): string | undefined;
  readAtDepth(depth: number, key: string): string | undefined;
  readThroughEvals(key: string, depth: number): string | undefined;
  readRightAfter(fn: () => unknown, key: string): string | undefined;
  readNextTick(fn: () => unknown, key: string): Promise<string | undefined>;
  callProbe<A, T>(probe: (arg: A) => T, arg?: A): T;
  callProbeThroughBuiltin<A, T>(probe: (arg: A) => T, arg?: A): T;
  callProbeThroughBuiltins<A, T>(probe: (arg: A) => T, arg?: A): T;
  callProbeAtDepth<A, T>(depth: number, probe: (arg: A) => T, arg?: A): T;
  callProbeThroughEvals<A, T>(probe: (arg: A) => T, arg: A, depth: number): T;
}

function loadFresh<T>(dir: string): T {
  const resolved = requireCjs.resolve(dir);
  delete requireCjs.cache[resolved];
  return requireCjs(dir) as T;
}

type Recorded = { pkg: string; decision: Decision };

/** `SECRET` readable by fixture-dep; `fixture-envpeek` appears nowhere. */
function policy(): Policy {
  return loadPolicyFromObject(
    {
      version: 1,
      mode: "enforce",
      packages: { "fixture-dep": { env: [SECRET] } },
    },
    { projectRoot: here },
  );
}

let uninstall: (() => void) | null = null;

/** Install in enforce mode and hand back both fixtures plus the live decision log. */
function boot(options: { maxFrames?: number } = {}): {
  dep: Dep;
  peek: Peek;
  decisions: Recorded[];
} {
  const decisions: Recorded[] = [];
  const handle = install(policy(), "enforce", {
    projectRoot: here,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
    ...(options.maxFrames !== undefined ? { attribution: { maxFrames: options.maxFrames } } : {}),
  });
  uninstall = () => handle.uninstall();
  return { dep: loadFresh<Dep>(DEP), peek: loadFresh<Peek>(PEEK), decisions };
}

/** Decisions naming the secret, in order. Enumeration noise on other keys is not the subject. */
function forSecret(decisions: readonly Recorded[]): Recorded[] {
  return decisions.filter((d) => {
    const observed = d.decision.observed;
    return observed !== undefined && observed.kind === "env" && observed.key === SECRET;
  });
}

process.env[SECRET] = SECRET_VALUE;

afterEach(() => {
  uninstall?.();
  uninstall = null;
});

describe("#133 fast path is the same function, not an approximation", () => {
  /*
   * BOTH PROBES ARE INVOKED BY THE FIXTURE, never by this file, and that is the whole design of
   * this block. `attributeCallerVia` skips up to and including its boundary's frame;
   * `attributeCaller` skips only capwall's. So a probe called from here would leave an `<app>`
   * frame between the fixture and the entry point — visible to one and not the other — and the
   * two would answer different questions while looking like they disagreed.
   *
   * Called through `callProbe*`, the frame directly below both entry points is the fixture's, so
   * "nearest package below capwall's frames" is the same question for both and the answers are
   * comparable. `probeVia` passes ITSELF as the boundary, which is what the env traps do.
   */
  const options = { projectRoot: here };
  function probeVia(opts: typeof options): string {
    return attributeCallerVia(probeVia, opts);
  }
  const probeFull = attributeCaller;
  /*
   * The DECLINE path's reference. When the short capture reaches nothing it may believe,
   * `attributeCallerVia` re-runs the full walk FROM ITS OWN FRAME — so the boundary's frame,
   * skipped by the fast path, is back in play. In production that is invisible: the boundary is
   * an env trap, which lives in capwall's tree and the full walk skips it anyway. Here the
   * boundary is `probeVia`, a function in this test file, so the fallback resolves it to `<app>`.
   * That is the honest reference for the fallback, and the reason the decline cases that MATTER
   * are asserted through the real Proxy in the block below rather than here.
   */
  function probeFallback(opts: typeof options): string {
    return attributeCaller(opts);
  }

  it("agrees with the full walk for a call straight out of a dependency frame", () => {
    const { peek } = boot();
    expect(peek.callProbe(probeVia, options)).toBe("fixture-envpeek");
    expect(peek.callProbe(probeVia, options)).toBe(peek.callProbe(probeFull, options));
  });

  it("agrees when a native builtin frame sits between the caller and the entry point", () => {
    const { peek } = boot();
    // `[x].map(cb)` puts a file-name-less native frame directly above the caller — the shape
    // `Object.assign({}, process.env)` and `JSON.stringify(process.env)` both have, and the
    // reason the fast path materializes more than one frame.
    expect(peek.callProbeThroughBuiltin(probeVia, options)).toBe("fixture-envpeek");
    expect(peek.callProbeThroughBuiltin(probeVia, options)).toBe(
      peek.callProbeThroughBuiltin(probeFull, options),
    );
  });

  it("agrees when three native frames sit in between", () => {
    const { peek } = boot();
    expect(peek.callProbeThroughBuiltins(probeVia, options)).toBe(
      peek.callProbeThroughBuiltins(probeFull, options),
    );
    expect(peek.callProbeThroughBuiltins(probeVia, options)).toBe("fixture-envpeek");
  });

  it("agrees when the caller's own frames are 40 deep", () => {
    const { peek } = boot();
    // Attribution is NEAREST-package: depth below the top frame changes nothing, and the fast
    // path never looks that far, so this is really a check that it does not accidentally care.
    expect(peek.callProbeAtDepth(40, probeVia, options)).toBe("fixture-envpeek");
    expect(peek.callProbeAtDepth(40, probeFull, options)).toBe("fixture-envpeek");
  });

  it("declines, and the full walk answers, when opaque frames fill the short capture", () => {
    const { peek } = boot();
    // Three nested direct `eval`s put three OPAQUE frames above the caller — as many as the fast
    // path materializes, so its whole prefix is frames it may not believe. The observable proof
    // that it DECLINED rather than guessing: the answer is the fallback's, and the fallback sees
    // the boundary's own frame (see `probeFallback`). A fast path that believed an opaque prefix
    // would have reported `fixture-envpeek` here, from a frame it never looked at.
    expect(peek.callProbeThroughEvals(probeVia, options, 3)).toBe(
      peek.callProbeThroughEvals(probeFallback, options, 3),
    );
    // And it is emphatically not the frame the HIT case would have produced.
    expect(peek.callProbeThroughEvals(probeVia, options, 3)).not.toBe(
      peek.callProbe(probeFull, options),
    );
  });

  it("still reaches <unknown>, not <app>, for app code behind an opaque frame", () => {
    boot();
    // The `<app>`-below-opaque rule (#60) lives in the shared walk, so the fast path inherits it
    // rather than reimplementing it. If it were ever reimplemented, this is where the copy rots.
    // This file IS application code, so a working fast path that skipped the rule would answer
    // `<app>` — the trust root, exempt from the env gate entirely.
    // eslint-disable-next-line no-eval -- the eval frame IS the subject of this assertion
    const viaEval = eval("probeVia(options)") as string;
    expect(viaEval).toBe(UNATTRIBUTED);
    expect(viaEval).not.toBe(APP_ROOT);
  });

  it("stands down entirely below the minimum budget, rather than offering a second opinion", () => {
    const { peek } = boot();
    // A `maxFrames` too small for the prefix argument to hold must not produce a different
    // answer. Whatever the full walk says on that budget is the answer.
    const tiny = { projectRoot: here, maxFrames: 4 };
    function probeTiny(opts: typeof tiny): string {
      return attributeCallerVia(probeTiny, opts);
    }
    expect(peek.callProbe(probeTiny, tiny)).toBe(peek.callProbe(probeFallback, tiny));
    // Not merely equal by luck: below the minimum budget the fast path never runs, so the
    // answer is the pre-#133 one and differs from what a hit would have produced.
    expect(peek.callProbe(probeTiny, tiny)).not.toBe(peek.callProbe(probeVia, options));
  });

  it("falls back rather than answering when the boundary is not on the stack", () => {
    const { peek } = boot();
    // V8 returns NO frames when the constructorOpt is absent, so a wrong boundary cannot make
    // the short capture answer anything at all — it can only make it slow. The full walk then
    // sees the fixture frame, as always.
    const stranger = (): void => undefined;
    const answer = peek.callProbe(() => attributeCallerVia(stranger, options));
    // `<app>`: the full walk's nearest frame is this file's arrow, which is application code.
    // The point is that it is the FULL WALK's answer for this stack, not the fixture frame the
    // fast path would have reported had it believed a boundary it could not find.
    expect(answer).toBe(APP_ROOT);
  });
});

describe("#133 fast path grants no principal a dependency did not already have", () => {
  it("charges an ungranted read to the reader through every stack shape it can choose", () => {
    const { peek, decisions } = boot();
    const shapes: Array<[string, () => string | undefined]> = [
      ["direct", () => peek.read(SECRET)],
      ["one builtin frame", () => peek.readThroughBuiltin(SECRET)],
      ["three builtin frames", () => peek.readThroughBuiltins(SECRET)],
      ["40 own frames", () => peek.readAtDepth(40, SECRET)],
    ];
    for (const [label, run] of shapes) {
      decisions.length = 0;
      expect(run(), label).toBeUndefined(); // soft deny: the value never reaches the reader
      const recorded = forSecret(decisions);
      expect(recorded.length, label).toBeGreaterThan(0);
      for (const d of recorded) {
        expect(d.pkg, label).toBe("fixture-envpeek");
        expect(d.decision.allowed, label).toBe(false);
      }
    }
  });

  it("charges a read from inside nested evals to the package the evals ran in", () => {
    const { peek, decisions } = boot();
    // THE decline case, with a real boundary. The fast path's whole prefix is OPAQUE frames —
    // the one input an attacker has here is to make that prefix uninformative — so it declines,
    // and the full walk continues past the eval frames to the package that ran them. Note the
    // trap IS the boundary and lives in capwall's tree, so the fallback skips it as it always
    // did; nothing about the reader's identity depends on the fast path having looked.
    expect(peek.readThroughEvals(SECRET, 3)).toBeUndefined();
    const recorded = forSecret(decisions);
    expect(recorded.length).toBeGreaterThan(0);
    for (const d of recorded) {
      expect(d.pkg).toBe("fixture-envpeek");
      expect(d.pkg).not.toBe(APP_ROOT);
      expect(d.pkg).not.toBe(UNATTRIBUTED);
      expect(d.decision.allowed).toBe(false);
    }
  });

  it("keeps denying under a frame budget too small for the fast path to run", () => {
    const { peek, decisions } = boot({ maxFrames: 4 });
    // Below FAST_PATH_MIN_BUDGET the shim is bit-for-bit its pre-#133 self. A budget this small
    // cannot see past capwall's own frames, so the read is `<unknown>` — deny-by-default, which
    // is the direction a starved budget is allowed to be wrong in (#15/#60).
    expect(peek.read(SECRET)).toBeUndefined();
    const recorded = forSecret(decisions);
    expect(recorded.length).toBeGreaterThan(0);
    for (const d of recorded) {
      expect(d.pkg).not.toBe(APP_ROOT);
      expect(d.decision.allowed).toBe(false);
    }
  });

  it("does not let a granted package's 80-key spread bleed into the very next read", () => {
    const { dep, peek, decisions } = boot();
    // THE attack a per-enumeration principal cache would lose to. `fixture-dep` enumerates the
    // whole environment — a run of ~2 attributions per key, all resolving `fixture-dep`, all in
    // one synchronous stretch — and `fixture-envpeek` reads the secret with NOTHING in between.
    // A cached "who is enumerating" would answer `fixture-dep` and hand over the value.
    const stolen = peek.readRightAfter(() => dep.envSpread(), SECRET);
    expect(stolen).toBeUndefined();
    const recorded = forSecret(decisions);
    const last = recorded.at(-1);
    expect(last?.pkg).toBe("fixture-envpeek");
    expect(last?.decision.allowed).toBe(false);
  });

  it("does not let a granted package's descriptor read bleed into the next tick", async () => {
    const { dep, peek, decisions } = boot();
    // The lingering-entry variant: `Object.getOwnPropertyDescriptor` is a descriptor-trap call
    // with NO `get` behind it, so a consume-once pairing cache would still be holding
    // `fixture-dep`'s answer for this exact key when the timer fires.
    const stolen = await peek.readNextTick(() => dep.readEnvDescriptor(SECRET), SECRET);
    expect(stolen).toBeUndefined();
    const last = forSecret(decisions).at(-1);
    expect(last?.pkg).toBe("fixture-envpeek");
    expect(last?.decision.allowed).toBe(false);
  });

  it("does not let an ungranted read bleed into a granted one either", () => {
    const { dep, peek, decisions } = boot();
    // The mirror image, which matters for a different reason: a principal that got STUCK would
    // break the granted package (#86's shape — hardening that breaks an allowed operation).
    expect(peek.read(SECRET)).toBeUndefined();
    expect(dep.readEnv(SECRET)).toBe(SECRET_VALUE);
    const recorded = forSecret(decisions);
    expect(recorded.map((d) => `${d.pkg}:${String(d.decision.allowed)}`)).toEqual([
      "fixture-envpeek:false",
      "fixture-dep:true",
    ]);
  });

  it("interleaves two readers key-for-key without either inheriting the other", () => {
    const { dep, peek, decisions } = boot();
    for (let i = 0; i < 20; i++) {
      expect(dep.readEnv(SECRET)).toBe(SECRET_VALUE);
      expect(peek.read(SECRET)).toBeUndefined();
    }
    const recorded = forSecret(decisions);
    expect(recorded).toHaveLength(40);
    for (let i = 0; i < 40; i += 2) {
      expect(recorded[i]?.pkg).toBe("fixture-dep");
      expect(recorded[i]?.decision.allowed).toBe(true);
      expect(recorded[i + 1]?.pkg).toBe("fixture-envpeek");
      expect(recorded[i + 1]?.decision.allowed).toBe(false);
    }
  });

  it("still records one decision per key read out of a whole-environment spread", () => {
    const { peek, decisions } = boot();
    // "Cheaper" must not mean "fewer decisions". The `get` trap records every key; the
    // descriptor trap records none (#67). Both halves of that survive the fast path.
    const keyCount = Object.keys(peek.readAll()).length;
    const envReads = decisions.filter((d) => d.decision.observed?.kind === "env");
    expect(envReads.length).toBe(keyCount);
    for (const d of envReads) {
      expect(d.pkg).toBe("fixture-envpeek");
      expect(d.decision.allowed).toBe(false);
    }
  });

  it("keeps hiding the value from the descriptor trap, which is what makes it expensive", () => {
    const { peek } = boot();
    // The reason the descriptor trap still attributes at all: without it,
    // `Object.getOwnPropertyDescriptor(process.env, k).value` hands back what `get` denied.
    // If a future "optimization" drops that decision, this is the test that says so.
    const desc = Object.getOwnPropertyDescriptor(peek.readAll(), SECRET);
    expect(desc?.value).toBeUndefined();
  });
});
