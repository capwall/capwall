/**
 * `{ cjs, esm } × every install option` — issues #97 and #90.
 *
 * WHAT WENT WRONG, AND WHY NOTHING SAID SO. From #74 until #94,
 * `install(policy, mode, { hardened: true, esm: true })` produced **unfrozen ESM shims**. #74
 * built the ESM registry from a live context box and `applyTopOfStack` never mirrored `hardened`
 * onto it, so hardened mode was inert on the import path — the path the CLI preload enables by
 * DEFAULT — for many merges, silently, with the option accepted and no warning. The half that
 * mattered was wide open: `net.Socket.prototype.connect = evil` and
 * `dgram.Socket.prototype.send = evil` LANDED under `hardened: true`, which is the one-line,
 * process-wide un-guard the whole feature exists to close.
 *
 * `hardened.test.ts` covered the CJS path only, and every assertion in it passed with the ESM
 * path completely unhardened. #94 added a `Required<ShimContext>` mirroring test so a NEW field
 * cannot be forgotten the same way — good, and reactive: it checks that the plumbing copies a
 * field, not that the option has its effect.
 *
 * SO THIS FILE ASSERTS THE EFFECT, per option, on BOTH paths. Each row installs capwall with one
 * option changed and probes an identical dependency through `require` and through `import`:
 *
 *   | option                     | observable on each path                                    |
 *   |----------------------------|------------------------------------------------------------|
 *   | `hardened`                 | `Object.isFrozen(net.Socket.prototype)` — #97's exact cell  |
 *   | `mode`                     | an ungranted read denies (enforce) or is recorded (observe) |
 *   | `attribution.maxFrames`    | the read attributes to the package or to `<unknown>`        |
 *   | `esm`                      | the import path is mediated at all                          |
 *   | `env`                      | a dependency's `process.env` read is gated                  |
 *   | `globalEgress`             | a dependency's `fetch` is refused before any socket opens   |
 *   | `projectRoot`              | which principal the read is charged to                      |
 *   | `onDecision`               | both paths' decisions reach the sink                        |
 *
 * `policy` is not a row of its own — it is the subject of every row, and of most of the rest of
 * this directory.
 *
 * RUNTIME COST, stated because #90 asks for it: one subprocess per row (~9 total, ~2.5s
 * wall-clock). A subprocess per row is not incidental — `hardened` (registries are memoized per
 * hardened-ness), `esm` (a registered loader hook cannot be unregistered) and ESM module caching
 * (#62) are all process-sticky, so rows run in one process would contaminate each other and the
 * matrix would assert nothing. The probes themselves are batched: one process runs BOTH paths
 * and every observable at once, rather than one process per (path, option) pair.
 */
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { install, loadPolicyFromObject, type InstallHandle, type Policy } from "../src/index.js";
import { liveRegistry } from "../src/loader/live-context.js";
import { HOOK_TIMEOUT_MS, runNode } from "./helpers/subprocess.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const APP_DIR = path.join(here, "fixtures", "esm");
const PARITY_APP = path.join(APP_DIR, "option-parity-app.mjs");
const GAP_APP = path.join(APP_DIR, "harden-gap-app.mjs");
const DIST = createRequire(import.meta.url).resolve("../dist/index.js");

/** What one path reported. Identical shape for CJS and ESM, by construction. */
interface PathReport {
  read: string;
  frozen: boolean;
  readDeep: string;
  env: "hidden" | "visible";
  fetch: string;
}
interface ParityReport {
  installError: string | null;
  cjs: PathReport;
  esm: PathReport;
  decisions: Array<{ pkg: string; kind: string; allowed: boolean }>;
}

interface ParityConfig {
  mode?: "observe" | "enforce";
  projectRoot?: "node_modules";
  options?: Record<string, unknown>;
}

async function runApp(entry: string, config?: ParityConfig): Promise<string> {
  const r = await runNode([entry], {
    cwd: APP_DIR,
    env: {
      PARITY_PROBE_SECRET: "s3cr3t",
      // The app installs capwall itself, so the preload channel must stay out of the way.
      CAPWALL_MODE: "",
      CAPWALL_POLICY_FILE: "",
      NODE_OPTIONS: "",
      ...(config ? { CAPWALL_TEST_CONFIG: JSON.stringify(config) } : {}),
    },
  });
  if (r.code !== 0) throw new Error(`${entry} exited ${String(r.code)}: ${r.stderr}`);
  return r.stdout;
}

async function parity(config: ParityConfig): Promise<ParityReport> {
  const stdout = await runApp(PARITY_APP, config);
  const line = stdout.split("\n").find((l) => l.startsWith("PARITY:"));
  expect(line, `no PARITY line in:\n${stdout}`).toBeDefined();
  return JSON.parse((line as string).slice("PARITY:".length)) as ParityReport;
}

/** The reference configuration every row is a one-option delta from. */
const BASE: ParityConfig = { mode: "enforce", options: { esm: true } };

let base: ParityReport;

beforeAll(async () => {
  expect(existsSync(DIST), `built core not found at ${DIST} — run 'pnpm build' first`).toBe(true);
  base = await parity(BASE);
}, HOOK_TIMEOUT_MS);

/** Which observables changed between two reports, per path. Comparing the SET of changes is what
 * makes "the option had the same effect on both paths" a single assertion instead of a
 * hand-maintained expectation per path. */
function changedKeys(a: PathReport, b: PathReport): string[] {
  return (Object.keys(a) as Array<keyof PathReport>).filter((k) => a[k] !== b[k]).sort();
}

describe("#97 — every install option is observable on BOTH the CJS and the ESM path", () => {
  it("the two paths agree on every observable under the reference configuration", () => {
    // The control. Every row below is a delta from here, so a difference that already existed
    // would otherwise be attributed to the option under test.
    expect(base.installError).toBeNull();
    // Byte-identical reports. Both deps are deny-by-default here, so even the `fs` probe answers
    // the same string — any later row that differs between paths differs because of the option.
    expect(changedKeys(base.cjs, base.esm)).toEqual([]);
    expect(base.cjs.read).toBe("CapabilityError");
    expect(base.esm.read).toBe("CapabilityError");
  });

  it("hardened: freezes the guarded prototypes on BOTH paths — #97's exact regression", async () => {
    const r = await parity({ ...BASE, options: { esm: true, hardened: true } });
    expect(r.installError).toBeNull();
    // THE assertion #97 asks for. On `main` between #74 and #94 the ESM half of this was `false`
    // while the CJS half was `true`, and nothing in the suite said a word.
    expect([r.cjs.frozen, r.esm.frozen]).toEqual([true, true]);
    expect([base.cjs.frozen, base.esm.frozen]).toEqual([false, false]);
    // …and hardening changed NOTHING else, on either path (the #86 lesson, restated per path).
    expect(changedKeys(base.cjs, r.cjs)).toEqual(["frozen"]);
    expect(changedKeys(base.esm, r.esm)).toEqual(["frozen"]);
  }, 60_000);

  it("mode: observe allows and records on both paths; enforce denies on both", async () => {
    const r = await parity({ mode: "observe", options: { esm: true } });
    expect(r.cjs.read).toMatch(/^OK:/);
    expect(r.esm.read).toMatch(/^OK:/);
    // Observe never blocks — but it must still RECORD, on both paths, or `gen-policy` emits a
    // policy that covers only half the process.
    const allowedFs = (pkg: string): boolean =>
      r.decisions.some((d) => d.pkg === pkg && d.kind === "fs" && d.allowed);
    expect([allowedFs("parity-cjs-dep"), allowedFs("parity-esm-dep")]).toEqual([true, true]);
  }, 60_000);

  it("attribution.maxFrames: the budget applies to both paths, not just the one it was tested on", async () => {
    const r = await parity({ ...BASE, options: { esm: true, attribution: { maxFrames: 1 } } });
    // A budget of 1 is below every real call's depth, so every decision — from either path —
    // must fall back to `<unknown>`. A path that quietly kept the default would show its own
    // package name here.
    expect(r.decisions.every((d) => d.pkg === "<unknown>")).toBe(true);
    // At the default budget both paths attribute to their own package, including behind twelve
    // nested frames.
    const named = (pkg: string): boolean => base.decisions.some((d) => d.pkg === pkg);
    expect([named("parity-cjs-dep"), named("parity-esm-dep")]).toEqual([true, true]);
  }, 60_000);

  it("esm: off leaves the import path un-mediated and the require path untouched", async () => {
    const r = await parity({ ...BASE, options: { esm: false } });
    // This is the one option whose effect is deliberately ASYMMETRIC — that asymmetry IS the
    // option — so it is asserted as such rather than as parity.
    expect(r.esm.read).toMatch(/^OK:/); // reached the raw builtin
    expect(r.cjs.read).toBe("CapabilityError"); // require path unaffected
    expect(r.decisions.some((d) => d.pkg === "parity-esm-dep" && d.kind === "fs")).toBe(false);
  }, 60_000);

  it("env: off leaves process.env untouched for callers on both paths", async () => {
    const r = await parity({ ...BASE, options: { esm: true, env: false } });
    expect([r.cjs.env, r.esm.env]).toEqual(["visible", "visible"]);
    expect([base.cjs.env, base.esm.env]).toEqual(["hidden", "hidden"]);
    expect(r.decisions.some((d) => d.kind === "env")).toBe(false);
  }, 60_000);

  it("globalEgress: off leaves globalThis.fetch un-guarded for callers on both paths", async () => {
    const r = await parity({ ...BASE, options: { esm: true, globalEgress: false } });
    // Node's own `TypeError` from a refused connection, not capwall's refusal.
    expect([r.cjs.fetch, r.esm.fetch]).toEqual(["TypeError", "TypeError"]);
    expect([base.cjs.fetch, base.esm.fetch]).toEqual(["CapabilityError", "CapabilityError"]);
    expect(r.decisions.some((d) => d.kind === "net")).toBe(false);
  }, 60_000);

  it("projectRoot: re-roots attribution identically on both paths", async () => {
    // Rooting the install AT the `node_modules` directory makes both dependencies application
    // code (`installChainFor` strips the root before scanning for `node_modules` segments — the
    // "the project itself lives inside a node_modules" case). If either path ignored
    // `projectRoot` it would keep naming its own package here.
    const r = await parity({ ...BASE, projectRoot: "node_modules" });
    expect(r.decisions.some((d) => d.kind === "fs")).toBe(true);
    expect(r.decisions.filter((d) => d.kind === "fs").every((d) => d.pkg === "<app>")).toBe(true);
    expect(r.decisions.some((d) => d.pkg === "parity-cjs-dep")).toBe(false);
    expect(r.decisions.some((d) => d.pkg === "parity-esm-dep")).toBe(false);
  }, 60_000);

  it("onDecision: receives decisions from both paths, through the one sink", () => {
    // The sink lives on `liveCtx`, shared by both paths — a per-path sink would be the #87
    // divergence in another guise.
    const from = (pkg: string): number => base.decisions.filter((d) => d.pkg === pkg).length;
    expect(from("parity-cjs-dep")).toBeGreaterThan(0);
    expect(from("parity-esm-dep")).toBeGreaterThan(0);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * The structural half #97 proposes: refuse an option capwall cannot honor.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("#97 — a security option accepted but not applied is a startup error", () => {
  /**
   * "If capwall cannot honor `hardened: true` on a path it is mediating, that is worth failing
   * loudly at `install()` time. Failing closed on a config it cannot satisfy is the right default
   * for a security tool." — #97.
   *
   * `install()` now VERIFIES the post-condition rather than predicting the failure: it asks
   * whether the objects it just built are frozen and whether the globals it just replaced are
   * pinned. That is what makes it safe to ship — a check that observes cannot produce a false
   * positive, and it only ever inspects surfaces capwall itself installed on paths this call
   * actually mediates. A spurious throw at install time breaks every host app, so "if capwall did
   * not install it, this does not check it" is the rule.
   *
   * The subprocess is load-bearing: creating a surface capwall genuinely cannot harden means
   * pinning an egress global NON-configurable, which nothing can undo. Doing that in the test
   * runner would poison `globalThis.fetch` for every later test in the worker.
   */
  it("throws — naming the surface — when a mediated global cannot be pinned, and rolls back", async () => {
    const stdout = await runApp(GAP_APP);
    const lines = stdout.trim().split("\n").filter((l) => l.startsWith("GAP:"));
    expect(lines).toEqual([
      "GAP:baseline:OK:parity cjs data",
      // Refused, and the message names the surface so an operator can act on it.
      "GAP:hardened:THREW:names-fetch",
      // The refused install undid itself: the FIRST install's grants are still in force. A
      // half-wired install would have left the tighter policy live and denied this read.
      "GAP:after-refusal:OK:parity cjs data",
      // And teardown does not throw over the one global it can no longer restore — an escaping
      // TypeError there would abort the handle loop and strand the loader patch, the env proxy
      // and the dlopen gate for the life of the process.
      "GAP:teardown:ok",
      "GAP:env-restored:yes",
    ]);
  }, 60_000);

  const open: InstallHandle[] = [];
  afterEach(() => {
    while (open.length > 0) open.pop()?.uninstall();
  });
  const anyPolicy = (): Policy =>
    loadPolicyFromObject({ version: 1, mode: "enforce", packages: {} }, { projectRoot: here });

  it("does NOT throw for any ordinary hardened install — the false-positive guard", () => {
    // The whole risk of this feature is a spurious startup throw, so the shapes a host app or the
    // preload actually produces are asserted to install cleanly. Nested and repeated hardened
    // installs are included because that is where a predictive check would have gone wrong.
    for (const options of [
      { hardened: true },
      { hardened: true, env: false },
      { hardened: true, globalEgress: false },
      { hardened: true, env: false, globalEgress: false },
    ]) {
      const handle = install(anyPolicy(), "enforce", { projectRoot: here, ...options });
      open.push(handle);
      handle.uninstall();
      open.pop();
    }
    const outer = install(anyPolicy(), "enforce", { projectRoot: here, hardened: true });
    open.push(outer);
    const inner = install(anyPolicy(), "enforce", { projectRoot: here, hardened: true });
    open.push(inner);
    expect(Object.isFrozen((globalThis as { fetch?: object }).fetch)).toBe(true);
  });

  it("hardens the egress globals when a hardened install lands on top of a plain one", () => {
    // The composition case the check exists to catch, and the reason the guard grew a pin
    // upgrade: the globals are installed ONCE (they are process-global and must be restorable),
    // so a hardened install arriving second has to pin what is already there rather than wrap it
    // again. Without the upgrade this is #97's shape exactly — accepted, not applied.
    const plain = install(anyPolicy(), "enforce", { projectRoot: here });
    open.push(plain);
    expect(Object.getOwnPropertyDescriptor(globalThis, "fetch")?.writable).toBe(true);
    const hardened = install(anyPolicy(), "enforce", { projectRoot: here, hardened: true });
    open.push(hardened);
    expect(Object.getOwnPropertyDescriptor(globalThis, "fetch")?.writable).toBe(false);
    // …and the pin is a ratchet, not lifted when the hardened install unwinds — un-pinning would
    // hand a dependency a window in which a still-mediated global became writable again.
    hardened.uninstall();
    open.pop();
    expect(Object.getOwnPropertyDescriptor(globalThis, "fetch")?.writable).toBe(false);
    // It goes away entirely with the LAST install, which is the contract that matters.
    plain.uninstall();
    open.pop();
    expect(Object.getOwnPropertyDescriptor(globalThis, "fetch")?.writable).toBe(true);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * #129 — hardened is a RATCHET, on every surface, not last-writer-wins on some of them.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

/**
 * #97's principle ("a security option accepted and not applied is worse than one refused") held at
 * install time and was then silently reversible by the multi-install path #107 made a supported
 * shape. `liveRegistry` memoized one registry per hardened-ness and took the hardened-ness from
 * whichever install was NEWEST, so with a `hardened: true` install still active a later
 * `install({ hardened: false })` handed every subsequent `require("node:fs")` an UNFROZEN shim —
 * which the caller can monkey-patch, process-wide and unlogged, which is the one-liner hardened
 * mode exists to close. Meanwhile the egress globals stayed pinned, because `pin` is a ratchet. One
 * `install()` left the process half-hardened and NEITHER behaviour was documented, so a reader
 * could not tell which one was the bug.
 *
 * The semantics chosen, and now uniform: **hardened engages when any install asks for it and lifts
 * only when capwall fully uninstalls** — the egress half's behaviour, applied to the shim
 * registries too. The rows below assert it on both axes at once (`{cjs, esm}` × the downgrade
 * attempt), which is the cross that #97 survived many merges by not having.
 */
describe("#129 — a later non-hardened install cannot downgrade an active hardened one", () => {
  const open: InstallHandle[] = [];
  afterEach(() => {
    while (open.length > 0) open.pop()?.uninstall();
  });
  const anyPolicy = (): Policy =>
    loadPolicyFromObject({ version: 1, mode: "enforce", packages: {} }, { projectRoot: here });

  it("a fresh require after install({hardened:false}) still gets a FROZEN shim", async () => {
    // A subprocess: the registries are memoized per hardened-ness for the life of the process, and
    // the ESM half registers a loader hook that cannot be unregistered. Both halves are probed in
    // one run so the two axes actually cross.
    const r = await parity({ ...BASE, options: { esm: true, hardened: true, downgradeAfter: true } });
    expect(r.installError).toBeNull();
    // Measured against the unfixed source, both halves reported `false`: same policy, same
    // process, `hardened: true` install still active and its post-condition already verified —
    // and every shim handed out afterwards patchable. Meanwhile `globalThis.fetch` stayed pinned,
    // which is the half-hardened process #129 is about.
    expect([r.cjs.frozen, r.esm.frozen]).toEqual([true, true]);
  }, 60_000);

  it("the shim ratchet releases on the same boundary the egress pin does — the LAST uninstall", () => {
    // In-process, because the boundary under test is the transition itself. Asserting the two
    // surfaces together is the point: #129 is not "the registries were wrong", it is "the two
    // halves of one option disagreed", and a test that checked only one half would not notice
    // them diverging again.
    const hardened = install(anyPolicy(), "enforce", { projectRoot: here, hardened: true });
    open.push(hardened);
    const fetchWritable = (): boolean | undefined =>
      Object.getOwnPropertyDescriptor(globalThis, "fetch")?.writable;
    expect([Object.isFrozen(liveRegistry("cjs").get("node:fs")), fetchWritable()]).toEqual([
      true,
      false,
    ]);

    // The downgrade attempt. Both surfaces must ignore it.
    const plain = install(anyPolicy(), "enforce", { projectRoot: here });
    open.push(plain);
    expect([Object.isFrozen(liveRegistry("cjs").get("node:fs")), fetchWritable()]).toEqual([
      true,
      false,
    ]);

    // The hardened install unwinds but capwall is still mediating: still hardened, on both.
    hardened.uninstall();
    open.pop();
    expect([Object.isFrozen(liveRegistry("cjs").get("node:fs")), fetchWritable()]).toEqual([
      true,
      false,
    ]);

    // The last install goes: the ratchet releases, on both, together.
    plain.uninstall();
    open.pop();
    expect(fetchWritable()).toBe(true);
    const after = install(anyPolicy(), "enforce", { projectRoot: here });
    open.push(after);
    expect([Object.isFrozen(liveRegistry("cjs").get("node:fs")), fetchWritable()]).toEqual([
      false,
      true,
    ]);
  });

  it("install({hardened:true}) on top of a plain install still satisfies its own post-condition", () => {
    // The other order, which #103's install-time check must keep agreeing with: the ratchet has to
    // make `liveRegistry` hand back the FROZEN registry by the time `hardeningGaps` inspects it,
    // or `install()` would refuse an install it is perfectly able to honour.
    const plain = install(anyPolicy(), "enforce", { projectRoot: here });
    open.push(plain);
    expect(Object.isFrozen(liveRegistry("cjs").get("node:fs"))).toBe(false);
    expect(() => {
      open.push(install(anyPolicy(), "enforce", { projectRoot: here, hardened: true }));
    }).not.toThrow();
    expect(Object.isFrozen(liveRegistry("cjs").get("node:fs"))).toBe(true);
  });
});
