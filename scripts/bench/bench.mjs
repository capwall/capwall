#!/usr/bin/env node
/**
 * capwall performance benchmark harness (roadmap S4, GitHub issue #14; coverage audit #132).
 *
 * WHAT THIS IS FOR. capwall's design target is <1ms of ADDED latency per intercepted call.
 * `pnpm bench` is the only thing that checks that claim, so it has two jobs, and the second one
 * is the one that rots: measure the overhead, and measure the overhead OF THE THINGS CAPWALL
 * ACTUALLY DOES. When this harness was written capwall mediated `fs` and a few egress modules;
 * it now also carries a third principal (`<unknown>`) with fail-closed budget exhaustion,
 * install-chain package identity, a `compile` gate, a `native` gate, global egress guards on
 * `fetch`/`WebSocket`/`EventSource`, a `globalAgent` Proxy, the `fs.glob` family,
 * accessor-flattening clones on every egress and spawn options bag, per-key env authorization
 * during spawn, and an ESM path that is ON BY DEFAULT under the CLI. A benchmark that only
 * times `fs.readFileSync` reports a healthy number forever regardless of what happens to any of
 * those. So every mediated surface below gets a row, and `scripts/bench/README.md` carries the
 * coverage table stating which are measured and which are deliberately not.
 *
 * METHODOLOGY — read this before trusting a number out of here.
 *
 *  1. PAIRED ARMS, ABBA-INTERLEAVED. Wherever an un-mediated equivalent exists, the mediated and
 *     un-mediated arms are the SAME call, driven from the SAME fixture package, alternating
 *     call-by-call inside one loop, with the order of the pair FLIPPED on every other block
 *     (A/B, B/A, A/B, …). Interleaving makes both arms share the same GC and scheduler jitter;
 *     flipping cancels the systematic "the second call of a pair runs on a warmer cache" bias
 *     that a fixed order bakes in. The per-iteration `mediated − unmediated` delta is capwall's
 *     added latency.
 *  2. BLOCKS AND A MIN ESTIMATOR. Every measurement runs in {@link BLOCKS} independent blocks.
 *     The reported figure is the MINIMUM over blocks of each block's MEDIAN. Noise on a shared
 *     machine only ever ADDS time, so the minimum block is the one least contaminated; a single
 *     block with a mean estimator (what this harness used to do) reports the machine's mood.
 *     The spread across block medians is printed with every row so instability is visible
 *     rather than averaged away.
 *  3. THE TIMER IS NOT FREE. `process.hrtime.bigint()` costs tens of nanoseconds per pair, which
 *     is a rounding error against a 40µs fs call and a large fraction of a 150ns `evaluate()`.
 *     Sub-microsecond scenarios are therefore timed in BATCHES (one timestamp pair per N calls,
 *     divided by N); the measured timer overhead is printed at the top so the reader can judge.
 *     Batched rows report no tail percentiles, because the tail of a batch mean is not the tail
 *     of a call.
 *  4. THE HARNESS CHECKS ITS OWN PREMISE. Every paired scenario is probed before it is timed:
 *     the mediated arm must produce at least one capwall decision, the un-mediated arm must
 *     produce ZERO, and the decision must be charged to the principal the scenario claims. A
 *     prior PR found `projectRoot` pointing at the DEPENDENCY's directory, which quietly
 *     resolved the fixture's own frames to `<app>` and broke the benchmark's whole premise; the
 *     class of error is "the two arms differ in something other than mediation", and the
 *     self-check table at the top of the output is what makes it visible instead of silent.
 *
 * GATES (exit code). Three, all printed in the verdict:
 *   BUDGET      — every added latency PER INTERCEPTED CALL must be under 1ms. That is the roadmap
 *                 S4 claim. Rows where ONE JS call is MANY interceptions (`{...process.env}`) are
 *                 listed separately under AMPLIFICATION, because the per-call budget genuinely
 *                 does not hold for them and averaging that away would be a lie.
 *   RATIO       — the fs added latency divided by a CPU calibration CO-SAMPLED in the same loop
 *                 must be under {@link RATIO_LIMIT}. An absolute microsecond threshold is not
 *                 portable across machines, and a 1ms budget with 20x headroom would not notice a
 *                 3x regression. See README § "The regression gate".
 *   SELF-CHECKS — every premise the rows rest on, verified rather than assumed.
 *
 * Run: `pnpm -r build` first (this imports the BUILT packages/core/dist), then `pnpm bench`.
 * Flags: --quick (fewer blocks/iterations — what the CI gate runs), --json (machine-readable
 * results on stdout), --no-esm (skip the ESM arm).
 */

import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import * as path from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";

import { preflight } from "../mutation-sentinel.mjs";

// ── configuration ─────────────────────────────────────────────────────────────────────────

const ARGV = new Set(process.argv.slice(2));
const QUICK = ARGV.has("--quick");
const JSON_OUT = ARGV.has("--json");
const WITH_ESM = !ARGV.has("--no-esm");

const here = path.dirname(fileURLToPath(import.meta.url));
const CORE_DIST = path.join(here, "..", "..", "packages", "core", "dist", "index.js");
const FIXTURE_DIR = path.join(here, "fixtures", "node_modules", "bench-dep");
const DENIED_DIR = path.join(here, "fixtures", "node_modules", "bench-dep-denied");
/**
 * The "project" capwall is installed into: the directory whose `node_modules/` holds the
 * fixture dependencies. This used to be FIXTURE_DIR itself, which declared the DEPENDENCY to be
 * the project root — harmless while `packageForPath` ignored the root, but wrong by the
 * documented meaning of `projectRoot` ("distinguish app code from dependencies"), and since #92
 * it actually resolves the fixture's own frames to `<app>` rather than to a package. The
 * benchmark's whole premise is that attribution lands on a real package name, so the root has to
 * be the app. The self-check table proves it still does.
 */
const PROJECT_ROOT = path.join(here, "fixtures");

/** Independent blocks per measurement. The estimator is the MIN over blocks of block medians. */
const BLOCKS = QUICK ? 4 : 10;
/** Scale factor on every scenario's per-block iteration count. */
const SCALE = QUICK ? 0.25 : 1;

const NS_PER_MS = 1_000_000;
/** The <1ms/req target from AGENTS.md § 5 and docs/roadmap.md § S4. */
const BUDGET_NS = 1 * NS_PER_MS;
/**
 * Ratio gate: the fs added latency divided by a synthetic CPU calibration CO-SAMPLED in the same
 * interleaved loop (see `runPaired`'s `reference` arm). Scale-free by construction, which is what
 * lets it be a tight bound where the 1ms budget — with 20x headroom — cannot notice anything.
 *
 * THE LIMIT IS DERIVED FROM MEASUREMENT, NOT PICKED. Measured on an idle 16-core Linux box and
 * in the Node 20 CI container, the ratio sits at 2.3–2.7 and moves by under 0.1 run to run, even
 * across runs whose absolute fs added latency swings 40% — that swing is exactly what the
 * co-sampled reference cancels. Under deliberate CPU oversubscription it degrades and then
 * PLATEAUS: 8 concurrent benchmark processes on 16 cores reach 4.2, and 16 concurrent processes
 * reach 4.6 and go no further. 7 therefore sits ~1.5x above the worst contention observed and
 * still fails a 2.7x algorithmic regression. Override with CAPWALL_BENCH_RATIO_LIMIT.
 *
 * If you change {@link CAL_REPEATS} or the calibration body, this number is invalid until it is
 * re-derived the same way. Do not nudge it until a red run goes green.
 *
 * #143 MOVED THE NUMERATOR AND THIS LIMIT WAS DELIBERATELY NOT MOVED WITH IT. Every figure above
 * is pre-#143; the observed ratio is now 0.89–1.73 on a contended box, so the gate has far more
 * headroom than it was designed with — and, stated plainly, a change that undid #143 entirely
 * would come back around 2.5 and still pass. Tightening it honestly means re-running the
 * contention sweep on an idle machine, which is the one thing the paragraph above says not to
 * shortcut. See `scripts/bench/README.md` § The regression gate.
 */
const RATIO_LIMIT = Number(process.env["CAPWALL_BENCH_RATIO_LIMIT"] ?? 7);

function fail(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

if (!fs.existsSync(CORE_DIST)) {
  fail(`${CORE_DIST} not found — run "pnpm -r build" first (see scripts/bench/README.md).`);
}

// ── is this capwall still armed? (issue #184) ─────────────────────────────────────────────
//
// Everything below measures `packages/core/dist`, which is GITIGNORED. #184 is an audit that
// spent a batch of measurements against a `dist/loader/module-read.js` carrying a deleted gate
// while `git status` was clean. Numbers taken from a disarmed capwall are not conservative or
// noisy — they are a different program's numbers, and they read as a real result.
//
// Two cheap checks, in the order that gives the most specific message first: the sentinel/stamp
// scan names the file and line if a mutation is present, and the canary then proves end to end,
// in a child process under the real `--import dist/preload.js`, that one granted operation is
// allowed and two ungranted ones are denied. Both are silent when correct.
const armed = preflight({ kinds: ["src", "dist"], label: "the benchmark" });
if (!armed.ok) {
  process.stderr.write(`\n${armed.message}\n`);
  process.exit(1);
}
{
  const canary = spawnSync(process.execPath, [path.join(here, "..", "canary.mjs")], {
    encoding: "utf8",
  });
  if (canary.status !== 0) {
    process.stderr.write(
      `${canary.stdout ?? ""}${canary.stderr ?? ""}\n` +
        "error: the enforcement canary failed — refusing to benchmark a capwall that is not\n" +
        "enforcing. Any number produced here would be a measurement of the wrong program (#184).\n",
    );
    process.exit(1);
  }
}

// ── stats + timing primitives ─────────────────────────────────────────────────────────────

/** Sink for benchmarked return values, so V8 cannot eliminate a call whose result is unused. */
let SINK = 0;

/** Nearest-rank percentile over an ASCENDING-sorted sample. */
function percentile(sortedAsc, p) {
  if (sortedAsc.length === 0) return 0;
  const idx = Math.min(
    sortedAsc.length - 1,
    Math.max(0, Math.ceil((p / 100) * sortedAsc.length) - 1),
  );
  return sortedAsc[idx];
}

function median(values) {
  const sorted = Float64Array.from(values).sort();
  return percentile(sorted, 50);
}

function stats(samplesNs) {
  const sorted = Float64Array.from(samplesNs).sort();
  let sum = 0;
  for (const v of sorted) sum += v;
  return {
    n: sorted.length,
    mean: sum / sorted.length,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
    min: sorted[0],
    max: sorted[sorted.length - 1],
  };
}

function fmtNs(ns) {
  if (!Number.isFinite(ns)) return "     n/a";
  const abs = Math.abs(ns);
  if (abs >= NS_PER_MS) return `${(ns / NS_PER_MS).toFixed(3)} ms`;
  if (abs >= 1000) return `${(ns / 1000).toFixed(3)} µs`;
  return `${ns.toFixed(0)} ns`;
}

/**
 * One timing sample, in nanoseconds PER CALL. `batch > 1` amortises the timestamp pair over N
 * calls — required for anything whose own cost is within an order of magnitude of the timer.
 */
function sampler(fn, batch) {
  if (batch <= 1) {
    return () => {
      const t0 = process.hrtime.bigint();
      SINK = fn();
      const t1 = process.hrtime.bigint();
      return Number(t1 - t0);
    };
  }
  return () => {
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < batch; i++) SINK = fn();
    const t1 = process.hrtime.bigint();
    return Number(t1 - t0) / batch;
  };
}

function asyncSampler(fn) {
  return async () => {
    const t0 = process.hrtime.bigint();
    SINK = await fn();
    const t1 = process.hrtime.bigint();
    return Number(t1 - t0);
  };
}

/** The min-over-blocks-of-block-medians estimator, plus the spread that justifies trusting it. */
function reduceBlocks(blockSamples) {
  const blockMedians = blockSamples.map(median);
  const pooled = [];
  for (const b of blockSamples) for (const v of b) pooled.push(v);
  const s = stats(pooled);
  return {
    est: Math.min(...blockMedians),
    blockMedians,
    blockSpread: Math.max(...blockMedians) - Math.min(...blockMedians),
    pooledMean: s.mean,
    p50: s.p50,
    p95: s.p95,
    p99: s.p99,
    n: s.n,
  };
}

const RESULTS = [];

/**
 * How many capability DECISIONS one call of `fn` produces.
 *
 * Recorded for every row, because "added latency per call" and "added latency per intercepted
 * call" are the same number only when a call intercepts once. `{...process.env}` intercepts
 * ~2 × the size of the environment, and the difference between those two readings is the
 * difference between the <1ms budget holding and not holding — see the verdict.
 */
function decisionsPerCall(fn) {
  const seen = observe(fn);
  return seen.filter((d) => d.pkg !== undefined).length;
}

/** A single-armed measurement: no un-mediated equivalent exists (deny paths, pure functions). */
function runSingle({ id, label, fn, iters, batch = 1, warmup = 200, note = "" }) {
  const n = Math.max(4, Math.round(iters * SCALE));
  const decisions = decisionsPerCall(fn);
  const take = sampler(fn, batch);
  for (let i = 0; i < warmup; i++) SINK = fn();
  const blocks = [];
  for (let b = 0; b < BLOCKS; b++) {
    const samples = new Array(n);
    for (let i = 0; i < n; i++) samples[i] = take();
    blocks.push(samples);
  }
  const r = reduceBlocks(blocks);
  const row = { id, label, kind: "absolute", batched: batch > 1, note, decisions, absolute: r };
  RESULTS.push(row);
  return row;
}

/**
 * A paired measurement. `baseline` runs without capwall in the path, `mediated` runs through it;
 * they are otherwise the same call. Arms alternate call-by-call, and the ORDER of the pair flips
 * every other block (ABBA).
 */
function runPaired({
  id,
  label,
  baseline,
  mediated,
  reference,
  iters,
  batch = 1,
  warmup = 200,
  note = "",
}) {
  const n = Math.max(4, Math.round(iters * SCALE));
  const decisions = decisionsPerCall(mediated);
  const takeBase = sampler(baseline, batch);
  const takeMed = sampler(mediated, batch);
  // The gate's machine-speed REFERENCE, when supplied, is sampled INSIDE this same loop rather
  // than in a run of its own. That is the whole trick behind the ratio gate being usable on a
  // shared machine: contention that inflates the mediated arm inflates the reference in the same
  // block, at the same moment, so the per-block ratio moves far less than either term does. A
  // reference measured minutes earlier (which is what a separate scenario is) does not cancel.
  const takeRef = reference === undefined ? null : sampler(reference, batch);
  for (let i = 0; i < warmup; i++) {
    SINK = baseline();
    SINK = mediated();
    if (reference !== undefined) SINK = reference();
  }
  const baseBlocks = [];
  const medBlocks = [];
  const deltaBlocks = [];
  const refBlocks = [];
  for (let b = 0; b < BLOCKS; b++) {
    const forward = b % 2 === 0;
    const bs = new Array(n);
    const ms = new Array(n);
    const ds = new Array(n);
    const rs = takeRef === null ? null : new Array(n);
    for (let i = 0; i < n; i++) {
      let tb;
      let tm;
      let tr = 0;
      if (forward) {
        tb = takeBase();
        tm = takeMed();
        if (takeRef !== null) tr = takeRef();
      } else {
        if (takeRef !== null) tr = takeRef();
        tm = takeMed();
        tb = takeBase();
      }
      bs[i] = tb;
      ms[i] = tm;
      ds[i] = tm - tb;
      if (rs !== null) rs[i] = tr;
    }
    baseBlocks.push(bs);
    medBlocks.push(ms);
    deltaBlocks.push(ds);
    if (rs !== null) refBlocks.push(rs);
  }
  const perBlockRatio =
    takeRef === null
      ? null
      : deltaBlocks.map((d, i) => median(d) / median(refBlocks[i]));
  const row = {
    ...(perBlockRatio === null
      ? {}
      : { ratio: Math.min(...perBlockRatio), ratioBlocks: perBlockRatio, reference: reduceBlocks(refBlocks) }),
    id,
    label,
    kind: "paired",
    batched: batch > 1,
    note,
    decisions,
    baseline: reduceBlocks(baseBlocks),
    mediated: reduceBlocks(medBlocks),
    added: reduceBlocks(deltaBlocks),
  };
  RESULTS.push(row);
  return row;
}

/** Async twin of {@link runPaired}. One await per sample, so event-loop jitter is in the sample. */
async function runPairedAsync({ id, label, baseline, mediated, iters, warmup = 30, note = "" }) {
  const n = Math.max(4, Math.round(iters * SCALE));
  const decisions = (await observeAsync(mediated)).filter((d) => d.pkg !== undefined).length;
  const takeBase = asyncSampler(baseline);
  const takeMed = asyncSampler(mediated);
  for (let i = 0; i < warmup; i++) {
    SINK = await baseline();
    SINK = await mediated();
  }
  const baseBlocks = [];
  const medBlocks = [];
  const deltaBlocks = [];
  for (let b = 0; b < BLOCKS; b++) {
    const baseFirst = b % 2 === 0;
    const bs = new Array(n);
    const ms = new Array(n);
    const ds = new Array(n);
    for (let i = 0; i < n; i++) {
      let tb;
      let tm;
      if (baseFirst) {
        tb = await takeBase();
        tm = await takeMed();
      } else {
        tm = await takeMed();
        tb = await takeBase();
      }
      bs[i] = tb;
      ms[i] = tm;
      ds[i] = tm - tb;
    }
    baseBlocks.push(bs);
    medBlocks.push(ms);
    deltaBlocks.push(ds);
  }
  const row = {
    id,
    label,
    kind: "paired",
    batched: false,
    note,
    decisions,
    baseline: reduceBlocks(baseBlocks),
    mediated: reduceBlocks(medBlocks),
    added: reduceBlocks(deltaBlocks),
  };
  RESULTS.push(row);
  return row;
}

/** Async twin of {@link runSingle}. */
async function runSingleAsync({ id, label, fn, iters, warmup = 30, note = "" }) {
  const n = Math.max(4, Math.round(iters * SCALE));
  const decisions = (await observeAsync(fn)).filter((d) => d.pkg !== undefined).length;
  const take = asyncSampler(fn);
  for (let i = 0; i < warmup; i++) SINK = await fn();
  const blocks = [];
  for (let b = 0; b < BLOCKS; b++) {
    const samples = new Array(n);
    for (let i = 0; i < n; i++) samples[i] = await take();
    blocks.push(samples);
  }
  const row = {
    id,
    label,
    kind: "absolute",
    batched: false,
    note,
    decisions,
    absolute: reduceBlocks(blocks),
  };
  RESULTS.push(row);
  return row;
}

// ── output ────────────────────────────────────────────────────────────────────────────────

const log = JSON_OUT ? () => {} : (...a) => console.log(...a);

function printRow(row) {
  const pad = (s, w) => String(s).padStart(w);
  const est = row.kind === "paired" ? row.added.est : row.absolute.est;
  const r = row.kind === "paired" ? row.added : row.absolute;
  const tail = row.batched ? "    batched" : `${pad(fmtNs(r.p95), 11)}`;
  const tail99 = row.batched ? "    batched" : `${pad(fmtNs(r.p99), 11)}`;
  // A delta smaller than the run-to-run spread of the very blocks it was computed from is not a
  // measurement, it is a coin flip. Say so on the row rather than letting a reader quote it.
  if (Math.abs(est) < r.blockSpread) row.resolutionLimited = true;
  log(
    `  ${row.label.padEnd(38)} ${pad(`${row.resolutionLimited === true ? "≲" : ""}${fmtNs(est)}`, 11)}  ` +
      `${pad(fmtNs(r.blockSpread), 11)}  ${tail}  ${tail99}  ${pad(row.decisions ?? 0, 4)}` +
      (row.kind === "paired" ? `  (base ${fmtNs(row.baseline.est)})` : ""),
  );
  if (row.resolutionLimited === true) {
    log(
      `  ${"".padEnd(38)} below this row's own resolution (|delta| < block spread) — read it as an upper bound`,
    );
  }
  if (row.note !== "") log(`  ${"".padEnd(38)} ${row.note}`);
}

function printHeader() {
  log(
    `  ${"surface".padEnd(38)} ${"added/cost".padStart(11)}  ${"blk spread".padStart(11)}  ` +
      `${"p95".padStart(11)}  ${"p99".padStart(11)}  ${"dec".padStart(4)}`,
  );
}

// ── capwall setup ─────────────────────────────────────────────────────────────────────────

const core = await import(pathToFileURL(CORE_DIST).href);
const {
  install,
  loadPolicyFromObject,
  attributeCaller,
  packageForPath,
  evaluate,
} = core;

const requireCjs = createRequire(import.meta.url);
const nodeModule = requireCjs("node:module");

/** require() a fixture fresh (cache cleared) so its top-level captures re-run. */
function loadFresh(dir) {
  const resolved = requireCjs.resolve(dir);
  delete requireCjs.cache[resolved];
  return requireCjs(dir);
}

log("capwall performance benchmark (scripts/bench/bench.mjs)");
log(`node ${process.version} on ${process.platform}/${process.arch} — ${os.cpus().length} cpu`);
log(`blocks=${BLOCKS} scale=${SCALE} estimator=min(block medians) esm=${WITH_ESM}\n`);

// PRE-INSTALL captures. Everything the un-mediated arms use has to be taken now: `Module._load`,
// `process.env`, `globalThis.fetch` and every mediated builtin are patched process-wide by
// `install()`, so a reference taken afterwards is the shim no matter how it is reached.
const realLoad = nodeModule._load;
const realHttp = requireCjs("node:http");
const realNet = requireCjs("node:net");
const REAL_READ_FILE_SYNC = requireCjs("node:fs").readFileSync;
/**
 * The two STARTUP gates' un-patched originals (issue #134).
 *
 * `install()` replaces both process-wide, so — exactly like `Module._load` above — the baseline
 * arm's reference has to be taken now. `_compile` is a prototype method and `dlopen` is a
 * property of `process`; neither is reachable un-patched afterwards by any spelling, which is the
 * whole design of those two gates (`shims/module.ts` on `getBuiltinModule`, `loader/native.ts`).
 */
const REAL_COMPILE = nodeModule.prototype._compile;
const REAL_DLOPEN = process.dlopen;
/** The real environment object, before `install()` puts the read-gating Proxy on `process.env`. */
const REAL_ENV = process.env;
const baselineDep = loadFresh(FIXTURE_DIR);
const baselineEsm = WITH_ESM
  ? await import(`${pathToFileURL(path.join(FIXTURE_DIR, "esm.mjs")).href}?arm=baseline`)
  : null;

// Local servers, created from the REAL modules before install, so the mediated and un-mediated
// egress arms talk to exactly the same peer and the paired delta is capwall and nothing else.
const netServer = realNet.createServer((s) => s.destroy());
await new Promise((res) => netServer.listen(0, "127.0.0.1", res));
const NET_PORT = netServer.address().port;
const httpServer = realHttp.createServer((_req, res) => res.end("ok"));
httpServer.keepAliveTimeout = 60_000;
await new Promise((res) => httpServer.listen(0, "127.0.0.1", res));
const HTTP_PORT = httpServer.address().port;
const HTTP_URL = `http://127.0.0.1:${HTTP_PORT}/`;

const dataPath = path.join(FIXTURE_DIR, "data.txt");
// NOT prefixed `CAPWALL_`: the env guard exempts its own plumbing keys by prefix, so a key named
// that way would measure the exemption's `startsWith` and nothing else.
const ENV_KEY = "BENCH_DEP_ENV_KEY";
process.env[ENV_KEY] = "1";

const policy = loadPolicyFromObject(
  {
    version: 1,
    mode: "enforce",
    packages: {
      "bench-dep": {
        fs: { read: [dataPath, FIXTURE_DIR, `${FIXTURE_DIR}/**`], write: [] },
        net: { hosts: ["127.0.0.1"], ports: ["*"] },
        child_process: true,
        env: [ENV_KEY],
        // #134's startup rows. `native` so the `dlopen` gate measures the ALLOWED path (the gate
        // runs to completion and forwards) rather than a second deny row — the deny shape is
        // already priced by section [C]. `compile` is granted for the same reason, though the
        // per-module-load path never reaches the policy: it is recognized as Node's own loader
        // and short-circuits before attribution. Granting it means a row that ever stopped being
        // recognized would show up as a slower number rather than as a crash.
        native: true,
        compile: true,
      },
      // `bench-dep-denied` is deliberately absent: deny-by-default is the point of it.
    },
  },
  { projectRoot: PROJECT_ROOT },
);

/**
 * The decision sink. In production this is the observe-mode logger / gen-policy trace; here it
 * is a no-op on the hot path (so the measurement includes a realistic sink call and nothing
 * more) with a recording mode used only by the self-checks.
 */
let recording = null;
function onDecision(pkg, decision) {
  if (recording !== null) {
    recording.push({ pkg, allowed: decision.allowed, kind: decision.observed?.kind });
  }
}

const handle = install(policy, "enforce", {
  projectRoot: PROJECT_ROOT,
  onDecision,
  ...(WITH_ESM ? { esm: true } : {}),
});

const dep = loadFresh(FIXTURE_DIR);
const denied = loadFresh(DENIED_DIR);
const shimmedEsm = WITH_ESM
  ? await import(`${pathToFileURL(path.join(FIXTURE_DIR, "esm.mjs")).href}?arm=shimmed`)
  : null;

// ── startup-surface fixtures (issue #134) ─────────────────────────────────────────────────
//
// Three gates fire once per module / once per addon / once per resolution rather than once per
// request, so nothing in sections [A]–[F] touches them and the coverage table in README.md has
// carried them as gaps since #132. They are not per-request latency and are deliberately NOT
// folded into the budget gate; they are startup cost, and startup cost is what a preload adds to
// every process that loads it.

/** capwall's patched `_compile` / `dlopen`, captured now so the rows can drive both arms. */
const GATED_COMPILE = nodeModule.prototype._compile;
const GATED_DLOPEN = process.dlopen;

/**
 * Scratch tree for the generated CJS modules and the placeholder addon.
 *
 * INSIDE the fixture package, which is load-bearing twice over. A file under `node_modules`
 * needs no `fs.read` decision from the CJS module-read gate (`moduleLoadNeedsDecision`), so the
 * `_compile` row measures the compile gate rather than the module-read gate stacked on top of it.
 * And an addon whose path resolves to `bench-dep` makes the `dlopen` gate's two subjects (#49 —
 * caller and owner) the SAME principal, which is the shape a package loading its own addon has.
 *
 * Written with the `node:fs` this file imported BEFORE `install()`, so creating them is not
 * itself a mediated call. Removed at teardown; git-ignored in case a run dies first.
 */
const SCRATCH = path.join(FIXTURE_DIR, ".bench-scratch");
fs.rmSync(SCRATCH, { recursive: true, force: true });
fs.mkdirSync(SCRATCH, { recursive: true });

/**
 * A pool of distinct trivial CJS modules, cycled through by the `_compile` row.
 *
 * DISTINCT rather than one file re-required: V8 keeps a compilation cache keyed on source text,
 * so a single file would measure a cache hit after the first compile. Both arms draw from the
 * same pool in the same order, so whatever caching does survive is identical on both sides of the
 * delta.
 */
const COMPILE_POOL_SIZE = 256;
const compilePool = [];
for (let i = 0; i < COMPILE_POOL_SIZE; i++) {
  const file = path.join(SCRATCH, `compile-probe-${i}.js`);
  fs.writeFileSync(file, `"use strict";\n// generated by scripts/bench/bench.mjs (#134)\nmodule.exports = ${i};\n`);
  compilePool.push(file);
}
let compileCursor = 0;
const nextCompileFile = () => compilePool[compileCursor++ % COMPILE_POOL_SIZE];

/** Placeholder `.node`. Not a real addon — see `bench-dep.dlopen` for why that is the point. */
const ADDON_PATH = path.join(SCRATCH, "bench-addon.node");
fs.writeFileSync(ADDON_PATH, "capwall benchmark placeholder — deliberately not a loadable addon\n");

const ESM_COLD_MEDIATED = pathToFileURL(path.join(FIXTURE_DIR, "esm-cold-mediated.mjs")).href;
const ESM_COLD_PLAIN = pathToFileURL(path.join(FIXTURE_DIR, "esm-cold-plain.mjs")).href;
let esmColdCursor = 0;
/** A fresh `?n=` query is a distinct ESM cache key, so every import really re-resolves. */
const importColdMediated = () => import(`${ESM_COLD_MEDIATED}?n=${esmColdCursor++}`);
const importColdPlain = () => import(`${ESM_COLD_PLAIN}?n=${esmColdCursor++}`);

/**
 * Both `_compile` arms write the prototype slot before requiring, so the write is on BOTH sides
 * of the delta rather than only the baseline's. The gated implementation is put back at the end
 * of the row; nothing between here and there requires anything.
 */
const compileHolder = nodeModule.prototype;
const CAN_COMPILE_ROW =
  typeof REAL_COMPILE === "function" &&
  typeof GATED_COMPILE === "function" &&
  REAL_COMPILE !== GATED_COMPILE &&
  (Object.getOwnPropertyDescriptor(compileHolder, "_compile") ?? {}).writable === true;

// ── self-checks: does each arm do what the row claims? ────────────────────────────────────

const CHECKS = [];

/** Run `fn` with the decision sink recording, and return what capwall saw. */
function observe(fn) {
  recording = [];
  try {
    fn();
  } catch (err) {
    recording.push({ threw: err && err.name });
  }
  const seen = recording;
  recording = null;
  return seen;
}

async function observeAsync(fn) {
  recording = [];
  try {
    await fn();
  } catch (err) {
    recording.push({ threw: err && err.name });
  }
  const seen = recording;
  recording = null;
  return seen;
}

function check(name, ok, detail) {
  CHECKS.push({ name, ok, detail });
  if (!ok) process.exitCode = 1;
}

/**
 * Assert the premise of a paired row: the mediated arm produces decisions charged to `principal`,
 * and the un-mediated arm produces NONE. This is what would have caught the `projectRoot`
 * mistake, and it is what stops a future refactor from silently benchmarking two identical arms.
 */
function checkPair(name, baselineFn, mediatedFn, principal, allowedBaselineKinds = []) {
  const base = observe(baselineFn);
  const med = observe(mediatedFn);
  // `process.env` is a PROCESS-GLOBAL surface: `install()` replaces the object itself, so an
  // "un-mediated" arm that reaches an env read through Node's own internals (fs.glob does) still
  // trips the gate. That is not the harness measuring the wrong thing — both arms pay it
  // identically and it cancels in the delta — but it has to be named rather than silently
  // tolerated, which is what the explicit kind allowlist is for.
  const baseDecisions = base
    .filter((d) => d.pkg !== undefined)
    .filter((d) => !allowedBaselineKinds.includes(d.kind));
  const medDecisions = med.filter((d) => d.pkg !== undefined);
  const charged = [...new Set(medDecisions.map((d) => d.pkg))];
  const ok =
    baseDecisions.length === 0 &&
    medDecisions.length > 0 &&
    charged.length === 1 &&
    charged[0] === principal;
  check(
    name,
    ok,
    `unmediated=${baseDecisions.length} unexpected decision(s), mediated=${medDecisions.length} charged to ${
      charged.join(",") || "(none)"
    }`,
  );
}

function checkSingle(name, fn, principal, expectAllowed) {
  const seen = observe(fn);
  const decisions = seen.filter((d) => d.pkg !== undefined);
  const charged = [...new Set(decisions.map((d) => d.pkg))];
  const allowed = decisions.every((d) => d.allowed === expectAllowed);
  const ok = decisions.length > 0 && charged.length === 1 && charged[0] === principal && allowed;
  check(
    name,
    ok,
    `${decisions.length} decision(s) charged to ${charged.join(",") || "(none)"}, allowed=${
      decisions.map((d) => d.allowed).join(",") || "-"
    }`,
  );
}

// ── the scenarios ─────────────────────────────────────────────────────────────────────────

const CONNECT_OPTS = () => ({
  host: "127.0.0.1",
  port: NET_PORT,
  family: 4,
  noDelay: true,
  keepAlive: false,
  allowHalfOpen: false,
});

const SPAWN_CMD = process.platform === "win32" ? null : "/bin/true";
const CAN_SPAWN = SPAWN_CMD !== null && fs.existsSync(SPAWN_CMD);
/**
 * Both spawn arms pass an EXPLICIT `env`, and it has to be the pre-install object.
 *
 * Left to inherit, Node's own `options.env || { ...process.env }` enumerates whatever
 * `process.env` currently is — which, for the "un-mediated" arm, is capwall's read-gating Proxy,
 * because that is a process-global surface and not something a pre-install `require` can dodge.
 * The un-mediated arm then pays ~2 attributions per environment variable and comes out an ORDER
 * OF MAGNITUDE slower than the mediated one (capwall's shim supplies an explicit env precisely
 * to delete that enumeration — issue #89), which would print as a large NEGATIVE "added
 * latency". That number is real, but it is a measurement of the env Proxy, not of the spawn
 * gate, and it belongs in its own row — see the `{...process.env}` row in section [A].
 */
const SPAWN_OPTS = { env: REAL_ENV };
const CAN_GLOB = dep.hasGlobSync === true;

// `<unknown>` (#60): an eval frame has no filesystem identity, so a call reached THROUGH one
// from application code can no longer claim the trust root. Built here, in bench.mjs (which is
// application code relative to PROJECT_ROOT), because the opaque frame has to sit ABOVE an app
// frame — routed through a dependency it would attribute to that dependency instead. For the
// same reason the eval'd body calls `fs` DIRECTLY: bouncing through `bench-dep.readSync()` would
// put a real dependency frame nearest the call and attribute to `bench-dep`, which is a
// positively-identified principal and not the `<unknown>` path at all.
const shimmedFs = requireCjs("node:fs");
const opaqueReadRaw = new Function("fsMod", "p", "return fsMod.readFileSync(p, 'utf8')");
const opaqueRead = () => opaqueReadRaw(shimmedFs, dataPath);
const opaqueAttribute = new Function("attr", "opts", "return attr(opts)");
const deepOpaqueAttribute = new Function(
  "attr",
  "opts",
  "n",
  "function r(k){ return k <= 0 ? attr(opts) : r(k - 1); } return r(n);",
);

checkPair("fs.readFileSync arms differ only in mediation", () => baselineDep.readSync(), () => dep.readSync(), "bench-dep");
checkPair(
  "fs.readFileSync at depth 24 attributes to the package",
  () => baselineDep.readSyncAtDepth(24),
  () => dep.readSyncAtDepth(24),
  "bench-dep",
);
if (CAN_GLOB) {
  checkPair(
    "fs.globSync arms differ only in mediation",
    () => baselineDep.globSync("*.txt", { cwd: FIXTURE_DIR }),
    () => dep.globSync("*.txt", { cwd: FIXTURE_DIR }),
    "bench-dep",
    ["env"], // Node's own glob internals read process.env, which is mediated process-wide
  );
}
checkPair(
  "net.connect arms differ only in mediation",
  () => baselineDep.connect(CONNECT_OPTS()),
  () => dep.connect(CONNECT_OPTS()),
  "bench-dep",
);
if (CAN_SPAWN) {
  checkPair(
    "child_process.spawnSync arms differ only in mediation",
    () => baselineDep.spawnSync(SPAWN_CMD, [], SPAWN_OPTS),
    () => dep.spawnSync(SPAWN_CMD, [], SPAWN_OPTS),
    "bench-dep",
    // Node reads `process.env.NODE_V8_COVERAGE` BY NAME even when the caller supplied an env
    // (it is the left operand of an `&&`), so the un-mediated arm trips the process-global env
    // Proxy once. capwall's own spawn authorizes exactly that key (#89) — hence the asymmetry.
    ["env"],
  );
}
checkPair(
  "process.env read arms differ only in mediation",
  () => baselineDep.envRead(ENV_KEY),
  () => dep.envRead(ENV_KEY),
  "bench-dep",
);
checkPair(
  "{...process.env} arms differ only in mediation",
  () => baselineDep.envSpread(),
  () => dep.envSpread(),
  "bench-dep",
);
checkSingle("<unknown> is charged for a call through an opaque frame", opaqueRead, "<unknown>", false);
checkSingle("bench-dep-denied is denied fs", () => denied.readDenied(), "bench-dep-denied", false);
checkSingle("bench-dep-denied is denied net", () => denied.connectDenied("127.0.0.1", 1), "bench-dep-denied", false);
if (CAN_SPAWN) {
  checkSingle("bench-dep-denied is denied child_process", () => denied.spawnDenied(SPAWN_CMD, []), "bench-dep-denied", false);
}
if (dep.hasFetch === true) {
  const seen = await observeAsync(() => dep.fetchCall(HTTP_URL).then((r) => r.text()));
  const charged = [...new Set(seen.filter((d) => d.pkg !== undefined).map((d) => d.pkg))];
  check(
    "global fetch is mediated and charged to the caller",
    charged.length === 1 && charged[0] === "bench-dep",
    `charged to ${charged.join(",") || "(none)"}`,
  );
}
// ── startup-surface premises (#134) ───────────────────────────────────────────────────────
check(
  "Module.prototype._compile is patched and swappable for the paired arm",
  CAN_COMPILE_ROW,
  `real!==gated=${REAL_COMPILE !== GATED_COMPILE} writable=${(Object.getOwnPropertyDescriptor(compileHolder, "_compile") ?? {}).writable}`,
);
if (CAN_COMPILE_ROW) {
  // NOT `checkPair`: the premise of this row is the OPPOSITE of every row above. The gate's whole
  // job on a loader-driven compile is to recognize Node's own frame and charge NOTHING — so
  // "the mediated arm produces a decision" would be a failure, not a success. What must be true
  // is that the patched implementation really is in the path and really does stay silent, which
  // is what makes the measured delta the cost of `calledByNodeLoader()` rather than a policy
  // evaluation. If a future change ever made this path attribute, this check flips and the row's
  // note stops being true.
  compileHolder._compile = GATED_COMPILE;
  const seen = observe(() => dep.requireFresh(nextCompileFile()));
  const decisions = seen.filter((d) => d.pkg !== undefined);
  check(
    "the _compile gate recognizes Node's loader and charges nobody",
    decisions.length === 0,
    `${decisions.length} decision(s) — expected 0 on the loader path`,
  );
}
checkPair(
  "process.dlopen arms differ only in mediation",
  () => baselineDep.dlopen(REAL_DLOPEN, ADDON_PATH),
  () => dep.dlopen(GATED_DLOPEN, ADDON_PATH),
  "bench-dep",
);
if (WITH_ESM) {
  const coldMediated = await importColdMediated();
  const coldPlain = await importColdPlain();
  check(
    "ESM cold arm A resolves node:fs through capwall's load hook",
    coldMediated.boundReadFileSync !== REAL_READ_FILE_SYNC,
    "the mediated specifier binds a generated shim, not the builtin",
  );
  check(
    "ESM cold arm B resolves node:path untouched",
    coldPlain.boundJoin === requireCjs("node:path").join,
    "the non-mediated specifier binds the real builtin — the arms differ only in mediation",
  );
}
if (WITH_ESM) {
  check(
    "ESM baseline arm binds the REAL fs.readFileSync",
    baselineEsm.boundReadFileSync === REAL_READ_FILE_SYNC,
    "identity against the pre-install builtin",
  );
  check(
    "ESM shimmed arm binds a DIFFERENT (capwall) fs.readFileSync",
    shimmedEsm.boundReadFileSync !== baselineEsm.boundReadFileSync,
    "identity differs from the real builtin",
  );
  const seen = observe(() => shimmedEsm.readSync());
  const charged = [...new Set(seen.filter((d) => d.pkg !== undefined).map((d) => d.pkg))];
  check(
    "ESM import path is mediated and charged to the package",
    charged.length === 1 && charged[0] === "bench-dep",
    `charged to ${charged.join(",") || "(none)"}`,
  );
}

log("SELF-CHECKS — does each arm measure what its row claims?");
for (const c of CHECKS) {
  log(`  ${c.ok ? "ok  " : "FAIL"}  ${c.name.padEnd(56)} ${c.detail}`);
}
log("");

// ── 0. calibration + timer overhead ───────────────────────────────────────────────────────

/**
 * A fixed, deterministic CPU workload used ONLY as a machine-speed reference for the ratio gate.
 * Deliberately shaped like the work capwall's hot path actually does — small integer arithmetic,
 * a path split, a Map probe — so it tracks the same execution characteristics rather than, say,
 * memory bandwidth. It touches nothing of capwall's, so a capwall regression cannot move it.
 */
const CAL_MAP = new Map([["a", 1], ["b", 2], ["c", 3]]);
const CAL_PATH = "/proj/node_modules/a/node_modules/b/lib/index.js";
/**
 * `CAL_REPEATS` is sized so one calibration unit costs the same order of magnitude as one
 * mediated fs call (tens of microseconds). That is purely so the printed ratio is a readable
 * small number instead of a three-digit one — the gate is scale-invariant either way. Changing
 * it changes the ratio and therefore invalidates {@link RATIO_LIMIT}; if you must, re-derive the
 * limit from a fresh observation rather than nudging it until the run goes green.
 */
const CAL_REPEATS = 25;
function calibrationUnit() {
  let acc = 0;
  for (let r = 0; r < CAL_REPEATS; r++) {
    for (let i = 0; i < 64; i++) acc = (acc * 31 + i) >>> 0;
    const parts = CAL_PATH.split("/node_modules/");
    acc += parts.length + (CAL_MAP.get("b") ?? 0);
  }
  return acc;
}

const timerOverheadNs = (() => {
  const N = 20_000;
  for (let i = 0; i < 5_000; i++) {
    const a = process.hrtime.bigint();
    const b = process.hrtime.bigint();
    SINK = Number(b - a);
  }
  const samples = new Array(N);
  for (let i = 0; i < N; i++) {
    const a = process.hrtime.bigint();
    const b = process.hrtime.bigint();
    samples[i] = Number(b - a);
  }
  return median(samples);
})();

const calibration = runSingle({
  id: "calibration",
  label: "cpu calibration (gate reference)",
  fn: calibrationUnit,
  iters: 300,
  batch: 1,
  warmup: 2_000,
  note: "not capwall — a machine-speed reference for the ratio gate",
});

log(`timer overhead (hrtime.bigint pair, median): ${fmtNs(timerOverheadNs)} — rows under ~1µs are batched\n`);

// ── 1. per-call hot path, paired ──────────────────────────────────────────────────────────

log("[A] MEDIATED CALL — added latency vs the same call un-mediated (paired, ABBA)");
printHeader();

const fsShallow = runPaired({
  id: "fs.readFileSync@shallow",
  label: "fs.readFileSync (3-frame stack)",
  baseline: () => baselineDep.readSync(),
  mediated: () => dep.readSync(),
  iters: 2000,
  note: "the legacy scenario-1 number — kept for continuity, NOT representative (see next row)",
});
printRow(fsShallow);

const fsDeep = runPaired({
  id: "fs.readFileSync@depth24",
  label: "fs.readFileSync (27-frame stack)",
  baseline: () => baselineDep.readSyncAtDepth(24),
  mediated: () => dep.readSyncAtDepth(24),
  reference: calibrationUnit, // co-sampled: this is the row the ratio gate is computed from
  iters: 2000,
  note: "since #143 the capture starts at the shim's OWN entry frame, so this row is close to the shallow one — before it, a 27-frame stack cost ~40% more",
});
printRow(fsDeep);

if (CAN_GLOB) {
  printRow(
    runPaired({
      id: "fs.globSync",
      label: "fs.globSync('*.txt')",
      baseline: () => baselineDep.globSync("*.txt", { cwd: FIXTURE_DIR }),
      mediated: () => dep.globSync("*.txt", { cwd: FIXTURE_DIR }),
      iters: 300,
      warmup: 50,
      note: "one decision per pattern, on the walk's base directory (#106)",
    }),
  );
} else {
  log("  fs.globSync                              skipped — Node < 22 has no fs.globSync");
}

printRow(
  runPaired({
    id: "net.connect",
    label: "net.connect (6-key options bag)",
    baseline: () => baselineDep.connect(CONNECT_OPTS()),
    mediated: () => dep.connect(CONNECT_OPTS()),
    iters: 200,
    warmup: 100,
    note: "includes the accessor-flattening clone of the options bag (#26/#56)",
  }),
);

if (CAN_SPAWN) {
  printRow(
    runPaired({
      id: "child_process.spawnSync",
      label: `child_process.spawnSync (${Object.keys(REAL_ENV).length} env keys)`,
      baseline: () => baselineDep.spawnSync(SPAWN_CMD, [], SPAWN_OPTS),
      mediated: () => dep.spawnSync(SPAWN_CMD, [], SPAWN_OPTS),
      iters: 20,
      warmup: 10,
      note: "pins the options bag and snapshots the un-proxied env key by key (#89)",
    }),
  );
} else {
  log("  child_process.spawnSync                  skipped — no /bin/true on this platform");
}

printRow(
  runPaired({
    id: "process.env.read",
    label: "process.env read (Proxy get trap)",
    baseline: () => baselineDep.envRead(ENV_KEY),
    mediated: () => dep.envRead(ENV_KEY),
    iters: 1000,
    note: "every env read by a dependency is attributed and evaluated",
  }),
);

printRow(
  runPaired({
    id: "process.env.spread",
    label: `{...process.env} (${dep.envKeyCount} keys)`,
    baseline: () => baselineDep.envSpread(),
    mediated: () => dep.envSpread(),
    iters: 40,
    warmup: 20,
    note: "ONE call, ~2 attributions per key (each now a 3-frame capture, #133) — still the most expensive mediated operation measured",
  }),
);

printRow(
  runPaired({
    id: "http.globalAgent.property",
    label: "http.globalAgent property read",
    baseline: () => baselineDep.agentProperty(),
    mediated: () => dep.agentProperty(),
    iters: 200,
    batch: 100,
    note: "per-property Proxy trap (#65) — paid by every read, not just createConnection",
  }),
);

if (dep.hasFetch === true) {
  printRow(
    await runPairedAsync({
      id: "fetch",
      label: "fetch (global egress guard)",
      baseline: () => baselineDep.fetchCall(HTTP_URL).then((r) => r.text()),
      mediated: () => dep.fetchCall(HTTP_URL).then((r) => r.text()),
      iters: 60,
      note: "not a module surface (#80): pin the URL argument, re-parse it, attribute, evaluate",
    }),
  );
}

if (WITH_ESM) {
  printRow(
    runPaired({
      id: "esm.fs.readFileSync",
      label: "fs.readFileSync via ESM import",
      baseline: () => baselineEsm.readSync(),
      mediated: () => shimmedEsm.readSync(),
      iters: 2000,
      note: "the ESM path builds its OWN shim objects (esm-runtime.ts) — measured, not assumed",
    }),
  );
}

log("");

// ── 2. module system, paired ──────────────────────────────────────────────────────────────

log("[B] MODULE SYSTEM — the tax every require() pays, mediated or not (paired, ABBA)");
printHeader();

const parentModule = requireCjs.cache[requireCjs.resolve(FIXTURE_DIR)];
printRow(
  runPaired({
    id: "Module._load:passthrough",
    label: "Module._load('node:path') passthrough",
    baseline: () => realLoad.call(nodeModule, "node:path", parentModule, false),
    mediated: () => nodeModule._load("node:path", parentModule, false),
    iters: 200,
    batch: 200,
    note: "the defineRelinkedPatch indirection on a NON-mediated specifier",
  }),
);
printRow(
  runPaired({
    id: "Module._load:mediated",
    label: "Module._load('node:fs') mediated",
    baseline: () => realLoad.call(nodeModule, "node:fs", parentModule, false),
    mediated: () => nodeModule._load("node:fs", parentModule, false),
    iters: 200,
    batch: 200,
    note: "registry hit — returns the shim instead of the builtin",
  }),
);
log("");

// ── 3. enforce-mode deny path, absolute ───────────────────────────────────────────────────

log("[C] ENFORCE DENY — attribute → evaluate → throw. No un-mediated equivalent exists.");
printHeader();

printRow(
  runSingle({
    id: "deny.fs",
    label: "fs read, denied",
    fn: () => denied.readDenied(),
    iters: 1000,
    note: "no real syscall happens: the throw precedes it",
  }),
);
printRow(
  runSingle({
    id: "deny.net",
    label: "net connect, denied",
    fn: () => denied.connectDenied("127.0.0.1", 1),
    iters: 1000,
  }),
);
if (CAN_SPAWN) {
  printRow(
    runSingle({
      id: "deny.spawn",
      label: "spawnSync, denied",
      fn: () => denied.spawnDenied(SPAWN_CMD, []),
      iters: 1000,
      note: "no process is created — the options bag is never even pinned",
    }),
  );
}
if (denied.hasFetch === true) {
  printRow(
    await runSingleAsync({
      id: "deny.fetch",
      label: "fetch, denied (rejected promise)",
      fn: () => denied.fetchDenied("http://denied.example/").then(
        () => "resolved",
        (e) => e.name,
      ),
      iters: 200,
      note: "includes the promise rejection, which is how the global guard reports a denial",
    }),
  );
}
printRow(
  runSingle({
    id: "deny.unknown.fs",
    label: "fs read via opaque frame → <unknown>",
    fn: () => {
      try {
        return opaqueRead();
      } catch {
        return 0;
      }
    },
    iters: 1000,
    note: "the fail-closed path (#60): an app frame reached through eval is not the trust root",
  }),
);
log("");

// ── 4. attribution, isolated ──────────────────────────────────────────────────────────────

log("[D] ATTRIBUTION — the stack walk alone, as a function of the stack it walks");
printHeader();

const attrOpts = { projectRoot: PROJECT_ROOT };
for (const d of [0, 8, 24]) {
  printRow(
    runSingle({
      id: `attribution@${d}`,
      label: `attributeCaller() at depth ${d}`,
      fn: () => baselineDep.attributeAtDepth(attributeCaller, attrOpts, d),
      iters: 2000,
    }),
  );
}
printRow(
  runSingle({
    id: "attribution.unknown",
    label: "attributeCaller() through opaque frame",
    fn: () => opaqueAttribute(attributeCaller, attrOpts),
    iters: 2000,
    note: "resolves <unknown>: the walk cannot stop at the app frame it reaches",
  }),
);
printRow(
  runSingle({
    id: "attribution.exhausted",
    label: "attributeCaller() budget-exhausted",
    fn: () => deepOpaqueAttribute(attributeCaller, attrOpts, 40),
    iters: 1000,
    note: "40 opaque frames: the walk spends the whole maxFrames budget and fails closed",
  }),
);
log("");

// ── 5. policy + memoization ───────────────────────────────────────────────────────────────

log("[E] POLICY + MEMOIZATION");
printHeader();

const evalReq = { kind: "fs", access: "read", path: dataPath };
printRow(
  runSingle({
    id: "evaluate",
    label: "evaluate() (pure, no stack walk)",
    fn: () => evaluate(policy, "enforce", "bench-dep", evalReq),
    iters: 200,
    batch: 200,
  }),
);

let coldFlat = 0;
printRow(
  runSingle({
    id: "packageForPath.cold.flat",
    label: "packageForPath cold, top-level install",
    fn: () => packageForPath(`/probe/node_modules/dep-${coldFlat++}/index.js`, PROJECT_ROOT),
    iters: 2000,
    warmup: 50,
  }),
);
let coldChain = 0;
printRow(
  runSingle({
    id: "packageForPath.cold.chain",
    label: "packageForPath cold, 4-link chain",
    fn: () =>
      packageForPath(
        `/probe/node_modules/a-${coldChain}/node_modules/b/node_modules/@sc/c/node_modules/d-${coldChain++}/index.js`,
        PROJECT_ROOT,
      ),
    iters: 2000,
    warmup: 50,
    note: "install-chain identity (#92) parses EVERY node_modules segment, not the last one",
  }),
);
const warmPath = "/probe/node_modules/warm-dep/index.js";
packageForPath(warmPath, PROJECT_ROOT);
printRow(
  runSingle({
    id: "packageForPath.warm",
    label: "packageForPath warm (memoized)",
    fn: () => packageForPath(warmPath, PROJECT_ROOT),
    iters: 200,
    batch: 200,
  }),
);
log("");

// ── 6. hardened mode ──────────────────────────────────────────────────────────────────────

// Hardened shims are a SEPARATE memoized registry (live-context.ts), keyed on hardened-ness, so
// a hardened install can be stacked on top of the plain one and a freshly-required fixture picks
// up hardened shims while the existing instance keeps plain ones. Both read the same live
// context, so the policy and the decisions are identical and the only difference is the freezing
// — which is exactly the thing being priced.
const hardenedHandle = install(policy, "enforce", {
  projectRoot: PROJECT_ROOT,
  onDecision,
  hardened: true,
});
const hardenedDep = loadFresh(FIXTURE_DIR);

log("[F] HARDENED MODE (#17) — cost of the opt-in freeze, vs the default mutable shims");
printHeader();
// Not `checkPair`: BOTH arms are mediated here, so "the baseline arm produces no decisions" is
// the wrong premise. What has to be true instead is that the two arms are genuinely different
// shim objects (one frozen, one not) charged to the same principal under the same policy.
{
  const plain = observe(() => dep.readSync()).filter((d) => d.pkg !== undefined);
  const frozen = observe(() => hardenedDep.readSync()).filter((d) => d.pkg !== undefined);
  const distinctObjects = dep.readSync !== hardenedDep.readSync;
  check(
    "hardened arm is a distinct, frozen shim charged the same way",
    distinctObjects &&
      plain.length === 1 &&
      frozen.length === 1 &&
      plain[0].pkg === "bench-dep" &&
      frozen[0].pkg === "bench-dep" &&
      plain[0].allowed === frozen[0].allowed,
    `distinct=${distinctObjects} plain=${plain.length} hardened=${frozen.length}`,
  );
  log(`  ${CHECKS[CHECKS.length - 1].ok ? "ok  " : "FAIL"}  hardened-mode premise`);
}
printRow(
  runPaired({
    id: "hardened.fs.readFileSync",
    label: "fs.readFileSync, hardened vs plain",
    baseline: () => dep.readSync(),
    mediated: () => hardenedDep.readSync(),
    iters: 2000,
    note: "BOTH arms are mediated — this row is hardening's own cost, not capwall's",
  }),
);
hardenedHandle.uninstall();
log("");

// ── 7. startup surfaces (issue #134) ──────────────────────────────────────────────────────

log("[G] STARTUP — paid once per module load / addon / cold resolution, NOT per request");
printHeader();

if (CAN_COMPILE_ROW) {
  printRow(
    runPaired({
      id: "startup.compile-gate",
      label: "Module._compile gate, per CJS load",
      baseline: () => {
        compileHolder._compile = REAL_COMPILE;
        return dep.requireFresh(nextCompileFile());
      },
      mediated: () => {
        compileHolder._compile = GATED_COMPILE;
        return dep.requireFresh(nextCompileFile());
      },
      iters: 200,
      warmup: 50,
      note: "one `calledByNodeLoader()` 1-frame capture per module (#93); the policy is never consulted on this path",
    }),
  );
  compileHolder._compile = GATED_COMPILE; // leave the gate in place for anything after this row
} else {
  log("  Module._compile gate                     skipped — the prototype slot is not swappable here");
}

printRow(
  runPaired({
    id: "startup.dlopen-gate",
    label: "process.dlopen native gate, per addon",
    baseline: () => baselineDep.dlopen(REAL_DLOPEN, ADDON_PATH),
    mediated: () => dep.dlopen(GATED_DLOPEN, ADDON_PATH),
    iters: 200,
    warmup: 50,
    note: "S2/#49: pins the filename, then evaluates BOTH subjects (caller and addon owner)",
  }),
);

if (WITH_ESM) {
  printRow(
    await runPairedAsync({
      id: "startup.esm-cold-resolve",
      label: "ESM cold resolve, mediated specifier",
      baseline: importColdPlain,
      mediated: importColdMediated,
      iters: 60,
      warmup: 20,
      note: "both arms pay Node's resolve/load hook chain; the delta is the synthetic module + getEsmShim",
    }),
  );
}
log("");

// ── teardown ──────────────────────────────────────────────────────────────────────────────

handle.uninstall();
fs.rmSync(SCRATCH, { recursive: true, force: true });
netServer.close();
httpServer.close();
httpServer.closeAllConnections?.();

// Read SINK once, so neither V8 nor the linter can conclude that the value every benchmarked
// call was assigned into is dead. It never holds a symbol; the branch exists to be a read.
if (typeof SINK === "symbol") fail("unreachable: the benchmark sink held a symbol");

// ── verdict ───────────────────────────────────────────────────────────────────────────────

/**
 * THE BUDGET GATE, AND WHY IT IS PER INTERCEPTED CALL RATHER THAN PER JS CALL.
 *
 * "<1ms/req" is a claim about ONE intercepted capability request: attribute the caller, evaluate
 * the policy, allow or throw. Every surface measured here is comfortably inside it. But a single
 * JavaScript operation is not necessarily a single interception — `{...process.env}` is ~2
 * interceptions per environment variable, so on an 80-key environment it costs MILLISECONDS, and
 * a request handler that does it once has blown the per-request budget on its own.
 *
 * Both numbers are gated and both are printed. The per-interception figure is what the design
 * target is about and what a regression would move. The AMPLIFIED list below is the honest
 * asterisk on the headline claim, and it is printed loudly rather than being averaged into a
 * healthy-looking mean: see docs/roadmap.md § S4 and scripts/bench/README.md § "Where the budget
 * does not hold".
 */
const perCallRows = RESULTS.filter(
  (r) =>
    r.kind === "paired" &&
    r.id !== "hardened.fs.readFileSync" &&
    !r.id.startsWith("Module._load") &&
    // #134's section [G] is startup cost — once per module load, once per addon, once per cold
    // resolution. Judging it against a PER-REQUEST budget would be a category error in both
    // directions: it would either pass meaninglessly or fail for being what it is. It is printed,
    // and it is subject to the self-checks, but the budget gate is about intercepted calls.
    !r.id.startsWith("startup."),
);
const perDecision = (r) => r.added.est / Math.max(1, r.decisions);
const worst = perCallRows.reduce((a, b) => (perDecision(a) >= perDecision(b) ? a : b));
const budgetPass = perCallRows.every((r) => perDecision(r) < BUDGET_NS);
const amplified = perCallRows.filter((r) => r.added.est >= BUDGET_NS);
const ratio = fsDeep.ratio;
const ratioPass = ratio < RATIO_LIMIT;
const checksPass = CHECKS.every((c) => c.ok);
const pass = budgetPass && ratioPass && checksPass;

const summary = {
  node: process.version,
  platform: `${process.platform}/${process.arch}`,
  blocks: BLOCKS,
  estimator: "min over blocks of block medians",
  timerOverheadNs,
  calibrationNs: calibration.absolute.est,
  ratio,
  ratioLimit: RATIO_LIMIT,
  budgetNs: BUDGET_NS,
  worstPerDecisionNs: perDecision(worst),
  worstPerDecisionSurface: worst.id,
  amplified: amplified.map((r) => ({ id: r.id, addedNs: r.added.est, decisions: r.decisions })),
  pass,
  gates: { budget: budgetPass, ratio: ratioPass, selfChecks: checksPass },
  rows: RESULTS,
};

if (JSON_OUT) {
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
} else {
  log("=".repeat(99));
  log(`RESULT: ${pass ? "PASS" : "FAIL"}`);
  log(
    `  budget      ${budgetPass ? "PASS" : "FAIL"} — worst added latency PER INTERCEPTED CALL ` +
      `${fmtNs(perDecision(worst))} on '${worst.id}' (budget ${fmtNs(BUDGET_NS)})`,
  );
  log(
    `  ratio       ${ratioPass ? "PASS" : "FAIL"} — fs added ${fmtNs(fsDeep.added.est)} ÷ co-sampled cpu ` +
      `calibration ${fmtNs(fsDeep.reference.est)} = ${ratio.toFixed(2)} (limit ${RATIO_LIMIT}, ` +
      `per-block ${Math.min(...fsDeep.ratioBlocks).toFixed(2)}–${Math.max(...fsDeep.ratioBlocks).toFixed(2)})`,
  );
  log(
    `  self-checks ${checksPass ? "PASS" : "FAIL"} — ${CHECKS.filter((c) => c.ok).length}/${CHECKS.length} premises verified`,
  );
  if (amplified.length > 0) {
    log("");
    log("  AMPLIFICATION — one JS call, many interceptions. These exceed 1ms PER CALL:");
    for (const r of amplified) {
      log(
        `    ${r.label.padEnd(34)} ${fmtNs(r.added.est)} added over ${r.decisions} decisions ` +
          `(${fmtNs(perDecision(r))} each)`,
      );
    }
    log("  The per-call budget does NOT hold for these. See README § Where the budget does not hold.");
  }
  log("=".repeat(99));
}

process.exit(pass ? 0 : 1);
