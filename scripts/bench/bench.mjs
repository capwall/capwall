#!/usr/bin/env node
/**
 * capwall performance benchmark harness (roadmap S4, GitHub issue #14).
 *
 * Measures capwall's ADDED per-call latency on the hot path documented in AGENTS.md §5:
 * attribution (stack-walk + module→package resolution) + policy/evaluate (lookup +
 * glob/host match), for a capability-sensitive call intercepted by a shim. The calls are
 * driven from a VENDORED dependency fixture (scripts/bench/fixtures/node_modules/bench-dep)
 * so attribution does real work resolving a `node_modules/…` path to a package name — a call
 * from app code short-circuits to the `<app>` sentinel and would under-measure.
 *
 * Scenarios:
 *   1. fs read      — baseline (unshimmed) vs capwall-enforced, interleaved, per-call delta.
 *   2. attribution-only — `attributeCaller()` alone, called from the fixture's frame.
 *   3. evaluate-only    — `evaluate()` alone (pure function, no stack walk).
 *   4. net (denied)      — attribute→evaluate→throw, no real socket I/O (informational).
 *   5. path→package cache — cold (unique paths, guaranteed miss) vs warm (repeated path, hit).
 *
 * Methodology: warm up every scenario before measuring; measure with
 * `process.hrtime.bigint()` only (no benchmarking library — AGENTS.md §5 forbids new runtime
 * deps); compute percentiles ourselves from the raw sample; interleave baseline and shimmed
 * calls call-by-call in scenario 1 so both share the same GC/scheduler jitter, then take the
 * per-iteration delta as "added latency" (paired samples, not independently-summarized
 * populations).
 *
 * Gate: PASS/FAIL is decided on the scenario-1 (fs read) added-latency MEDIAN against the
 * <1ms/req budget from AGENTS.md §5 and scripts/bench/README.md's original intent ("fail if
 * median per-call overhead regresses past the target"). Tail (p95/p99) is reported for every
 * scenario because it matters for the per-request claim, but only the median gates exit code.
 *
 * Run: `pnpm -r build` first (this imports the BUILT packages/core/dist — see
 * scripts/bench/README.md), then `node scripts/bench/bench.mjs` (or `pnpm bench`).
 */

import { createRequire } from "node:module";
import * as path from "node:path";
import * as fs from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const CORE_DIST = path.join(here, "..", "..", "packages", "core", "dist", "index.js");
const FIXTURE_DIR = path.join(here, "fixtures", "node_modules", "bench-dep");

const WARMUP = 5_000;
const ITERATIONS = 60_000; // "50k+" per the issue, for stable percentiles
const CACHE_COLD_N = 20_000;
const CACHE_WARM_N = 60_000;
const NET_ITERATIONS = 20_000;

const NS_PER_MS = 1_000_000;
const BUDGET_NS = 1 * NS_PER_MS; // the <1ms/req target

function fail(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

if (!fs.existsSync(CORE_DIST)) {
  fail(`${CORE_DIST} not found — run "pnpm -r build" first (see scripts/bench/README.md).`);
}

const core = await import(pathToFileURL(CORE_DIST).href);
const { install, loadPolicyFromObject, attributeCaller, packageForPath, evaluate } = core;

const requireCjs = createRequire(import.meta.url);

/** require() the fixture fresh (cache cleared) so its top-level require("fs"/"net") re-runs
 * and captures whichever module the loader currently resolves — real or capwall-shimmed. */
function loadFixtureFresh() {
  const resolved = requireCjs.resolve(FIXTURE_DIR);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE_DIR);
}

// --- timing + stats helpers -------------------------------------------------------------

/** Time a single synchronous call, in nanoseconds. */
function timeOnce(fn) {
  const t0 = process.hrtime.bigint();
  fn();
  const t1 = process.hrtime.bigint();
  return Number(t1 - t0);
}

/** Nearest-rank percentile over an ASCENDING-sorted sample. */
function percentile(sortedAsc, p) {
  if (sortedAsc.length === 0) return 0;
  const idx = Math.min(sortedAsc.length - 1, Math.max(0, Math.ceil((p / 100) * sortedAsc.length) - 1));
  return sortedAsc[idx];
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
  if (ns >= NS_PER_MS) return `${(ns / NS_PER_MS).toFixed(3)} ms`;
  if (ns >= 1000) return `${(ns / 1000).toFixed(3)} µs`;
  return `${ns.toFixed(0)} ns`;
}

function printStats(label, s) {
  console.log(
    `  ${label.padEnd(28)} mean ${fmtNs(s.mean).padStart(11)}  p50 ${fmtNs(s.p50).padStart(11)}` +
      `  p95 ${fmtNs(s.p95).padStart(11)}  p99 ${fmtNs(s.p99).padStart(11)}  (n=${s.n})`,
  );
}

console.log("capwall performance benchmark (scripts/bench/bench.mjs)");
console.log(`node ${process.version} on ${process.platform}/${process.arch}`);
console.log(`fixture: ${FIXTURE_DIR}`);
console.log(`warmup=${WARMUP} iterations=${ITERATIONS}\n`);

// --- fixture + capwall setup --------------------------------------------------------------

// Baseline instance: loaded BEFORE capwall installs, so its closed-over `fs`/`net` are the
// real, un-shimmed builtins.
const baselineDep = loadFixtureFresh();

const dataPath = path.join(FIXTURE_DIR, "data.txt");
const policy = loadPolicyFromObject(
  {
    version: 1,
    mode: "enforce",
    packages: {
      "bench-dep": { fs: { read: [dataPath], write: [] } },
      // Deliberately no `net` grant for bench-dep — scenario 4 exercises the deny path.
    },
  },
  { projectRoot: FIXTURE_DIR },
);

const handle = install(policy, "enforce", {
  projectRoot: FIXTURE_DIR,
  onDecision: () => {}, // same shape as production observe-mode logging; no-op cost only
});

// Shimmed instance: loaded fresh AFTER install, so its closed-over `fs`/`net` are capwall's
// shims. Baseline and shimmed instances now coexist in the same process (same trick
// packages/core/test/fs-slice.test.ts uses), so scenario 1 can interleave them.
const shimmedDep = loadFixtureFresh();

// --- scenario 1: fs read — baseline vs shimmed, interleaved, paired delta ----------------

console.log("[1] fs read — added latency per call (capwall enforce vs unshimmed baseline)");
console.log("    both calls originate in bench-dep (attribution resolves a real package).");

for (let i = 0; i < WARMUP; i++) {
  baselineDep.readSync();
  shimmedDep.readSync();
}

const baselineNs = new Array(ITERATIONS);
const shimmedNs = new Array(ITERATIONS);
const deltaNs = new Array(ITERATIONS);
for (let i = 0; i < ITERATIONS; i++) {
  const b = timeOnce(() => baselineDep.readSync());
  const s = timeOnce(() => shimmedDep.readSync());
  baselineNs[i] = b;
  shimmedNs[i] = s;
  deltaNs[i] = s - b;
}

const baselineStats = stats(baselineNs);
const shimmedStats = stats(shimmedNs);
const deltaStats = stats(deltaNs);
printStats("baseline (unshimmed)", baselineStats);
printStats("shimmed (capwall enforce)", shimmedStats);
printStats("added latency (delta)", deltaStats);
console.log();

// --- scenario 2: attribution-only ---------------------------------------------------------

console.log("[2] attribution only — attributeCaller() called from bench-dep's frame");
const attrOpts = { projectRoot: FIXTURE_DIR };
for (let i = 0; i < WARMUP; i++) baselineDep.callAttribute(attributeCaller, attrOpts);
const attrNs = new Array(ITERATIONS);
for (let i = 0; i < ITERATIONS; i++) {
  attrNs[i] = timeOnce(() => baselineDep.callAttribute(attributeCaller, attrOpts));
}
const attrStats = stats(attrNs);
printStats("attributeCaller()", attrStats);
console.log(
  `  -> ${((attrStats.mean / deltaStats.mean) * 100).toFixed(1)}% of scenario 1's mean added latency ` +
    `(AGENTS.md §5: attribution is expected to dominate)`,
);
console.log();

// --- scenario 3: evaluate-only -------------------------------------------------------------

console.log("[3] evaluate only — evaluate(policy, mode, pkg, req), no stack walk");
const evalReq = { kind: "fs", access: "read", path: dataPath };
for (let i = 0; i < WARMUP; i++) evaluate(policy, "enforce", "bench-dep", evalReq);
const evalNs = new Array(ITERATIONS);
for (let i = 0; i < ITERATIONS; i++) {
  evalNs[i] = timeOnce(() => evaluate(policy, "enforce", "bench-dep", evalReq));
}
const evalStats = stats(evalNs);
printStats("evaluate()", evalStats);
console.log();

// --- scenario 4: net (denied) — attribute+evaluate+throw, no real socket I/O -------------

console.log("[4] net connect, denied — attribute→evaluate→throw path (no grant, no real I/O)");
console.log("    informational only: no unshimmed baseline is comparable (a real connect()");
console.log("    does async DNS/socket work a synchronous throw never reaches).");
for (let i = 0; i < WARMUP; i++) shimmedDep.connectDenied("127.0.0.1", 1);
const netNs = new Array(NET_ITERATIONS);
let netThrew = 0;
for (let i = 0; i < NET_ITERATIONS; i++) {
  let threw = false;
  netNs[i] = timeOnce(() => {
    threw = shimmedDep.connectDenied("127.0.0.1", 1).threw;
  });
  if (threw) netThrew++;
}
const netStats = stats(netNs);
printStats("net connect (denied)", netStats);
console.log(`  -> denied ${netThrew}/${NET_ITERATIONS} calls (expect ${NET_ITERATIONS}: no grant, enforce mode)`);
console.log();

// --- scenario 5: path→package cache — cold vs warm --------------------------------------

console.log("[5] path→package cache — cold (unique path, miss) vs warm (repeated path, hit)");
const coldNs = new Array(CACHE_COLD_N);
for (let i = 0; i < CACHE_COLD_N; i++) {
  // A fresh, never-before-seen path every call: guaranteed cache miss.
  const fabricated = `/bench-cache-probe/node_modules/cache-dep-${i}/index.js`;
  coldNs[i] = timeOnce(() => packageForPath(fabricated));
}
const warmPath = "/bench-cache-probe/node_modules/cache-dep-warm/index.js";
packageForPath(warmPath); // prime the cache
for (let i = 0; i < WARMUP; i++) packageForPath(warmPath);
const warmNs = new Array(CACHE_WARM_N);
for (let i = 0; i < CACHE_WARM_N; i++) warmNs[i] = timeOnce(() => packageForPath(warmPath));

const coldStats = stats(coldNs);
const warmStats = stats(warmNs);
printStats("cold (cache miss)", coldStats);
printStats("warm (cache hit)", warmStats);
console.log(`  -> cache speedup: ${(coldStats.mean / warmStats.mean).toFixed(1)}x (mean cold / mean warm)`);
console.log();

handle.uninstall();

// --- verdict --------------------------------------------------------------------------------

const pass = deltaStats.p50 < BUDGET_NS;
console.log("=".repeat(78));
console.log(
  `RESULT: ${pass ? "PASS" : "FAIL"} — fs read added-latency median (p50) = ${fmtNs(deltaStats.p50)}` +
    ` (budget: ${fmtNs(BUDGET_NS)} / 1ms/call)`,
);
console.log(
  `        mean=${fmtNs(deltaStats.mean)}  p50=${fmtNs(deltaStats.p50)}  p95=${fmtNs(deltaStats.p95)}` +
    `  p99=${fmtNs(deltaStats.p99)}`,
);
if (deltaStats.p99 >= BUDGET_NS && pass) {
  console.log("        note: p99 exceeds the 1ms budget even though the median gate passes — tail matters.");
}
console.log("=".repeat(78));

process.exit(pass ? 0 : 1);
