#!/usr/bin/env node
/**
 * capwall STARTUP benchmark harness — the second axis, and the one `bench.mjs` deliberately
 * does not measure (see `scripts/bench/README.md` § Coverage).
 *
 * `bench.mjs` prices one intercepted CALL, in microseconds. This prices one mediated PROCESS, in
 * milliseconds: what `node --import @capwall/core/preload app.js` costs before the app's first
 * line runs, paid once per process by every capwall user on every process they mediate — a CLI
 * that shells out, a test runner spawning workers, a serverless cold start.
 *
 * WHY IT IS COMMITTED. The ~180 ms breakdown in `README.md` § Startup came from a throwaway
 * harness that was never checked in, so every later claim about startup had to be taken on
 * trust or re-derived from scratch. This is that harness, written down. #152 (the
 * `module.register()` → `module.registerHooks()` migration) is a ~53 ms startup change, and it
 * should not have to build its own measuring device first.
 *
 * ── WHAT IS TIMED ─────────────────────────────────────────────────────────────────────────────
 *
 * Each sample spawns one child and reads THREE numbers:
 *
 *   - `wall` — `performance.now()` read on the FIRST line of the target's entry point, i.e.
 *     milliseconds since the child's own timeOrigin, after the whole `--import` chain has run.
 *     This is the headline figure.
 *   - `cpu`  — the same instant's `process.cpuUsage()` (user+system), which counts the ESM
 *     loader thread's work as well as the main thread's. On a mediated child `cpu > wall`,
 *     and the gap IS the loader thread.
 *   - `spawn` — the parent's wall clock around `spawnSync`, printed only under `--verbose`.
 *     It folds in fork/exec, parent scheduling and teardown, which on a loaded machine are
 *     hundreds of milliseconds of variance on top of a ~200 ms signal. Recorded so the
 *     difference between it and `wall` is visible rather than argued about.
 *
 * ── METHODOLOGY (the same discipline as bench.mjs, one level up) ──────────────────────────────
 *
 *  1. ABBA-INTERLEAVED ARMS. Every arm is sampled once per ROUND and the round's arm ORDER is
 *     reversed on odd rounds, so no arm systematically runs first. Fixed-order sampling on a
 *     shared box measures the machine's mood and attributes it to whichever arm went last.
 *  2. A MIN ESTIMATOR. The reported figure is the MINIMUM over samples, with p50 beside it.
 *     Noise only ever ADDS time, so the minimum sample is the least contaminated one. p90 —
 *     what the pre-floor measurements in the README quote — is reported under `--verbose`; it is
 *     the honest figure on an IDLE box and pure contention on a busy one.
 *  3. CONTROL ROWS ARE NOT OPTIONAL. `bare node` and `CAPWALL_ESM=0` are printed on every run.
 *     A change that claims the ESM loader thread and moves `bare node` did not measure what it
 *     says it measured.
 *  4. THE HARNESS CHECKS ITS OWN PREMISE, before it times anything. Every arm is probed once:
 *     the target requires a granted-NOTHING fixture dependency and attempts an `fs` read, and
 *     the harness asserts that the mediated arms DENIED it and charged `bench-dep-denied` —
 *     not `<app>`, not `<unknown>` — while the bare arm allowed it. Without that, a preload
 *     that silently failed to install (a bad path, a policy that parsed to inert, a `--import`
 *     Node quietly ignored) is timed as "bare node twice" and reported as a spectacular win.
 *
 * ── USAGE ─────────────────────────────────────────────────────────────────────────────────────
 *
 *   pnpm build                       # this harness spawns the BUILT dist/preload.js
 *   node scripts/bench/startup.mjs                  # 20 rounds, 3 arms
 *   node scripts/bench/startup.mjs --quick          # 8 rounds
 *   node scripts/bench/startup.mjs --compile-cache  # + the NODE_COMPILE_CACHE arms
 *   node scripts/bench/startup.mjs --node /path/to/node   # measure a different Node
 *   node scripts/bench/startup.mjs --json
 *
 * Exits non-zero if a premise check fails. It does NOT gate on a threshold: startup is a
 * machine-dependent number and a CI gate on it would be a flake generator. Dependency-free, on
 * purpose (AGENTS.md § 5).
 */
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(here, "fixtures");
const PROJECT_ROOT = FIXTURES;
const APP = path.join(FIXTURES, "startup-app.cjs");
const PRELOAD = path.join(here, "..", "..", "packages", "core", "dist", "preload.js");

const argv = process.argv.slice(2);
const has = (f) => argv.includes(`--${f}`);
const opt = (f, d) => {
  const i = argv.indexOf(`--${f}`);
  return i === -1 ? d : argv[i + 1];
};

const NODE = opt("node", process.execPath);
const ROUNDS = Number(opt("rounds", has("quick") ? "8" : "20"));
const WITH_CACHE = has("compile-cache");
const JSON_OUT = has("json");
const VERBOSE = has("verbose");

function fail(msg) {
  process.stderr.write(`\n[startup] FAIL: ${msg}\n`);
  process.exit(1);
}

if (!fs.existsSync(PRELOAD)) {
  fail(`${PRELOAD} not found — run "pnpm build" first (see scripts/bench/README.md).`);
}

/**
 * The policy the mediated arms run under: `enforce`, and `bench-dep-denied` is deliberately
 * absent, so the fixture's `fs` read is denied by default. That denial is the premise check.
 */
const POLICY = { version: 1, mode: "enforce", packages: {} };
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "capwall-startup-"));
const POLICY_FILE = path.join(scratch, "capabilities.json");
fs.writeFileSync(POLICY_FILE, JSON.stringify(POLICY));

const cacheDir = (name) => {
  const d = path.join(scratch, "cc", name);
  fs.mkdirSync(d, { recursive: true });
  return d;
};

const baseEnv = { ...process.env };
// The harness controls both of these; inheriting either from the caller's shell would silently
// mediate (or cache) an arm that claims not to be.
delete baseEnv["NODE_OPTIONS"];
delete baseEnv["NODE_COMPILE_CACHE"];
Object.assign(baseEnv, {
  CAPWALL_POLICY_FILE: POLICY_FILE,
  CAPWALL_MODE: "enforce",
  CAPWALL_PROJECT_ROOT: PROJECT_ROOT,
});

const preloadOpt = `--import ${pathToFileURL(PRELOAD).href}`;

/**
 * `mediated: false` marks a CONTROL arm — one the premise check requires to produce no capwall
 * decision at all. Getting this wrong in either direction is the failure the check exists for.
 */
const arms = [
  { name: "bare node (control)", mediated: false, opts: [], env: {} },
  {
    name: "CAPWALL_ESM=0 (control)",
    mediated: true,
    opts: [preloadOpt],
    env: { CAPWALL_ESM: "0" },
  },
  { name: "mediated, esm ON", mediated: true, opts: [preloadOpt], env: {} },
];

if (WITH_CACHE) {
  // NODE_COMPILE_CACHE is Node's own env channel (>=22.1) and needs nothing from capwall — see
  // README.md § The V8 compile cache. Each arm gets its OWN cache directory so one arm's writes
  // cannot warm another's reads.
  arms.push(
    {
      name: "bare node + compile cache",
      mediated: false,
      opts: [],
      env: { NODE_COMPILE_CACHE: cacheDir("bare") },
    },
    {
      name: "CAPWALL_ESM=0 + compile cache",
      mediated: true,
      opts: [preloadOpt],
      env: { CAPWALL_ESM: "0", NODE_COMPILE_CACHE: cacheDir("esm0") },
    },
    {
      name: "mediated, esm ON + compile cache",
      mediated: true,
      opts: [preloadOpt],
      env: { NODE_COMPILE_CACHE: cacheDir("med") },
    },
  );
}

function run(arm) {
  const t0 = process.hrtime.bigint();
  const r = spawnSync(NODE, [APP], {
    env: { ...baseEnv, ...arm.env, NODE_OPTIONS: arm.opts.join(" ") },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const spawnMs = Number(process.hrtime.bigint() - t0) / 1e6;
  if (r.error) fail(`arm '${arm.name}' failed to spawn: ${r.error.message}`);
  if (r.status !== 0) fail(`arm '${arm.name}' exited ${r.status}\n${r.stderr}`);
  const stamp = /^STAMP wall=(\d+(?:\.\d+)?) cpu=(\d+(?:\.\d+)?)$/m.exec(r.stdout);
  if (!stamp) fail(`arm '${arm.name}' printed no stamp:\n${r.stdout}\n${r.stderr}`);
  const probe = /^PROBE threw=(true|false) name=(\S*)$/m.exec(r.stdout);
  if (!probe) fail(`arm '${arm.name}' printed no probe line:\n${r.stdout}\n${r.stderr}`);
  return {
    wall: Number(stamp[1]),
    cpu: Number(stamp[2]),
    spawn: spawnMs,
    denied: probe[1] === "true",
    errorName: probe[2],
    stderr: r.stderr,
  };
}

// ── The premise check ────────────────────────────────────────────────────────────────────────
// One probe run per arm, before any timing. See the header: an arm that is not mediated when it
// says it is turns this harness into a very confident random number generator.
const checks = [];
for (const arm of arms) {
  const r = run(arm);
  const problems = [];
  if (arm.mediated) {
    if (!r.denied) problems.push("the fixture's fs read was ALLOWED — capwall did not install");
    if (r.errorName !== "CapabilityError") {
      problems.push(`denial was '${r.errorName}', expected CapabilityError`);
    }
    if (!r.stderr.includes("bench-dep-denied")) {
      problems.push("no decision charged to 'bench-dep-denied' on stderr");
    }
  } else {
    if (r.denied) problems.push("the fixture's fs read was DENIED in an un-mediated arm");
    if (r.stderr.includes("[capwall]")) problems.push("capwall spoke in an un-mediated arm");
  }
  checks.push({ arm: arm.name, ok: problems.length === 0, problems });
}
const broken = checks.filter((c) => !c.ok);
if (broken.length > 0) {
  for (const c of broken) process.stderr.write(`[startup] ${c.arm}: ${c.problems.join("; ")}\n`);
  fail(`${broken.length} arm(s) failed the premise check — the numbers below would be fiction.`);
}

// ── Sampling ─────────────────────────────────────────────────────────────────────────────────
// Warm-up passes also POPULATE the compile-cache arms, so those rows report the steady state
// (a hit) rather than the first run's cache WRITE.
for (let i = 0; i < 3; i++) for (const arm of arms) run(arm);

const samples = new Map(arms.map((a) => [a.name, []]));
for (let round = 0; round < ROUNDS; round++) {
  for (const arm of round % 2 === 0 ? arms : arms.toReversed()) {
    samples.get(arm.name).push(run(arm));
  }
}

const pct = (xs, p) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
};
const stat = (xs, key) => ({
  min: +pct(xs.map((x) => x[key]), 0).toFixed(1),
  p50: +pct(xs.map((x) => x[key]), 50).toFixed(1),
  p90: +pct(xs.map((x) => x[key]), 90).toFixed(1),
});

const rows = arms.map((a) => {
  const xs = samples.get(a.name);
  return { arm: a.name, n: xs.length, wall: stat(xs, "wall"), cpu: stat(xs, "cpu"), spawn: stat(xs, "spawn") };
});

const nodeVersion = spawnSync(NODE, ["-v"], { encoding: "utf8" }).stdout.trim();
fs.rmSync(scratch, { recursive: true, force: true });

if (JSON_OUT) {
  process.stdout.write(
    JSON.stringify({ node: nodeVersion, rounds: ROUNDS, cpus: os.cpus().length, loadavg: os.loadavg(), rows }, null, 2) + "\n",
  );
} else {
  const load = os.loadavg().map((n) => n.toFixed(2)).join(" ");
  process.stdout.write(
    `\ncapwall STARTUP — node ${nodeVersion}, ${os.cpus().length} cpus, loadavg ${load}, ` +
      `${ROUNDS} rounds, ABBA-interleaved\n` +
      `all ${checks.length} premise checks PASS\n\n`,
  );
  const cols = VERBOSE
    ? ["wall min", "wall p50", "wall p90", "cpu min", "cpu p50", "spawn min"]
    : ["wall min", "wall p50", "cpu min", "cpu p50"];
  process.stdout.write("arm".padEnd(34) + cols.map((c) => c.padStart(10)).join("") + "\n");
  for (const r of rows) {
    const vals = VERBOSE
      ? [r.wall.min, r.wall.p50, r.wall.p90, r.cpu.min, r.cpu.p50, r.spawn.min]
      : [r.wall.min, r.wall.p50, r.cpu.min, r.cpu.p50];
    process.stdout.write(r.arm.padEnd(34) + vals.map((v) => String(v).padStart(10)).join("") + "\n");
  }
  const bare = rows.find((r) => r.arm === "bare node (control)");
  process.stdout.write("\ncapwall's own cost (arm − bare node), min estimator:\n");
  for (const r of rows) {
    if (r === bare) continue;
    const ref = r.arm.includes("compile cache")
      ? rows.find((x) => x.arm === "bare node + compile cache") ?? bare
      : bare;
    process.stdout.write(
      `  ${r.arm.padEnd(32)} wall ${(r.wall.min - ref.wall.min).toFixed(1).padStart(7)} ms` +
        `   cpu ${(r.cpu.min - ref.cpu.min).toFixed(1).padStart(7)} ms\n`,
    );
  }
  process.stdout.write(
    "\nms, lower is better. `wall` is measured INSIDE the child on the first line of the entry\n" +
      "point; `cpu` is that child's own user+system CPU and includes the ESM loader thread.\n",
  );
}
