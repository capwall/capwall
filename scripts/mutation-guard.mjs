#!/usr/bin/env node
/**
 * MUTATION GUARD — "does this test still pass with the mechanism it names deleted?" (issue #112)
 *
 * WHY THIS EXISTS. `pnpm test` is capwall's only gate (GitHub Actions is billing-blocked, #3), so
 * a test that passes for the wrong reason is worse than a missing one: it is a green light nobody
 * re-examines. #112 found six of them by hand. The cheapest reliable way to find the rest is the
 * method that found those: revert a mechanism, re-run the tests that claim to cover it, and see
 * which still pass.
 *
 * This automates that method over a hand-written catalog (`scripts/mutants.json`) of the
 * security-critical mechanisms — the guards, the gates, the pinning, the attribution rules.
 * It is deliberately NOT a general mutation tester: no new dependency, no whole-tree operator
 * pass, no mutation score. A curated catalog is the right shape here because the interesting
 * question is not "what fraction of lines is covered" but "is THIS named security property
 * asserted anywhere", and that question needs a human to phrase the mutation.
 *
 * USAGE
 *   node scripts/mutation-guard.mjs              # every mutant
 *   node scripts/mutation-guard.mjs --only <id>  # one mutant (repeatable)
 *   node scripts/mutation-guard.mjs --list       # print the catalog and exit
 *   node scripts/mutation-guard.mjs --recover    # undo an interrupted run (see SAFETY)
 *
 * Exit code 0 when every mutant was CAUGHT; 1 when any SURVIVED or the catalog is stale.
 *
 * ── SAFETY, AND THE HOLE #184 FOUND IN IT ────────────────────────────────────────────────────
 *
 * This header used to say: "If it ever does die hard, `git diff` shows exactly one changed line
 * and `git checkout --` undoes it." That was FALSE for the artifact that actually runs, and the
 * falseness cost an audit a batch of measurements.
 *
 * Every package's `dist/` is gitignored. `dist` is what the CLI executes, what `examples/` runs,
 * what every `--import .../dist/preload.js` reproduction loads, and what `pnpm bench` imports. So
 * a `needsBuild` mutant compiles a DELETED SECURITY GATE into `dist`, and if this process dies
 * between the build and the restore, `git status` is clean, `git diff` is empty, and the tree
 * silently enforces nothing. A PoC then "proves" a bypass that does not exist — or, just as bad, a
 * fix "proves" a bypass is closed when it is not. That is #184.
 *
 * Three things close it. They are layered rather than redundant, because each one covers a way of
 * dying that the one above it cannot:
 *
 *   1. TEARDOWN REBUILDS. `teardown()` restores the sources AND re-runs `tsc` for every package it
 *      touched, then re-scans — from the `finally`, from an unexpected throw, and from an
 *      interrupt. Restoring sources without rebuilding was the specific hole. Read the comment
 *      above the signal handlers before trusting the word "interrupt": a fully synchronous script
 *      cannot service a JS signal handler, so what actually catches Ctrl-C is the `spawnSync`
 *      child reporting `signal: "SIGINT"`, in band, where this code can act on it.
 *
 *   2. IT STAMPS, and this is the layer that survives what layer 1 cannot — `kill -9`, a crash, a
 *      container torn out from under the process. `.capwall-mutation-guard.json` exists for
 *      exactly as long as this process holds a mutation and carries the ORIGINAL BYTES of every
 *      file it changed. It is removed only after restore + rebuild + a clean re-scan. Finding one
 *      at startup therefore means a run died or a rebuild failed, and this script refuses to
 *      start — as do `pnpm bench`, `pnpm canary` and `pnpm ci:local`. `--recover` puts the
 *      recorded bytes back, rebuilds, and clears it; that is the ONE command every refusal
 *      message points at.
 *
 *   3. EVERY MUTATION IS GREPPABLE, which is the layer that does not depend on this script having
 *      run at all — #184's mutation was written by something else. Each one carries
 *      `AUDIT MUTANT <id>` in a comment, which survives `tsc` into `dist`. See
 *      `scripts/mutation-sentinel.mjs` for who scans for it, and `pnpm canary` for the check that
 *      needs no marker of any kind.
 *
 * The stamp is also the interlock against the other way this bites: `mutation:gate` edits
 * `packages/core/src` IN PLACE while `ci:local` streams the working tree into its Docker context.
 * Two separate agents have corrupted runs that way. While this script is running, `ci:local`,
 * `bench`, `bench:startup` and `canary` refuse to start and say why.
 *
 * Nothing is committed by this script. `--list` touches no files.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import {
  clearStamp,
  preflight,
  readStamp,
  RECOVER_CMD,
  scanForSentinels,
  SENTINEL,
  sentinelComment,
  STAMP_NAME,
  writeStamp,
} from "./mutation-sentinel.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CATALOG = path.join(REPO_ROOT, "scripts", "mutants.json");

/**
 * The running major, for `minNodeMajor` (issue #156).
 *
 * A mechanism that only EXISTS on a newer Node cannot be mutated into a failure on an older one:
 * its claimed tests `skipIf` themselves away, so the mutant would report SURVIVED — a red gate
 * that says nothing about the tests. Reporting it as SKIPPED, by name and with the reason, is the
 * same rule AGENTS.md § 7 applies to tests: never a silent branch, always something the reporter
 * shows. It is counted out of the denominator and it never affects the exit code, so
 * `pnpm mutation:gate` on the floor is honest about what it did not run.
 */
const NODE_MAJOR = Number(process.versions.node.split(".")[0]);

/** Files this process has mutated and not yet restored: absolute path → original contents. */
const dirty = new Map();
/**
 * Packages whose `dist/` this run may have compiled a mutation into — or simply may have, because
 * a concurrent `pnpm build` is not something this process can rule out. Once a package appears
 * here it is rebuilt at teardown whether or not the mutant declared `needsBuild`: the cost is one
 * `tsc` at the end of a multi-minute run, and the thing it buys is that "the guard exited" and
 * "`dist` is the real capwall again" stop being two separate claims.
 */
const touchedPackages = new Set();
let tearingDown = false;
/**
 * Did THIS process write the stamp?
 *
 * The teardown must never clear a stamp it does not own. `--list` and `--recover` both reach the
 * same `finally`, and a `--list` that deleted a live run's stamp would hand the next `ci:local`
 * exactly the silent green this file exists to prevent.
 */
let ownStamp = false;
const RUN_STARTED_AT = new Date().toISOString();

/** Rewrite the stamp to say exactly what is held right now — `{}` when nothing is. */
function stamp(holding, files) {
  ownStamp = true;
  writeStamp({
    pid: process.pid,
    startedAt: RUN_STARTED_AT,
    node: process.version,
    argv: process.argv.slice(1),
    holding,
    files,
  });
}

const log = (s) => process.stderr.write(`[mutation-guard] ${s}\n`);

/** `packages/<name>` for a catalog `file`, which is what `tsc -p` needs. */
function packageDirFor(relFile) {
  const parts = relFile.split("/");
  return parts.length >= 2 && parts[0] === "packages" ? `${parts[0]}/${parts[1]}` : null;
}

function buildPackage(pkgDir) {
  try {
    execFileSync("npx", ["tsc", "-p", "tsconfig.json"], {
      cwd: path.join(REPO_ROOT, pkgDir),
      stdio: "pipe",
    });
  } catch (err) {
    assertNotInterrupted(err?.signal, `tsc in ${pkgDir}`);
    throw err;
  }
}

function restoreFiles() {
  let failures = 0;
  for (const [file, original] of dirty) {
    try {
      writeFileSync(file, original);
    } catch (err) {
      failures++;
      process.stderr.write(`[mutation-guard] FAILED to restore ${file}: ${String(err)}\n`);
    }
  }
  dirty.clear();
  return failures;
}

/**
 * Put the tree back the way it was found — sources AND artifacts — and only then drop the stamp.
 *
 * The order matters and the stamp is the point: if the rebuild throws, or the re-scan still finds
 * a sentinel, the stamp STAYS. A tree that could not be restored must keep refusing the next run
 * rather than quietly hand it a disarmed capwall, which is precisely what #184 describes.
 *
 * Synchronous throughout so it can run from a signal handler and from `process.exit()`'s path.
 */
function teardown({ quiet = false } = {}) {
  if (tearingDown || !ownStamp) return true;
  tearingDown = true;

  const hadWork = dirty.size > 0 || touchedPackages.size > 0;
  if (!hadWork) {
    clearStamp();
    return true;
  }

  if (!quiet) log("restoring sources and rebuilding dist — do not interrupt");
  const restoreFailures = restoreFiles();

  let buildFailures = 0;
  for (const pkgDir of touchedPackages) {
    try {
      buildPackage(pkgDir);
    } catch (err) {
      buildFailures++;
      process.stderr.write(
        `[mutation-guard] FAILED to rebuild ${pkgDir}: ${String(err?.message ?? err)}\n`,
      );
    }
  }

  const residue = scanForSentinels(["src", "dist"]);
  if (restoreFailures === 0 && buildFailures === 0 && residue.length === 0) {
    clearStamp();
    return true;
  }

  process.stderr.write(
    `\n[mutation-guard] TEARDOWN INCOMPLETE — this tree may still be DISARMED.\n` +
      (restoreFailures > 0 ? `  ${restoreFailures} source file(s) could not be restored\n` : "") +
      (buildFailures > 0 ? `  ${buildFailures} package(s) could not be rebuilt\n` : "") +
      residue.map((h) => `  ${SENTINEL} still in ${h.file}:${h.line}\n`).join("") +
      `\n  ./${STAMP_NAME} has been LEFT IN PLACE on purpose: bench, canary and ci:local will\n` +
      `  refuse to run until this is resolved. Fix the build error, then:\n\n` +
      `    ${RECOVER_CMD}\n\n`,
  );
  return false;
}

/** Thrown when the operator interrupted the run. Not a failure — a request to stop, cleanly. */
class Interrupted extends Error {}

/**
 * ── HOW AN INTERRUPT ACTUALLY REACHES THIS SCRIPT, WHICH IS NOT WHAT IT LOOKED LIKE ──────────
 *
 * `main()` is synchronous from end to end: `spawnSync` per mutant, `execFileSync` per build,
 * nothing that yields. Node dispatches signals on the EVENT LOOP, so while a mutation is applied
 * this process is never in a state where a `process.on("SIGINT", …)` callback can run. Measured,
 * not assumed: `kill -INT` on a synchronous loop of `spawnSync` calls runs the handler zero times
 * and the process exits 0 through its own `finally`. The handler below was therefore DECORATIVE
 * for the entire window it claimed to cover, which is a large part of why #184 was possible.
 *
 * What really happens on Ctrl-C is that the terminal signals the whole FOREGROUND PROCESS GROUP,
 * so the `vitest`/`tsc` child dies first — and `spawnSync` reports that as `signal: "SIGINT"`.
 * That is a synchronous, in-band interrupt notification, available at exactly the moment this
 * script can act on it, and {@link Interrupted} is how it is raised. It also fixes a correctness
 * bug hiding in the same place: a child killed by Ctrl-C exits non-zero, which the old code read
 * as "the tests failed", i.e. reported the mutant CAUGHT on the strength of the operator's
 * keystroke.
 *
 * The handlers stay registered because they are correct whenever the loop IS free (during the
 * catalog scan, during teardown's own re-scan), and because SIGTERM from a supervisor can arrive
 * there. But neither path can cover `SIGKILL`, a power cut, or a container being torn out from
 * under the process — and that is the honest argument for the stamp: it is the only part of this
 * design that survives the process not running any more code at all.
 */
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    log(`${sig} — restoring sources and rebuilding dist before exiting; do not kill -9`);
    const clean = teardown({ quiet: true });
    process.exit(clean ? 130 : 1);
  });
}

/** Did this child die because the operator interrupted the process group? */
function assertNotInterrupted(signal, what) {
  if (signal === "SIGINT" || signal === "SIGTERM") {
    throw new Interrupted(`${what} was killed by ${signal}`);
  }
}

function loadCatalog() {
  /** @type {{ mutants: Array<{id: string, mechanism: string, file: string, anchor: string, mutation: string, tests: string[], needsBuild?: boolean, note?: string}> }} */
  const parsed = JSON.parse(readFileSync(CATALOG, "utf8"));
  return parsed.mutants;
}

/** Run the claimed tests. Returns true when they FAILED, i.e. the mutant was caught. */
function testsFail(testFiles) {
  // One vitest invocation per package, from that package's directory, so its vitest.config.ts
  // applies (the `.cts` transform widening — see packages/core/vitest.config.ts).
  const byPackage = new Map();
  for (const rel of testFiles) {
    const pkgDir = rel.split("/").slice(0, 2).join("/"); // packages/<name>
    if (!byPackage.has(pkgDir)) byPackage.set(pkgDir, []);
    byPackage.get(pkgDir).push(path.relative(pkgDir, rel));
  }
  for (const [pkgDir, files] of byPackage) {
    // `--reporter=dot`, NOT `--silent`: vitest's CAC parser swallows the next positional after a
    // bare `--silent`, which turns every run into an argument error — i.e. exit 1, i.e. every
    // mutant reported CAUGHT. That false green is exactly the failure mode this script exists to
    // find, and it is why `baselinePasses` below is not optional.
    const r = spawnSync("npx", ["vitest", "run", "--reporter=dot", ...files], {
      cwd: path.join(REPO_ROOT, pkgDir),
      stdio: "pipe",
      encoding: "utf8",
    });
    // BEFORE reading the status: a Ctrl-C that killed vitest also produced a non-zero exit, and
    // scoring that as "the mutant was caught" would turn an interrupted run into a false green.
    assertNotInterrupted(r.signal, `vitest in ${pkgDir}`);
    if (r.status !== 0) return true;
  }
  return false;
}

/**
 * `--recover`: undo whatever an interrupted run left behind, using the bytes it recorded.
 *
 * NOT `git checkout -- packages`, which is the advice this replaces. That would also throw away
 * the operator's own in-progress edits — and an operator who has just been told their tree is
 * disarmed is exactly the person who should not be handed a destructive command. The stamp holds
 * the original AND the mutated text of each file, so this can tell "still mutated" (restore) from
 * "already restored" (leave it) from "edited since" (refuse to touch it, and say so).
 *
 * The rebuild is unconditional: `dist` is the artifact whose state cannot be inferred from `git`,
 * so the only honest way to know it is clean is to make it.
 */
function recover() {
  const held = readStamp();
  const entries = Object.entries(held?.files ?? {});

  if (held === null) {
    log(`no ./${STAMP_NAME} — nothing was recorded as held.`);
  } else {
    log(`./${STAMP_NAME}: pid ${held.pid}, started ${held.startedAt}`);
  }

  const conflicts = [];
  for (const [rel, record] of entries) {
    const abs = path.join(REPO_ROOT, rel);
    let current;
    try {
      current = readFileSync(abs, "utf8");
    } catch (err) {
      conflicts.push(`${rel}: unreadable (${String(err?.message ?? err)})`);
      continue;
    }
    if (current === record.original) {
      log(`already restored: ${rel}`);
    } else if (current === record.mutated) {
      writeFileSync(abs, record.original);
      log(`restored: ${rel}`);
    } else {
      conflicts.push(
        `${rel}: has been edited since the guard mutated it — NOT overwritten. Compare it with ` +
          `the "original" field in ./${STAMP_NAME} and fix it by hand.`,
      );
    }
  }

  // Always rebuild everything, even with an empty stamp: the reason to be running this command is
  // that dist is under suspicion, and a partial rebuild would leave the suspicion in place.
  log("rebuilding all packages");
  try {
    execFileSync("pnpm", ["build"], { cwd: REPO_ROOT, stdio: "pipe" });
  } catch (err) {
    process.stderr.write(
      `\n[mutation-guard] RECOVERY FAILED — \`pnpm build\` did not succeed:\n${String(err?.stdout ?? "")}${String(err?.message ?? err)}\n\n` +
        `  ./${STAMP_NAME} kept. Fix the build, then re-run \`${RECOVER_CMD}\`.\n\n`,
    );
    return 1;
  }

  const residue = scanForSentinels(["src", "dist"]);
  if (conflicts.length > 0 || residue.length > 0) {
    process.stderr.write(
      `\n[mutation-guard] RECOVERY INCOMPLETE — this tree is still DISARMED.\n` +
        conflicts.map((c) => `  ${c}\n`).join("") +
        residue.map((h) => `  ${SENTINEL} still in ${h.file}:${h.line}\n    ${h.text}\n`).join("") +
        `\n  ./${STAMP_NAME} kept, so bench/canary/ci:local keep refusing. Remove the marked\n` +
        `  lines (or \`git checkout --\` the files, if you have no other edits in them), then\n` +
        `  re-run \`${RECOVER_CMD}\`.\n\n`,
    );
    return 1;
  }

  clearStamp();
  log(
    entries.length > 0
      ? `recovered ${entries.length} file(s), rebuilt, no sentinels remain. Stamp cleared.`
      : "nothing to restore; rebuilt, no sentinels remain. Stamp cleared.",
  );
  return 0;
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes("--recover")) return recover();

  const only = new Set();
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--only") only.add(argv[++i]);
  }
  const mutants = loadCatalog().filter((m) => only.size === 0 || only.has(m.id));

  if (argv.includes("--list")) {
    for (const m of mutants) process.stdout.write(`${m.id}\n    ${m.mechanism}\n    ${m.file}\n`);
    return 0;
  }
  if (mutants.length === 0) {
    process.stderr.write("[mutation-guard] no mutants selected\n");
    return 1;
  }

  // Refuse to mutate a tree that is already mutated. Running two of these at once, or on top of a
  // dead run's residue, means every result afterwards is measuring an unknown mixture — and the
  // second run's restore would write the FIRST run's mutation back as if it were pristine.
  const armed = preflight({ kinds: ["src", "dist"], label: "pnpm mutation:gate" });
  if (!armed.ok) {
    process.stderr.write(`\n${armed.message}\n`);
    return 1;
  }

  stamp(null, {});

  const survivors = [];
  const stale = [];
  const baselineRed = [];
  const skipped = [];
  let caught = 0;

  /**
   * Claimed-test-set → does it pass with NO mutation applied?
   *
   * Without this control the whole run is meaningless: a mutant would be reported CAUGHT by any
   * pre-existing red test, or by vitest failing to start at all. "The tests fail with the
   * mutation" only means something once "the tests pass without it" is established.
   */
  const baseline = new Map();
  const baselinePasses = (tests) => {
    const key = tests.join(" ");
    if (!baseline.has(key)) baseline.set(key, !testsFail(tests));
    return baseline.get(key);
  };

  for (const m of mutants) {
    if (typeof m.minNodeMajor === "number" && NODE_MAJOR < m.minNodeMajor) {
      skipped.push(`${m.id}: needs Node >=${m.minNodeMajor}, running ${process.version}`);
      process.stdout.write(`SKIPPED   ${m.id}  (needs Node >=${m.minNodeMajor})\n`);
      continue;
    }
    const file = path.join(REPO_ROOT, m.file);
    const original = readFileSync(file, "utf8");
    const occurrences = original.split(m.anchor).length - 1;
    if (occurrences !== 1) {
      // The catalog no longer describes the code. Loud, not silent: a mutant whose anchor moved
      // would otherwise be a no-op edit that "catches" nothing and reports green forever.
      stale.push(`${m.id}: anchor occurs ${occurrences}x in ${m.file} (expected exactly 1)`);
      process.stdout.write(`STALE     ${m.id}\n`);
      continue;
    }

    if (!baselinePasses(m.tests)) {
      baselineRed.push(`${m.id}: ${m.tests.join(", ")} do not pass unmutated`);
      process.stdout.write(`BASELINE-RED  ${m.id}\n`);
      continue;
    }

    // The sentinel rides along with every mutation, in a BLOCK comment so it is safe after an
    // anchor that ends mid-expression, and it reaches dist/ because `removeComments` is off.
    // It is what makes a mutated artifact greppable rather than invisible (#184).
    const mutated = original.replace(m.anchor, `${m.mutation} ${sentinelComment(m.id)}`);
    const pkgDir = packageDirFor(m.file);

    const started = Date.now();
    let failed;
    dirty.set(file, original);
    if (pkgDir !== null) touchedPackages.add(pkgDir);
    stamp({ id: m.id, file: m.file, needsBuild: m.needsBuild === true }, {
      [m.file]: { original, mutated },
    });
    try {
      writeFileSync(file, mutated);
      if (m.needsBuild === true && pkgDir !== null) buildPackage(pkgDir);
      failed = testsFail(m.tests);
    } finally {
      writeFileSync(file, original);
      dirty.delete(file);
      if (m.needsBuild === true && pkgDir !== null) buildPackage(pkgDir);
      stamp(null, {});
    }

    const secs = ((Date.now() - started) / 1000).toFixed(1);
    if (failed) {
      caught++;
      process.stdout.write(`CAUGHT    ${m.id}  (${secs}s)\n`);
    } else {
      survivors.push(m);
      process.stdout.write(`SURVIVED  ${m.id}  (${secs}s)\n`);
    }
  }

  const ran = mutants.length - stale.length - baselineRed.length - skipped.length;
  process.stdout.write(`\n${caught}/${ran} caught\n`);
  for (const s of skipped) process.stdout.write(`SKIPPED — ${s}\n`);
  for (const s of stale) process.stdout.write(`\nSTALE CATALOG ENTRY — ${s}\n`);
  for (const b of baselineRed) process.stdout.write(`\nBASELINE RED — ${b}\n`);
  for (const m of survivors) {
    process.stdout.write(
      `\nSURVIVED — ${m.id}\n` +
        `  mechanism: ${m.mechanism}\n` +
        `  removed from: ${m.file}\n` +
        `  and these still passed: ${m.tests.join(", ")}\n` +
        `  ⇒ that mechanism has no discriminating assertion in its claimed coverage.\n`,
    );
  }
  return survivors.length > 0 || stale.length > 0 || baselineRed.length > 0 ? 1 : 0;
}

let code = 1;
try {
  code = main();
} catch (err) {
  // An interrupt is not a result. Whatever verdicts were printed before it stand; nothing is
  // inferred about the mutant that was in flight, because its tests were killed rather than run.
  if (!(err instanceof Interrupted)) throw err;
  process.stdout.write(`\nINTERRUPTED — ${err.message}. No verdict for the mutant in flight.\n`);
  code = 130;
} finally {
  if (!teardown()) code = 1;
}
process.exit(code);
