#!/usr/bin/env node
/**
 * THE CANARY — "is the capwall in `dist/` still armed?" asked before anything trusts it (#184).
 *
 * WHY THIS EXISTS. #184 is an audit whose measurements were invalidated because
 * `packages/core/dist/loader/module-read.js` was carrying a deleted gate while `git status` was
 * clean. The reviewers' recovery, both times, was the same instinct: before believing any number,
 * run one operation you KNOW must be denied and one you KNOW must be allowed, and throw the batch
 * away if either answer is wrong. That instinct is correct and it should not have to be
 * re-invented per audit, so it lives here.
 *
 * IT RUNS AGAINST THE ARTIFACT, NOT THE SOURCE. A child process, launched with
 * `--import packages/core/dist/preload.js` — the exact path the CLI, `examples/`, and every manual
 * reproduction take. Checking `src` would be checking the thing `git status` already covers; `dist`
 * is the gitignored one that can lie.
 *
 * WHAT IT PROVES, AND WHAT IT DOES NOT. It proves that enforcement is switched on end to end: the
 * preload installs, attribution resolves two sibling packages to two different principals, one
 * gets its grant and one gets denied, on two different capability families. It is a smoke test for
 * "armed vs disarmed", not a substitute for `pnpm test` (which asserts the semantics) or
 * `pnpm mutation:gate` (which asserts the tests would notice). A canary is worth having precisely
 * because it is cheap enough to run before every measurement.
 *
 * IT REFUSES TO SPEAK UNLESS SPOKEN TO. Silent output on success beyond one PASS line; on failure
 * it prints every check, what was expected, what happened, and what to do — because a canary that
 * fails is a claim that something else you just measured was wrong.
 *
 * USAGE
 *   pnpm canary              # or: node scripts/canary.mjs
 *   node scripts/canary.mjs --json
 * Exit 0 when armed, 1 when not.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { preflightOrExit, REPO_ROOT } from "./mutation-sentinel.mjs";

const JSON_OUT = process.argv.includes("--json");
const SCRIPTS = path.dirname(fileURLToPath(import.meta.url));
const PRELOAD = path.join(REPO_ROOT, "packages", "core", "dist", "preload.js");
const TARGET = path.join(SCRIPTS, "canary-target.cjs");
const FIXTURES = path.join(SCRIPTS, "bench", "fixtures", "node_modules");
const DATA_PATH = path.join(FIXTURES, "bench-dep", "data.txt");

function die(msg) {
  process.stderr.write(`\nerror: ${msg}\n`);
  process.exit(1);
}

// The sentinel/stamp preflight comes FIRST. If a mutation is sitting in dist, the canary would
// dutifully report DISARMED — true, but far less useful than naming the file and the line.
preflightOrExit({ kinds: ["src", "dist"], label: "pnpm canary" });

if (!existsSync(PRELOAD)) {
  die(`${path.relative(REPO_ROOT, PRELOAD)} not found — run \`pnpm build\` first.`);
}

/**
 * `bench-dep` may read exactly one file; `bench-dep-denied` is absent, so deny-by-default is the
 * whole of its policy. Two sibling packages under the same `node_modules` is the smallest shape
 * that can distinguish "capwall is enforcing" from "capwall allowed/denied everything".
 */
const policy = {
  version: 1,
  mode: "enforce",
  packages: {
    "bench-dep": { fs: { read: [DATA_PATH], write: [] } },
  },
};

const tmp = mkdtempSync(path.join(os.tmpdir(), "capwall-canary-"));
let child;
try {
  const policyFile = path.join(tmp, "capabilities.json");
  writeFileSync(policyFile, `${JSON.stringify(policy, null, 2)}\n`);
  child = spawnSync(process.execPath, ["--import", pathToFileURL(PRELOAD).href, TARGET], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: {
      ...process.env,
      // Do not inherit an outer capwall install: a second preload in NODE_OPTIONS would make
      // "which capwall answered" ambiguous, which is the one thing a canary cannot afford.
      NODE_OPTIONS: "",
      CAPWALL_MODE: "enforce",
      CAPWALL_POLICY_FILE: policyFile,
      CAPWALL_PROJECT_ROOT: REPO_ROOT,
    },
  });
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

if (child.error) die(`could not launch the canary target: ${child.error.message}`);
const line = (child.stdout ?? "").split("\n").find((l) => l.startsWith("CANARY-JSON "));
if (line === undefined) {
  die(
    `the canary target produced no result (exit ${child.status}).\n` +
      `--- stdout ---\n${child.stdout}\n--- stderr ---\n${child.stderr}`,
  );
}

/** @type {{installed: boolean, allowedRead: object, deniedRead: object, deniedSpawn: object|null}} */
const seen = JSON.parse(line.slice("CANARY-JSON ".length));

const CHECKS = [];
function check(name, ok, expected, actual) {
  CHECKS.push({ name, ok, expected, actual });
}

const denialLooksRight = (r) => r?.threw === true && r?.name === "CapabilityError";

check(
  "the preload installed in the child",
  seen.installed === true && child.status === 0,
  "the target loaded its fixtures and exited 0",
  `installed=${seen.installed} exit=${child.status}`,
);
check(
  "GRANTED: bench-dep may read the file its policy names",
  seen.allowedRead?.threw === false && seen.allowedRead?.value === true,
  "the read returns the file's contents",
  seen.allowedRead?.threw === true
    ? `threw ${seen.allowedRead.name}: ${seen.allowedRead.message}`
    : `value=${seen.allowedRead?.value}`,
);
check(
  "DENIED: bench-dep-denied may not read that same file",
  denialLooksRight(seen.deniedRead),
  "CapabilityError",
  seen.deniedRead?.threw === true ? String(seen.deniedRead.name) : "the read SUCCEEDED",
);
if (seen.deniedSpawn !== null) {
  check(
    "DENIED: bench-dep-denied may not spawn a process",
    denialLooksRight(seen.deniedSpawn),
    "CapabilityError",
    seen.deniedSpawn?.threw === true ? String(seen.deniedSpawn.name) : "the spawn SUCCEEDED",
  );
}

const pass = CHECKS.every((c) => c.ok);

if (JSON_OUT) {
  process.stdout.write(`${JSON.stringify({ pass, checks: CHECKS }, null, 2)}\n`);
} else if (pass) {
  process.stdout.write(
    `canary PASS — ${CHECKS.length}/${CHECKS.length} enforcement checks against ` +
      `${path.relative(REPO_ROOT, PRELOAD)} (node ${process.version})\n`,
  );
} else {
  process.stderr.write(
    `\ncanary FAIL — capwall in ${path.relative(REPO_ROOT, PRELOAD)} is NOT enforcing as declared.\n\n`,
  );
  for (const c of CHECKS) {
    process.stderr.write(
      `  ${c.ok ? "ok  " : "FAIL"} ${c.name}\n` +
        (c.ok ? "" : `         expected: ${c.expected}\n         actual:   ${c.actual}\n`),
    );
  }
  process.stderr.write(
    "\nDO NOT TRUST ANY MEASUREMENT TAKEN AGAINST THIS TREE — a bypass PoC that 'works' here may\n" +
      "only be working because the gate is gone, and a fix that 'holds' here may not hold at all.\n" +
      "This is #184. Rebuild from a known-good source and re-run:\n\n" +
      "  pnpm mutation:recover   # if a mutation-guard run left a stamp\n" +
      "  git status && git diff -- packages/*/src\n" +
      "  pnpm build && pnpm canary\n\n" +
      `--- child stderr ---\n${child.stderr}`,
  );
}

process.exit(pass ? 0 : 1);
