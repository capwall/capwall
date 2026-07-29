#!/usr/bin/env node
/**
 * MUTATION SENTINEL + RUN STAMP — "is the capwall in this tree still armed?" (issue #184)
 *
 * WHY THIS EXISTS. `scripts/mutation-guard.mjs` deletes a security mechanism, runs the tests that
 * claim to cover it, and puts it back. Its stated safety net was "`git diff` shows exactly one
 * changed line" — and that sentence is false for the artifact that actually runs. Every package's
 * `dist` is gitignored, so a mutated `dist/loader/module-read.js` is invisible to `git status`, invisible
 * to `git diff`, and is nonetheless what the CLI, `examples/`, every manual reproduction and every
 * `--import dist/preload.js` run execute. #184 is that exact hole being hit: a disarmed enforcement
 * gate, a clean-looking tree, and a batch of audit measurements that had to be thrown away because
 * a PoC "proved" a bypass that was not there.
 *
 * A silently-disarmed gate is the worst failure this tooling can have, because it is wrong in both
 * directions — it makes a bypass look real, and it makes a fix look effective. So there are two
 * independent traces, and either one alone is enough to catch it:
 *
 *   1. THE SENTINEL. Every mutation the guard writes carries {@link SENTINEL} in a comment, and it
 *      survives `tsc` into `dist` (`removeComments` is off). Anything that is about to trust this
 *      tree — `pnpm bench`, `pnpm ci:local`, `pnpm canary`, the guard itself — greps for it first
 *      and refuses to produce numbers if it is there. This is the convention two separate
 *      adversarial reviewers adopted ad hoc after being burned; it is built in so it stops being
 *      re-invented per audit.
 *
 *   2. THE STAMP. The guard writes {@link STAMP_PATH} for the whole time it holds a mutation, and
 *      removes it only after sources are restored AND `dist` is rebuilt AND the rebuild scans
 *      clean. A stamp that is still there means one of three things, and the message says which:
 *      a run is live right now (do not race it), a run died (recover), or a rebuild failed
 *      (recover). It carries the original bytes of every file it mutated, so recovery is exact
 *      rather than a `git checkout` that would also discard the operator's own edits.
 *
 * The stamp is also the interlock. `mutation:gate` edits `packages/core/src` IN PLACE while
 * `ci:local` streams the working tree into its Docker context and `bench` imports `dist` — running
 * them together has now corrupted runs for two separate agents. That rule used to live in prose;
 * the stamp is what enforces it.
 *
 * ZERO DEPENDENCIES, and deliberately no `dist` content HASH. A recorded digest of `dist` sounds
 * stronger and is in practice a flake generator: `dist` legitimately changes on every build, every
 * TypeScript bump, every source edit, so a hash mismatch cannot distinguish "someone rebuilt" from
 * "someone disarmed a gate". #149 priced what a gate that cries wolf costs — people stop running
 * it, and then it protects nothing. The sentinel has no such false-positive mode.
 *
 * USAGE (module)
 *   import { preflight, scanForSentinels, readStamp } from "./mutation-sentinel.mjs";
 *
 * USAGE (CLI — this is what `scripts/ci-local.sh` calls)
 *   node scripts/mutation-sentinel.mjs --scan src,dist --label "pnpm ci:local"
 *   node scripts/mutation-sentinel.mjs --status        # print what the stamp says, exit 0
 * Exit 0 when the tree is armed, 1 when it is not — with the recovery command in the message.
 */
import { existsSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The fixed marker every mutation carries.
 *
 * `AUDIT MUTANT` is not a fresh invention: it is the string the ESM adversarial reviewer found in
 * `dist` in #184, and the one the reviewers' ad-hoc `grep` aborts were already keyed on. Keeping
 * the same spelling means the tooling catches mutations written by hand during an audit, not only
 * the ones this repo's guard writes. `MUTATION-GUARD` is scanned as well because the issue names
 * both spellings and an audit that picks the other one should still be caught.
 */
export const SENTINEL = "AUDIT MUTANT";
export const SENTINELS = Object.freeze([SENTINEL, "MUTATION-GUARD"]);

/** Where the guard records that it is holding a mutation. Gitignored — see `.gitignore`. */
export const STAMP_PATH = path.join(REPO_ROOT, ".capwall-mutation-guard.json");
export const STAMP_NAME = path.basename(STAMP_PATH);

/** The one command that undoes every state this module refuses to start on. */
export const RECOVER_CMD = "pnpm mutation:recover";

/**
 * The comment appended to every mutation. A BLOCK comment, not `//`: an anchor can end mid-line
 * (`this !== auth.socket ||` is one of them), and a line comment there would swallow the rest of
 * the expression and turn a mutant into a syntax error — which the guard would then report as
 * CAUGHT, i.e. a false green in the one script whose entire job is finding false greens.
 */
export function sentinelComment(id) {
  return `/* ${SENTINEL} ${id} — scripts/mutation-guard.mjs is mid-run; recover with "${RECOVER_CMD}" */`;
}

// ── scanning ──────────────────────────────────────────────────────────────────────────────

/** Files big enough that they are not hand-written source; `.map`s stay in scope on purpose. */
const MAX_SCAN_BYTES = 8 * 1024 * 1024;

function* walk(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      yield* walk(full);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

/**
 * Every `packages/<pkg>/<kind>` that exists, for `kind` in `kinds`.
 *
 * Scoped to `packages/` rather than the whole repo for one reason: this file, the guard, and the
 * catalog all legitimately contain the sentinel string, and a scanner that flagged its own source
 * would be exactly the noisy gate #149 says not to build. `src` and `dist` are the two places the
 * string can only mean "a mechanism has been deleted".
 */
export function scanRoots(kinds) {
  const roots = [];
  const packagesDir = path.join(REPO_ROOT, "packages");
  if (!existsSync(packagesDir)) return roots;
  for (const pkg of readdirSync(packagesDir).sort()) {
    for (const kind of kinds) {
      const root = path.join(packagesDir, pkg, kind);
      if (existsSync(root)) roots.push(root);
    }
  }
  return roots;
}

/**
 * Every occurrence of a sentinel under `packages/*\/{kinds}`.
 *
 * @returns {Array<{file: string, line: number, text: string, sentinel: string}>} `file` relative
 *   to the repo root, `line` 1-based, `text` trimmed and clipped to something printable.
 */
export function scanForSentinels(kinds = ["src", "dist"]) {
  const hits = [];
  for (const root of scanRoots(kinds)) {
    for (const file of walk(root)) {
      let size;
      try {
        size = statSync(file).size;
      } catch {
        continue;
      }
      if (size > MAX_SCAN_BYTES) continue;
      let text;
      try {
        text = readFileSync(file, "utf8");
      } catch {
        continue;
      }
      const found = SENTINELS.find((s) => text.includes(s));
      if (found === undefined) continue;
      const lines = text.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const sentinel = SENTINELS.find((s) => line.includes(s));
        if (sentinel === undefined) continue;
        hits.push({
          file: path.relative(REPO_ROOT, file),
          line: i + 1,
          text: line.trim().slice(0, 160),
          sentinel,
        });
      }
    }
  }
  return hits;
}

// ── the stamp ─────────────────────────────────────────────────────────────────────────────

/** @returns {null | {pid: number, startedAt: string, argv: string[], holding: object|null, files: Record<string, {original: string, mutated: string}>}} */
export function readStamp() {
  try {
    const parsed = JSON.parse(readFileSync(STAMP_PATH, "utf8"));
    return typeof parsed === "object" && parsed !== null ? parsed : null;
  } catch {
    return null;
  }
}

export function writeStamp(stamp) {
  writeFileSync(STAMP_PATH, `${JSON.stringify(stamp, null, 2)}\n`);
}

export function clearStamp() {
  rmSync(STAMP_PATH, { force: true });
}

/**
 * Is `pid` a live process?
 *
 * `EPERM` counts as alive: the pid exists, this user just cannot signal it. Guessing "dead" there
 * would tell an operator to recover a run that is actively mutating files underneath them.
 */
export function pidAlive(pid) {
  if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code === "EPERM";
  }
}

function describeHolding(stamp) {
  const ids = Object.keys(stamp.files ?? {});
  const held = stamp.holding?.id;
  const parts = [`pid ${stamp.pid}`, `started ${stamp.startedAt}`];
  if (held !== undefined) parts.push(`mutant "${held}"`);
  if (ids.length > 0) parts.push(`${ids.length} file(s) held: ${ids.join(", ")}`);
  return parts.join(", ");
}

// ── the preflight every consumer runs ─────────────────────────────────────────────────────

function indent(lines) {
  return lines.map((l) => `  ${l}`).join("\n");
}

/**
 * Refuse to proceed if this tree is, or might be, carrying a mutation.
 *
 * Silent when correct — it returns `{ok: true}` and prints nothing, because a gate that narrates
 * its successes is a gate people learn to scroll past. Loud and specific when not: every failure
 * message names what was found, why it invalidates whatever you were about to run, and the exact
 * command that fixes it.
 *
 * @param {{kinds?: string[], label?: string}} [options]
 * @returns {{ok: true} | {ok: false, message: string}}
 */
export function preflight({ kinds = ["src", "dist"], label = "this command" } = {}) {
  const stamp = readStamp();
  if (stamp !== null) {
    if (pidAlive(stamp.pid) && stamp.pid !== process.pid) {
      return {
        ok: false,
        message:
          `error: \`pnpm mutation:gate\` is running RIGHT NOW (${describeHolding(stamp)}).\n\n` +
          indent([
            "It deletes a security mechanism from packages/core/src in place for the duration of",
            "each mutant. Anything that reads this tree while it does — `pnpm ci:local` streams the",
            "working tree into its Docker context, `pnpm bench` imports packages/core/dist — would",
            `measure a deliberately disarmed capwall. That is why ${label} is stopping here.`,
            "",
            "Wait for it to finish. Interrupting it is safe: it restores the sources and rebuilds",
            "dist on SIGINT/SIGTERM before exiting.",
          ]) +
          "\n",
      };
    }
    return {
      ok: false,
      message:
        `error: a previous \`pnpm mutation:gate\` run did not tear down (./${STAMP_NAME}).\n\n` +
        indent([
          describeHolding(stamp),
          "",
          "That process is gone, so it never restored its sources and never rebuilt dist. Both",
          "packages/core/src and packages/core/dist may still have a security mechanism deleted —",
          "and because dist/ is gitignored, `git status` will look clean either way. This is the",
          `#184 failure mode exactly, so ${label} will not run against it.`,
          "",
          "Recover (restores the exact original bytes the guard recorded, rebuilds, re-checks):",
          `  ${RECOVER_CMD}`,
        ]) +
        "\n",
    };
  }

  const hits = scanForSentinels(kinds);
  if (hits.length > 0) {
    const shown = hits.slice(0, 10);
    const more = hits.length - shown.length;
    return {
      ok: false,
      message:
        `error: capwall's mutation sentinel is present in ${hits.length} place(s) — this tree is DISARMED.\n\n` +
        indent([
          ...shown.map((h) => `${h.file}:${h.line}\n    ${h.text}`),
          ...(more > 0 ? [`… and ${more} more`] : []),
          "",
          `An "${SENTINEL}" marker means a security mechanism has been deleted on purpose — by`,
          "`pnpm mutation:gate`, or by hand during an audit. Nothing measured against this tree is",
          "trustworthy until it is gone: a denial that does not fire proves nothing about a bypass,",
          `and neither does one that does. ${label} is refusing to produce numbers.`,
          "",
          "Recover:",
          `  ${RECOVER_CMD}          # if the guard left a stamp, this restores exactly what it took`,
          "  git checkout -- packages && pnpm build   # otherwise: the mutation came from elsewhere",
        ]) +
        "\n",
    };
  }

  return { ok: true };
}

/** `preflight`, but it prints and exits instead of returning. Used by every CLI consumer. */
export function preflightOrExit(options) {
  const result = preflight(options);
  if (result.ok) return;
  process.stderr.write(`\n${result.message}\n`);
  process.exit(1);
}

// ── CLI ───────────────────────────────────────────────────────────────────────────────────

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  const valueOf = (flag, fallback) => {
    const i = argv.indexOf(flag);
    return i === -1 ? fallback : (argv[i + 1] ?? fallback);
  };

  if (argv.includes("--status")) {
    const stamp = readStamp();
    process.stdout.write(
      stamp === null
        ? `no ${STAMP_NAME} — no mutation-guard run is holding this tree\n`
        : `${STAMP_NAME}: ${describeHolding(stamp)} (${pidAlive(stamp.pid) ? "ALIVE" : "DEAD — recover with " + RECOVER_CMD})\n`,
    );
    const hits = scanForSentinels(["src", "dist"]);
    process.stdout.write(
      hits.length === 0
        ? "no sentinels in packages/*/src or packages/*/dist\n"
        : hits.map((h) => `SENTINEL ${h.file}:${h.line}  ${h.text}\n`).join(""),
    );
    process.exit(0);
  }

  preflightOrExit({
    kinds: valueOf("--scan", "src,dist")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    label: valueOf("--label", "this command"),
  });
}
