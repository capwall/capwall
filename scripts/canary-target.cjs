/**
 * CANARY TARGET — the child process `scripts/canary.mjs` launches under capwall's real preload.
 *
 * It is CJS on purpose. This is the shape a mediated program actually has: application code that
 * `require`s dependencies out of `node_modules`, one of which is granted a capability and one of
 * which is granted nothing. Everything interesting happens inside those packages' own frames,
 * because attribution charges the NEAREST frame — a read issued from this file would be charged to
 * `<app>` and would prove nothing about per-package enforcement.
 *
 * It prints one machine-readable line and exits 0 REGARDLESS of what capwall did. Deciding whether
 * the answers are right is `scripts/canary.mjs`'s job; a target that exited non-zero on a denial
 * would make "capwall denied correctly" and "the child crashed for an unrelated reason" the same
 * observation, which is the ambiguity this whole exercise is about.
 */
"use strict";
const path = require("node:path");

const FIXTURES = path.join(__dirname, "bench", "fixtures", "node_modules");
const allowed = require(path.join(FIXTURES, "bench-dep"));
const denied = require(path.join(FIXTURES, "bench-dep-denied"));

const SPAWN_CMD = process.platform === "win32" ? null : "/bin/true";

/** Run `fn`, and report what happened in the shape the runner asserts against. */
function attempt(fn) {
  try {
    return { threw: false, value: fn() };
  } catch (err) {
    // Match on `name`, not `instanceof`: the error crosses the CJS/ESM realm boundary between
    // this file and capwall's own module graph (see packages/core/src/errors.ts).
    return { threw: true, name: err && err.name, message: err && err.message };
  }
}

const result = {
  installed: typeof allowed.readSync === "function",
  platform: process.platform,
  /** GRANTED: `bench-dep` holds `fs.read` on exactly this file. A throw here means over-blocking. */
  allowedRead: attempt(() => allowed.readSync().trim().length > 0),
  /** GRANTED NOTHING: `bench-dep-denied` is absent from the policy. A pass here means DISARMED. */
  deniedRead: denied.readDenied(),
  /** GRANTED NOTHING, second capability family — one disarmed shim should not hide behind another. */
  deniedSpawn: SPAWN_CMD === null ? null : denied.spawnDenied(SPAWN_CMD, []),
};

process.stdout.write(`CANARY-JSON ${JSON.stringify(result)}\n`);
