// The target application for `scripts/bench/startup.mjs`, and the harness's clock.
//
// THE FIRST STATEMENT IS THE MEASUREMENT. `performance.now()` is milliseconds since this
// process's own timeOrigin and `process.cpuUsage()` is its own user+system CPU, so reading both
// on line one of the entry point prices exactly one thing: everything Node and capwall did to
// get here — bootstrap, the `--import` preload, `install()`, and (on a mediated child) the ESM
// loader thread, which the CPU figure picks up and the wall figure does not.
//
// Reading the clock INSIDE the child is what keeps the number usable on a contended machine.
// The parent's `spawnSync` wall time folds in fork/exec, parent scheduling and teardown, which
// on a loaded box are hundreds of milliseconds of variance sitting on top of a ~200 ms signal.
// The harness records that figure too, and prints it under `--verbose`, so the difference is
// visible rather than argued about.
//
// Everything after the stamp is the PREMISE CHECK, not the measurement: one `require` of a
// granted-NOTHING fixture dependency and one `fs` read that capwall must deny and must charge
// to `bench-dep-denied`. A target that did nothing at all would let a preload which silently
// failed to install be timed as "bare node twice" and reported as a spectacular win.
"use strict";
const c = process.cpuUsage();
process.stdout.write(
  `STAMP wall=${performance.now().toFixed(3)} cpu=${((c.user + c.system) / 1000).toFixed(3)}\n`,
);

const dep = require("bench-dep-denied");
const r = dep.readDenied();
process.stdout.write(`PROBE threw=${r.threw} name=${r.name ?? ""}\n`);
