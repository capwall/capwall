/**
 * THE REAL `node:fs`, captured NARROWLY for the modules Node's ESM loader thread evaluates.
 *
 * Every word of `../real-builtins.cts`'s reasoning applies here unchanged — this is the same
 * capture mechanism (a CommonJS `require`, so the ESM module cache stays untouched and the `load`
 * hook's re-mediation backstop stays reachable), in the same shape, subject to the same source
 * scan. What follows is only WHY there is a second file at all.
 *
 * ── WHY NARROW (issue #150) ─────────────────────────────────────────────────────────────────
 * `attribution/index.ts` needs `realFs` and nothing else, and it is one of the ~10 modules Node's
 * ESM LOADER THREAD evaluates: `loader/esm-hooks.ts` → `loader/module-read.ts` → here. That thread
 * is a separate realm with its own module registry, and `module.register()` BLOCKS the main thread
 * while it resolves, compiles and evaluates that graph — so everything on it is paid for serially,
 * at startup, on every mediated process.
 *
 * Importing the twelve-wide aggregate there made the loader thread `require` `node:http2`,
 * `node:dgram`, `node:tls`, `node:vm`, `node:child_process` and the rest to reach one of them.
 * Measured on Node 22: ~14 ms of a ~93 ms `registerEsmHook()`, for modules that realm never uses.
 *
 * ── WHAT THIS DOES **NOT** CHANGE, AND WHY THAT IS THE POINT ─────────────────────────────────
 * The MAIN thread is byte-for-byte unaffected. `../real-builtins.cts` still `require`s all twelve,
 * still eagerly, still from `index.js`'s static import graph (`index` → `loader/require` → there),
 * so the mediated set still comes out of the CJS cache WHOLE before `install()` can patch
 * `Module._load`. This file does not defer, weaken or reorder that: `require("node:fs")` here and
 * `require("node:fs")` there hit the same CJS cache entry and yield the SAME OBJECT, which
 * `test/real-builtins.test.ts` asserts by identity rather than by argument.
 *
 * ── THE NO-RECURSION ARGUMENT, RESTATED FOR THIS FILE ───────────────────────────────────────
 * A capture that ran AFTER `install()` patched `Module._load` would capture a shim, not a builtin.
 * That cannot happen here, for the same structural reason and on both realms:
 *
 *   - MAIN THREAD: this file sits in `index.js`'s static import graph (index → loader/live-context
 *     → shims/index → shims/fs → ../real-builtins.cjs is the aggregate's route; THIS file's route
 *     is index → loader/require → ../shims/runtime → ../attribution/index → here). ES module
 *     evaluation completes the whole graph before the entry module's body runs, let alone before
 *     any caller can reach `install()`.
 *   - LOADER THREAD: capwall never installs there. `Module._load` on that thread is pristine for
 *     the life of the process, because nothing on it calls `install()` and a patch on one thread
 *     is invisible to another.
 *
 * ── ADDING ONE ──────────────────────────────────────────────────────────────────────────────
 * Add a narrow file only for a builtin some loader-thread module needs. The scan in
 * `test/real-builtins.test.ts` requires every `require` under `src/real-builtins/` to also appear
 * in the aggregate, so a narrow capture can never introduce a builtin the whole set does not
 * already cover.
 */

export const realFs: typeof import("node:fs") = require("node:fs");
