/**
 * THE REAL `node:worker_threads`, captured NARROWLY. See `./fs.cts` for the full reasoning — this
 * file is the second instance of exactly that shape, for exactly that reason (#150).
 *
 * WHO NEEDS IT, and why both consumers are on this file rather than the aggregate:
 *
 *  - `loader/esm-hooks.ts` (LOADER THREAD) uses `receiveMessageOnPort` to drain the module-read
 *    gate's policy channel synchronously (#123). It is the reason a narrow capture exists at all.
 *  - `loader/esm-hook.ts` (MAIN THREAD) uses `MessageChannel` to create that channel. It imports
 *    this file rather than the aggregate DELIBERATELY: it puts this module inside `index.js`'s
 *    static import graph, so the "captured during static evaluation, before `install()` can have
 *    patched `Module._load`" argument holds for the main thread verbatim, rather than resting on
 *    the loader thread's separate realm alone. Both halves of the channel therefore come from one
 *    capture, which is also the clearer read.
 *
 * The aggregate `../real-builtins.cts` still captures `node:worker_threads` too, eagerly and in
 * the same graph; both `require`s hit the same CJS cache entry and yield the same object, asserted
 * by identity in `test/real-builtins.test.ts`.
 */

export const realWorkerThreads: typeof import("node:worker_threads") = require("node:worker_threads");
