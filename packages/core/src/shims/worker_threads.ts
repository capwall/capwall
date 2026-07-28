/**
 * `worker_threads` capability shim (roadmap M4, issue #7).
 *
 * Gates whether a package may START a Worker at all: `new Worker(...)` goes through a guarded
 * SUBCLASS whose constructor calls `guard(ctx, { kind: "worker_threads" })` before `super(...)`,
 * so an enforce-mode denial throws synchronously before the worker thread is created — the
 * real `Worker` constructor is what spawns the thread, so nothing runs on denial. `instanceof`
 * still works for real and guarded instances alike via a `Symbol.hasInstance` override.
 * Everything else on the module (`isMainThread`, `parentPort`, `threadId`, `MessageChannel`,
 * `SHARE_ENV`, …) passes through untouched.
 *
 * NOT a construct-trap `Proxy` (#64). A Proxy forwards `.prototype` to its target, so
 * `new (worker_threads.Worker.prototype.constructor)(script)` spawned a worker with the guard
 * never firing. That is the highest-consequence escape in the codebase: a worker is a fresh
 * Node context with none of capwall's shims installed, so it is a full capability escape, not
 * just an unmediated call. See {@link guardedConstructorSubclass}.
 *
 * This is a GATE, not confinement (see docs/threat-model.md): capwall decides whether a
 * package may start a Worker at all; once a worker is allowed to start, this shim does not
 * confine what code runs inside it — a spawned worker is a fresh Node isolate outside this
 * shim's in-process interception unless capwall is separately installed inside it.
 */
import { realWorkerThreads } from "../real-builtins.cjs"; // never `import … from "node:worker_threads"` — see #78
import {
  guard,
  guardedConstructorSubclass,
  type AnyCtor,
  type ShimContext,
  type ShimRegistry,
} from "./runtime.js";
import { harden } from "./harden.js";

/**
 * Build a shimmed `worker_threads` module: the `Worker` constructor is guarded; everything
 * else (`isMainThread`, `parentPort`, `threadId`, `MessageChannel`, `SHARE_ENV`, …) is the
 * real thing, passed through.
 */
export function createWorkerThreadsShim(ctx: ShimContext): typeof import("node:worker_threads") {
  const real = realWorkerThreads as unknown as Record<string, unknown>;
  const shim: Record<string, unknown> = {};
  for (const key of Object.keys(real)) {
    shim[key] = real[key];
  }

  const RealWorker = real["Worker"];
  if (typeof RealWorker === "function") {
    shim["Worker"] = guardedConstructorSubclass(
      RealWorker as AnyCtor,
      () => {
        guard(ctx, { kind: "worker_threads" }); // throws on enforce-deny, BEFORE super() spawns
        // Nothing to pin: `worker_threads` is a boolean gate, so no argument decides a target
        // that Node could later re-read differently (the #99 audit's verdict for this entry
        // point). The `filename`/`options` bag is forwarded exactly as the caller wrote it.
        return undefined;
      },
      ctx, // hardened mode (#17) freezes the guarded subclass; no-op by default
    );
  }

  return harden(ctx, shim) as typeof import("node:worker_threads");
}

/** Register the worker_threads shim's specifiers into the loader registry. */
export function registerWorkerThreadsShim(reg: ShimRegistry, ctx: ShimContext): void {
  const shim = createWorkerThreadsShim(ctx);
  reg.set("worker_threads", shim);
  reg.set("node:worker_threads", shim);
}
