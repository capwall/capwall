/**
 * `worker_threads` capability shim (roadmap M4, issue #7).
 *
 * Gates whether a package may START a Worker at all: `new Worker(...)` goes through a
 * construct-trap `Proxy` (same technique as `wrapPathClass` in fs.ts) that calls
 * `guard(ctx, { kind: "worker_threads" })` before `Reflect.construct`, so an enforce-mode
 * denial throws synchronously before the worker thread is created. `instanceof` and class
 * identity are preserved. Everything else on the module (`isMainThread`, `parentPort`,
 * `threadId`, `MessageChannel`, `SHARE_ENV`, …) passes through untouched.
 *
 * This is a GATE, not confinement (see docs/threat-model.md): capwall decides whether a
 * package may start a Worker at all; once a worker is allowed to start, this shim does not
 * confine what code runs inside it — a spawned worker is a fresh Node isolate outside this
 * shim's in-process interception unless capwall is separately installed inside it.
 */
import realWorkerThreads from "node:worker_threads";
import { guard, type ShimContext, type ShimRegistry } from "./runtime.js";

export type { DecisionSink, ShimContext } from "./runtime.js";

type WorkerClass = abstract new (...a: never[]) => unknown;

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
    shim["Worker"] = new Proxy(RealWorker as WorkerClass, {
      construct(target, argArray, newTarget) {
        guard(ctx, { kind: "worker_threads" }); // throws on enforce-deny, before the worker starts
        return Reflect.construct(target, argArray as never[], newTarget);
      },
    });
  }

  return shim as typeof import("node:worker_threads");
}

/** Register the worker_threads shim's specifiers into the loader registry. */
export function registerWorkerThreadsShim(reg: ShimRegistry, ctx: ShimContext): void {
  const shim = createWorkerThreadsShim(ctx);
  reg.set("worker_threads", shim);
  reg.set("node:worker_threads", shim);
}
