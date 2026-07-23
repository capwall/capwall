/**
 * `worker_threads` capability shim (roadmap M4).
 *
 * A GATE: decides whether a package may start a Worker. A spawned worker runs its own
 * capwall install (it is a fresh Node isolate); confining the worker's own capabilities is
 * handled by capwall re-installing inside the worker, not by this gate.
 */
import type { ShimContext } from "./fs.js";

/**
 * TODO(capwall): wrap the Worker constructor to build a { kind: "worker_threads" } request,
 * attribute + evaluate, then construct or deny. Consider auto-installing capwall in the
 * worker so its threads inherit enforcement.
 */
export function createWorkerThreadsShim(
  _ctx: ShimContext,
): typeof import("node:worker_threads") {
  throw new Error("capwall: worker_threads shim not yet implemented — see roadmap M4");
}
