/**
 * `child_process` capability shim (roadmap M4).
 *
 * This is a GATE, not confinement (see docs/threat-model.md): capwall decides whether a
 * package may spawn a subprocess at all; once a child runs, capwall does not confine what it
 * does — the child is a separate process outside capwall's in-process shims.
 */
import type { ShimContext } from "./fs.js";

/**
 * TODO(capwall): wrap spawn/exec/execFile/fork (+ sync variants) to build a
 * { kind: "child_process" } request, attribute + evaluate, then forward or deny.
 */
export function createChildProcessShim(
  _ctx: ShimContext,
): typeof import("node:child_process") {
  throw new Error("capwall: child_process shim not yet implemented — see roadmap M4");
}
