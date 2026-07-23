/**
 * `vm` capability shim (roadmap M4).
 *
 * A GATE: decides whether a package may use `node:vm` at all. Note that `vm`/`eval` are
 * themselves listed in docs/threat-model.md as a way a determined attacker can sidestep the
 * shimmed API surface — gating vm use is defense-in-depth, not a guarantee.
 */
import type { ShimContext } from "./fs.js";

/**
 * TODO(capwall): wrap runInNewContext/runInThisContext/compileFunction/Script to build a
 * { kind: "vm" } request, attribute + evaluate, then forward or deny.
 */
export function createVmShim(_ctx: ShimContext): typeof import("node:vm") {
  throw new Error("capwall: vm shim not yet implemented — see roadmap M4");
}
