/**
 * `child_process` capability shim (roadmap M4, issue #6).
 *
 * Gates whether a package may START a subprocess at all — `spawn`, `exec`, `execFile`,
 * `fork`, and their sync counterparts (`spawnSync`, `execSync`, `execFileSync`) each call
 * `guard(ctx, { kind: "child_process" })` before delegating to the real function, so an
 * enforce-mode denial throws synchronously BEFORE any process is created. Everything else on
 * the module (the `ChildProcess` class, `_forkChild`, …) passes through untouched.
 *
 * This is a GATE, not confinement (see docs/threat-model.md): capwall decides whether a
 * package may spawn a subprocess at all; once a child is allowed to start, capwall does not
 * confine what it does — the child is a separate OS process outside capwall's in-process
 * shims, running with the full privileges of the host process.
 */
import realChildProcess from "node:child_process";
import { guard, type ShimContext, type ShimRegistry } from "./runtime.js";

export type { DecisionSink, ShimContext } from "./runtime.js";

/** The child_process functions that start a new process; every one of these is gated. */
const GATED_METHODS = [
  "spawn",
  "exec",
  "execFile",
  "fork",
  "spawnSync",
  "execSync",
  "execFileSync",
] as const;

type AnyFn = (...args: unknown[]) => unknown;

/**
 * Build a shimmed `child_process` module: the process-starting methods above are guarded;
 * everything else (`ChildProcess`, `_forkChild`, …) is the real thing, passed through.
 */
export function createChildProcessShim(ctx: ShimContext): typeof import("node:child_process") {
  function wrapFn(orig: AnyFn): AnyFn {
    const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
      guard(ctx, { kind: "child_process" }); // throws on enforce-deny, before any spawn
      return orig.apply(this, args);
    };
    Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
    return wrapped;
  }

  const real = realChildProcess as unknown as Record<string, unknown>;
  const shim: Record<string, unknown> = {};
  for (const key of Object.keys(real)) {
    shim[key] = real[key];
  }
  for (const name of GATED_METHODS) {
    const orig = real[name];
    if (typeof orig !== "function") continue;
    shim[name] = wrapFn(orig as AnyFn);
  }
  return shim as typeof import("node:child_process");
}

/** Register the child_process shim's specifiers into the loader registry. */
export function registerChildProcessShim(reg: ShimRegistry, ctx: ShimContext): void {
  const shim = createChildProcessShim(ctx);
  reg.set("child_process", shim);
  reg.set("node:child_process", shim);
}
