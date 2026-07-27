/**
 * `child_process` capability shim (roadmap M4, issue #6).
 *
 * Gates whether a package may START a subprocess at all — `spawn`, `exec`, `execFile`,
 * `fork`, and their sync counterparts each call `guard(ctx, { kind: "child_process" })`
 * before delegating, so an enforce-mode denial throws synchronously BEFORE any process is
 * created. The `ChildProcess` class is also wrapped: `new ChildProcess().spawn(opts)` is the
 * low-level launch primitive the module functions are sugar over, so a bare instance's
 * `.spawn()` must be gated too (otherwise it is a trivial bypass, exactly like the
 * fs.ReadStream-class bypass a prior review caught).
 *
 * ENV INTERACTION: Node builds the child's environment block by reading `process.env`
 * synchronously inside the real spawn call. Those reads happen while the spawning dependency
 * is the nearest stack frame, so without care the env shim would soft-deny them and the child
 * would launch with an empty environment (no PATH/HOME). Each real spawn is therefore
 * bracketed with `suspendEnvGate()`/`resumeEnvGate()` so the env-copy passes through — the
 * child inheriting the parent environment is expected (this is a gate, not confinement).
 *
 * This is a GATE, not confinement (see docs/threat-model.md): capwall decides whether a
 * package may spawn a subprocess at all; once a child is allowed to start, capwall does not
 * confine what it does — the child is a separate OS process outside capwall's in-process
 * shims, running with the full privileges of the host process.
 */
import realChildProcess from "node:child_process";
import {
  guard,
  resumeEnvGate,
  suspendEnvGate,
  type ShimContext,
  type ShimRegistry,
} from "./runtime.js";
import { harden, hardenClass } from "./harden.js";

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

/** Run `fn` with the env gate suspended so Node's env-block copy reaches the child intact. */
function spawnWithEnv<T>(fn: () => T): T {
  suspendEnvGate();
  try {
    return fn();
  } finally {
    resumeEnvGate();
  }
}

/**
 * Build a shimmed `child_process` module: the process-starting methods above are guarded,
 * the `ChildProcess` class's `.spawn()` is guarded, and everything else passes through.
 */
export function createChildProcessShim(ctx: ShimContext): typeof import("node:child_process") {
  function wrapFn(orig: AnyFn): AnyFn {
    const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
      guard(ctx, { kind: "child_process" }); // throws on enforce-deny, before any spawn
      return spawnWithEnv(() => orig.apply(this, args));
    };
    Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
    return harden(ctx, wrapped);
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

  // Gate the ChildProcess class: `new ChildProcess().spawn(options)` is the low-level launch
  // primitive. A guarded SUBCLASS guards `ChildProcess.prototype.spawn` itself — a
  // construct-trap Proxy would be bypassable via `(new ChildProcess()).constructor` and
  // `ChildProcess.prototype.spawn.call(...)`. Symbol.hasInstance keeps `instanceof` working.
  const RealChildProcess = real["ChildProcess"];
  if (typeof RealChildProcess === "function") {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const RealCP = RealChildProcess as new (...a: any[]) => object;
    const realSpawn = (RealCP.prototype as Record<string, unknown>)["spawn"];
    const Guarded = class extends RealCP {};
    if (typeof realSpawn === "function") {
      Object.defineProperty(Guarded.prototype, "spawn", {
        value: function (this: unknown, ...spawnArgs: unknown[]) {
          guard(ctx, { kind: "child_process" });
          return spawnWithEnv(() => (realSpawn as AnyFn).apply(this, spawnArgs));
        },
        writable: true,
        configurable: true,
      });
    }
    Object.defineProperty(Guarded, Symbol.hasInstance, {
      value: (x: unknown) => x instanceof RealCP,
      configurable: true,
    });
    Object.defineProperty(Guarded, "name", {
      value: (RealCP as { name: string }).name,
      configurable: true,
    });
    // Hardened mode (#17): freeze the subclass + its prototype so
    // `ChildProcess.prototype.spawn = evil` fails instead of removing the gate. See harden.ts.
    hardenClass(ctx, Guarded);
    shim["ChildProcess"] = Guarded;
  }

  return harden(ctx, shim) as typeof import("node:child_process");
}

/** Register the child_process shim's specifiers into the loader registry. */
export function registerChildProcessShim(reg: ShimRegistry, ctx: ShimContext): void {
  const shim = createChildProcessShim(ctx);
  reg.set("child_process", shim);
  reg.set("node:child_process", shim);
}
