/**
 * Shared child-process runner: launch the target command with @capwall/core's preload
 * injected via NODE_OPTIONS, so capwall installs before the target's entry point runs.
 */
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

/** Resolve the core preload module and build the `--import <url>` NODE_OPTIONS fragment. */
function preloadNodeOptions(): string {
  const require = createRequire(import.meta.url);
  const preloadPath = require.resolve("@capwall/core/preload");
  // A file:// URL percent-encodes spaces, so it is safe to embed in NODE_OPTIONS unquoted.
  return `--import ${pathToFileURL(preloadPath).href}`;
}

/** How a mediated child ended. */
export interface RunResult {
  /** Child exit code; signal terminations (SIGINT/SIGTERM, e.g. Ctrl-C on a server) map to 0. */
  exitCode: number;
  /** The signal that killed the child, or `null` when it exited on its own. */
  signal: NodeJS.Signals | null;
}

/**
 * Run `target` (argv after `--`) with capwall configured through `capwallEnv`.
 * Forwards SIGINT/SIGTERM to the child and keeps the parent alive until the child exits,
 * so observe mode can still write its policy after Ctrl-C.
 *
 * @param target the command and its arguments — `target[0]` is spawned, the rest are its argv.
 *     `stdio` is inherited, so the child writes straight to this process's streams.
 * @param capwallEnv the `CAPWALL_*` variables configuring the install (see `core/src/preload.ts`
 *     for the full set). Merged over `process.env` LAST, so it wins over an inherited value.
 *     The preload's own `--import` is appended to any existing `NODE_OPTIONS` rather than
 *     replacing it.
 * @returns how the child ended, once it has fully exited.
 * @throws (as a rejection) when `target` is empty, or when the command could not be launched at
 *     all. A child that runs and fails is a resolved {@link RunResult} with a non-zero
 *     `exitCode`, not a rejection.
 */
export function runWithCapwall(
  target: string[],
  capwallEnv: Record<string, string>,
): Promise<RunResult> {
  const [cmd, ...args] = target;
  if (!cmd) {
    return Promise.reject(new Error("missing target command (expected `-- <command...>`)"));
  }
  const nodeOptions = [process.env["NODE_OPTIONS"], preloadNodeOptions()]
    .filter(Boolean)
    .join(" ");

  const child = spawn(cmd, args, {
    stdio: "inherit",
    env: { ...process.env, NODE_OPTIONS: nodeOptions, ...capwallEnv },
  });

  const forward = (signal: NodeJS.Signals) => () => {
    child.kill(signal);
  };
  const onInt = forward("SIGINT");
  const onTerm = forward("SIGTERM");
  process.on("SIGINT", onInt);
  process.on("SIGTERM", onTerm);

  return new Promise<RunResult>((resolve, reject) => {
    child.on("error", (err) => {
      process.off("SIGINT", onInt);
      process.off("SIGTERM", onTerm);
      reject(new Error(`failed to launch '${cmd}': ${err.message}`));
    });
    child.on("close", (code, signal) => {
      process.off("SIGINT", onInt);
      process.off("SIGTERM", onTerm);
      const exitCode = code ?? (signal === "SIGINT" || signal === "SIGTERM" ? 0 : 1);
      resolve({ exitCode, signal });
    });
  });
}
