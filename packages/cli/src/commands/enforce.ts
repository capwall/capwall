/**
 * `capwall enforce -- <cmd...>` (roadmap M3).
 *
 * Runs <cmd> with @capwall/core preloaded in `enforce` mode, loading the policy file.
 * Any capability a package uses that is not in its grant is denied (deny-by-default) and
 * throws a CapabilityError inside the target process.
 */
import { existsSync } from "node:fs";
import * as path from "node:path";
import { runWithCapwall } from "../run.js";

const HELP = `usage: capwall enforce [--policy <capabilities.json>] -- <command...>

Runs <command> in enforce mode: deny-by-default against the policy file
(default ./capabilities.json). Generate a starter policy first with 'capwall observe'.
`;

/**
 * @param args capwall's own flags: `-p`/`--policy <file>`, `-h`/`--help`.
 * @param target the command to run, as split off after `--`.
 * @returns the TARGET's exit code, or 2 for a usage error or a missing policy file. A denial
 *     surfaces as a `CapabilityError` thrown INSIDE the target, so whether it is fatal is the
 *     target's decision — this command has no exit code of its own for "something was denied".
 * @throws a rejection when the target cannot be launched at all.
 */
export async function runEnforce(args: string[], target: string[]): Promise<number> {
  let policyFile = "capabilities.json";
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-h" || arg === "--help") {
      process.stdout.write(HELP);
      return 0;
    }
    if (arg === "--policy" || arg === "-p") {
      const value = args[++i];
      if (!value) {
        process.stderr.write(`capwall enforce: ${arg} requires a value\n`);
        return 2;
      }
      policyFile = value;
    } else {
      process.stderr.write(`capwall enforce: unknown option '${arg}'\n${HELP}`);
      return 2;
    }
  }
  if (target.length === 0) {
    process.stderr.write(HELP);
    return 2;
  }

  const projectRoot = process.cwd();
  const policyPath = path.resolve(projectRoot, policyFile);
  if (!existsSync(policyPath)) {
    process.stderr.write(
      `capwall enforce: policy file not found: ${policyFile}\n` +
        `Generate one first: capwall observe -- ${target.join(" ")}\n`,
    );
    return 2;
  }

  const result = await runWithCapwall(target, {
    CAPWALL_MODE: "enforce",
    CAPWALL_POLICY_FILE: policyPath,
    CAPWALL_PROJECT_ROOT: projectRoot,
  });
  return result.exitCode;
}
