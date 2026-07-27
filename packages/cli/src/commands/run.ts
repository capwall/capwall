/**
 * `capwall run -- <cmd...>` — the modeless entry point (issue #55).
 *
 * `observe` and `enforce` name the mode in the command line. `run` doesn't: it takes the mode
 * from the policy document's own `mode` field, which is what makes that field real rather
 * than decoration. Commit `"mode": "enforce"` next to the policy it enforces and CI runs one
 * unchanging command; flipping the project from on-ramp to enforcement is a one-word diff in
 * a reviewed file instead of a change to whatever invokes capwall.
 *
 * It deliberately does NOT set `CAPWALL_MODE`, so an operator who exports `CAPWALL_MODE` in
 * the environment still overrides the file — the same precedence every other capwall option
 * follows (core/src/policy/mode.ts).
 */
import { existsSync } from "node:fs";
import * as path from "node:path";
import { loadPolicy } from "@capwall/core";
import { runWithCapwall } from "../run.js";

const HELP = `usage: capwall run [--policy <capabilities.json>] -- <command...>

Runs <command> in the mode the policy file declares (its "mode" field), rather than one named
on the command line. The policy (default ./capabilities.json) must declare a mode.
An explicit CAPWALL_MODE in the environment still overrides it.
`;

export async function runRun(args: string[], target: string[]): Promise<number> {
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
        process.stderr.write(`capwall run: ${arg} requires a value\n`);
        return 2;
      }
      policyFile = value;
    } else {
      process.stderr.write(`capwall run: unknown option '${arg}'\n${HELP}`);
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
      `capwall run: policy file not found: ${policyFile}\n` +
        `Generate one first: capwall observe -- ${target.join(" ")}\n`,
    );
    return 2;
  }

  // Read it here purely to fail fast with a good message: the preload re-reads and re-resolves
  // it in the child, and IT is the authority on the mode actually used.
  const policy = await loadPolicy(policyPath, { projectRoot });
  const declared = policy.mode;
  if (declared === undefined) {
    process.stderr.write(
      `capwall run: ${policyFile} declares no "mode" — nothing to run under.\n` +
        `Add "mode": "observe" or "mode": "enforce" to it, or name the mode explicitly:\n` +
        `  capwall observe -- ${target.join(" ")}\n` +
        `  capwall enforce -- ${target.join(" ")}\n`,
    );
    return 2;
  }

  // The child inherits our environment, so an ambient CAPWALL_MODE reaches the preload and
  // wins. Report that when it's valid; refuse when it isn't, because the preload treats an
  // unrecognized CAPWALL_MODE as "stay inert" — which would silently run the target with NO
  // mediation at all under a command whose whole job is to mediate it.
  const override = process.env["CAPWALL_MODE"];
  if (override === undefined || override === "") {
    process.stderr.write(`[capwall] run: mode "${declared}" (declared in ${policyFile})\n`);
  } else if (override === "observe" || override === "enforce") {
    if (override !== declared) {
      process.stderr.write(
        `[capwall] run: CAPWALL_MODE=${override} overrides the "${declared}" declared in ${policyFile}\n`,
      );
    }
  } else {
    process.stderr.write(
      `capwall run: CAPWALL_MODE is set to '${override}', which is not "observe" or "enforce".\n` +
        `It would take precedence and leave capwall inert. Unset it, or fix the value.\n`,
    );
    return 2;
  }

  const result = await runWithCapwall(target, {
    CAPWALL_POLICY_FILE: policyPath,
    CAPWALL_PROJECT_ROOT: projectRoot,
  });
  return result.exitCode;
}
