#!/usr/bin/env node
/**
 * capwall CLI entry point.
 *
 * `observe` and `enforce` launch the target command with @capwall/core preloaded (via
 * NODE_OPTIONS --import); `gen-policy` aggregates a recorded trace; `explain` answers
 * policy questions with the same evaluate() the enforcer uses. Kept dependency-light (no
 * arg-parser lib) on purpose — add one only with justification (AGENTS.md § 5).
 */
import { runObserve } from "./commands/observe.js";
import { runEnforce } from "./commands/enforce.js";
import { runGenPolicy } from "./commands/gen-policy.js";
import { runExplain } from "./commands/explain.js";
import { runDiff } from "./commands/diff.js";
import { runRun } from "./commands/run.js";

const USAGE = `capwall — runtime per-package capability firewall for Node.js

Usage:
  capwall observe   -- <command...>          run in observe mode; emit a starter policy
  capwall enforce   -- <command...>          run in enforce mode; deny-by-default
  capwall run       -- <command...>          run in the mode the policy file declares
  capwall gen-policy [--from <trace>]         (re)generate policy from a trace
  capwall explain <package> <capability> [target]
  capwall diff -- <command...>                observe, then diff vs committed policy (CI drift check)

Run 'capwall <command> --help' for details. Docs: docs/roadmap.md, docs/policy-format.md.
`;

/** Split argv into capwall's own args and the target command after a `--` separator. */
function splitArgs(argv: string[]): { own: string[]; target: string[] } {
  const i = argv.indexOf("--");
  if (i === -1) return { own: argv, target: [] };
  return { own: argv.slice(0, i), target: argv.slice(i + 1) };
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const { own, target } = splitArgs(argv);
  const [command, ...rest] = own;

  switch (command) {
    case undefined:
    case "-h":
    case "--help":
    case "help":
      process.stdout.write(USAGE);
      return 0;
    case "observe":
      return runObserve(rest, target);
    case "enforce":
      return runEnforce(rest, target);
    case "run":
      return runRun(rest, target);
    case "gen-policy":
      return runGenPolicy(rest);
    case "explain":
      return runExplain(rest);
    case "diff":
      return runDiff(rest, target);
    default:
      process.stderr.write(`capwall: unknown command '${command}'\n\n${USAGE}`);
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err: unknown) => {
    process.stderr.write(`capwall: ${(err as Error).message}\n`);
    process.exit(1);
  });
