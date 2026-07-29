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
import { versionReport } from "./version.js";

// The doc links are ABSOLUTE URLs on purpose (#124). From `node_modules/@capwall/cli` a
// repo-relative `docs/policy-format.md` names nothing, and the CLI banner is the one place a
// reader who installed the package meets this project's documentation. `roadmap.md` used to be
// here and is gone: it is the internal build-order tracker, not something to send a user to.
const DOCS = "https://github.com/williamzujkowski/capwall";

const USAGE = `capwall — runtime per-package capability firewall for Node.js

Usage:
  capwall observe   -- <command...>          run in observe mode; emit a starter policy
  capwall enforce   -- <command...>          run in enforce mode; deny-by-default
  capwall run       -- <command...>          run in the mode the policy file declares
  capwall gen-policy [--from <trace>]         (re)generate policy from a trace
  capwall explain <package> <capability> [target]
  capwall diff -- <command...>                observe, then diff vs committed policy (CI drift check)
  capwall --version                           print the CLI and @capwall/core versions

Run 'capwall <command> --help' for details.
Policy format: ${DOCS}/blob/main/docs/policy-format.md
Threat model:  ${DOCS}/blob/main/docs/threat-model.md
`;

/**
 * Format a policy-validation failure readably (#124).
 *
 * `parsePolicy` throws a ZodError whose `.message` is the raw issue array, so the best error
 * text in the project — the package-key grammar explainer, for one — used to arrive as escaped
 * JSON. The check is STRUCTURAL rather than `instanceof z.ZodError`: the CLI does not depend on
 * zod, and adding a runtime dep to format an error message would be the wrong trade in a repo
 * whose whole argument is that every dependency is attack surface.
 */
function formatError(err: unknown): string {
  const issues: unknown = (err as { issues?: unknown }).issues;
  if (!Array.isArray(issues) || issues.length === 0) return (err as Error).message;
  return issues
    .map((raw) => {
      const issue = raw as { path?: unknown; message?: unknown };
      const message = typeof issue.message === "string" ? issue.message : "invalid";
      const segments: unknown[] = Array.isArray(issue.path) ? issue.path : [];
      if (segments.length === 0) return message;
      // `["packages", "sneak*", "net", 0]` -> `packages["sneak*"].net[0]`.
      const [head, ...rest] = segments;
      const where = rest.reduce<string>((acc, s) => {
        if (typeof s === "number") return `${acc}[${String(s)}]`;
        return /^[A-Za-z_$][\w$]*$/.test(String(s))
          ? `${acc}.${String(s)}`
          : `${acc}[${JSON.stringify(s)}]`;
      }, String(head));
      return `${where}: ${message}`;
    })
    .join("\n");
}

/** Split argv into capwall's own args and the target command after a `--` separator. */
function splitArgs(argv: string[]): { own: string[]; target: string[] } {
  const i = argv.indexOf("--");
  if (i === -1) return { own: argv, target: [] };
  return { own: argv.slice(0, i), target: argv.slice(i + 1) };
}

/**
 * Dispatch one capwall command. The CLI's programmatic entry point, and what the `capwall`
 * bin runs.
 *
 * IMPORTING THIS MODULE RUNS `main()`. The call at the bottom of this file is unconditional and
 * ends in `process.exit()`, which is right for a `bin` and is the thing to know before reaching
 * for `@capwall/cli` as a library: embedding the commands means importing
 * `./commands/<name>.js` directly, or spawning the binary. There is no "am I the entry module"
 * guard, deliberately — adding one is a behaviour change, not a doc change.
 *
 * @param argv capwall's own arguments, WITHOUT the node and script paths. The target command
 *     goes after a `--` separator and is split off here, so `["observe", "--", "node", "app.js"]`
 *     is the shape `observe`/`enforce`/`run`/`diff` expect. Defaults to the real command line.
 * @returns the process exit code: 0 success, 1 a denial or drift found, 2 a usage error or a
 *     missing policy file. `explain` uses 1 for "denied", which is an answer rather than a
 *     failure.
 * @throws whatever a command throws — notably a ZodError from an invalid policy file. The
 *     bottom-of-file caller formats it and exits 1; a programmatic caller must catch it itself.
 */
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
    // `-v` too: it is what people type, and capwall has no other meaning for it (no verbose
    // flag), so claiming it costs nothing and refusing it would only produce a usage error.
    case "-V":
    case "-v":
    case "--version":
    case "version":
      process.stdout.write(versionReport());
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
    process.stderr.write(`capwall: ${formatError(err)}\n`);
    process.exit(1);
  });
