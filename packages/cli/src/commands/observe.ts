/**
 * `capwall observe -- <cmd...>` — the HEADLINE feature (roadmap M2).
 *
 * Runs <cmd> with @capwall/core preloaded in `observe` mode: every attributed capability
 * decision is logged and recorded (nothing is ever blocked), and on exit the trace is
 * merged into a starter `capabilities.json`. This is the zero-friction on-ramp: run once,
 * review/tighten the emitted policy, then flip to `capwall enforce`.
 */
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { runWithCapwall } from "../run.js";
import {
  loadExistingPolicy,
  mergeTraceIntoPolicy,
  parseTrace,
  unmatchedKeyWarning,
  writePolicy,
} from "../trace.js";

const HELP = `usage: capwall observe [-o <capabilities.json>] -- <command...>

Runs <command> in observe mode (logs capability use, never blocks) and merges what it saw
into the policy file (default ./capabilities.json). Re-runs merge, not overwrite.
`;

export async function runObserve(args: string[], target: string[]): Promise<number> {
  let outFile = "capabilities.json";
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-h" || arg === "--help") {
      process.stdout.write(HELP);
      return 0;
    }
    if (arg === "-o" || arg === "--out") {
      const value = args[++i];
      if (!value) {
        process.stderr.write(`capwall observe: ${arg} requires a value\n`);
        return 2;
      }
      outFile = value;
    } else {
      process.stderr.write(`capwall observe: unknown option '${arg}'\n${HELP}`);
      return 2;
    }
  }
  if (target.length === 0) {
    process.stderr.write(HELP);
    return 2;
  }

  const projectRoot = process.cwd();
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-"));
  const traceFile = path.join(tmpDir, "trace.jsonl");

  try {
    const env: Record<string, string> = {
      CAPWALL_MODE: "observe",
      CAPWALL_TRACE_FILE: traceFile,
      CAPWALL_PROJECT_ROOT: projectRoot,
    };
    const policyPath = path.resolve(projectRoot, outFile);
    if (existsSync(policyPath)) env["CAPWALL_POLICY_FILE"] = policyPath;

    const result = await runWithCapwall(target, env);

    const traceRaw = existsSync(traceFile) ? await readFile(traceFile, "utf8") : "";
    const entries = parseTrace(traceRaw);
    const existing = await loadExistingPolicy(policyPath);
    const policy = mergeTraceIntoPolicy(entries, existing, projectRoot);
    await writePolicy(policyPath, policy, projectRoot);

    const pkgCount = Object.keys(policy.packages).length;
    process.stderr.write(
      `[capwall] observed ${entries.length} capability event(s) across ` +
        `${pkgCount} package(s); ${existing ? "merged into" : "wrote"} ${outFile}\n` +
        // #118: keys this run proved dead. Only ever pre-existing hand edits — everything the
        // merge just wrote matched by construction — which is exactly the audience.
        unmatchedKeyWarning(policy, entries, outFile) +
        `[capwall] review/tighten it, then run: capwall enforce -- ${target.join(" ")}\n`,
    );
    return result.exitCode;
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}
