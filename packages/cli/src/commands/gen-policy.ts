/**
 * `capwall gen-policy --from <trace> [-o capabilities.json]` (roadmap M2).
 *
 * Turns a recorded observe trace (JSONL, as written by the preload via CAPWALL_TRACE_FILE)
 * into a `capabilities.json`, merging into an existing one rather than overwriting so
 * repeated runs accumulate coverage without clobbering hand edits. `capwall observe` does
 * this automatically; this command exists for traces captured out-of-band.
 */
import { readFile } from "node:fs/promises";
import * as path from "node:path";
import {
  loadExistingPolicy,
  mergeTraceIntoPolicy,
  parseTrace,
  writePolicy,
} from "../trace.js";

const HELP = `usage: capwall gen-policy --from <trace.jsonl> [-o <capabilities.json>]

Aggregates a capwall observe trace into a policy file (default ./capabilities.json),
merging with the existing file if present.
`;

export async function runGenPolicy(args: string[]): Promise<number> {
  let traceFile: string | undefined;
  let outFile = "capabilities.json";
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-h" || arg === "--help") {
      process.stdout.write(HELP);
      return 0;
    }
    if (arg === "--from") {
      const value = args[++i];
      if (!value) {
        process.stderr.write("capwall gen-policy: --from requires a value\n");
        return 2;
      }
      traceFile = value;
    } else if (arg === "-o" || arg === "--out") {
      const value = args[++i];
      if (!value) {
        process.stderr.write(`capwall gen-policy: ${arg} requires a value\n`);
        return 2;
      }
      outFile = value;
    } else {
      process.stderr.write(`capwall gen-policy: unknown option '${arg}'\n${HELP}`);
      return 2;
    }
  }
  if (!traceFile) {
    process.stderr.write(HELP);
    return 2;
  }

  const projectRoot = process.cwd();
  const entries = parseTrace(await readFile(traceFile, "utf8"));
  const policyPath = path.resolve(projectRoot, outFile);
  const existing = await loadExistingPolicy(policyPath);
  const policy = mergeTraceIntoPolicy(entries, existing, projectRoot);
  await writePolicy(policyPath, policy);
  process.stderr.write(
    `[capwall] ${existing ? "merged" : "wrote"} ${entries.length} trace event(s) into ${outFile}\n`,
  );
  return 0;
}
