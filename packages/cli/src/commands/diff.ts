/**
 * `capwall diff -- <cmd...>` (roadmap S3 — CI-friendly observed-vs-declared drift check).
 *
 * Runs <cmd> in observe mode (mirroring `capwall observe`'s NODE_OPTIONS preload + trace
 * collection), then diffs what it actually did against the *committed* policy using the same
 * `evaluate()` the enforcer uses: any observed capability that policy would DENY in `enforce`
 * mode is drift — e.g. a dependency exercising a capability it never had before (a possible
 * compromise signal). Nothing is ever blocked while collecting the trace; this command only
 * reports. Exits non-zero on drift so CI can gate on it.
 */
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { evaluate, loadPolicy, type CapabilityRequest } from "@capwall/core";
import { runWithCapwall } from "../run.js";
import { parseTrace } from "../trace.js";

const HELP = `usage: capwall diff [--policy <capabilities.json>] [--json] -- <command...>

Runs <command> in observe mode and diffs what it actually did against the committed policy
(default ./capabilities.json): any observed capability the policy would DENY in enforce mode
is reported as drift (e.g. a dependency using a capability it never used before).

CI-friendly: exit 0 = no drift, 1 = drift found, 2 = usage error / policy file missing.

  --policy, -p <file>   policy file to diff against (default ./capabilities.json)
  --json                emit drift as a single compact JSON array of {pkg, kind, detail},
                         written as the LAST line of stdout (the target's own stdout is
                         inherited and may precede it — take the last line to parse)
`;

/** One observed capability the committed policy would deny — a drift signal. */
export interface DriftEntry {
  pkg: string;
  kind: CapabilityRequest["kind"];
  detail: string;
}

/** Human-readable rendering of a capability request, matching evaluate()'s `describe`. */
function describeRequest(req: CapabilityRequest): string {
  switch (req.kind) {
    case "fs":
      return `fs:${req.access} ${req.path}`;
    case "net":
      return `net ${req.host}:${req.port}`;
    case "env":
      return `env ${req.key}`;
    case "child_process":
      return "child_process";
    case "worker_threads":
      return "worker_threads";
    case "vm":
      return "vm";
  }
}

export async function runDiff(args: string[], target: string[]): Promise<number> {
  let policyFile = "capabilities.json";
  let json = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-h" || arg === "--help") {
      process.stdout.write(HELP);
      return 0;
    }
    if (arg === "--policy" || arg === "-p") {
      const value = args[++i];
      if (!value) {
        process.stderr.write(`capwall diff: ${arg} requires a value\n`);
        return 2;
      }
      policyFile = value;
    } else if (arg === "--json") {
      json = true;
    } else {
      process.stderr.write(`capwall diff: unknown option '${arg}'\n${HELP}`);
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
      `capwall diff: policy file not found: ${policyFile}\n` +
        `Generate one first: capwall observe -- ${target.join(" ")}\n`,
    );
    return 2;
  }

  // Loaded (not the trace.ts as-authored loader) so relative fs globs are normalized against
  // projectRoot exactly like the real enforcer (core/src/preload.ts) does — otherwise a
  // committed policy's typical "./node_modules/**"-style relative grants would never match
  // the absolute paths the trace records, and every fs use would misreport as drift.
  const policy = await loadPolicy(policyPath, { projectRoot });

  const tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-diff-"));
  const traceFile = path.join(tmpDir, "trace.jsonl");

  try {
    const result = await runWithCapwall(target, {
      CAPWALL_MODE: "observe",
      CAPWALL_TRACE_FILE: traceFile,
      CAPWALL_PROJECT_ROOT: projectRoot,
    });

    const traceRaw = existsSync(traceFile) ? await readFile(traceFile, "utf8") : "";
    const entries = parseTrace(traceRaw);

    const drift: DriftEntry[] = [];
    for (const { pkg, req } of entries) {
      const decision = evaluate(policy, "enforce", pkg, req);
      if (!decision.allowed) {
        drift.push({ pkg, kind: req.kind, detail: describeRequest(req) });
      }
    }

    if (json) {
      // Compact, single-line, and written only after the target has exited: the target's own
      // (inherited) stdout may precede it, so this is reliably the LAST line of stdout.
      process.stdout.write(JSON.stringify(drift) + "\n");
    } else if (drift.length === 0) {
      process.stderr.write(
        `[capwall] diff: observed ${entries.length} capability event(s) against ${policyFile}; no drift\n`,
      );
    } else {
      const byPkg = new Map<string, DriftEntry[]>();
      for (const d of drift) {
        const list = byPkg.get(d.pkg);
        if (list) list.push(d);
        else byPkg.set(d.pkg, [d]);
      }
      process.stderr.write(
        `[capwall] diff: DRIFT — ${drift.length} observed capability event(s) not granted by ${policyFile}\n`,
      );
      for (const [pkg, list] of [...byPkg.entries()].sort(([a], [b]) => a.localeCompare(b))) {
        for (const d of list) {
          process.stderr.write(`  ${pkg}  ${d.detail} (not granted)\n`);
        }
      }
    }

    if (result.exitCode !== 0) {
      process.stderr.write(
        `[capwall] diff: note: target exited with code ${result.exitCode}\n`,
      );
    }

    return drift.length > 0 ? 1 : 0;
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}
