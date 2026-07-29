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
import { parseTrace, unmatchedKeyWarning } from "../trace.js";

const HELP = `usage: capwall diff [--policy <capabilities.json>] [--json] -- <command...>

Runs <command> in observe mode and diffs what it actually did against the committed policy
(default ./capabilities.json): any observed capability the policy would DENY in enforce mode
is reported as drift (e.g. a dependency using a capability it never used before).

Drift is reported in both directions (#118): observed-but-not-granted (a dependency using a
capability it never had) and declared-but-never-matched (a "packages" key that names no
principal that ran, so the grant does nothing).

CI-friendly: exit 0 = no drift, 1 = drift found, 2 = usage error / policy file missing.

  --policy, -p <file>   policy file to diff against (default ./capabilities.json)
  --strict              also exit 1 when a policy key matched no package in this run
  --json                emit drift as a single compact JSON array of {pkg, kind, detail},
                         written as the LAST line of stdout (the target's own stdout is
                         inherited and may precede it — take the last line to parse).
                         Unmatched keys are reported on stderr in every mode: the array is
                         a stable, documented contract that parsers already read.
`;

/**
 * One observed capability the committed policy would deny — a drift signal.
 *
 * This is the shape `--json` emits, as a single array on the LAST line of stdout, and it is a
 * documented contract that parsers already read: adding a field is safe, renaming one is not.
 */
export interface DriftEntry {
  /** The principal that performed the operation. */
  pkg: string;
  /** Which capability — `fs`, `net`, `ipc`, `env`, `native`, `compile`, … */
  kind: CapabilityRequest["kind"];
  /** The operation rendered the way `evaluate()` renders it, e.g. `fs:write /etc/passwd`. */
  detail: string;
}

/** Human-readable rendering of a capability request, matching evaluate()'s `describe`. */
function describeRequest(req: CapabilityRequest): string {
  switch (req.kind) {
    case "fs":
      return `fs:${req.access} ${req.path}`;
    case "net":
      return `net ${req.host}:${req.port}`;
    // The socket path, not the old `<ipc>:0` pseudo-target (#72): "a dep opened a unix socket"
    // and "a dep opened /var/run/docker.sock" are very different drift reports.
    case "ipc":
      return `ipc ${req.path}`;
    case "env":
      return `env ${req.key}`;
    case "child_process":
      return "child_process";
    case "worker_threads":
      return "worker_threads";
    case "vm":
      return "vm";
    // The path is informational only (the grant is a boolean), but drift is far more
    // actionable with it: "some dep started loading native code" is a very different report
    // from "dep X loaded ./node_modules/X/build/Release/X.node".
    case "native":
      return `native ${req.path}`;
    // The filename is informational only (the grant is a boolean), but it is the whole story
    // for a reviewer: "some dep started compiling foreign code" is a very different report from
    // "ts-node compiled ./src/index.ts".
    case "compile":
      return `compile ${req.filename}`;
  }
}

/**
 * @param args capwall's own flags: `-p`/`--policy <file>`, `--strict`, `--json`, `-h`/`--help`.
 * @param target the command to observe, as split off after `--`.
 * @returns 0 no drift, 1 drift found (or, under `--strict`, a policy key that matched nothing),
 *     2 a usage error or a missing policy file. The TARGET's own exit code is reported on
 *     stderr and deliberately not propagated: this command's exit code answers "did the policy
 *     still describe this run", not "did the run succeed".
 * @throws whatever `loadPolicy` throws on an invalid policy file, and a rejection when the
 *     target cannot be launched.
 */
export async function runDiff(args: string[], target: string[]): Promise<number> {
  let policyFile = "capabilities.json";
  let json = false;
  let strict = false;
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
    } else if (arg === "--strict") {
      strict = true;
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

    // The other half of drift (#118): keys the policy declares that named nothing which ran.
    // Reported in `--json` mode too, on stderr — the JSON array is a documented contract that
    // parsers already read as "the drift list", and quietly changing its shape to carry a
    // second, differently-shaped category is how a CI check starts passing for the wrong
    // reason. Non-gating unless `--strict`: see `unmatchedKeyWarning` for why a dead key is a
    // trust defect rather than a hole.
    const unmatched = unmatchedKeyWarning(policy, entries, policyFile);
    if (unmatched) process.stderr.write(unmatched);

    if (result.exitCode !== 0) {
      process.stderr.write(
        `[capwall] diff: note: target exited with code ${result.exitCode}\n`,
      );
    }

    return drift.length > 0 || (strict && unmatched !== "") ? 1 : 0;
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}
