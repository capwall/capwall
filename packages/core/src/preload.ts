/**
 * Preload entry — injected into target processes by the capwall CLI via
 * `NODE_OPTIONS=--import <this module>`, so capwall installs BEFORE the app's entry point
 * (and before any dependency can capture a raw builtin).
 *
 * Configured entirely through environment variables (the only channel available to a
 * preload):
 *   CAPWALL_MODE          "observe" | "enforce" — wins over the policy's own `mode`. When
 *                         absent, the mode comes from the policy document's `mode` field;
 *                         if neither declares one, capwall stays inert. See
 *                         `policy/mode.ts` for the full precedence rules.
 *   CAPWALL_POLICY_FILE   path to capabilities.json (optional in observe mode)
 *   CAPWALL_TRACE_FILE    where to append the JSONL decision trace (optional)
 *   CAPWALL_PROJECT_ROOT  project root for attribution/glob resolution (default: cwd)
 *   CAPWALL_ESM           "0" disables the ESM loader hook (default: on)
 *   CAPWALL_MAX_FRAMES    attribution stack-walk frame budget (default: 25, see issue #15)
 *
 * Trace format: one JSON object per line, `{ "pkg": string, "req": CapabilityRequest }`,
 * deduplicated per process. `capwall gen-policy` aggregates this into a capabilities.json.
 */
import { appendFileSync, readFileSync } from "node:fs";
import { install, loadPolicyFromObject, resolveMaxFrames, type Mode, type Policy } from "./index.js";
import { resolveMode } from "./policy/mode.js";

function readPolicy(file: string | undefined, projectRoot: string): Policy {
  if (!file) {
    // No policy: fine for observe (everything is allowed and recorded anyway); enforce
    // without a policy denies everything by default, so the CLI requires the file instead.
    return loadPolicyFromObject({ version: 1 }, { projectRoot });
  }
  const json: unknown = JSON.parse(readFileSync(file, "utf8"));
  return loadPolicyFromObject(json, { projectRoot });
}

interface Activation {
  mode: Mode;
  policy: Policy;
  projectRoot: string;
}

/** Decide whether capwall turns on here, and under which mode. `undefined` = stay inert. */
function activation(): Activation | undefined {
  const envMode = process.env["CAPWALL_MODE"];
  const policyFile = process.env["CAPWALL_POLICY_FILE"];
  // Neither channel present => nothing can supply a mode, so don't even touch the filesystem:
  // a NODE_OPTIONS left over in a shell must not start mediating unrelated processes.
  if (envMode === undefined && policyFile === undefined) return undefined;
  const projectRoot = process.env["CAPWALL_PROJECT_ROOT"] ?? process.cwd();
  const policy = readPolicy(policyFile, projectRoot);
  const resolved = resolveMode(envMode, policy.mode);
  return resolved ? { mode: resolved.mode, policy, projectRoot } : undefined;
}

const active = activation();
if (active) {
  const { mode, policy, projectRoot } = active;
  const traceFile = process.env["CAPWALL_TRACE_FILE"];

  // Env is a string channel, so validate before handing the value to install(): a typo like
  // CAPWALL_MAX_FRAMES=abc must degrade to the default (with a warning), never abort the
  // host app and never reach Error.stackTraceLimit as NaN — see resolveMaxFrames (#15).
  const maxFrames = resolveMaxFrames(process.env["CAPWALL_MAX_FRAMES"], "CAPWALL_MAX_FRAMES");

  // A budget-exhausted attribution means capwall may have charged a dependency's call to
  // <app> (issue #15) — warn ONCE per process rather than per call, since a deep-stack
  // framework would otherwise flood stderr with an identical line.
  let warnedTruncated = false;

  const seen = new Set<string>();
  install(policy, mode, {
    projectRoot,
    attribution: { maxFrames },
    // Mediate ESM `import` of builtins too (roadmap M5), on by default. Set CAPWALL_ESM=0 to
    // disable (leaves the CJS `require` path unaffected). The preload is loaded via --import,
    // which runs before the target's entry point, so the ESM hook is registered in time.
    esm: process.env["CAPWALL_ESM"] !== "0",
    onDecision(pkg, decision) {
      if (decision.attributionTruncated && !warnedTruncated) {
        warnedTruncated = true;
        process.stderr.write(
          `[capwall] attribution hit the ${maxFrames}-frame budget and fell back to '<app>'; ` +
            `some calls may be attributed to the wrong package. ` +
            `Raise CAPWALL_MAX_FRAMES if a deep dependency stack is involved.\n`,
        );
      }
      const req = decision.observed;
      const key = `${pkg} ${JSON.stringify(req)} ${decision.allowed}`;
      if (seen.has(key)) return;
      seen.add(key);
      // Note: this runs inside the shim's guard, but uses capwall's own real-fs reference
      // (ESM import above), so it is not itself mediated or attributed.
      if (traceFile) {
        appendFileSync(traceFile, JSON.stringify({ pkg, req }) + "\n");
      }
      if (mode === "observe") {
        process.stderr.write(`[capwall] ${decision.reason}\n`);
      } else if (!decision.allowed) {
        process.stderr.write(`[capwall] ${decision.reason}\n`);
      }
    },
  });
}
