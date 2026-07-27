/**
 * Preload entry — injected into target processes by the capwall CLI via
 * `NODE_OPTIONS=--import <this module>`, so capwall installs BEFORE the app's entry point
 * (and before any dependency can capture a raw builtin).
 *
 * Configured entirely through environment variables (the only channel available to a
 * preload):
 *   CAPWALL_MODE          "observe" | "enforce" (required to activate; absent = inert)
 *   CAPWALL_POLICY_FILE   path to capabilities.json (optional in observe mode)
 *   CAPWALL_TRACE_FILE    where to append the JSONL decision trace (optional)
 *   CAPWALL_PROJECT_ROOT  project root for attribution/glob resolution (default: cwd)
 *   CAPWALL_ESM           "0" disables the ESM loader hook (default: on)
 *   CAPWALL_HARDENED      "1" enables hardened mode — freeze the shims so a dependency
 *                         cannot monkey-patch away mediation (default: off; BREAKS
 *                         graceful-fs — see docs/threat-model.md § hardened mode)
 *
 * Trace format: one JSON object per line, `{ "pkg": string, "req": CapabilityRequest }`,
 * deduplicated per process. `capwall gen-policy` aggregates this into a capabilities.json.
 */
import { appendFileSync, readFileSync } from "node:fs";
import { install, loadPolicyFromObject, type Policy } from "./index.js";

function readPolicy(file: string | undefined, projectRoot: string): Policy {
  if (!file) {
    // No policy: fine for observe (everything is allowed and recorded anyway); enforce
    // without a policy denies everything by default, so the CLI requires the file instead.
    return loadPolicyFromObject({ version: 1 }, { projectRoot });
  }
  const json: unknown = JSON.parse(readFileSync(file, "utf8"));
  return loadPolicyFromObject(json, { projectRoot });
}

const mode = process.env["CAPWALL_MODE"];
if (mode === "observe" || mode === "enforce") {
  const projectRoot = process.env["CAPWALL_PROJECT_ROOT"] ?? process.cwd();
  const traceFile = process.env["CAPWALL_TRACE_FILE"];
  const policy = readPolicy(process.env["CAPWALL_POLICY_FILE"], projectRoot);

  const seen = new Set<string>();
  install(policy, mode, {
    projectRoot,
    // Mediate ESM `import` of builtins too (roadmap M5), on by default. Set CAPWALL_ESM=0 to
    // disable (leaves the CJS `require` path unaffected). The preload is loaded via --import,
    // which runs before the target's entry point, so the ESM hook is registered in time.
    esm: process.env["CAPWALL_ESM"] !== "0",
    // Opt-in hardened mode (#17): freeze the shims. Off unless CAPWALL_HARDENED is exactly
    // "1" — it is a breaking change for graceful-fs-style patchers, so it never defaults on.
    hardened: process.env["CAPWALL_HARDENED"] === "1",
    onDecision(pkg, decision) {
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
