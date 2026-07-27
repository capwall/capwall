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
 *   CAPWALL_HARDENED      "1" enables hardened mode — freeze the shims so a dependency
 *                         cannot monkey-patch away mediation (default: off; BREAKS
 *                         graceful-fs — see docs/threat-model.md § hardened mode)
 *   CAPWALL_ALLOW_LOADER_HOOKS
 *                         "1" lets a DEPENDENCY call module.register/registerHooks, which is
 *                         otherwise application-only (#61). Read in shims/module.ts, not
 *                         here; still warns loudly. Default: off.
 *
 * That is the complete set — capwall reads no other CAPWALL_* variable. They are also never
 * gated or recorded by the env shim, being capwall's own plumbing rather than the target's
 * environment. The same table is in packages/core/README.md § Environment variables.
 *
 * Trace format: one JSON object per line, `{ "pkg": string, "req": CapabilityRequest }`,
 * deduplicated per process. `capwall gen-policy` aggregates this into a capabilities.json.
 * `pkg` may be `<app>` (application code) or `<unknown>` (a call capwall could not attribute
 * to any source file — see the attribution module and issue #60).
 */
import { appendFileSync, readFileSync } from "node:fs";
import {
  install,
  loadPolicyFromObject,
  resolveMaxFrames,
  UNATTRIBUTED,
  type Mode,
  type PackagePolicy,
  type Policy,
} from "./index.js";
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

/**
 * Is this `<unknown>` grant wider than the one shape every policy legitimately needs — a
 * concrete list of `env` keys? Any other capability, or an `env: ["*"]` wildcard, hands
 * unnamed code authority it should not have (#60).
 */
function isBroadGrant(grant: PackagePolicy): boolean {
  return Object.entries(grant).some(([capability, value]) => {
    if (value === undefined) return false;
    if (capability !== "env") return true; // fs / net / child_process / worker_threads / vm
    return Array.isArray(value) && value.includes("*");
  });
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

  // A budget-exhausted attribution means the real owner may sit past the cap (issue #15) —
  // warn ONCE per process rather than per call, since a deep-stack framework would otherwise
  // flood stderr with an identical line.
  let warnedTruncated = false;

  // The `<unknown>` escape hatch (#60) applies to EVERY call capwall could not attribute,
  // which includes a dependency deliberately running its payload from a `data:` module or an
  // `eval`. An ALLOWED decision is not logged in enforce mode, so the hatch would otherwise be
  // silent — hence a one-time note at startup.
  //
  // But only for a BROAD grant. Every run under the CLI produces one unattributable env read
  // (Node's own ESM loader reads WATCH_REPORT_DEPENDENCIES from a stack with no caller frame),
  // so a concrete `env` key list under `<unknown>` is the normal, expected shape — warning on
  // it would fire on essentially every correctly-authored policy and train operators to ignore
  // the line, the same cry-wolf failure #67 removed from the env trace. What is worth saying
  // out loud is authority that unnamed code should never hold: a capability other than `env`,
  // or an `env: ["*"]` wildcard.
  // Enforce only: in observe nothing is denied anyway, so the warning would just be noise.
  const unknownGrant =
    mode === "enforce" && Object.hasOwn(policy.packages, UNATTRIBUTED)
      ? policy.packages[UNATTRIBUTED]
      : undefined;
  if (unknownGrant !== undefined && isBroadGrant(unknownGrant)) {
    process.stderr.write(
      `[capwall] policy grants '${UNATTRIBUTED}' beyond a concrete env key list — EVERY call ` +
        `capwall cannot attribute to a package is allowed under it, including code running ` +
        `from a data:/eval frame (see docs/threat-model.md § attribution outcomes)\n`,
    );
  }

  const seen = new Set<string>();
  install(policy, mode, {
    projectRoot,
    attribution: { maxFrames },
    // Mediate ESM `import` of builtins too (roadmap M5), on by default. Set CAPWALL_ESM=0 to
    // disable (leaves the CJS `require` path unaffected). The preload is loaded via --import,
    // which runs before the target's entry point, so the ESM hook is registered in time.
    esm: process.env["CAPWALL_ESM"] !== "0",
    // Opt-in hardened mode (#17): freeze the shims. Off unless CAPWALL_HARDENED is exactly
    // "1" — it is a breaking change for graceful-fs-style patchers, so it never defaults on.
    hardened: process.env["CAPWALL_HARDENED"] === "1",
    onDecision(pkg, decision) {
      if (decision.attributionTruncated && !warnedTruncated) {
        warnedTruncated = true;
        process.stderr.write(
          `[capwall] attribution hit the ${maxFrames}-frame budget and fell back to ` +
            `'${UNATTRIBUTED}' (denied by default in enforce); the owning package may sit ` +
            `past the cap. Raise CAPWALL_MAX_FRAMES if a deep dependency stack is involved.\n`,
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
