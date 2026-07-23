/**
 * Policy evaluation — the decision function at the heart of enforcement.
 *
 * Given a policy, the active mode, the attributed owning package, and a capability request,
 * decide whether the operation is allowed. All logic here is REAL and tested: deny-by-default,
 * the boolean/env gates, and `fs` path-glob matching (see `./glob.ts`). Host-glob matching for
 * `net` is still a conservative exact/`*` check pending the net shim (roadmap M4).
 *
 * Semantics:
 *  - `enforce` mode: deny-by-default. A package with no matching grant is DENIED.
 *  - `observe` mode: never denies. Every request returns { allowed: true }, but
 *    `observed` carries what was seen so the CLI can synthesize a starter policy.
 */
import type { Mode, PackagePolicy, Policy } from "@capwall/policy-schema";
import { matchesGlob } from "./glob.js";

/** A capability-sensitive operation, attributed to a package, awaiting a decision. */
export type CapabilityRequest =
  | { kind: "fs"; access: "read" | "write"; path: string }
  | { kind: "net"; host: string; port: number }
  | { kind: "child_process" }
  | { kind: "worker_threads" }
  | { kind: "env"; key: string }
  | { kind: "vm" };

/** The outcome of evaluating a request. `reason` is human-readable for `explain`/logs. */
export interface Decision {
  allowed: boolean;
  reason: string;
  /** The request as observed, for trace→policy generation in observe mode. */
  observed: CapabilityRequest;
}

/** Resolve the effective per-package policy: explicit entry, else the `default` fallback. */
function policyFor(policy: Policy, pkg: string): PackagePolicy {
  // Own-property check only: a package name like "__proto__"/"constructor", or a polluted
  // Object.prototype, must not resolve a grant. Deny-by-default means the `default` fallback
  // applies to any pkg without its OWN entry. (Defense-in-depth; prototype pollution remains
  // a documented out-of-scope threat, but the policy lookup itself should not be a vector.)
  return Object.hasOwn(policy.packages, pkg) ? policy.packages[pkg]! : policy.default;
}

/**
 * Decide whether `pkg` may perform `req` under `mode`.
 *
 * In `observe` mode this always allows (recording `observed`); in `enforce` mode it applies
 * deny-by-default against the package's grant.
 */
export function evaluate(
  policy: Policy,
  mode: Mode,
  pkg: string,
  req: CapabilityRequest,
): Decision {
  if (mode === "observe") {
    return { allowed: true, reason: `observe: recorded ${describe(req)} for '${pkg}'`, observed: req };
  }

  const grant = policyFor(policy, pkg);
  const allowed = isGranted(grant, req);
  return {
    allowed,
    reason: allowed
      ? `enforce: '${pkg}' is granted ${describe(req)}`
      : `enforce: DENY '${pkg}' ${describe(req)} (not in policy; deny-by-default)`,
    observed: req,
  };
}

/** True only if `grant` has its OWN boolean `key` set to true (ignores a polluted prototype). */
function ownGate(grant: PackagePolicy, key: "child_process" | "worker_threads" | "vm"): boolean {
  return Object.hasOwn(grant, key) && grant[key] === true;
}

/** Pure grant check (no mode). Exposed for `explain` and tests. */
export function isGranted(grant: PackagePolicy, req: CapabilityRequest): boolean {
  switch (req.kind) {
    case "child_process":
      return ownGate(grant, "child_process");
    case "worker_threads":
      return ownGate(grant, "worker_threads");
    case "vm":
      return ownGate(grant, "vm");
    case "env":
      return (grant.env ?? []).some((k) => k === "*" || k === req.key);
    case "fs": {
      const globs = req.access === "read" ? grant.fs?.read : grant.fs?.write;
      // Globs are matched lexically against the request path. The policy loader normalizes
      // relative globs against the project root (loadPolicy `projectRoot` option); shims
      // resolve call-time paths to absolute, so absolute-vs-absolute is the common case.
      return (globs ?? []).some((g) => matchesGlob(g, req.path));
    }
    case "net": {
      const net = grant.net;
      if (!net) return false;
      // Host matching is exact or the "*" wildcard. Host GLOBS (e.g. "*.internal") are a
      // follow-up (tracked separately); the net shim (M4) is wired against this exact/`*` gate.
      const hostOk = net.hosts.some((h) => h === "*" || h === req.host);
      const portOk = net.ports.includes(req.port);
      return hostOk && portOk;
    }
  }
}

function describe(req: CapabilityRequest): string {
  switch (req.kind) {
    case "fs":
      return `fs:${req.access} ${req.path}`;
    case "net":
      return `net ${req.host}:${req.port}`;
    case "env":
      return `env:${req.key}`;
    default:
      return req.kind;
  }
}
