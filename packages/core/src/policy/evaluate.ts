/**
 * Policy evaluation — the decision function at the heart of enforcement.
 *
 * Given a policy, the active mode, the attributed owning package, and a capability request,
 * decide whether the operation is allowed. All logic here is REAL and tested: deny-by-default,
 * the boolean/env gates, `fs` path-glob matching (see `./glob.ts`), `net` host matching (the
 * grammar lives in `@capwall/policy-schema` `host.ts`, which also VALIDATES it at policy-load
 * time — issue #83) and `ipc` socket-path matching (`./ipc.ts`, issue #72).
 *
 * Semantics:
 *  - `enforce` mode: deny-by-default. A package with no matching grant is DENIED.
 *  - `observe` mode: never denies. Every request returns { allowed: true }, but
 *    `observed` carries what was seen so the CLI can synthesize a starter policy.
 */
// The two grammar modules are imported by their OWN subpaths rather than through
// `@capwall/policy-schema`'s barrel, and that is a startup-cost decision rather than a style one
// (#150). The barrel builds the whole Zod schema tree at module scope, so importing `ANY_HOST`
// through it drags `zod` into every graph that evaluates a decision — and evaluating a decision
// needs no schema at all, since this module is handed an already-parsed policy. `parsePolicy` —
// the one consumer that genuinely needs Zod — imports the barrel from `policy/load.ts`.
//
// #150 wrote this rule about Node's ESM loader thread, which reached this file through
// `loader/esm-hooks.ts` and paid for its whole graph serially at startup. #152 removed that
// thread, and with it the guard that used to hold this line in place: `src/index.ts` re-exports
// `loadPolicyFromObject`, so zod is on `@capwall/core`'s entry graph regardless and there is no
// honest scan left to write. The subpath import is still right and still free; it is simply no
// longer load-bearing enough to test.
import { ANY_HOST, matchesHostPattern } from "@capwall/policy-schema/host";
import { widenedPackageKeys } from "@capwall/policy-schema/package-key";
import type { Mode, PackagePolicy, Policy } from "@capwall/policy-schema";
import { matchesGlob } from "./glob.js";
import { IPC_PSEUDO_HOST, matchesIpcPath } from "./ipc.js";

/** A capability-sensitive operation, attributed to a package, awaiting a decision. */
export type CapabilityRequest =
  | { kind: "fs"; access: "read" | "write"; path: string }
  | { kind: "net"; host: string; port: number }
  /**
   * A unix-domain-socket / Windows-named-pipe connect (issue #72). `path` is the destination,
   * canonicalized by `./ipc.ts` — an absolute `/`-separated path, `/./pipe/NAME` for a named
   * pipe, or `<unknown>` when the call's shape hid it. IPC is its OWN capability rather than a
   * `net` host because it has no host:port pair to name; modelling it as the single pseudo-
   * target `<ipc>:0` is what made one socket grant equal every socket grant.
   */
  | { kind: "ipc"; path: string }
  | { kind: "child_process" }
  | { kind: "worker_threads" }
  | { kind: "env"; key: string }
  | { kind: "vm" }
  /**
   * A DIRECT call to `Module.prototype._compile(source, filename)` (issue #93) — compiling
   * source under a caller-chosen filename, which every resulting stack frame then reports as
   * its `getFileName()`. Only calls that do not come from Node's own module loader reach here,
   * and only when the filename does not already belong to the calling package; see
   * `shims/module.ts` for both discriminators.
   *
   * `filename` is carried for OBSERVABILITY ONLY — logs, the observe trace, `capwall diff` —
   * and is deliberately NOT consulted by {@link isGranted}, for the same reason `native` ignores
   * its path: the grant is the question "may this package name code as somebody else?", which is
   * a boolean, and a filename allowlist would be a per-machine, per-run artifact. It is also the
   * more honest grant, because a package that may compile ONE foreign filename may compile any.
   */
  | { kind: "compile"; filename: string }
  /**
   * A native (`.node`) addon load (roadmap S2, issue #49). `path` is the addon file as
   * resolved at load time; it is carried for OBSERVABILITY ONLY — logs, the observe trace,
   * `capwall diff` — and is deliberately NOT consulted by {@link isGranted}, because the
   * grant is a boolean. See `PackagePolicy.native` for why a path-shaped grant would be
   * non-reproducible across platform/arch/ABI.
   */
  | { kind: "native"; path: string };

/** The outcome of evaluating a request. `reason` is human-readable for `explain`/logs. */
export interface Decision {
  /** The verdict. Always `true` in observe mode, which never denies anything. */
  allowed: boolean;
  reason: string;
  /** The request as observed, for trace→policy generation in observe mode. */
  observed: CapabilityRequest;
  /**
   * Set (by the shim runtime, not by `evaluate`) when attribution fell back to `<unknown>`
   * only because it ran out of stack frames — i.e. a real package owns this call and sits
   * beyond `maxFrames` (issue #15). Absent on every normally-attributed decision.
   * Observability only: the allow/deny outcome above is already final, and since #60 that
   * outcome is deny-by-default rather than the trust root's grants.
   */
  attributionTruncated?: boolean;
}

/**
 * Resolve the effective per-package policy: exact entry, then the wildcard keys that could cover
 * it (most specific first), else the `default` fallback.
 *
 * Own-property checks only: a package name like `__proto__`/`constructor`, or a polluted
 * `Object.prototype`, must not resolve a grant. Deny-by-default means the `default` fallback
 * applies to any pkg without its OWN entry. (Defense-in-depth; prototype pollution remains a
 * documented out-of-scope threat, but the policy lookup itself should not be a vector.)
 *
 * WHY THERE IS A WILDCARD AT ALL (issue #92). Attribution names a nested install by its install
 * chain — `evil>lodash`, `webpack>lodash` — so a hand-written `"lodash": {…}` covers the
 * TOP-LEVEL install only. That is the fix: a dependency that vendors a directory called `lodash`
 * must not inherit `lodash`'s grants. It is also a real cost for the author who genuinely has two
 * copies of a library in the tree and means "the library, wherever npm put it", so that reading
 * stays available as `"*>lodash"` (nested one level) / `"**>lodash"` (any depth) — the same
 * one-vs-many sigils `net.hosts` uses, over `>` instead of `.`. Neither covers the top-level
 * install: "everywhere" is two keys, and being made to write both is the intended friction.
 *
 * The widening is an EXPLICIT, per-package opt-in rather than an implicit fallback, because
 * writing it says something specific and unpleasant: *any* package in the tree may ship a
 * directory named `lodash` and receive these grants. For an `fs.read` glob that is usually fine;
 * for `child_process` it is a bypass with extra steps. An implicit fallback would have made that
 * trade for every package silently, which is the original bug with a longer name.
 *
 * The grammar — including which keys are REFUSED at load time, so a mistyped wildcard is an error
 * rather than a key that quietly matches nothing (#83's lesson) — lives in `@capwall/policy-schema`
 * `package-key.ts`, alongside the host grammar and for the same reason.
 *
 * COST: `widenedPackageKeys` returns an empty array for a top-level name or a sentinel, which is
 * every principal in a tree with no nesting, so the common case is still exactly the one
 * `Object.hasOwn` it always was.
 */
function policyFor(policy: Policy, pkg: string): PackagePolicy {
  if (Object.hasOwn(policy.packages, pkg)) return policy.packages[pkg]!;
  for (const key of widenedPackageKeys(pkg)) {
    if (Object.hasOwn(policy.packages, key)) return policy.packages[key]!;
  }
  return policy.default;
}

/**
 * Decide whether `pkg` may perform `req` under `mode`.
 *
 * In `observe` mode this always allows (recording `observed`); in `enforce` mode it applies
 * deny-by-default against the package's grant.
 *
 * @param policy the loaded policy document.
 * @param mode which of the two semantics above to apply.
 * @param pkg the principal attribution charged the call to — a package name, an install chain
 *     (`webpack>lodash`), or one of the `<app>` / `<unknown>` sentinels.
 * @param req the capability-sensitive operation awaiting a verdict.
 * @returns the verdict plus a human-readable `reason` and the request as `observed`. Pure: it
 *     never throws, never logs, and never mutates `policy`. Enforcement — reporting to
 *     `onDecision` and throwing a `CapabilityError` — is the shim runtime's job, not this
 *     function's.
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

/**
 * Read `grant[key]` only if it is an OWN property, so a polluted `Object.prototype` cannot
 * inject a grant into an empty `{}` (the deny-by-default fallback grant). All grant reads in
 * `isGranted` go through this — defense-in-depth; prototype pollution is a documented
 * out-of-scope threat, but the policy lookup itself must not be a vector.
 */
function own<K extends keyof PackagePolicy>(grant: PackagePolicy, key: K): PackagePolicy[K] | undefined {
  return Object.hasOwn(grant, key) ? grant[key] : undefined;
}

/**
 * Pure grant check (no mode). Exposed for `explain` and tests.
 *
 * @param grant one package's grants — an ALREADY-RESOLVED entry, not the whole document. This
 *     does no `packages` lookup, so wildcard keys and the `default` fallback are the caller's
 *     problem; {@link evaluate} resolves them.
 * @param req the operation to check.
 * @returns whether the grant permits it. `false` for an empty grant, which is what
 *     deny-by-default means.
 */
export function isGranted(grant: PackagePolicy, req: CapabilityRequest): boolean {
  switch (req.kind) {
    case "child_process":
      return own(grant, "child_process") === true;
    case "worker_threads":
      return own(grant, "worker_threads") === true;
    case "vm":
      return own(grant, "vm") === true;
    // `req.filename` is intentionally ignored — see CapabilityRequest's `compile` variant.
    // The grant answers "may this package compile code under a filename that is not its own",
    // and the answer cannot usefully be narrowed to a file list.
    case "compile":
      return own(grant, "compile") === true;
    // `req.path` is intentionally ignored: the grant is a boolean gate on "may this package
    // bring compiled code into the process", not an allowlist of addon files. Matching the
    // path would make every generated policy machine-specific (see PackagePolicy.native).
    case "native":
      return own(grant, "native") === true;
    case "env":
      return (own(grant, "env") ?? []).some((k) => k === "*" || k === req.key);
    case "fs": {
      const fs = own(grant, "fs");
      const globs = req.access === "read" ? fs?.read : fs?.write;
      // Globs are matched lexically against the request path. The policy loader normalizes
      // relative globs against the project root (loadPolicy `projectRoot` option); shims
      // resolve call-time paths to absolute, so absolute-vs-absolute is the common case.
      return (globs ?? []).some((g) => matchesGlob(g, req.path));
    }
    case "net": {
      const net = own(grant, "net");
      if (!net) return false;
      // Exact hostname, the single literal "*", or a wildcard pattern ("*.internal",
      // "**.internal") — one grammar, validated at load time and applied here (#83). See
      // `@capwall/policy-schema` host.ts and docs/policy-format.md § net.
      const hostOk = net.hosts.some((h) => matchesHostPattern(h, req.host));
      // A `"*"` port grants any port — needed for deps that connect to a dynamically-assigned
      // (ephemeral) port, where a concrete observed port won't match on the next run (#27).
      const portOk = net.ports.some((p) => p === "*" || p === req.port);
      return hostOk && portOk;
    }
    case "ipc": {
      // The narrow, preferred form: a glob list over socket paths (#72).
      if ((own(grant, "ipc")?.paths ?? []).some((g) => matchesIpcPath(g, req.path))) return true;
      // BACKWARD COMPATIBILITY. Before #72 every IPC connect was gated as the pseudo-target
      // `<ipc>:0`, so a pre-#72 policy grants IPC through `net`. That shape is still honored and
      // still means EVERY socket and pipe — deliberately unchanged rather than silently
      // narrowed, because a policy that becomes MORE restrictive on upgrade breaks a working
      // deployment just as surely as one that becomes more permissive. The test is written
      // with literal comparisons, NOT through matchesHostPattern: a new host wildcard must
      // never be able to acquire IPC authority as a side effect.
      const net = own(grant, "net");
      if (!net) return false;
      const hostOk = net.hosts.some((h) => h === ANY_HOST || h === IPC_PSEUDO_HOST);
      const portOk = net.ports.some((p) => p === ANY_HOST || p === 0);
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
    case "ipc":
      return `ipc ${req.path}`;
    case "env":
      return `env:${req.key}`;
    case "native":
      return `native ${req.path}`;
    case "compile":
      return `compile ${req.filename}`;
    default:
      return req.kind;
  }
}
