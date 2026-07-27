# AGENTS.md — build onboarding for capwall

You are an autonomous coding agent picking up **capwall** from its scaffold. Read this
whole file, then `docs/roadmap.md`, before writing code. Run `pnpm install` first
(`node_modules` is gitignored; a `pnpm-lock.yaml` is committed).

## 1. Mission

Build a **runtime, per-package capability firewall for Node.js**: intercept the
capability-sensitive core surface (`fs`, `net`/`http(s)`, `child_process`,
`worker_threads`, `process.env`, `vm`), attribute each call to the **owning package**, and
allow or deny it against a declarative per-package policy (`capabilities.json`). Two modes:
`observe` (log, never block — the on-ramp) and `enforce` (deny-by-default, throw).

The differentiators, and the reason this project exists, are: **no SES tax** (we shim the
core API surface instead of hardening every primordial, so adoption friction is near-zero),
**per-package granularity** (unlike Node's process-global `--permission`), and the headline
**trace-to-policy DX** — run once in `observe`, auto-emit a starter policy, tighten, flip to
`enforce`. Inspired by the KTH-LangSec **NodeShield** prototype (CCS 2025,
DOI 10.1145/3719027.3765136); capwall is the usable, DX-first realization of that idea.

capwall is **defense-in-depth, not a formal sandbox.** It stops opportunistic, worm-style
supply-chain malware (Shai-Hulud, Glassworm class) that runs at application-runtime. It does
**not** withstand a determined in-process attacker. Keep every doc claim consistent with
that — see § 8.

## 2. Current state

**Roadmap M1–M4 are implemented (all core shims, CJS path).** Working end-to-end:
`Module._load` patch → stack-walk attribution (nearest-package policy) → shims → policy
evaluate, in both modes. Shims: `fs`, `net`/`http`/`https` (egress), `child_process`,
`worker_threads`, `vm` (via the require registry in `core/src/shims/index.ts`), and
`process.env` (a read allowlist via a Proxy, installed in `install()`). `capwall observe`
emits/merges a starter `capabilities.json` covering all capability kinds, and `capwall
enforce` denies-by-default (`malicious-dep-demo` is blocked on both env and fs; `express-app`
runs clean — zero denials, `capwall diff` exits 0 — under the **observed-then-hand-reviewed**
policy committed in that directory).

Mind that qualifier. A raw `observe` policy is a draft, not a shippable artifact: its `env`
entries are host-specific, because a package that merely enumerates `process.env` is recorded
as reading every key the machine has (`examples/express-app/README.md` works the case;
issues #57, #67). **When you add or change a capability shim, re-verify both committed
example policies** — the express-app claim above silently became false when M4's env shim
landed, and stayed false until #57. `packages/cli/test/express-app-policy.test.ts` gates it
now.

Two stretch items also landed: **S1** SBOM/CBOM →
policy (`@capwall/sbom-import`) and **S4** the perf benchmark (`pnpm bench`; measured overhead
is ~30x under the <1ms/req budget — see issue #34 on the cost model). The **ESM hook (M5)** is implemented (both static and dynamic `import` of mediated builtins are intercepted via a `module.register` hook; on by default under the CLI, `CAPWALL_ESM=0` to disable). Build order is
authoritative in `docs/roadmap.md` and mirrored in § 4 below.

## 3. Architecture orientation

Data flow: **`require`/`import` → attribute the call to its owning package → look up that
package's policy → observe-log the capability, or enforce-deny it.**

Where each concern lives:

| Concern | Location |
|---|---|
| Public API — `install(policy, mode)` | `packages/core/src/index.ts` |
| CJS `require` patch | `packages/core/src/loader/require.ts` |
| ESM loader hook (`module.register`) | `packages/core/src/loader/esm-hook.ts` |
| Core-API capability shims | `packages/core/src/shims/{fs,net,child_process,worker_threads,env,vm}.ts` |
| Stack-walk → owning package | `packages/core/src/attribution/index.ts` |
| Policy load / mode resolution / evaluate | `packages/core/src/policy/{load,mode,evaluate}.ts` |
| Policy schema + shared TS types (imported directly, never restated in core) | `packages/policy-schema` |
| CLI (`observe`/`enforce`/`run`/`diff`/`gen-policy`/`explain`) | `packages/cli/src/commands/*` |
| SBOM → policy (stretch) | `packages/sbom-import` |

The shims are the enforcement point: each wraps a core module, and on every
capability-sensitive call asks `attribution` "who is calling?" then asks `policy/evaluate`
"is this allowed for that package in this mode?".

## 4. Build order (authoritative)

Mirror `docs/roadmap.md`. **Get observe→policy→enforce working end-to-end on ONE capability
(`fs`) before adding breadth.**

1. **Vertical slice on `fs`.** CJS `require` patch + attribution + the `fs` shim, wired
   behind `observe` mode, with the `express-app` example running end-to-end (observe logs
   its fs/net use, nothing blocked).
2. **Trace → `capabilities.json` generation.** `capwall observe` records observed
   capabilities and emits a starter policy. This is the headline feature — do it early.
3. **`enforce` mode.** Deny-by-default; throw on violation; `malicious-dep-demo` is blocked.
4. **Remaining shims.** `net`/`http(s)`, `child_process`, `worker_threads`, `env`, `vm`.
5. **ESM.** Loader hooks via `module.register`; reach parity with the CJS path.
6. **SBOM import (stretch).** CycloneDX/CBOM → policy in `packages/sbom-import`.

Do not start step *n+1* until step *n* has passing tests and a clean typecheck.

## 5. Conventions

- **TypeScript strict + `exactOptionalPropertyTypes`.** Config is in `tsconfig.base.json`;
  each package extends it. Also on: `noUncheckedIndexedAccess`, `noImplicitOverride`.
- **CJS-first.** The CJS `require` path is the primary target; ESM fast-follows (step 5).
  Source is authored in TS and compiled with `tsc` per package.
- **pnpm workspace.** Packages reference each other with `workspace:*`. No new **runtime**
  dependencies without justification in the PR description — every dep is attack surface for
  a supply-chain tool. Dev deps (vitest, typescript) are fine.
- **vitest** for tests; **`tsc --noEmit`** for typecheck (see § 6 — build alone is not
  enough); **oxlint** (`pnpm lint`, config in `.oxlintrc.json`) for lint. Lint is a *defect*
  gate, not a style gate — it is configured to catch what `tsc` cannot (unused bindings,
  `no-explicit-any`, misuse patterns) and the pedantic/style rules are deliberately off. If a
  new rule would mean reformatting the codebase, it does not belong here.
- **Performance.** Keep the hot path (attribution + policy lookup per intercepted call) with
  the **<1ms/req** target in mind — the S4 benchmark (`pnpm bench`) measures ~30x headroom.
  The cost splits roughly evenly between **attribution stack-walking (~40%)** and the **shim
  wrapper's own dispatch (~55%)** — not attribution-dominant as originally assumed (see issue
  #34); policy `evaluate()` is negligible. Cache module→package resolution (the path→package
  cache gives ~20x cold-vs-warm); if you need more headroom, profile the shim wrapper too.
- **License hygiene.** capwall is MIT. **Do NOT** pull in non-compete / source-available
  code (e.g. PolyForm-licensed Socket code). Prefer permissive (MIT/BSD/Apache-2.0) deps
  only.

## 6. Definition of done (per feature)

A feature is done only when **all** of:

- Tests pass: `pnpm test`.
- Typecheck is clean over **src *and* tests**: `pnpm typecheck` (which runs
  `tsc --noEmit`). Note: `pnpm build` (per-package `tsc` emit) does **not** type-check test
  files — a green build is not a green typecheck. Run the typecheck.
- Lint is clean: `pnpm lint` (oxlint, whole repo, one pass).
- Once `enforce` exists: the `malicious-dep-demo` fixture is **blocked in `enforce` mode**
  and **allowed (only logged) in `observe` mode**.

**GitHub Actions is billing-blocked (issue #3), so there is no automated CI.** Reproduce the
full `ci.yml` matrix (Node 20 **and** 22, clean install → build → typecheck → test → lint) in
Docker with `pnpm ci:local` — a green run there is a green CI run. See
[`docs/ci-local.md`](docs/ci-local.md). Until Actions billing is restored, treat `pnpm ci:local`
as the gate.

## 7. Testing

- vitest, colocated in each package's `test/`.
- Required regression: a **fixture-based test that a package NOT present in the policy is
  denied `fs` access in `enforce` mode** (deny-by-default), and merely logged in `observe`.
- The `express-app` example must actually run under `capwall observe` and `capwall enforce`,
  and must run **clean** under its own committed policy: zero `DENY` lines in enforce, and
  `capwall diff` exiting 0. Gated by `packages/cli/test/express-app-policy.test.ts`, which
  runs it in a scrubbed, deliberately noisy environment — a policy that only passes in your
  shell is not a passing policy (#57).
- Keep smoke tests trivial but real (the scaffold's `packages/core/test/core.test.ts`
  already asserts deny-by-default on the stub evaluator — extend, don't delete).

## 8. Threat-model guardrails

- **Never claim formal-sandbox or isolation guarantees.** capwall is pragmatic
  defense-in-depth. Keep `docs/threat-model.md` honest and in sync with any capability you
  add or weaken.
- The "what it does NOT stop" list (prototype pollution, shared mutable primordials,
  fd/symlink escapes, un-patching shims, `vm`/`eval`, native `.node` addons, subprocess
  internals) is a feature of the docs, not an embarrassment. Do not quietly drop it.
- **Malicious fixtures must stay obviously inert.** `examples/malicious-dep-demo` may only
  `console.log("would exfiltrate …")`. Never write real exfiltration, real network egress,
  or anything that touches a real secret. The demo proves the **block**, not the attack.

## 9. Non-goals (MVP)

- **Native-addon confinement.** `.node` addons can be gated (allowed to load or not) but not
  confined once loaded.
- **Subprocess-internal confinement.** We can gate whether a `child_process` spawn happens;
  we do not confine what the child does.
- **Browser / bundler builds.** That is LavaMoat's turf.
- **Being a package scanner.** Detection of known-bad packages is guarddog's / Socket's job;
  capwall assumes a bad package got through and contains it at runtime.

## 10. References

- **NodeShield** — KTH-LangSec research prototype and the CCS 2025 paper "Runtime
  Enforcement of Security-Enhanced SBOMs for Node.js" (Cornelissen & Balliu),
  [DOI 10.1145/3719027.3765136](https://doi.org/10.1145/3719027.3765136). *The core
  mechanism capwall productizes; a dead single-commit prototype with no DX.*
- **LavaMoat** — <https://github.com/LavaMoat/LavaMoat>. *The mature SES-based OSS analog;
  capwall's non-SES contrast (lower isolation strength, far lower adoption friction).*
- **Node.js permission model** — <https://nodejs.org/api/permissions.html>. *Process-global,
  not per-package; capwall adds the per-package dimension.*
- **Endo / SES** — <https://github.com/endojs/endo>. *The hardened-primordials approach
  capwall deliberately does not take; read it to understand the isolation we trade away.*
