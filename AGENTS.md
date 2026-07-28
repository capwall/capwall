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

**The roadmap is complete: M1–M5 and S1–S4 are all implemented.** `docs/roadmap.md`'s
milestone table is the single source of truth for that — this section describes *what exists*,
not *how far along it is*, so it does not need editing every milestone.

Working end-to-end on **both** the CJS `require` and the ESM `import` paths:
`Module._load` patch / `module.register` hook → stack-walk attribution (nearest-package
policy) → shims → policy evaluate, in both modes. Shims: `fs`; the six egress modules
`net`/`http`/`https`/`tls`/`http2`/`dgram` (registered **separately** — one shim never covers
another, see `docs/threat-model.md` for why that is a security property and not a style
choice); `child_process`; `worker_threads`; `vm`; and `node:module` (gating loader-hook
registration, #61) — all via the require registry in `core/src/shims/index.ts` — plus **four
surfaces that are not import-routed and so are installed eagerly by `install()`**:
`process.env` (a read allowlist via a Proxy), the `native` `.node` load gate (a
`process.dlopen` patch, `core/src/loader/native.ts`), the **global egress guard** (#80 —
`globalThis.fetch`/`WebSocket`/`EventSource` replaced on `globalThis`,
`core/src/shims/global-egress.ts`), and the **`Module.prototype._compile` gate** (#93 — the
`compile` capability, `core/src/shims/module.ts`). Capability kinds in the policy language:
`fs`, `net`, `ipc` (#72), `env`, `child_process`, `worker_threads`, `vm`, `native` (#49) and
`compile` (#93). Two of those are decided at **module-load time** rather than at a capability
call: `compile`, and (since #123) an `fs.read` on a `require`/`import` of a file outside every
`node_modules` tree — the module system was a second, un-gated route to the bytes `fs` guards.
`capwall observe`
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

The stretch items also landed: **S1** SBOM/CBOM →
policy (`@capwall/sbom-import`), **S4** the perf benchmark (`pnpm bench`; measured overhead is
tens of microseconds per INTERCEPTED CALL, well inside the <1ms budget — with one measured
exception, `{...process.env}`, where a single JS call is one interception per env key; see
§ 5 and `scripts/bench/README.md`), **S3** the observed-vs-declared drift diff (`capwall diff`), and **S2** the
native-addon load gate
(`native` capability, `core/src/loader/native.ts` — a `process.dlopen` patch; gating only,
never confinement, see `docs/threat-model.md` § Native `.node` addons). The **ESM hook (M5)**
is implemented (both static and dynamic `import` of mediated builtins are intercepted via a `module.register` hook; on by default under the CLI, `CAPWALL_ESM=0` to disable). Shims are handed out
**mutable by default** (graceful-fs compatibility); opt-in **hardened mode**
(`install(…, { hardened: true })` / `CAPWALL_HARDENED=1`, issue #17) freezes them instead —
see `core/src/shims/harden.ts` and threat-model.md § Hardened mode for what it does and does
not close. Build order is
authoritative in `docs/roadmap.md` and mirrored in § 4 below.

**Nothing is published to npm.** All four packages are `version: 0.0.0` and neither
`@capwall/cli` nor `@capwall/core` exists on the registry, so every user-facing doc must show
the run-from-a-clone path (`pnpm install && pnpm build`, then
`node packages/cli/dist/index.js …`) rather than an install command that 404s. Revisit every
such spot at first publish.

**A third principal, `<unknown>` (#60).** Unattributable calls no longer collapse into the
exempt `<app>` sentinel — they charge `<unknown>`, an ordinary deny-by-default principal that
a policy can grant explicitly. Any doc that describes attribution as two-valued is stale; see
`docs/threat-model.md` § attribution outcomes and `docs/policy-format.md` § Two sentinel keys.

**Global egress IS mediated (#80, shipped in #85).** `globalThis.fetch`/`WebSocket`/
`EventSource` are not module surfaces, so the loader mechanism never sees them — they are
guarded by replacing them on `globalThis` instead, against the same `net` grant a module-surface
egress call is checked against, on by default under the CLI (`CAPWALL_GLOBAL_EGRESS=0` to
disable). Earlier revisions of this file called that an open gap; it is not, and describing it
as one understates the tool. The residuals that *are* real — redirect hops guarded only after
the request has gone out, `init.dispatcher`, pre-install capture, and
`Object.defineProperty(globalThis, "fetch", …)` even under hardened mode — are named in
`docs/threat-model.md` § Global egress surfaces. Quote those, not the old paragraph.

**Nothing published yet, but the release path exists.** `docs/releasing.md` is the runbook and
`.github/workflows/release.yml` is the workflow (whose *filename* is part of npm trusted
publishing's trust configuration — do not rename it). Two guards enforce the one rule that
matters: `scripts/assert-pnpm-pack.mjs` (`prepack`) refuses an `npm pack`, because only pnpm
rewrites `workspace:*` into a real version (#116); `scripts/assert-pnpm-install.mjs` (root
`preinstall`) refuses an `npm install` at the clone root, which otherwise exits 0 having linked
nothing (#122). `scripts/check-release-versions.mjs` is the
pre-publish guard that keeps the four packages in **version lockstep** and matching the tag
(#115) — so a version bump is all four manifests or none. All four are `0.0.0` today; read
version numbers from `package.json`, never hardcode one.

## 3. Architecture orientation

Data flow: **`require`/`import` → attribute the call to its owning package → look up that
package's policy → observe-log the capability, or enforce-deny it.**

Where each concern lives:

| Concern | Location |
|---|---|
| Public API — `install(policy, mode)` | `packages/core/src/index.ts` |
| CJS `require` patch | `packages/core/src/loader/require.ts` |
| ESM loader hook (`module.register`) | `packages/core/src/loader/{esm-hook,esm-hooks,esm-runtime}.ts` |
| Real-builtin capture (the ONLY place a mediated builtin is loaded — CJS on purpose, #78) | `packages/core/src/real-builtins.cts` |
| Native `.node` load gate (`process.dlopen`) | `packages/core/src/loader/native.ts` |
| Core-API capability shims | `packages/core/src/shims/{fs,net,child_process,worker_threads,env,vm}.ts` (`net.ts` registers all six egress modules) |
| Global egress guard — `globalThis.fetch`/`WebSocket`/`EventSource` (#80) | `packages/core/src/shims/global-egress.ts` |
| The module system as a read channel — an `fs.read` decision on a `require`/`import` outside every `node_modules` tree (#123) | `packages/core/src/loader/module-read.ts` |
| Loader-hook registration gate (`node:module`) **and** the `Module.prototype._compile` / `compile` gate (#93) | `packages/core/src/shims/module.ts` |
| **Process-global patch lifecycle** — the ONLY file in `core/src` allowed to write a process global; every new patch site goes through it (#107, enforced by `test/process-patch-sites.test.ts`) | `packages/core/src/lifecycle/process-patch.ts` |
| **The live install-context box** — what every guard reads, so a policy swap is live in both directions (#62/#87); also the `hardened` ratchet (#129) | `packages/core/src/loader/live-context.ts` |
| Shared shim plumbing / opt-in hardened mode / option pinning | `packages/core/src/shims/{runtime,harden,pin,url-snapshot}.ts` |
| Stack-walk → owning package | `packages/core/src/attribution/index.ts` |
| Linked/workspace dependency identity — a link's source is its principal (#127) | `packages/core/src/attribution/link-map.ts`, `packages/core/src/loader/linked-packages.ts` |
| Policy load / mode resolution / evaluate / IPC paths | `packages/core/src/policy/{load,mode,evaluate,glob,ipc}.ts` |
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
- **CJS-first.** The CJS `require` path is the primary target and was built first; the ESM
  `import` path reached parity in M5 and is on by default under the CLI. New capability work
  still lands CJS-first, then gets ESM coverage — but "ESM is not done yet" is no longer a
  true statement about the repo. Source is authored in TS and compiled with `tsc` per package.
- **pnpm workspace.** Packages reference each other with `workspace:*`. No new **runtime**
  dependencies without justification in the PR description — every dep is attack surface for
  a supply-chain tool. Dev deps (vitest, typescript) are fine.
- **vitest** for tests; **`tsc --noEmit`** for typecheck (see § 6 — build alone is not
  enough); **oxlint** (`pnpm lint`, config in `.oxlintrc.json`) for lint. Lint is a *defect*
  gate, not a style gate — it is configured to catch what `tsc` cannot (unused bindings,
  `no-explicit-any`, misuse patterns) and the pedantic/style rules are deliberately off. If a
  new rule would mean reformatting the codebase, it does not belong here.
- **Performance.** The target is **<1ms per INTERCEPTED CALL**, and that qualifier is now
  load-bearing. The S4 benchmark (`pnpm bench`) measures every mediated surface at tens of
  microseconds of added latency, comfortably inside the budget — but **one JS call is not
  always one interception**, and where it is not, the per-call budget does not hold:
  `{...process.env}` is ~2 interceptions per environment variable and costs **milliseconds**
  (measured ~4.4ms on an 81-key environment; issue #133). The harness prints those cases under
  `AMPLIFICATION` on every run; do not quote the headline without them. See
  `scripts/bench/README.md` § Where the budget does not hold.
  Two more things the benchmark now says that older notes here did not:
  **cost scales with stack depth** (attribution materializes up to `maxFrames` CallSites per
  call, so a 3-frame stack — what the old harness measured — under-reports a realistic one by
  ~40%), and at a realistic depth **attribution is ~70% of the added latency**, not the ~50%
  issue #34 recorded from a shallow stack. `evaluate()` is negligible (~125ns). Cache
  module→package resolution (the path→package cache gives ~50x cold-vs-warm); if you need
  headroom, the stack walk is where it is.
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
- Keep smoke tests trivial but real (`packages/core/test/core.test.ts` asserts the
  evaluator's deny-by-default semantics and observe-mode pass-through — extend, don't
  delete).

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

- **Native-addon confinement.** `.node` addons ARE gated (allowed to load or not — the
  `native` capability, S2/#49) but are never confined once loaded. Keep every doc claim on the
  gate side of that line; overclaiming here would be worse than not shipping the feature.
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
