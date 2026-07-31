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
`Module._load` patch / `module.registerHooks()` hooks → stack-walk attribution (nearest-package
policy) → shims → policy evaluate, in both modes. Shims: `fs`; the six egress modules
`net`/`http`/`https`/`tls`/`http2`/`dgram` (registered **separately** — one shim never covers
another, see `docs/threat-model.md` for why that is a security property and not a style
choice); `child_process`; `worker_threads`; `vm`; and `node:module` (mediated for a structural rule —
no own key may hand back an un-shimmed route to the shimmed surface — **not** for the #61
loader-hook gate, which #181 moved onto the function objects; see below) — all via the require
registry in `core/src/shims/index.ts` — plus **six
surfaces that are not import-routed and so are installed eagerly by `install()`**:
`process.env` (a read allowlist via a Proxy), the `native` `.node` load gate (a
`process.dlopen` patch, `core/src/loader/native.ts`), the **global egress guard** (#80 —
`globalThis.fetch`/`WebSocket`/`EventSource` replaced on `globalThis`,
`core/src/shims/global-egress.ts`), the **`Module.prototype._compile` gate** (#93 — the
`compile` capability, `core/src/shims/module.ts`), the **loader-hook registration gate** (#61,
moved here by #181 — `Module.register`/`Module.registerHooks` patched on the function objects
every route converges on, so `module.constructor.registerHooks` and
`process.getBuiltinModule("node:module").registerHooks` read the gated property too;
`core/src/shims/module.ts`), and the **Web Storage guard** (#156 —
`globalThis.localStorage` replaced on `globalThis`, its six members taking an **`fs`** read/write
decision on the `--localstorage-file` path Node otherwise reads and writes below the `fs` shim;
Node ≥26 and flag-gated, so it registers no patch site at all anywhere else,
`core/src/shims/web-storage.ts`). Capability kinds in the policy language:
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
is implemented (both static and dynamic `import` of mediated builtins are intercepted via
`module.registerHooks()` — synchronous, same-realm, same-thread hooks, which Node ≥22.15 has and
which #173 migrated to off the DEP0205-deprecated `module.register()`; on by default under the
CLI, `CAPWALL_ESM=0` to disable. Those hooks are consulted for `require()` as well as `import()`,
so the ESM perimeter now overlaps the CJS one — see `loader/esm-hooks.ts` on why that is a second
layer rather than a duplicate decision). Shims are handed out
**mutable by default** (graceful-fs compatibility); opt-in **hardened mode**
(`install(…, { hardened: true })` / `CAPWALL_HARDENED=1`, issue #17) freezes them instead —
see `core/src/shims/harden.ts` and threat-model.md § Hardened mode for what it does and does
not close. Build order is
authoritative in `docs/roadmap.md` and mirrored in § 4 below.

**Nothing is published to npm.** The manifests are staged at `0.1.0` but nothing has been
uploaded — neither `@capwall/cli` nor `@capwall/core` exists on the registry, so every
user-facing doc must show
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
nothing (#122). **Versions and `CHANGELOG.md` are owned by release-please** — never bump a
manifest by hand; `release-please-config.json` declares ONE package (the repo root) that writes
all five `version` fields through `extra-files`, which is what makes lockstep structural rather
than conventional, and the `linked-versions` plugin is deliberately *not* used (it cannot group a
component whose tag has no prefix — `docs/releasing.md` has the dry-run evidence).
`scripts/check-release-versions.mjs` is the pre-publish guard for everything a machine can check
about a release (#115): **version lockstep** across the four packages and the root, the tag
matching, internal deps declared `workspace:*` so they publish as exact pins, a dated
`CHANGELOG.md` section, the declared publish set, and that release-please's config still has the
shape lockstep depends on. `scripts/check-tarball-sources.mjs` opens the packed tarballs and
asserts every source map resolves inside its own tarball (#126), the packaging defect no other
gate can see. All four move together in lockstep; **read version numbers from `package.json`,
never hardcode one.**

**`@capwall/sbom-import` is deliberately not published** — nothing consumes it, so it would land
on npm as an unreachable library. It stays in lockstep in-repo.
The publish set is declared once, in `check-release-versions.mjs` (`--publish-list`); the
workflow reads it from there. See `docs/releasing.md` § What is published.

**`CHANGELOG.md` is generated by release-please from the commit messages — do not hand-edit it.**
The commit subject *is* the entry, which is why conventional commits are enforced on every pull
request (`scripts/check-commit-messages.mjs`, `.github/workflows/commit-conventions.yml`,
`pnpm lint:commits`) — a zero-dependency validator that reads the accepted types out of
`release-please-config.json` so the grammar and the release pipeline cannot drift apart —
and why the PR **title** is the one that matters: this repo squash-merges. `feat` → *Added*,
`fix` → *Fixed*, `perf` → *Performance*, `refactor` → *Changed*, and **`security`** — a type this
project adds to the conventional set — → *Security*, because "capwall stopped mediating X" has to
be findable without reading the diff. `docs`/`test`/`build`/`ci`/`chore`/`style` are hidden.
`CONTRIBUTING.md` § 3 is the short table; `docs/releasing.md` § How a release happens is the
pipeline.

## 3. Architecture orientation

Data flow: **`require`/`import` → attribute the call to its owning package → look up that
package's policy → observe-log the capability, or enforce-deny it.**

Where each concern lives:

| Concern | Location |
|---|---|
| Public API — `install(policy, mode)` | `packages/core/src/index.ts` |
| CJS `require` patch | `packages/core/src/loader/require.ts` |
| ESM loader hooks (`module.registerHooks()` — synchronous, this thread, also on the `require()` path) | `packages/core/src/loader/{esm-hook,esm-hooks,esm-runtime}.ts` |
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
5. **ESM.** Loader hooks via `module.registerHooks()`; reach parity with the CJS path.
6. **SBOM import (stretch).** CycloneDX/CBOM → policy in `packages/sbom-import`.

Do not start step *n+1* until step *n* has passing tests and a clean typecheck.

## 5. Conventions

- **TypeScript strict + `exactOptionalPropertyTypes`.** Config is in `tsconfig.base.json`;
  each package extends it. Also on: `noUncheckedIndexedAccess`, `noImplicitOverride`. The
  compiler is **TypeScript 7** (the Go rewrite). One thing about it is load-bearing and easy to
  undo by accident: `tsconfig.base.json` sets `"types": ["node"]` explicitly, because TS 7
  defaults that to `[]` where 5.x auto-included every `@types/*` package in scope. Delete the
  line and every build config loses all of `@types/node` at once (148 errors in `core` alone —
  `Cannot find name 'process'`). TS 7.0 also ships **no programmatic API**, so a `.d.ts`
  validation gate or an api-extractor-style check is not available until 7.1.
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
  (issue #133 halved the per-interception cost and it is still ~2 ms on an 81-key environment,
  down from ~4.4 ms). The harness prints those cases under `AMPLIFICATION` on every run; do not
  quote the headline without them. See `scripts/bench/README.md` § Where the budget does not
  hold — including why two captures per key is the floor rather than a to-do.
  Two more things the benchmark now says that older notes here did not:
  **cost was attribution-dominant** — ~70% of the added latency at a realistic stack depth, not
  the ~50% issue #34 recorded from a shallow stack — and **it scaled with stack depth**, so a
  3-frame stack (what the old harness measured) under-reported a realistic one by ~40%.
  Issue #143 took that lever: every guarded surface now hands its OWN entry frame to
  `Error.captureStackTrace`, which applies `stackTraceLimit` *after* the boundary skip, so a
  mediated call materializes 3 CallSites instead of 25 — same walk, same principal, and the
  depth-dependence is largely gone with it. Measured 2.8x on `fs` at the frame cap, 1.9x on
  `net.connect`, 1.7–2.0x on the deny paths; `spawnSync` shows no resolvable change because a
  3 ms syscall dominates it, and the `dlopen` gate is deliberately excluded (its callers are
  seven `node:internal/modules/*` frames away, so a short prefix would decline every time).
  When you add a guarded surface, `guard()` REQUIRES the entry frame — that is not a style
  preference, it is a 30 µs default nobody would notice.
  `evaluate()` is negligible (~125ns). Cache module→package resolution (the path→package cache
  gives ~50x cold-vs-warm).
  **There is a second budget, on a different axis: STARTUP.** A mediated child costs **141–179 ms**
  (min estimator, idle 16-core: 178.8 on Node 22, 161.9 on 24, 141.0 on 26) where a bare `node`
  costs **37–45 ms** — so ~100–135 ms is capwall, paid once per process by every user on every
  process they mediate. Quote those, not the ~250 ms / ~180 ms p90 pair an earlier revision of this
  bullet carried: that pair predates #152 and is high by ~80–95 ms. `bench.mjs` does not measure
  this axis at all; `pnpm bench:startup` does, and the breakdown is in `scripts/bench/README.md`
  § Startup and § After #152.
  **What gates that budget, stated precisely, because the previous version of this paragraph named
  a guard that no longer exists.** It said `module.register()` blocks the main thread while Node's
  loader thread evaluates the hook module's whole import graph, and that
  `test/esm-hook-graph.test.ts` fails on the two shapes that regress it (#150). Both halves went
  with #173: the perimeter is `module.registerHooks()`, so there is no loader thread and no
  blocking graph, and #150's two static scans were deleted in the same PR because the realm they
  described was gone (that test file's own header is the record). What `test/esm-hook-graph.test.ts`
  enforces **today** is three properties, each measured in a clean child:
  - **capwall's ESM install starts no module-customization thread** (#152) — read off
    `process.moduleLoadList`, with a bare `module.register()` in the same child as the positive
    control, so "no thread" cannot be confused with "the probe stopped reporting". Mutant
    `esm-no-loader-thread`.
  - **a mediated process writes NOTHING to stderr while registering** (#153) — asserted as exact
    emptiness, which is also how a loader crash or a new experimental warning surfaces.
  - **the main thread's startup graph does not silently widen** (#167) — a CEILING ON A MODULE
    COUNT: resolves under `zod/` once `policy/load.js` is in, budget 224 against an observed 180,
    the headroom derived from 15 ms at the measured ~0.34 ms per resolve, plus a self-check that
    pins the ceiling to that floor so raising one without re-deriving the other fails.
  **Nothing scans `loader/esm-hooks.ts`'s import graph any more, so keeping it narrow is a
  CONVENTION and not a gate — do not add an import there expecting a test to stop you.** #167's
  counter only sees modules under `zod/`; a first-party module, or any third-party module that is
  not zod, joins the startup graph with every gate green. It is still real money: #171 priced the
  main-thread graph at **~450–500 µs per ES module** (35 modules cost 15–18 ms over the identical
  source in one file), so roughly two modules is a millisecond. If you widen that graph, the way to
  learn what it cost is `pnpm bench:startup` on 22/24/26, not `pnpm test`.
  **The same reasoning applies to `preload.ts`'s graph, and zod 4 is what it cost.** `zod`
  3 → 4 (#161) added **~58 ms** to that graph: ~+60 ms of zod's own module evaluation (79 ES
  modules where v3 had 10), ~+11 ms building the schema tree, and *zero* in `parsePolicy` — zod 4
  validates the real policy file at exactly zod 3's speed. It was taken anyway, because every
  route to the milliseconds ran through not validating the policy at startup, and a policy that
  is trusted rather than validated is a fail-open in the one component that decides what
  everything else may do. Do not re-litigate that from `pnpm outdated`; the measurement, the
  entry points that were tried (`zod/mini`, `zod/v4/core`, CJS) and the one lever left unpulled
  (Node's on-disk V8 compile cache, worth ~34 ms) are in `scripts/bench/README.md` § zod 4.
  **The ESM perimeter's migration is DONE — #152 and #153 are closed, landed by #173. Do not
  re-do it.** `module.register()` is Stability 0 and runtime-deprecated as DEP0205 in Node 26,
  where it printed a DeprecationWarning in every mediated process and, under `--throw-deprecation`,
  stopped the application starting outright; capwall does not call it anywhere.
  `packages/core/src/loader/esm-hook.ts` registers with `module.registerHooks()` and calls the
  returned `deregister()` when the last install unwinds — the line `register()` could not offer,
  and the reason the CJS and ESM paths now agree after teardown instead of ESM being fail-closed.
  Two consequences are live constraints on new work rather than history: **these hooks are
  consulted for `require()` as well as `import()`**, so a change to `resolve`/`load` is a change to
  the CJS path too (see `loader/esm-hooks.ts` on why the module-read gate must not decide the same
  load twice), and `registerHooks()` is Stability 1.2, so its status per major is tracked in
  `docs/node-api-dependencies.md` and re-measured rather than assumed.
- **License hygiene.** capwall is MIT, and the gate is **scoped by whether the dependency
  ships**. An earlier revision of this bullet said "permissive only" without saying *where*,
  which read as one blanket rule and blocked a devDep major over a licence that never reaches
  a user (#158/#159). Three rules, in decreasing severity:
  - **Non-compete / source-available code is refused at ANY depth, dev or runtime.** PolyForm
    (e.g. Socket's), BUSL, SSPL, Elastic, anything "free for non-commercial use". No dev-only
    carve-out and no exceptions — this is the prohibition the section was written for, and it
    is about what capwall is allowed to be built from, not about what it distributes.
  - **Runtime dependencies: MIT / BSD / Apache-2.0 only.** That gate does not move. Weak
    copyleft is *not* acceptable here. Runtime deps are shipped inside the published tarballs,
    so their licences become every consumer's problem as well as ours. Today the entire
    runtime closure of all four publishable packages is one package — `zod`, MIT — and
    `pnpm --filter '@capwall/*' licenses list --prod` is how you confirm that in one command.
  - **Weak copyleft (MPL-2.0 and similar) is acceptable in devDependencies.** npm does not
    bundle devDeps, and capwall's `files` fields are narrow: a packed `@capwall/core` is
    `dist/`, `src/`, `LICENSE`, `README.md`, `package.json` — nothing else, no `node_modules`.
    An MPL-2.0 build tool is therefore never distributed by capwall and never reaches a user.
    This is what unblocked vitest 4, whose vite 8 hard-depends on MPL-2.0 `lightningcss`, a
    CSS transformer this project never calls.

  **The known trade-off, accepted deliberately rather than missed.** Some enterprise licence
  scanners flag copyleft anywhere in a dependency tree, devDeps included, and report on the
  lockfile rather than on the tarball. So capwall can be legally clean and still surface as a
  finding — in precisely the procurement review a security tool has to survive to get adopted.
  That was weighed against permanently freezing dev tooling one major behind, and the tooling
  won. If it ever bites a real adopter, the lever is a `pnpm.overrides` pin **with the reason
  written next to it**; #158 removed two overrides that had no reason attached and had quietly
  aged into version caps, so an unexplained pin is worse than none.

  Nothing in `scripts/` enforces any of this — it is a review gate, and `pnpm licenses list`
  is the command. If that ever changes, the check has to encode these three rules and not the
  blanket one, because a policy stated in prose and enforced more strictly in code is the
  drift this project keeps finding.

## 6. Definition of done (per feature)

A feature is done only when **all** of:

- Tests pass: `pnpm test`.
- Typecheck is clean over **src *and* tests**: `pnpm typecheck` (which runs
  `tsc --noEmit`). Note: `pnpm build` (per-package `tsc` emit) does **not** type-check test
  files — a green build is not a green typecheck. Run the typecheck.
- Lint is clean: `pnpm lint` (oxlint, whole repo, one pass).
- Once `enforce` exists: the `malicious-dep-demo` fixture is **blocked in `enforce` mode**
  and **allowed (only logged) in `observe` mode**.

**GitHub Actions now runs** — the repo was transferred to `capwall/capwall` and made public,
which gives it unlimited standard-runner minutes, so the billing block (issue #3) no longer
applies and is closed. `ci.yml` is green on the full Node 22/24/26 matrix, on `main` and on a
release-please PR branch. That does not retire `pnpm ci:local`: it is still the local pre-push
gate and the only thing that reproduces the matrix before you push, in Docker, against your
uncommitted edits. Reproduce the full `ci.yml` matrix (Node **22, 24 and 26**, clean install →
build → typecheck → test → lint) with `pnpm ci:local` — a green run there is still a green CI
run, and now Actions checks it again on the PR. See [`docs/ci-local.md`](docs/ci-local.md).

**The supported range is `>=22.15.0`, declared in all five manifests' `engines`** — the four
packages and the private root. Node 20 went
EOL on 2026-04-30 and was dropped. The floor is 22.15 rather than 22.0 for one reason:
`module.registerHooks()` landed in 22.15, and capwall wants it **without a version gate** (#152).
Four copies of that fact have to move together — `engines` in the five manifests, the
`node-version` matrix in both workflows, the default in `scripts/ci-local.sh`, and the
`ci:local:<version>` shortcuts in the root manifest. `packages/core/test/node-matrix.test.ts`
asserts all four agree, and that the stated manifest count is the number of manifests that
actually carry `engines`. Node 26 is in
the matrix as early warning: it becomes LTS on 2026-10-28, and it is already the leg that caught
`module.register()`'s DEP0205 deprecation and six new globals.

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
- **Start child processes through `packages/core/test/helpers/subprocess.ts`, and no more than
  two per test.** ~190 of the suite's children are a full `node` startup (122 in `core`, 69 in
  `cli`), because hardened mode and the ESM module registry are process-sticky: a synthetic
  `capwall-esm:` module, once evaluated, stays in the realm's registry for the life of the process,
  so a second install in the same process cannot re-decide an import the first one already served.
  **Hook REGISTRATION is no longer on that list** — `module.registerHooks()` returns a
  `deregister()` and `uninstall()` calls it (#152), where `module.register()` could not be undone
  at all. Each child costs ~0.5s, and the per-test timeout is arithmetic on that count —
  which a setup file enforces, so a third child fails by name rather than by quietly
  invalidating a budget nobody re-derived. The helper owns the budget, the measurements behind
  it, and the failure message. A test over budget usually wants splitting; two `it`s asserting
  different things about ONE run want `share: true` (#145).
- **Never gate on a wall-clock figure.** A per-call microsecond bound measures elapsed time,
  and a descheduled process accumulates elapsed time it did not spend running, so it goes red
  on a busy machine at any threshold that still catches a regression. Gate on a RATIO against
  a reference co-sampled in the same interleaved loop — `scripts/bench/bench.mjs` against a
  CPU calibration, `install-lifecycle.test.ts` against the same call unmediated.
- **A security test must be able to FAIL.** A test that passes for the wrong reason is worse
  than a missing one — it is a green light nobody re-examines, whether that light comes from
  `pnpm test` locally or from `ci.yml` in Actions. Issue #112 found six, including a "ReDoS
  hardening" test that passed with the hardening deleted. Two rules follow, and both are
  mechanically checkable:
  - **No silent `if (…) return;` in a test body.** Use `it.skipIf(...)`, which the reporter
    shows. A body that returns after doing nothing reports green with zero assertions, so an
    environment where it never runs looks exactly like coverage. Same for `if (cond) { expect
    … }` with no `else`: assert the other branch too.
  - **No assertion that the UN-guarded outcome would also satisfy.** `toMatch(/CapabilityError|
    TypeError/)`, `expect(typeof x).toBe("function")` on a guarded method, `expect(inside)
    .toEqual(outside)`, `.not.toThrow()` on its own — each is true whether or not the guard
    exists. Pin the identity, the decision, or the exact value.
- When you add or change a **guard, gate, pin or attribution rule**, add a mutant to
  `scripts/mutants.json` and run `pnpm mutation:gate`. It deletes the mechanism and re-runs
  only the tests that claim to cover it; anything it reports `SURVIVED` is an untested
  security property. See `docs/ci-local.md` § A sixth gate.
- **Before you trust a measurement or a bypass PoC, check that this tree is still armed.**
  `packages/*/dist` is gitignored and is what the CLI, `examples/` and every
  `--import .../dist/preload.js` reproduction execute, so a deleted gate there is invisible to
  `git status` — #184 lost an audit a batch of measurements that way. `pnpm canary` proves
  enforcement end to end in ~0.5s; `pnpm mutation:status` says whether a mutation-guard run is
  holding the tree; `pnpm mutation:recover` undoes an interrupted one. `bench`, `bench:startup`,
  `canary`, `ci:local` and `mutation:gate` now refuse to start on a tree that is or may be
  mutated (#196 added the startup harness, the last one measuring without asking), so
  "never run `mutation:gate` and `ci:local` concurrently" is enforced rather than remembered.

## 8. Threat-model guardrails

- **Never claim formal-sandbox or isolation guarantees.** capwall is pragmatic
  defense-in-depth. Keep `docs/threat-model.md` honest and in sync with any capability you
  add or weaken.
- The "what it does NOT stop" list (prototype pollution, shared mutable primordials,
  fd/symlink escapes, un-patching shims, `vm`/`eval`, native `.node` addons, subprocess
  internals) is a feature of the docs, not an embarrassment. Do not quietly drop it.
- **capwall's mechanism rests on unsupported Node internals, and the docs say so.**
  `docs/node-api-dependencies.md` is the per-API inventory — status on 22/24/26, the replacement
  if any, which capability dies without it — measured against real binaries rather than
  changelogs. Two rules follow. (1) A wrapper over a Node primitive forwards
  `Reflect.apply(real, this, args)` and states no arity (#128, #135); a *derived* argument handed
  to a DIFFERENT primitive needs the same treatment, which is where the #123 gate sprang a leak on
  Node 24.18. **#178 then showed the sharper form of that rule, and it is the one to remember: a
  re-resolution is a second opinion, and a second opinion the attacker parameterises is worthless.
  Where a gate needs to know what a primitive is about to do, take it from the point the primitive
  has already decided** — which is why the module-read gate now lives on `Module.prototype.load`
  and not inside the `Module._load` wrapper. (2) If you change one of those call sites, or claim a
  version fact in a comment, re-measure it — § Reproducing the measurement is written to be
  repeatable.
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
