# Running CI locally

GitHub Actions is currently billing-blocked ([issue #3](https://github.com/williamzujkowski/capwall/issues/3)), so PRs get no automated CI. Until that's fixed, use these to run the **exact same gates** locally.

## The fast path (no container)

The gates are plain pnpm scripts — run them directly on your machine:

```bash
pnpm install
pnpm build && pnpm typecheck && pnpm test && pnpm lint && pnpm bench:gate
```

This is what you should run while iterating. It uses whatever Node you have installed.

**`pnpm install` can fail on a fresh clone, and the failure is a security decision rather than a
build problem.** pnpm 11 removed `ignoredBuiltDependencies` and now **fails the install** with
`ERR_PNPM_IGNORED_BUILDS` (exit 1) where pnpm 10 printed a warning you could scroll past. It
fires when a dependency brings in an install script that `pnpm-workspace.yaml`'s `allowBuilds`
map does not decide. Today nothing in the tree declares one, so `allowBuilds` deliberately does
not exist as a key — read that file's header before adding it, because `true` there means "this
package may run arbitrary code at install time".

The five gates are genuinely five different checks:

| Gate | Runs | Catches |
|---|---|---|
| `build` | `tsc` emit, per package | Type errors in `src/`; produces `dist/`, which the CLI and ESM tests run against. |
| `typecheck` | `tsc --noEmit` over src **and** tests | Type errors the build never sees — `build` does not compile `test/`. |
| `test` | vitest, per package | Behaviour. It starts ~190 child `node` processes (122 from `@capwall/core`, 69 from `@capwall/cli` — children, not assertions: the core suite's 122 children carry 1052 assertions between them), because hardened mode and the ESM module registry are process-sticky. Those children go through `packages/core/test/helpers/subprocess.ts`, which owns the per-child wall-clock budget, the measurements it is derived from, and the failure message you get when one overruns (issue #145). |
| `lint` | [oxlint](https://oxc.rs) once over the whole repo, config in `.oxlintrc.json` | Defects `tsc` does not check — unused bindings, unreachable/duplicate code, `no-explicit-any`, misuse patterns. It is **not** a style gate; see the config's comments for why the pedantic rules are off. |
| `bench:gate` | `scripts/bench/bench.mjs --quick`, ~10s | Performance regressions on the mediated hot path. Gates on a **ratio** against a CPU calibration co-sampled in the same loop, not on absolute microseconds, so it is portable and not flaky on a busy machine — see `scripts/bench/README.md` § The regression gate for the derivation. Needs `pnpm build` first (it runs against `dist/`). `CI_BENCH=0 pnpm ci:local` skips it. |

### A sixth gate, run periodically rather than per-commit: `pnpm mutation:gate`

`node scripts/mutation-guard.mjs` (~2 min) answers the question issue #112 was opened over:
**does this test still pass with the mechanism it names deleted?** For each entry in
`scripts/mutants.json` it establishes that the claimed tests pass unmutated, edits one anchor
string out of one source file, re-runs only those tests, and restores. A mutant the tests still
pass is reported `SURVIVED` — not a bug in the source, a hole in the tests.

It is not in `ci:local` because it runs vitest once per mutant plus a baseline. What *is* in
`pnpm test` is the cheap half: `packages/core/test/mutation-catalog.test.ts` asserts every anchor
still occurs exactly once in its file, so a refactor that moves a guarded mechanism breaks loudly
instead of silently retiring a mutant into a no-op edit.

Run it when you touch a guard, a gate, the pinning, or the attribution rules — and add a mutant
when you add one. `pnpm mutation:gate --only <id>` runs a single entry; `--list` prints the
catalog.

#### Never run `mutation:gate` and `ci:local` at the same time — and you no longer have to remember

`mutation:gate` deletes a security mechanism from `packages/core/src` **in place** for the
duration of each mutant, and compiles it into `packages/core/dist` for the mutants marked
`needsBuild`. `ci:local` tars that same working tree into its Docker context; `bench` imports that
same `dist`. Running them together has corrupted runs for two separate agents.

Issue #184 is the sharper version of the same problem: `dist/` is **gitignored**, so a mutated
enforcement artifact is invisible to `git status` and `git diff`, and it is what the CLI,
`examples/`, and every `--import .../dist/preload.js` reproduction actually execute. An ESM audit
lost a batch of measurements to a `dist/loader/module-read.js` carrying `if (1) return;` against a
clean-looking tree — a PoC "proved" a bypass that was not there. It cuts the other way too: a fix
can "prove" a bypass is closed when it is not.

Four things now enforce what used to be prose. None of them says anything when the tree is fine.

| | |
|---|---|
| **Teardown rebuilds** | `mutation-guard.mjs` restores sources **and** re-runs `tsc` for every package it touched — from the `finally`, from a throw, and from the **SIGINT/SIGTERM** handler. Restoring sources without rebuilding was the specific hole. Ctrl-C is safe; it takes a few seconds to leave. |
| **A run stamp** | `.capwall-mutation-guard.json` (gitignored) exists for exactly as long as the guard holds a mutation, carrying the **original bytes** of the file it changed. It is removed only after restore + rebuild + a clean re-scan. `mutation:gate`, `bench`, `bench:startup`, `canary` and `ci:local` all refuse to start while it exists, and say whether the run is alive (wait) or dead (recover). |
| **A greppable sentinel** | Every mutation carries `AUDIT MUTANT <id>` in a block comment, which survives `tsc` into `dist`. `scripts/mutation-sentinel.mjs` scans `packages/*/src` and `packages/*/dist` for it before anything trusts the tree. |
| **A canary** | `pnpm canary` launches a child under the real `--import dist/preload.js` and asserts a granted operation is **allowed** and two ungranted ones are **denied**. `bench` runs it before measuring; `ci.Dockerfile` runs it once per Node version. If it fails, no numbers are produced. |

```bash
pnpm mutation:status     # what the stamp says, and whether any sentinel is present
pnpm mutation:recover    # restore the recorded bytes, rebuild, re-scan, clear the stamp
pnpm canary              # is the dist/ in this tree actually enforcing?  (~0.5s)
node scripts/canary.mjs --json   # the same four checks, machine-readable
```

`ci:local` deliberately does **not** refuse a dirty tree in general — streaming your uncommitted
edits into the container is the point of it. It refuses the one state in which the working tree is
not yours: a mutation-guard run holding it.

## The CI-faithful path (Docker matrix)

`.github/workflows/ci.yml` runs on **Node 22, 24 and 26**. To reproduce that matrix — clean install, every Node version, all gates — in Docker:

```bash
pnpm ci:local          # Node 22, 24 AND 26 (the ci.yml matrix)
pnpm ci:local:24       # just Node 24, the active LTS (faster)
pnpm ci:local:22       # just the floor
pnpm ci:local:26       # just `current` — the early-warning leg
scripts/ci-local.sh 25 # any single version
CI_NODE_VERSIONS="22 24" scripts/ci-local.sh      # custom set
CI_CPUSET=0,1 pnpm ci:local                       # pin to 2 cores — a GitHub hosted runner
```

### Why those three

| version | why it is in the matrix |
|---|---|
| **22** | The **floor**, and `engines` says `>=22.15.0`. 22.15 is where `module.registerHooks()` landed, which since #152 is capwall's entire ESM path — the floor is chosen for that API, not rounded to it. The floor leg is where code that reaches for a newer API breaks. |
| **24** | The **active LTS** (until 2028-04-30) — what most users upgrading off 20 land on. It is also the version the release workflow packs on. |
| **26** | `current`, and **LTS from 2026-10-28**. Carried now so breakage lands as a CI failure months before it becomes the version everyone runs. It has already paid for itself twice — see below. |

Node 20 went **EOL on 2026-04-30** and is no longer tested or supported.

**Node 26 needs one thing the others do not.** Corepack was unbundled from Node in 25, so the
`node:25`/`node:26` images have no `corepack` on `PATH` and `ci.Dockerfile` installs it from npm
when it is missing. `ci.yml` is unaffected — `pnpm/action-setup` installs pnpm directly.

**What this script does NOT reproduce, and it is the whole of `.github/workflows/`'s dependency
surface.** `ci:local` runs the *steps* in a container: install, build, typecheck, test, lint,
canary, bench:gate. It never runs `actions/checkout`, `actions/setup-node`, `pnpm/action-setup` or
`actions/upload-artifact` — it checks out nothing, installs no toolchain through an action, and
uploads no artifact. So a green matrix here says exactly nothing about the `uses:` lines in the
workflows — **three in `ci.yml`, seven in `release.yml`, four distinct actions between them** —
which since #168 are SHA-pinned and, while Actions billing is blocked (#3), entirely unexercised.
"A green run here is a green CI run" is a claim about capwall's code, not about the workflow
files.

Each version builds `.devcontainer/ci.Dockerfile` and runs, in order: `pnpm install --frozen-lockfile=false` → `build` → `typecheck` → `test` → `lint` → **`canary`** → `bench:gate`. **A green build == a green CI run for that Node version.** The script exits non-zero if any gate fails on any version, so it can gate a merge.

Note where `canary` sits: it runs **unconditionally**, including under `CI_BENCH=0`, because its
job is to prove the `dist/` in the container is actually enforcing before anything downstream is
believed. Skipping the benchmark does not skip it.

### How the context is built (why it's faithful)

The script streams the build context from `git ls-files --cached --others --exclude-standard` — your working tree's **tracked + new, non-ignored** files. That's exactly what CI checks out: source plus the committed vendored test/demo fixtures (which live under `node_modules/` dirs on purpose), but **not** your host's installed `node_modules/` or `dist/` (those are rebuilt fresh in the container). Uncommitted edits to tracked files are included, so you can test before committing.

> Run it via `scripts/ci-local.sh`, not `docker build .` directly — the script provides the clean git context. A plain directory build would drag in your host `node_modules/`.

### Notes

- Uses the classic Docker builder (`DOCKER_BUILDKIT=0`) so it works without the `buildx` CLI plugin and streams each step's output live. Set `CI_BUILDKIT=1` to force BuildKit if you have it wired up.
- `install`/`build`/`typecheck` layers cache when the source is unchanged; `test`/`lint`/`bench:gate` are forced to re-run every invocation (via a `CACHEBUST` arg) so `ci:local` always actually executes them.
- **`CI_CPUSET` is the one axis a dev box cannot otherwise reproduce.** GitHub's hosted runners are 2-core; a 16-core box hides everything that is only slow on two. `CI_CPUSET=0,1` maps to `docker build --cpuset-cpus` and takes the same syntax. It is off by default because it roughly triples the wall time — the suite starts ~190 child `node` processes, each ~0.5s of mostly-serial startup. The suite's timeouts were measured with it on: see `packages/core/test/helpers/subprocess.ts`, which states the budget, the measurements behind it, and why vitest's default 5000ms was not one (issue #145).
- **`pnpm bench:startup` is a second, separate performance axis and is in no gate.** `bench` and
  `bench:gate` measure cost *per intercepted call*; `scripts/bench/startup.mjs` measures what a
  mediated process pays **before it runs a line of your code** — ~100–135 ms on top of a bare
  `node`, paid once per process by every user of capwall on every process they mediate. Nothing
  in `ci:local` measures it, so a change that widens capwall's module graph passes every gate
  green. Run it by hand on 22/24/26 if you add an import to the preload's or the ESM hooks'
  graph; the derivation and the per-major numbers are in `scripts/bench/README.md` § Startup and
  § After #152.
- The perf gate adds ~10s per Node version. It is a genuine gate, not a smoke test — it fails the build on a ~2.7x regression on the mediated hot path. If a run ever goes red for reasons that turn out to be the machine rather than the code, that is a bug in the threshold derivation and belongs in an issue, not in a nudged constant; `CI_BENCH=0` is the escape hatch while it is investigated.

## Drift detection in CI (`capwall diff`)

Separate from the five gates above, and about *your* project rather than about capwall:
capwall ships a CI-facing subcommand for exactly this file's use case. `capwall diff` runs
your target in observe mode, then reports every capability the run actually used that the
committed `capabilities.json` would **deny** in enforce mode — a dependency that started
doing something it never did before.

```bash
capwall diff -- node ./src/server.js            # human-readable
capwall diff --json -- node ./src/server.js     # machine-readable
capwall diff --strict -- node ./src/server.js   # also fail on dead policy keys
capwall diff -p ./policies/prod.json -- npm test
```

| Exit code | Meaning |
|---|---|
| `0` | no drift — everything the run did is already granted |
| `1` | drift found — one or more observed capabilities the policy would deny. **Under `--strict`, also**: a `packages` key that matched no principal in this run |
| `2` | usage error, or the policy file is missing |

`--strict` is the flag to reach for once a policy is mature. Drift is reported in both directions
(#118) — observed-but-not-granted, and declared-but-never-matched — but only the first is an
error by default, because a key legitimately matches nothing when the dependency it names is
optional or on a path this run did not take. `--strict` promotes the second to a failure too, for
a pipeline that wants dead keys gone rather than accreted.

`--json` writes the drift as a compact JSON array of `{pkg, kind, detail}` on the **last**
line of stdout; the target's own stdout is inherited and may precede it, so parse the last
line. Unmatched keys are reported on stderr in every mode — the array is the stable contract.
Because a drifting dependency exits `1`, `capwall diff` can gate a merge directly.

Full flag and exit-code reference: [`cli.md`](./cli.md) § `diff`.

This repo uses it on itself: `packages/cli/test/express-app-policy.test.ts` asserts that
`examples/express-app` reports no drift under its committed policy, in a scrubbed
environment. That test exists because the claim silently became false once before (issue
#57).

## Dev container

`.devcontainer/devcontainer.json` gives a reproducible Node 24 dev environment — the active LTS, matching the primary CI target (VS Code Dev Containers / GitHub Codespaces). On create it enables the pinned pnpm, installs, and builds. It includes the `docker-outside-of-docker` feature so you can run `pnpm ci:local` from inside the container too.
