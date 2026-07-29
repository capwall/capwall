# Running CI locally

GitHub Actions is currently billing-blocked ([issue #3](https://github.com/williamzujkowski/capwall/issues/3)), so PRs get no automated CI. Until that's fixed, use these to run the **exact same gates** locally.

## The fast path (no container)

The gates are plain pnpm scripts — run them directly on your machine:

```bash
pnpm install
pnpm build && pnpm typecheck && pnpm test && pnpm lint && pnpm bench:gate
```

This is what you should run while iterating. It uses whatever Node you have installed.

The five gates are genuinely five different checks:

| Gate | Runs | Catches |
|---|---|---|
| `build` | `tsc` emit, per package | Type errors in `src/`; produces `dist/`, which the CLI and ESM tests run against. |
| `typecheck` | `tsc --noEmit` over src **and** tests | Type errors the build never sees — `build` does not compile `test/`. |
| `test` | vitest, per package | Behaviour. ~190 of its assertions run in a child `node` process (122 in `@capwall/core`, 69 in `@capwall/cli`), because hardened mode, ESM module caching and loader-hook registration are process-sticky. Those children go through `packages/core/test/helpers/subprocess.ts`, which owns the per-child wall-clock budget, the measurements it is derived from, and the failure message you get when one overruns (issue #145). |
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
| **A run stamp** | `.capwall-mutation-guard.json` (gitignored) exists for exactly as long as the guard holds a mutation, carrying the **original bytes** of the file it changed. It is removed only after restore + rebuild + a clean re-scan. `mutation:gate`, `bench`, `canary` and `ci:local` all refuse to start while it exists, and say whether the run is alive (wait) or dead (recover). |
| **A greppable sentinel** | Every mutation carries `AUDIT MUTANT <id>` in a block comment, which survives `tsc` into `dist`. `scripts/mutation-sentinel.mjs` scans `packages/*/src` and `packages/*/dist` for it before anything trusts the tree. |
| **A canary** | `pnpm canary` launches a child under the real `--import dist/preload.js` and asserts a granted operation is **allowed** and two ungranted ones are **denied**. `bench` runs it before measuring; `ci.Dockerfile` runs it once per Node version. If it fails, no numbers are produced. |

```bash
pnpm mutation:status     # what the stamp says, and whether any sentinel is present
pnpm mutation:recover    # restore the recorded bytes, rebuild, re-scan, clear the stamp
pnpm canary              # is the dist/ in this tree actually enforcing?
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
scripts/ci-local.sh 26 # any single version
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
bench:gate. It never runs `actions/checkout`, `actions/setup-node`, `pnpm/action-setup` or
`actions/upload-artifact` — it checks out nothing, installs no toolchain through an action, and
uploads no artifact. So a green matrix here says exactly nothing about the four `uses:` lines in
each workflow, which since #168 are SHA-pinned and, while Actions billing is blocked (#3),
entirely unexercised. "A green run here is a green CI run" is a claim about capwall's code, not
about the workflow files.

Each version builds `.devcontainer/ci.Dockerfile` and runs, in order: `pnpm install --frozen-lockfile=false` → `build` → `typecheck` → `test` → `lint` → `bench:gate`. **A green build == a green CI run for that Node version.** The script exits non-zero if any gate fails on any version, so it can gate a merge.

### How the context is built (why it's faithful)

The script streams the build context from `git ls-files --cached --others --exclude-standard` — your working tree's **tracked + new, non-ignored** files. That's exactly what CI checks out: source plus the committed vendored test/demo fixtures (which live under `node_modules/` dirs on purpose), but **not** your host's installed `node_modules/` or `dist/` (those are rebuilt fresh in the container). Uncommitted edits to tracked files are included, so you can test before committing.

> Run it via `scripts/ci-local.sh`, not `docker build .` directly — the script provides the clean git context. A plain directory build would drag in your host `node_modules/`.

### Notes

- Uses the classic Docker builder (`DOCKER_BUILDKIT=0`) so it works without the `buildx` CLI plugin and streams each step's output live. Set `CI_BUILDKIT=1` to force BuildKit if you have it wired up.
- `install`/`build`/`typecheck` layers cache when the source is unchanged; `test`/`lint`/`bench:gate` are forced to re-run every invocation (via a `CACHEBUST` arg) so `ci:local` always actually executes them.
- **`CI_CPUSET` is the one axis a dev box cannot otherwise reproduce.** GitHub's hosted runners are 2-core; a 16-core box hides everything that is only slow on two. `CI_CPUSET=0,1` maps to `docker build --cpuset-cpus` and takes the same syntax. It is off by default because it roughly triples the wall time — the suite starts ~190 child `node` processes, each ~0.5s of mostly-serial startup. The suite's timeouts were measured with it on: see `packages/core/test/helpers/subprocess.ts`, which states the budget, the measurements behind it, and why vitest's default 5000ms was not one (issue #145).
- The perf gate adds ~10s per Node version. It is a genuine gate, not a smoke test — it fails the build on a ~2.7x regression on the mediated hot path. If a run ever goes red for reasons that turn out to be the machine rather than the code, that is a bug in the threshold derivation and belongs in an issue, not in a nudged constant; `CI_BENCH=0` is the escape hatch while it is investigated.

## Drift detection in CI (`capwall diff`)

Separate from the four gates above, and about *your* project rather than about capwall:
capwall ships a CI-facing subcommand for exactly this file's use case. `capwall diff` runs
your target in observe mode, then reports every capability the run actually used that the
committed `capabilities.json` would **deny** in enforce mode — a dependency that started
doing something it never did before.

```bash
capwall diff -- node ./src/server.js            # human-readable
capwall diff --json -- node ./src/server.js     # machine-readable
capwall diff -p ./policies/prod.json -- npm test
```

| Exit code | Meaning |
|---|---|
| `0` | no drift — everything the run did is already granted |
| `1` | drift found — one or more observed capabilities the policy would deny |
| `2` | usage error, or the policy file is missing |

`--json` writes the drift as a compact JSON array of `{pkg, kind, detail}` on the **last**
line of stdout; the target's own stdout is inherited and may precede it, so parse the last
line. Because a drifting dependency exits `1`, `capwall diff` can gate a merge directly.

This repo uses it on itself: `packages/cli/test/express-app-policy.test.ts` asserts that
`examples/express-app` reports no drift under its committed policy, in a scrubbed
environment. That test exists because the claim silently became false once before (issue
#57).

## Dev container

`.devcontainer/devcontainer.json` gives a reproducible Node 24 dev environment — the active LTS, matching the primary CI target (VS Code Dev Containers / GitHub Codespaces). On create it enables the pinned pnpm, installs, and builds. It includes the `docker-outside-of-docker` feature so you can run `pnpm ci:local` from inside the container too.
