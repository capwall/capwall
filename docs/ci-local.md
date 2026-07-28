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
| `test` | vitest, per package | Behaviour. |
| `lint` | [oxlint](https://oxc.rs) once over the whole repo, config in `.oxlintrc.json` | Defects `tsc` does not check — unused bindings, unreachable/duplicate code, `no-explicit-any`, misuse patterns. It is **not** a style gate; see the config's comments for why the pedantic rules are off. |
| `bench:gate` | `scripts/bench/bench.mjs --quick`, ~10s | Performance regressions on the mediated hot path. Gates on a **ratio** against a CPU calibration co-sampled in the same loop, not on absolute microseconds, so it is portable and not flaky on a busy machine — see `scripts/bench/README.md` § The regression gate for the derivation. Needs `pnpm build` first (it runs against `dist/`). `CI_BENCH=0 pnpm ci:local` skips it. |

## The CI-faithful path (Docker matrix)

`.github/workflows/ci.yml` runs on **Node 20 and 22**. To reproduce that matrix — clean install, both Node versions, all gates — in Docker:

```bash
pnpm ci:local          # Node 20 AND 22 (the ci.yml matrix)
pnpm ci:local:22       # just Node 22 (faster)
scripts/ci-local.sh 20 # any single version
CI_NODE_VERSIONS="18 20 22" scripts/ci-local.sh   # custom set
```

Each version builds `.devcontainer/ci.Dockerfile` and runs, in order: `pnpm install --frozen-lockfile=false` → `build` → `typecheck` → `test` → `lint` → `bench:gate`. **A green build == a green CI run for that Node version.** The script exits non-zero if any gate fails on any version, so it can gate a merge.

### How the context is built (why it's faithful)

The script streams the build context from `git ls-files --cached --others --exclude-standard` — your working tree's **tracked + new, non-ignored** files. That's exactly what CI checks out: source plus the committed vendored test/demo fixtures (which live under `node_modules/` dirs on purpose), but **not** your host's installed `node_modules/` or `dist/` (those are rebuilt fresh in the container). Uncommitted edits to tracked files are included, so you can test before committing.

> Run it via `scripts/ci-local.sh`, not `docker build .` directly — the script provides the clean git context. A plain directory build would drag in your host `node_modules/`.

### Notes

- Uses the classic Docker builder (`DOCKER_BUILDKIT=0`) so it works without the `buildx` CLI plugin and streams each step's output live. Set `CI_BUILDKIT=1` to force BuildKit if you have it wired up.
- `install`/`build`/`typecheck` layers cache when the source is unchanged; `test`/`lint`/`bench:gate` are forced to re-run every invocation (via a `CACHEBUST` arg) so `ci:local` always actually executes them.
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

`.devcontainer/devcontainer.json` gives a reproducible Node 22 dev environment (VS Code Dev Containers / GitHub Codespaces). On create it enables the pinned pnpm, installs, and builds. It includes the `docker-outside-of-docker` feature so you can run `pnpm ci:local` from inside the container too.
