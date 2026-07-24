# Running CI locally

GitHub Actions is currently billing-blocked ([issue #3](https://github.com/williamzujkowski/capwall/issues/3)), so PRs get no automated CI. Until that's fixed, use these to run the **exact same gates** locally.

## The fast path (no container)

The gates are plain pnpm scripts — run them directly on your machine:

```bash
pnpm install
pnpm -r build && pnpm -r typecheck && pnpm -r test && pnpm -r lint
```

This is what you should run while iterating. It uses whatever Node you have installed.

## The CI-faithful path (Docker matrix)

`.github/workflows/ci.yml` runs on **Node 20 and 22**. To reproduce that matrix — clean install, both Node versions, all gates — in Docker:

```bash
pnpm ci:local          # Node 20 AND 22 (the ci.yml matrix)
pnpm ci:local:22       # just Node 22 (faster)
scripts/ci-local.sh 20 # any single version
CI_NODE_VERSIONS="18 20 22" scripts/ci-local.sh   # custom set
```

Each version builds `.devcontainer/ci.Dockerfile` and runs, in order: `pnpm install --frozen-lockfile=false` → `build` → `typecheck` → `test` → `lint`. **A green build == a green CI run for that Node version.** The script exits non-zero if any gate fails on any version, so it can gate a merge.

### How the context is built (why it's faithful)

The script streams the build context from `git ls-files --cached --others --exclude-standard` — your working tree's **tracked + new, non-ignored** files. That's exactly what CI checks out: source plus the committed vendored test/demo fixtures (which live under `node_modules/` dirs on purpose), but **not** your host's installed `node_modules/` or `dist/` (those are rebuilt fresh in the container). Uncommitted edits to tracked files are included, so you can test before committing.

> Run it via `scripts/ci-local.sh`, not `docker build .` directly — the script provides the clean git context. A plain directory build would drag in your host `node_modules/`.

### Notes

- Uses the classic Docker builder (`DOCKER_BUILDKIT=0`) so it works without the `buildx` CLI plugin and streams each step's output live. Set `CI_BUILDKIT=1` to force BuildKit if you have it wired up.
- `install`/`build`/`typecheck` layers cache when the source is unchanged; `test`/`lint` are forced to re-run every invocation (via a `CACHEBUST` arg) so `ci:local` always actually executes the tests.

## Dev container

`.devcontainer/devcontainer.json` gives a reproducible Node 22 dev environment (VS Code Dev Containers / GitHub Codespaces). On create it enables the pinned pnpm, installs, and builds. It includes the `docker-outside-of-docker` feature so you can run `pnpm ci:local` from inside the container too.
