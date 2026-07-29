# CI-parity image — reproduces the gates in .github/workflows/ci.yml inside a clean
# container, so the full build/typecheck/test/lint matrix can run locally while GitHub
# Actions is billing-blocked (issue #3). Built per Node version by scripts/ci-local.sh.
#
# The build CONTEXT is streamed by scripts/ci-local.sh from `git ls-files` (tracked + new,
# non-ignored files at their current working-tree content) — i.e. exactly what CI checks out:
# source + the committed vendored test/demo fixtures, WITHOUT the host's installed
# node_modules/ or dist/. Everything is installed and built fresh here, like CI.
ARG NODE_VERSION=24
FROM node:${NODE_VERSION}-bookworm-slim

# Match GitHub Actions: CI=true, non-interactive corepack (uses the repo-pinned pnpm).
ENV CI=true
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0

# COREPACK IS NOT BUNDLED FROM NODE 25 ONWARDS. It shipped with Node through 24 and was
# unbundled in 25, so `node:25`/`node:26` images have no `corepack` on PATH and this image
# failed at step 5 with "corepack: not found" the first time the matrix reached 26. Install it
# from npm only when it is missing, so 22 and 24 keep using the bundled one and the pinned pnpm
# still comes from `packageManager` on every version.
#
# ci.yml does not need this: `pnpm/action-setup@v4` installs pnpm directly rather than through
# corepack. This step is what keeps the container faithful to that on a version where the
# runtime image alone cannot get there.
RUN command -v corepack >/dev/null 2>&1 || npm install -g corepack@latest
RUN corepack enable

# GIT, WHICH `node:*-bookworm-slim` DOES NOT SHIP AND A GITHUB RUNNER ALWAYS HAS. Installing it
# makes the container MORE faithful to ci.yml, not less: `actions/checkout` cannot run without it,
# and `scripts/check-commit-messages.mjs` — the commit-conventions gate — reads commits with
# `git log`. Its test suite builds a throwaway repository (never this one) to prove the range
# walk, the merge-commit skip and the base..head restriction actually work; without git those
# cases `skipIf` themselves out, and the local matrix would go green over a gate it never ran.
RUN apt-get update \
  && apt-get install -y --no-install-recommends git \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# ci.yml step: "Install dependencies" — pnpm resolves its own pinned version (11.17.0) from
# package.json's `packageManager` field via corepack.
RUN pnpm install --frozen-lockfile=false

# ci.yml steps: Build → Typecheck (these cache when the source is unchanged).
RUN pnpm build
RUN pnpm typecheck

# ci.yml steps: Test → Lint (oxlint, whole repo, .oxlintrc.json). CACHEBUST forces these to
# re-run on every invocation even when nothing changed, so `ci:local` always actually executes
# the tests (not a cached layer).
ARG CACHEBUST=0
RUN echo "run ${CACHEBUST}" && pnpm test
RUN pnpm lint

# The enforcement canary (issue #184). Not a ci.yml step — this is the container asserting, once
# per Node version, that the `dist/` it just built actually enforces: one granted operation is
# allowed and two ungranted ones are denied, in a child process launched the way the CLI launches
# one (`--import dist/preload.js`). It runs even when BENCH=0, because "did the build produce a
# capwall that still says no?" is not a performance question. ~0.5s.
RUN echo "run ${CACHEBUST}" && pnpm canary

# ci.yml step: "Perf gate" — the reduced-iteration benchmark run (scripts/bench/bench.mjs
# --quick, ~10s). It gates on a CO-SAMPLED RATIO rather than an absolute microsecond figure, so
# it is portable across machines and does not go red because the host is busy; see
# scripts/bench/README.md § The regression gate for how the threshold was derived and what it
# will and will not catch. Set BENCH=0 to skip it (scripts/ci-local.sh passes CI_BENCH through).
ARG BENCH=1
RUN if [ "${BENCH}" = "1" ]; then pnpm bench:gate; else echo "perf gate skipped (BENCH=0)"; fi

# A green build of this image == a green CI run for this Node version.
