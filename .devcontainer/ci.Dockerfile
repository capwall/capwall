# CI-parity image — reproduces the gates in .github/workflows/ci.yml inside a clean
# container, so the full build/typecheck/test/lint matrix can run locally while GitHub
# Actions is billing-blocked (issue #3). Built per Node version by scripts/ci-local.sh.
#
# The build CONTEXT is streamed by scripts/ci-local.sh from `git ls-files` (tracked + new,
# non-ignored files at their current working-tree content) — i.e. exactly what CI checks out:
# source + the committed vendored test/demo fixtures, WITHOUT the host's installed
# node_modules/ or dist/. Everything is installed and built fresh here, like CI.
ARG NODE_VERSION=22
FROM node:${NODE_VERSION}-bookworm-slim

# Match GitHub Actions: CI=true, non-interactive corepack (uses the repo-pinned pnpm).
ENV CI=true
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable

WORKDIR /app
COPY . .

# ci.yml step: "Install dependencies" — pnpm resolves its own pinned version (10.33.0) from
# package.json's `packageManager` field via corepack.
RUN pnpm install --frozen-lockfile=false

# ci.yml steps: Build → Typecheck (these cache when the source is unchanged).
RUN pnpm build
RUN pnpm typecheck

# ci.yml steps: Test → Lint. CACHEBUST forces these to re-run on every invocation even when
# nothing changed, so `ci:local` always actually executes the tests (not a cached layer).
ARG CACHEBUST=0
RUN echo "run ${CACHEBUST}" && pnpm test
RUN pnpm lint

# A green build of this image == a green CI run for this Node version.
