#!/usr/bin/env bash
# Run the full GitHub Actions CI matrix (.github/workflows/ci.yml) locally in Docker.
#
# Why: GitHub Actions is billing-blocked (issue #3), so PRs get no CI. This reproduces the
# exact gates — pnpm install → build → typecheck → test → lint → bench:gate — on each Node
# version in the CI matrix, in a clean container, so a merge can be gated on a real green run.
#
# Usage:
#   scripts/ci-local.sh                 # Node 20 and 22 (the ci.yml matrix)
#   scripts/ci-local.sh 22              # just Node 22 (fast iteration)
#   CI_NODE_VERSIONS="18 20 22" scripts/ci-local.sh
#   CI_BENCH=0 scripts/ci-local.sh      # skip the perf gate (scripts/bench/README.md)
#   CI_CPUSET=0,1 scripts/ci-local.sh   # pin the build to 2 cores — a GitHub hosted runner
#
# CI_CPUSET is the one axis this script cannot otherwise reproduce: GitHub's hosted runners are
# 2-core, and a 16-core dev box hides everything that is only slow on two. It maps straight to
# `docker build --cpuset-cpus`. It is OFF by default because it roughly triples the wall time
# (the suite spawns ~190 child `node` processes); the timeouts the suite runs under were
# measured with it on — see packages/core/test/helpers/subprocess.ts and issue #145.
#
# The build context is your current working tree's tracked + new (non-ignored) files — the
# same set CI would check out, including the committed vendored fixtures and any uncommitted
# edits, but NOT the installed node_modules/ or dist/ (those are rebuilt in the container).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is not installed or not on PATH." >&2
  echo "Install Docker, or run the gates directly: pnpm build && pnpm typecheck && pnpm test && pnpm lint" >&2
  exit 127
fi
if ! docker info >/dev/null 2>&1; then
  echo "error: the Docker daemon is not reachable (is it running / do you have permission?)." >&2
  exit 1
fi

# Node versions: CLI args > $CI_NODE_VERSIONS > the ci.yml matrix (20, 22).
if [ "$#" -gt 0 ]; then
  NODE_VERSIONS=("$@")
else
  # shellcheck disable=SC2206
  NODE_VERSIONS=(${CI_NODE_VERSIONS:-20 22})
fi

DOCKERFILE=".devcontainer/ci.Dockerfile"
CACHEBUST="$(date +%s)"

# Stream only tracked + new, non-ignored files (current working-tree content) as the context.
build_context() { git ls-files --cached --others --exclude-standard -z | tar --null -T - -cf - ; }

# Optional CPU pin (see the header): `--cpuset-cpus` takes the same syntax docker does, e.g.
# "0,1" or "0-1". Empty means "every core", which is the default.
declare -a CPUSET_ARGS=()
if [ -n "${CI_CPUSET:-}" ]; then
  CPUSET_ARGS=(--cpuset-cpus "${CI_CPUSET}")
fi

declare -a RESULTS=()
overall=0
for v in "${NODE_VERSIONS[@]}"; do
  echo ""
  echo "═════════════════════ CI simulation · Node ${v}${CI_CPUSET:+ · cpus ${CI_CPUSET}} ═════════════════════"
  # Use the classic builder (DOCKER_BUILDKIT=0): it streams every RUN step's output live (so
  # you see the test results) and needs no buildx CLI plugin. Override with CI_BUILDKIT=1 if
  # you have buildx wired up and prefer it.
  if build_context | DOCKER_BUILDKIT="${CI_BUILDKIT:-0}" docker build \
      --build-arg "NODE_VERSION=${v}" \
      --build-arg "CACHEBUST=${CACHEBUST}" \
      --build-arg "BENCH=${CI_BENCH:-1}" \
      "${CPUSET_ARGS[@]+"${CPUSET_ARGS[@]}"}" \
      -f "${DOCKERFILE}" \
      -t "capwall-ci:node${v}" \
      - ; then
    echo "✅ Node ${v}: install + build + typecheck + test + lint + perf gate all PASSED"
    RESULTS+=("Node ${v}: PASS")
  else
    echo "❌ Node ${v}: a gate FAILED (see the output above)"
    RESULTS+=("Node ${v}: FAIL")
    overall=1
  fi
done

echo ""
echo "──────────────────────────── summary ────────────────────────────"
for r in "${RESULTS[@]}"; do echo "  ${r}"; done
if [ "${overall}" -eq 0 ]; then
  echo "All CI gates passed on all Node versions. ✅"
else
  echo "One or more CI gates failed. ❌"
fi
exit "${overall}"
