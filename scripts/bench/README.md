# capwall benchmarks

capwall's design target is **<1ms per intercepted request** of overhead — the same ballpark
NodeShield reported. `bench.mjs` is the harness that measures whether we hold that line, on
the actual hot path: **attribution** (stack-walk + module→package resolution) +
**`policy/evaluate`** (lookup + glob/host match), per intercepted core-API call.

## Run it

```sh
pnpm install        # once
pnpm -r build        # bench.mjs imports the BUILT packages/core/dist, not src
pnpm bench            # == node scripts/bench/bench.mjs
```

No extra setup: the vendored fixture dependency it drives calls through
(`scripts/bench/fixtures/node_modules/bench-dep/`) is committed, mirroring
`packages/core/test/fixtures/node_modules/fixture-dep`. Deliberately dependency-free — timing
uses `process.hrtime.bigint()` only, no benchmarking library (AGENTS.md §5: no new runtime
deps).

Exits `0` on PASS, non-zero on FAIL, so it can gate CI later (stretch goal, not yet wired into
`.github/workflows/ci.yml`).

## Why a vendored fixture, not app-code calls

Attribution's nearest-package walk short-circuits app-code frames straight to the `<app>`
sentinel (`packageForPath` never runs its `node_modules/` scan). Driving the benchmark from
app code would time a cheaper path than what dependencies actually hit and understate
capwall's real overhead. `bench-dep` lives under a committed `node_modules/` dir
(`scripts/bench/fixtures/node_modules/bench-dep/`, negated in `.gitignore` the same way the
other fixture `node_modules/` dirs are) specifically so its calls resolve a real package name.

## What it measures

1. **fs read — added latency.** A `bench-dep` instance loaded *before* capwall installs (so
   it closes over the real, unshimmed `fs`) and one loaded fresh *after* install (so it closes
   over capwall's shim) are called alternately, call-by-call, in the same loop — both share
   the same GC/scheduler jitter, and the per-iteration `shimmed − baseline` delta is capwall's
   added latency for that call. This is the number the PASS/FAIL gate uses.
2. **Attribution only.** `attributeCaller()` called directly from a `bench-dep` frame (no fs
   call attached), to see how much of scenario 1 attribution alone accounts for. This was
   originally expected to dominate; measurement says otherwise (see "What it found" below).
3. **Evaluate only.** `evaluate(policy, mode, pkg, req)` — a pure function, no stack walk — to
   show the (expected: small) policy-lookup contribution.
4. **net connect, denied.** `bench-dep` is never granted `net`, so the net shim throws
   `CapabilityError` synchronously before any socket opens (see
   `packages/core/test/net.test.ts`). Reported as an absolute attribute→evaluate→throw cost;
   there's no unshimmed baseline to diff against here, since a real `connect()` does async
   DNS/socket work a synchronous throw never reaches.
5. **Path→package cache, cold vs warm.** `packageForPath()` called with a unique, never-seen
   path each time (guaranteed miss) vs the same path repeated (guaranteed hit after the
   first), to quantify the documented memoization optimization.

## What it found (issue #34)

The original assumption — recorded in `AGENTS.md` § 5 and in `docs/architecture.md`'s Risks
list — was that attribution stack-walking would **dominate** the hot path. It does not.
Scenario 2 comes out at roughly half of scenario 1's added latency (issue #34 measured ~40%;
runs since have landed around half — it is machine-dependent), and the remainder is the shim
wrapper's own dispatch. `evaluate()` (scenario 3) is negligible, sub-microsecond. So if you
are looking for headroom, profile the wrapper as well as the walk. The path→package cache is
still worth having on its own terms — scenario 5 shows ~20x cold-vs-warm.

The absolute added latency measures well under the 1ms/call budget, but the ratio is a
property of the machine, not of capwall. Run it yourself rather than quoting a number from
here.

## How to read the output

Every scenario prints `mean` / `p50` / `p95` / `p99`, computed from the raw sample
(percentiles are nearest-rank over a sorted array — see `stats()`/`percentile()` in
`bench.mjs`), plus `min`/`max` implicitly via the sample. Report **median and tail, not just
mean** — tail latency is what the per-request claim is actually about.

The final block is the verdict:

```
RESULT: PASS — fs read added-latency median (p50) = 34.100 µs (budget: 1.000 ms / 1ms/call)
        mean=36.474 µs  p50=34.100 µs  p95=51.878 µs  p99=78.489 µs
```

The gate checks **scenario 1's p50 delta against the 1ms budget** (matching this file's
original intent: "fail if median per-call overhead regresses past the target"). p95/p99 are
always printed — if p99 blows past budget while p50 still passes, the harness prints a note,
but only the median fails the run. Numbers are machine-dependent by nature (CPU, Node build,
load); the harness reports actual measured numbers rather than asserting exact values, beyond
the budget gate.

## Layout

```
scripts/bench/
  bench.mjs                                    the harness (this is what "pnpm bench" runs)
  fixtures/node_modules/bench-dep/              vendored dependency the harness drives calls through
  README.md                                     (this file)
```

## Not yet covered (follow-up)

- **End-to-end request latency** on `examples/express-app` (observe/enforce/off, p50/p95/p99
  at the HTTP layer, not just the shim call). `bench.mjs` only measures the shim hot path in
  isolation.
- **CI gating.** `bench.mjs` already exits non-zero on FAIL; it isn't wired into
  `.github/workflows/ci.yml` yet.
