# capwall benchmarks

capwall's design target is **<1ms of added latency per intercepted call** — the same ballpark
NodeShield reported. `bench.mjs` is the harness that checks whether we hold that line.

```sh
pnpm install          # once
pnpm build            # bench.mjs imports the BUILT packages/core/dist, not src
pnpm bench            # the full run, ~20s
pnpm bench:gate       # the reduced run CI uses, ~10s
node scripts/bench/bench.mjs --json    # machine-readable
node scripts/bench/bench.mjs --no-esm  # skip the ESM arm and its loader thread
```

Exits `0` on PASS, non-zero on FAIL. Deliberately dependency-free — timing is
`process.hrtime.bigint()` and nothing else (AGENTS.md § 5: no new runtime deps).

## The headline number, and its asterisk

Two figures, and conflating them is how a benchmark tells a comfortable lie:

- **Per intercepted call**, every mediated surface measured here costs tens of microseconds:
  ~30–90 µs on a development box. That is 10–30x inside the 1ms budget, and the budget holds.
- **Per JS call**, one operation is not always one interception. `{...process.env}` on an 80-key
  environment is ~80 interceptions and costs **milliseconds**. A request handler that does it
  once has spent its entire per-request budget several times over.

The harness gates on the first and prints the second under `AMPLIFICATION`, by name, every run.
See § Where the budget does not hold.

## Coverage — what capwall mediates vs what this measures

The reason this file exists. A benchmark that only times `fs.readFileSync` reports a healthy
number forever no matter what happens to egress, spawn or attribution, and the guarded surface
has roughly doubled since the harness was written.

| Guarded surface | Measured? | Row / why not |
|---|---|---|
| `fs` read/write, sync | yes | `fs.readFileSync`, paired, at two stack depths |
| `fs` path pinning (file-URL args) | no | same `coercePath` as the sync read; not separately priced |
| `fs.glob`/`globSync`/`promises.glob` (#106) | yes (Node ≥22) | `fs.globSync`; skipped on Node 20, which has no `globSync` |
| `fs` stream/class constructors | no | same `guard()` call as `createReadStream`; priced by the fs row |
| `net.connect`, allowed | yes | with a **6-key options bag**, so the accessor-flattening clone (#26/#56) is in the number |
| `net`/`tls`/`http2`/`dgram`/`https` | partly | one guard implementation in `net.ts`; the `net.connect` row prices the shape |
| `http.globalAgent` per-property Proxy (#65) | yes | every property read pays the trap, not just `createConnection` |
| `child_process.spawn*`, allowed | yes | real `/bin/true` spawn, paired — but see § Resolution limits |
| per-key env authorization during spawn (#89) | yes | inside the spawn row; `SPAWN_OPTS` explains why the env must be explicit |
| `child_process`, denied | yes | deny-path row |
| global `fetch` (#80), allowed and denied | yes | two rows; the URL is pinned and re-parsed on every call |
| global `WebSocket` / `EventSource` | no | same `global-egress.ts` guard as `fetch`; the `fetch` row prices it |
| `process.env` single read | yes | paired against the pre-install env object |
| `process.env` enumeration (`{...env}`) | yes | the amplification row — the most expensive thing here |
| attribution, memoized hit | yes | `attributeCaller()` at depths 0 / 8 / 24 |
| attribution **miss** → `<unknown>` (#60) | yes | through an opaque `eval` frame, and a 40-frame budget-exhausted walk |
| install-chain identity parse (#92) | yes | `packageForPath` cold, top-level vs 4-link chain |
| `policy/evaluate` | yes | pure function, batch-timed |
| `Module._load` relink chain (#22) | yes | mediated and non-mediated specifiers |
| ESM `import` path (M5, on by default) | yes | the same fixture file imported under two URLs, before and after install |
| hardened mode (#17) | yes | a second, stacked hardened install; both arms mediated |
| `Module.prototype._compile` gate (#93) | **no** | fires once per CJS module load, and the loader-called path is a 1-frame capture. Pairing it needs an install/uninstall per block. Tracked as an issue. |
| `process.dlopen` native gate (S2) | **no** | once per `.node` addon load; no vendored addon in the bench tree. |
| `node:module` loader-hook registration gate (#61) | **no** | once per process. |
| `vm` / `worker_threads` gates | **no** | one `guard()` each, identical in shape to the `child_process` deny row, and the allowed form is dominated by thread/context creation. |
| ESM cold resolution (loader-thread hooks) | **no** | startup cost, not per-request. Tracked as an issue. |
| observe mode | **no** | the sink here is a no-op; a real `observe` run writes a trace line per decision, and that cost is the embedder's, not capwall's. |
| end-to-end request latency (express-app) | **no** | still the follow-up it always was: this harness measures the shim hot path in isolation. |

## Methodology

Read this before quoting a number out of here.

**Paired arms, ABBA-interleaved.** Where an un-mediated equivalent exists, the two arms are the
same call from the same fixture package, alternating call-by-call in one loop, with the order of
the pair flipped on every other block. Interleaving makes both arms share the same GC and
scheduler jitter; flipping cancels the "second call of a pair runs warmer" bias a fixed order
bakes in. The per-iteration `mediated − unmediated` delta is capwall's added latency.

**Blocks and a min estimator.** Every measurement runs in 10 independent blocks (4 with
`--quick`). The reported figure is the **minimum over blocks of each block's median**. Noise only
ever adds time, so the minimum block is the least contaminated one; the previous harness used a
single block and a mean, which reports the machine's mood — the same estimator artifact a recent
PR chased for a phantom +5% regression. The **spread across block medians** is printed on every
row so instability is visible instead of averaged away.

**The timer is not free.** A `process.hrtime.bigint()` pair costs ~100 ns here, printed at the top
of every run. That is a rounding error against a 40 µs fs call and a *large fraction* of a 125 ns
`evaluate()`. Sub-microsecond rows are therefore timed in batches (one timestamp pair per N calls)
and report no tail percentiles, because the tail of a batch mean is not the tail of a call. The
old harness timed every one of those calls individually; its `evaluate()` and warm-cache figures
were roughly 2–4x timer overhead.

**Rows below their own resolution are marked.** When `|delta| < block spread` the row prints `≲`
and says so. A delta smaller than the run-to-run spread of the blocks it came from is an upper
bound, not a measurement.

### The harness checks its own premise

Every run starts with a self-check table. For each paired row it drives both arms with the
decision sink recording, and asserts:

- the **mediated** arm produces at least one capability decision;
- the **un-mediated** arm produces none (with one named, deliberate exception — see below);
- the decision is charged to the **principal the row claims**, not to `<app>`.

This is not ceremony. A prior PR found `projectRoot` set to the *dependency's* directory —
harmless while `packageForPath` ignored the root, and silently fatal to the benchmark's premise
from the moment #92 made the root matter, because the fixture's own frames then resolved to
`<app>`. The failure mode is generic: **the two arms differ in something other than mediation.**
The table is what makes that visible.

The named exception: `process.env` is a **process-global** surface. `install()` replaces the
object itself, so an "un-mediated" arm that reaches an env read through Node's own internals
(`fs.glob` does; `spawnSync` reads `NODE_V8_COVERAGE` by name) still trips the gate. Those rows
declare `["env"]` as an allowed baseline decision kind, and it cancels in the delta.

### Why a vendored fixture, not app-code calls

Attribution short-circuits app-code frames to the `<app>` sentinel (`packageForPath` never runs
its `node_modules/` scan). Driving the benchmark from app code would time a cheaper path than
what dependencies actually hit. `bench-dep` lives under a committed `node_modules/` dir so its
calls resolve a real package name; `bench-dep-denied` is its granted-nothing twin, used for the
deny-path rows. The duplication between them is load-bearing — attribution charges the *nearest*
frame, so a deny row routed through `bench-dep`'s code would be attributed to `bench-dep` and
allowed.

## Stack depth is a parameter, not a constant

The single most important thing the old harness got wrong. Attribution captures up to
`maxFrames` (default 25) V8 `CallSite` objects on **every** mediated call, and V8 charges for
each frame it materializes. The old benchmark called `fs.readFileSync` from three frames down —
the cheapest stack a program can have — and reported that as capwall's overhead.

Measured on one machine, one run:

| stack depth below the call | `attributeCaller()` | fs read added latency |
|---|---|---|
| 0 (the old scenario) | ~16 µs | ~30 µs |
| 8 | ~22 µs | — |
| 24 (the budget cap) | ~30 µs | ~42 µs |

So the realistic figure is **~40% higher** than the number this file used to print, and
attribution is **~70%** of it at a realistic depth rather than the ~50% issue #34 recorded from a
shallow stack. Express, promise chains and `async_hooks`-heavy frameworks all put you at the cap.
If you are looking for headroom, the stack walk is where it is.

## Where the budget does not hold

`{...process.env}` — the shape `dotenv`, config loaders and Node's own spawn use — runs the env
Proxy's `getOwnPropertyDescriptor` **and** `get` traps once per key, and each of those attributes
the caller from scratch. On an 81-key environment that measured **~4.4 ms of added latency for a
single JS call**, against ~54 µs per interception. Nothing is wrong with the per-interception
number; the operation is simply 81 interceptions wearing one call's clothing.

Consequences worth stating plainly:

- The `<1ms/req` claim is about **one intercepted call**. A request that enumerates the
  environment blows it, and no amount of per-call optimization changes that.
- The cost scales with the size of the environment, so it is worse on CI runners and in
  containers with large env blocks than on a laptop. The harness prints the key count it measured
  and only lists the row under `AMPLIFICATION` when it actually exceeds 1 ms.
- capwall's own `child_process` shim does *not* pay this: #89 supplies an explicit `options.env`
  built from the un-proxied environment precisely to delete Node's `{ ...process.env }`. Which
  produces a genuinely odd artifact — an **un-shimmed** `spawnSync` running under capwall's env
  Proxy is an order of magnitude slower than the **shimmed** one. That is why both spawn arms in
  this harness pass an explicit env; see `SPAWN_OPTS` in `bench.mjs`.
- `install(..., { env: false })` removes the whole class of cost, at the price of the
  anti-exfiltration control.

## Resolution limits

Some deltas are smaller than the thing they sit on top of, and the harness says so rather than
printing a confident number:

- **`spawnSync`** — a real `/bin/true` spawn costs ~3 ms with hundreds of microseconds of
  block-to-block spread. capwall's added cost is far below that, so the row is marked `≲` and
  should be read as "somewhere under a few hundred microseconds". The **deny** row (~26 µs) is
  the trustworthy figure for the gate machinery itself.
- **`fetch`** — real localhost HTTP, ~500 µs baseline; the ~90 µs delta is resolvable but noisy.
- **hardened mode** — measured at or below resolution, i.e. hardening costs nothing per call,
  which is what you would expect from an `Object.freeze` that happens at shim-build time.

## The regression gate

Three gates, all printed in the verdict, all affecting the exit code.

**BUDGET.** Every added latency *per intercepted call* must be under 1 ms. Rows where one JS call
is many interceptions are listed separately under `AMPLIFICATION` rather than folded in.

**RATIO.** The fs added latency divided by a synthetic CPU calibration **co-sampled in the same
interleaved loop**. This is the actual regression detector, and the co-sampling is the point: an
absolute microsecond threshold is not portable across machines, and the 1 ms budget has so much
headroom that a 3x regression would sail through it. Contention that inflates the mediated arm
inflates the reference in the same block, at the same moment, so the ratio barely moves even when
the absolute figures swing 40%.

How the limit was derived, so it can be re-derived rather than nudged:

| condition | observed ratio |
|---|---|
| idle 16-core Linux box, 6 sequential runs | 2.57 – 2.63 |
| Node 20 in the CI container | 2.29 |
| 8 concurrent benchmark processes on 16 cores | 2.6 – 4.2 |
| 16 concurrent processes (it plateaus) | 4.4 – 4.6 |

The limit is **7**: ~1.5x above the worst contention ever observed, and low enough that a 2.7x
algorithmic regression fails the run. Override with `CAPWALL_BENCH_RATIO_LIMIT`. If you change
`CAL_REPEATS` or the calibration body, this number is invalid until it is re-derived the same way.

**SELF-CHECKS.** Every premise above, verified per run.

`pnpm bench:gate` (`--quick`: 4 blocks, quarter iterations, ~10 s) runs in CI — as a step in
`.github/workflows/ci.yml` and as a layer in `.devcontainer/ci.Dockerfile`, so `pnpm ci:local`
covers it on Node 20 and 22. `CI_BENCH=0 pnpm ci:local` skips it.

## Layout

```
scripts/bench/
  bench.mjs                                          the harness ("pnpm bench")
  fixtures/node_modules/bench-dep/index.js           granted fixture dependency (CJS arms)
  fixtures/node_modules/bench-dep/esm.mjs            the ESM arm, imported under two URLs
  fixtures/node_modules/bench-dep-denied/index.js    granted-nothing twin (deny-path arms)
  README.md                                          this file
```
