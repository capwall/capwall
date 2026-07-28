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
  ~20–70 µs on a development box since #143 (~30–90 µs before it). That is 15–50x inside the 1ms
  budget, and the budget holds.
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
| `Module.prototype._compile` gate (#93) | yes (#134) | `[G]` — N generated CJS modules `require`d fresh, with the real and the patched `_compile` swapped into the prototype slot per arm |
| `process.dlopen` native gate (S2) | yes (#134) | `[G]` — a placeholder `.node` inside the fixture package, so the gate's two subjects (#49) are one principal |
| ESM cold resolution (loader-thread hooks) | yes (#134) | `[G]` — a fresh `?n=` URL per iteration; paired against the same import with a NON-mediated specifier |
| `node:module` loader-hook registration gate (#61) | **no** | once per process. |
| `vm` / `worker_threads` gates | **no** | one `guard()` each, identical in shape to the `child_process` deny row, and the allowed form is dominated by thread/context creation. |
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

The second named exception, added with the startup section (#134): the **`_compile` gate's own
premise is the opposite one.** On a loader-driven compile the gate's job is to recognize Node's
frame and charge *nobody*, so "the mediated arm produces a decision" would be a failure there.
That row asserts the inverse — the patched implementation is in the path, and it stays silent —
which is what makes its delta the cost of `calledByNodeLoader()` rather than of a policy
evaluation. If the loader path ever started attributing, that check flips.

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

Measured on one machine, one run, **before #143**:

| stack depth below the call | `attributeCaller()` | fs read added latency |
|---|---|---|
| 0 (the old scenario) | ~16 µs | ~30 µs |
| 8 | ~22 µs | — |
| 24 (the budget cap) | ~30 µs | ~42 µs |

So the realistic figure was **~40% higher** than the number this file used to print, and
attribution was **~70%** of it at a realistic depth rather than the ~50% issue #34 recorded from a
shallow stack. Express, promise chains and `async_hooks`-heavy frameworks all put you at the cap.
That is where the headroom was.

That depth-dependence is *materialization*, not walking, and it is a lever. Timed in isolation on
Node 22, a capture costs a ~4–5 µs floor plus ~1.4 µs per frame it materializes: 1 frame ~6.1 µs,
3 frames ~7.6 µs, 6 frames ~12.2 µs, 25 frames ~37.8 µs. `Error.stackTraceLimit` applies *after*
the `Error.captureStackTrace` boundary skip, so a shim that hands **its own entry frame** in as
the boundary pays for the frames below it and nothing else.

#133 did this for the `process.env` traps. **#143 did it for every other guarded surface**, and
the depth-dependence above is largely gone with it: what a mediated call now pays is a 3-frame
capture regardless of how deep the caller's stack is, because the frames below the caller are
never materialized. `attributeCaller()` — the public full-walk API, which has no boundary to hand
in — still costs what the table says, which is why the `[D]` rows are unchanged and are the
control group for the measurement below.

### Measured prefix depth, per surface (#143)

The fast path materializes `FAST_PATH_FRAMES` (3) CallSites below the boundary and falls back to
the verbatim full walk when none of them qualifies. Whether 3 is enough is a fact about each
shim's own call chain, so it was measured rather than assumed — by dumping the frames V8 builds
below each candidate boundary on Node 22:

| surface | boundary handed in | frames between it and the caller | fast path |
|---|---|---|---|
| `fs.*` (sync, callback, promises, `glob`) | the wrapped method | 0 | hits |
| `fs.existsSync` / `fs.exists` | the probe function itself | 0 | hits |
| `new fs.ReadStream` / `WriteStream` | the guarded subclass | 0 | hits |
| `net.connect`, `Socket.prototype.connect`, `http(s).request`, `ClientRequest`, `http2.connect` | the wrapper / guarded class | 0 | hits |
| `dgram` `send` / `connect` | the guarded method | 0 | hits |
| `child_process.*`, `ChildProcess.prototype.spawn` | the wrapper | 0 | hits |
| `fetch`, `WebSocket`, `EventSource` | the wrapper / guarded class | 0 | hits |
| `vm.*`, `worker_threads.Worker` | the wrapper / guarded class | 0 | hits |
| `Module.prototype._compile`, direct call | the patched method | 0 | hits |
| `process.env` traps (#133) | the trap | 0–2 (builtin/`node:` hops) | hits |
| **`process.dlopen`** | — | **7** (`node:internal/modules/*` + capwall's `_load`) | **not used** |

`fs` needed the boundary to be *threaded* to reach 0: there are three capwall frames between the
wrapped method and the decision (`wrapped` → `guardCall` → `check`), and letting `guard` use its
own frame instead would have materialized and discarded all three — measured at ~4 µs a call for
nothing. The `via` parameter through those helpers is what buys that back.

The `dlopen` row is the honest negative result. `require('x.node')` is seven frames of Node's
loader away from the gate, so a 3-frame prefix would find nothing but neutral machinery, decline,
and pay the short capture **on top of** the full walk. Sizing the shared prefix for it would make
every `fs` and `net` call subsidise a gate that fires a handful of times per process and is
dominated by `dlopen` itself. That gate stays on the full walk, and the `[G]` row below confirms
it did not move.

### Before / after (#143)

Five full runs of each build, **alternated** (before/after, after/before, …) with the same
harness, on a contended 16-core box; the figure is the minimum over runs of each run's own
min-over-blocks estimate, with the run-to-run range beside it. Alternating the *builds* is the
same discipline the harness applies to blocks, one level up — a single run of each is exactly the
estimator artifact that produced a phantom +5% regression once before.

| row | before | after | |
|---|---|---|---|
| `fs.readFileSync` (3-frame stack) | 36.5 µs (36.5–43.3) | **19.8 µs** (19.8–41.5) | 1.85x |
| `fs.readFileSync` (27-frame stack) | 57.8 µs (57.8–101.1) | **20.5 µs** (20.5–46.1) | **2.82x** |
| `fs.globSync('*.txt')` | 49.6 µs (49.6–170.0) | **28.1 µs** (28.1–100.8) | 1.77x |
| `net.connect` (6-key options bag) | 32.1 µs (32.1–82.0) | **17.2 µs** (17.2–33.8) | 1.87x |
| `fs.readFileSync` via ESM import | 44.5 µs (44.5–90.2) | **20.6 µs** (20.6–27.9) | 2.16x |
| `fs` read, denied | 52.0 µs (52.0–56.6) | **28.7 µs** (28.7–61.4) | 1.81x |
| `net` connect, denied | 36.3 µs (36.3–40.6) | **21.3 µs** (21.3–46.1) | 1.70x |
| `spawnSync`, denied | 38.6 µs (38.6–40.4) | **19.9 µs** (19.9–42.2) | 1.95x |
| `fetch`, denied | 46.0 µs (46.0–86.8) | **24.7 µs** (24.7–34.6) | 1.86x |
| `fs` read via opaque frame → `<unknown>` | 54.6 µs (54.6–60.8) | **30.7 µs** (30.7–64.9) | 1.78x |
| `fetch` (allowed, real localhost HTTP) | ≲102.5 µs (102.5–223.0) | ≲68.8 µs (68.8–143.0) | below resolution in both |
| `child_process.spawnSync` (allowed) | ≲ (negative, 3 ms baseline) | ≲ (negative) | **no resolvable change** |
| `process.env` read | 13.6 µs (13.6–28.1) | 13.9 µs (13.9–33.7) | unchanged — #133 already did it |
| `{...process.env}` (81 keys) | 2.341 ms (2.341–5.296) | 2.369 ms (2.369–5.196) | unchanged, same reason |
| `http.globalAgent` property read | ≲102 ns | ≲104 ns | unchanged (no guard on the read) |
| `Module._load` passthrough / mediated | ≲114 ns / −1.8 µs | ≲104 ns / −1.9 µs | unchanged |
| hardened vs plain `fs.readFileSync` | ≲−1.9 µs | ≲−1.6 µs | unchanged |
| `attributeCaller()` at depth 0 / 8 / 24 | 19.6 / 34.7 / 44.9 µs | 19.8 / 28.7 / 42.1 µs | unchanged (the control group) |
| `attributeCaller()` opaque / budget-exhausted | 23.3 / 45.1 µs | 20.3 / 39.8 µs | unchanged |
| `evaluate()` | 184 ns | 170 ns | unchanged |
| `packageForPath` cold flat / chain / warm | 1.8 µs / 3.6 µs / ≲28 ns | 1.5 µs / 3.2 µs / ≲29 ns | unchanged |
| `[G]` `Module._compile` gate, per CJS load | ≲7.2 µs | ≲6.6 µs | unchanged **by design** |
| `[G]` `process.dlopen` gate, per addon | ≲30.9 µs | ≲27.8 µs | unchanged **by design** |
| `[G]` ESM cold resolve, mediated specifier | ≲ (negative) | ≲ (negative) | below resolution in both |
| **RATIO gate** (fs delta ÷ co-sampled cpu) | **2.49 – 4.14** | **0.89 – 1.73** | ~2.8x |

Reading the table honestly:

- **The rows that should not have moved did not.** The `[D]` attribution rows call the public
  `attributeCaller()`, which takes no boundary and still walks the full budget; `evaluate()`,
  `packageForPath` and `Module._load` are untouched code. They are the control group, and a
  version of this table where they *had* moved would mean the two builds differed in something
  other than the change.
- **The env rows did not move either, and this change does not claim them.** `shims/env.ts` is
  byte-identical; #133 had already converted it. An earlier three-run pass showed the env rows
  moving ~2x, which was a machine-mood artifact of too few runs — exactly the failure mode the
  five-run alternation exists to catch. It is recorded here rather than quietly dropped.
- **`spawnSync` did not benefit and was left alone in the reporting.** A real `/bin/true` spawn is
  ~3 ms with hundreds of microseconds of block-to-block spread; the gate's ~20 µs is far under
  that, so the paired delta is noise in both builds. The **deny** row (1.95x) is where that gate's
  own cost is visible.
- **The `_compile` and `dlopen` gates did not move, and that was predicted before it was
  measured.** `_compile`'s per-module-load path never reaches attribution at all — it recognizes
  Node's loader frame with a one-frame capture and returns — and `dlopen` was deliberately left on
  the full walk for the prefix-depth reason above. Both rows exist (thanks to #134) so that
  "no change" is a measurement rather than an assumption.

## Where the budget does not hold

`{...process.env}` — the shape `dotenv`, config loaders and Node's own spawn use — runs the env
Proxy's `getOwnPropertyDescriptor` **and** `get` traps once per key, and each of those attributes
the caller from scratch. It is 81 interceptions wearing one call's clothing, and no amount of
per-interception optimization changes the multiplier.

**#133 halved the per-interception cost, and the row still blows the budget.** Attribution's
price is dominated by how many V8 CallSites the capture materializes (~4 µs fixed plus ~1.4 µs
per frame), and the reading package is nearly always the frame directly below the trap — so the
env traps now start the capture below their own frame and materialize 3 frames instead of 25.
Measured on an 81-key environment, twelve alternating runs of the two builds:

| | before #133 | after #133 |
|---|---|---|
| `{...process.env}`, added latency for one JS call | 4.0 – 4.9 ms | **1.9 – 2.2 ms** |
| per attribution (162 of them) | ~25 – 30 µs | **~12 – 13 µs** |
| single `process.env.K` read by a dependency | ~26 – 29 µs | **~10 – 14 µs** |

That is the honest ceiling for this shape. Both traps must still decide independently on every
key — the descriptor trap cannot tell a spread from a real
`Object.getOwnPropertyDescriptor(env, k).value`, and sharing one decision between them would put
a cache with attacker-schedulable invalidation inside the anti-exfiltration control — so the
floor is two stack captures per key, and `Error.captureStackTrace` itself costs ~4 µs no matter
how few frames it materializes. **80 keys × 2 captures cannot fit in 1 ms.**

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
  anti-exfiltration control. It remains the only way to get this shape under 1 ms.

## Resolution limits

Some deltas are smaller than the thing they sit on top of, and the harness says so rather than
printing a confident number:

- **`spawnSync`** — a real `/bin/true` spawn costs ~3 ms with hundreds of microseconds of
  block-to-block spread. capwall's added cost is far below that, so the row is marked `≲` and
  should be read as "somewhere under a few hundred microseconds". The **deny** row (~20 µs) is
  the trustworthy figure for the gate machinery itself. This is also why #143 reports **no
  resolvable change** for this row: the improvement it made to every other gate is real here too,
  and it is invisible under a 3 ms syscall.
- **`fetch`** — real localhost HTTP, a ~500 µs–3 ms baseline; the delta is noisy enough that both
  the before and after #143 figures print `≲`. The **`fetch`, denied** row is the resolvable one.
- **hardened mode** — measured at or below resolution, i.e. hardening costs nothing per call,
  which is what you would expect from an `Object.freeze` that happens at shim-build time.
- **`[G]` ESM cold resolve** — a loader-thread round trip is milliseconds with millisecond spread,
  and capwall's synthetic-module half is far under it, so the paired delta prints `≲` and is
  frequently negative. Read it as "the mediated half of a cold resolution is below the noise floor
  of the resolution itself", which is a genuine answer to #134's question and not a measurement.

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

How the limit was derived, so it can be re-derived rather than nudged (all figures **pre-#143**):

| condition | observed ratio |
|---|---|
| idle 16-core Linux box, 6 sequential runs | 2.57 – 2.63 |
| Node 20 in the CI container | 2.29 |
| 8 concurrent benchmark processes on 16 cores | 2.6 – 4.2 |
| 16 concurrent processes (it plateaus) | 4.4 – 4.6 |

The limit is **7**: ~1.5x above the worst contention ever observed, and low enough that a 2.7x
algorithmic regression fails the run. Override with `CAPWALL_BENCH_RATIO_LIMIT`. If you change
`CAL_REPEATS` or the calibration body, this number is invalid until it is re-derived the same way.

**#143 moved the numerator, and the limit is deliberately NOT nudged down to match.** The observed
ratio fell from 2.49–4.14 to **0.89–1.73** across five alternated runs on a contended box, so the
gate now has far more headroom than it was designed with — and a change that undid #143 entirely
would come back at ~2.5 and still pass. Tightening it properly means re-running the contention
sweep in the table above (8 and 16 concurrent processes) on an otherwise idle machine, which is
the one thing this README says not to shortcut; deriving a new limit from a busy box would be
exactly the nudge it warns about. Left as a follow-up, stated here rather than silently accepted.
The `[A]` and `[C]` absolute figures in § Before / after are the interim guard against a #143
reversion.

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
