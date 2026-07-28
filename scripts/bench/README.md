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
| `fs.glob`/`globSync`/`promises.glob` (#106) | yes (Node ≥22) | `fs.globSync`; present on every supported Node since the floor moved to ≥22.15 |
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
| **process startup** (loading the preload + `install()`) | **no** — by `bench.mjs`; **yes** by `startup.mjs` | a different unit — milliseconds once per process, not microseconds per call — so folding it in would put two incomparable numbers in one table. It has its own harness, `pnpm bench:startup`; the breakdown is in § Startup below (#150) and the per-major numbers in § The ≥22.15 floor. |

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

## Startup — what a mediated process pays before it runs (#150)

Everything above is per intercepted CALL. This section is the other axis: the fixed cost of
`node --import dist/preload.js`, paid once per process, by every user of capwall on every process
they mediate — a CLI that shells out, a test runner spawning workers, a serverless cold start.
`bench.mjs` does not measure it (see the coverage table); these numbers come from a separate
ABBA-interleaved harness, described below so they can be re-derived rather than trusted.

### The breakdown, before the fix

Node 22.22, idle 16-core box. Phase marks are `Date.now()` stamps compiled into a throwaway copy of
`dist`, so the main thread and the loader thread share one clock. **Read the shares, not the
totals** — the totals move with the machine, the shares do not.

| phase | ms | whose cost |
|---|---|---|
| Node's own bootstrap, before capwall's first module | ~48 | Node's (this is the `bare node` reference) |
| **main thread — capwall's module graph** | **~81** | |
| … resolving + compiling ~33 modules | ~40 | capwall's, and only a bundler would move it |
| … `real-builtins.cts` — twelve `require`s | 13 | **immovable** (#78; see below) |
| … `globalThis.Request` → undici materialization | 21 | **immovable** (see below) |
| … `policy/evaluate` + policy-schema + zod | 4 | needed: the preload parses a policy |
| … the other ~28 modules' evaluation | ~1 | |
| preload body: read + `parsePolicy` the policy file | 2 | |
| `install()` — require patch, link observer, `_compile` gate, native gate, env guard, egress guard | 2 | |
| **`registerEsmHook()`** | **93** (min) / 112 (p50) | |
| … Node's loader-thread bootstrap | ~53 | **Node's** — measured by registering a no-op hook module in the same process |
| … capwall's hook graph on that thread | ~40 | 22 resolve+compile, 18 evaluate |
| … ESM shim registry (all 11 specifiers) + `esmExportNames` + `MessageChannel` | 3 | |

So of ~180 ms of capwall in a ~250 ms child: **`module.register()` is 93 ms of it, and 53 ms of
that is Node starting a thread.** The ESM loader thread is the startup story; nothing else is close.

### What moved, and what did not

**Moved (#150): the ~40 ms capwall's own graph cost on the loader thread → ~17 ms.** That thread
evaluates ~10 capwall modules and needs almost nothing they were dragging in:

- **zod**, via `@capwall/policy-schema`'s barrel, which builds the whole schema tree at module
  scope. The loader thread never parses a policy — it is handed an already-parsed one in an
  `EsmGateSnapshot`. `policy/evaluate.ts` and `attribution/index.ts` now import
  `@capwall/policy-schema/host` and `/package-key` instead, which are pure string grammar.
- **ten of the twelve mediated builtins**, via `real-builtins.cts`. That realm uses `fs` (attribution
  reads package.json) and `worker_threads` (#123's synchronous port drain). Narrow captures under
  `src/real-builtins/` give it those two.

`test/esm-hook-graph.test.ts` holds both in place — a static scan of the hook's transitive graph
plus a runtime probe in a clean child with positive controls — and both have mutants in
`scripts/mutants.json`, because the regression in each case is a one-line import that breaks nothing
and fails nothing.

**Did not move, with the reason rather than a shrug:**

| cost | ms | why it stays |
|---|---|---|
| Node's loader-thread bootstrap | ~53 | Node's, and `register()` blocks until it is done. `module.registerHooks()` (synchronous, no thread) would remove it. **The version objection is gone**: it is Node ≥22.15, which is exactly the supported floor, so it needs no gate and no second version-conditional implementation of a security-critical hook. Node 26 additionally DEPRECATED `module.register()` (DEP0205) in its favour. Tracked as #152 — still a follow-up with a real design question in it (the ESM perimeter is where #59/#61/#62 lived), not a tweak. |
| `real-builtins.cts`'s twelve `require`s on the MAIN thread | 13 | #78. They must be eager and inside `index.js`'s static graph: that is the whole proof that they run against a pristine `Module._load` rather than capturing capwall's own shims. Narrowing helps a realm that needs two of them; it cannot help the realm that needs all twelve. |
| `globalThis.Request` → undici | 21 | `global-egress.ts` captures the real `Request.prototype.url` getter at module scope, and V8 materializes undici on the first *observation* of that global (even `getOwnPropertyDescriptor` triggers it — verified). The capture is load-bearing: it is what stops a `Request` with a shadowed own `url` accessor reporting a granted destination while undici dials another (#26/#56). Deferring it to first `fetch()` would put that capture *after* dependencies have run, which is the window it exists to close. Note the guard itself is nearly free once undici is resident — `installGlobalEgressGuard` is ~1 ms — so this is the price of the TOCTOU capture, not of the guard. |
| zod on the MAIN thread | 4 | `parsePolicy` is real validation of a real document, and the preload always parses one. |
| the ESM shim registry being built eagerly | 3 | #150 opened by asking whether lazy shim construction was the win. **It is worth 3 ms.** `registerEsmHook` needs every specifier's export names to ship to the loader thread, so the registry cannot be lazy there — and it turns out not to matter. Recorded because "we checked and it was small" is a result. |

### Before / after

ABBA-interleaved: the two builds' `dist` trees are swapped on disk between **every** sample, so both
arms share the machine's mood — the same discipline the block estimator applies one level down.
p90 over ≥15 samples per arm. `bare node` and `CAPWALL_ESM=0` are the **control rows**: this change
is entirely on the loader-thread path, so a version of this table where either had moved would mean
the two builds differed in something other than the change.

| condition | child | before p90 | after p90 | |
|---|---|---|---|---|
| idle 16-core, Node 22 | mediated, esm ON | 253 ms | **221 ms** | −31 ms |
| | `CAPWALL_ESM=0` (control) | 146 ms | 144 ms | −2 ms |
| | bare node (control) | 48 ms | 54 ms | +6 ms — the noise floor |
| `docker --cpus=2`, Node 22 | mediated, esm ON | 280 ms | **259 ms** | −21 ms |
| | `CAPWALL_ESM=0` (control) | 156 ms | 158 ms | +2 ms |
| `docker --cpus=2`, Node 20 (EOL; historical) | mediated, esm ON | 289 ms | **249 ms** | −40 ms |
| | `CAPWALL_ESM=0` (control) | 166 ms | 160 ms | −5 ms |
| 16-core, 24 spinners (load 21) | mediated, esm ON | 1102 ms | **950 ms** | −152 ms |
| | `CAPWALL_ESM=0` (control) | 576 ms | 602 ms | +26 ms |

**Every row of the per-call table above is unchanged**, which is the expected result for a change
that only moves module loading: three alternated full `pnpm bench --json` runs of each build put
every row inside its own run-to-run range, the RATIO gate at 0.89–0.90 in both, and all 21
self-checks green in all six runs.

Read honestly: this is **12–14%** off a mediated process's startup, not a rewrite of it. The
dominant term is still Node starting a loader thread, and the two largest capwall-side terms
(#78's capture and the undici materialization) are each bought by a guarantee that is worth more
than the milliseconds.

## The ≥22.15 floor — five leads, measured (#159)

Dropping EOL Node 20 (#155) made a set of APIs unconditionally available that capwall was written
without. This section is what each of them turned out to be worth. **One was taken — as a
documented operator switch rather than as capwall behaviour — and four were rejected.** The
rejections are the useful half: each one is a thing the next person does not have to re-derive.

**Read the deltas, not the totals.** Everything below was measured on a *contended* 16-core box
(loadavg 10–18 throughout, other suites running), so absolute figures run ~1.4x the idle numbers
in § Startup above. The arms are ABBA-interleaved and the estimator is min-over-samples, so the
differences survive the contention; the totals do not. Where the contention swallowed a result
this section says so rather than rounding it into a claim.

### The startup harness is committed now

`scripts/bench/startup.mjs`, wired as **`pnpm bench:startup`**. The ~180 ms breakdown in § Startup
came from a harness that was never checked in, so every claim about startup since has had to be
taken on trust or rebuilt from scratch — twice now (#150, and again for #161's zod measurement).
It applies the same discipline `bench.mjs` applies one level down: ABBA-interleaved arms with the
round order reversed on odd rounds, a min estimator, `bare node` and `CAPWALL_ESM=0` as mandatory
control rows, and — the part that matters — **a premise check before it times anything**. Every
arm's target `require`s the granted-nothing `bench-dep-denied` fixture and attempts an `fs` read;
the mediated arms must DENY it, with a `CapabilityError`, charged to `bench-dep-denied`; the bare
arm must allow it and capwall must not speak. Without that, a preload that silently failed to
install (a bad path, a policy that parsed to inert, a `--import` Node quietly ignored) is timed as
"bare node twice" and reported as a spectacular win.

Two measurement choices worth knowing before quoting a number out of it:

- **The clock is read inside the child**, on the first line of the target's entry point, not
  around `spawnSync` in the parent. Fork/exec, parent scheduling and teardown are hundreds of
  milliseconds of variance on a loaded box sitting on top of a ~200 ms signal. The parent-side
  figure is still recorded, and printed under `--verbose`, so the difference is visible rather
  than argued about.
- **`cpu` is the child's own `process.cpuUsage()`** at the same instant, which counts the ESM
  loader thread's work as well as the main thread's. On a mediated child `cpu > wall`, and the gap
  is that thread.

It deliberately does **not** gate. Startup is a machine-dependent wall-clock number and gating on
one is the flake generator AGENTS.md § 7 forbids; #167 is where the gate question lives, and a
module-COUNT gate is the candidate there, not this.

### 1. `module.enableCompileCache()` — real, and an operator's switch rather than capwall's

**TAKEN, as documentation.** Node's on-disk V8 compile cache (`NODE_COMPILE_CACHE` since 22.1,
`module.enableCompileCache()` since 22.8) does work on a `--import` preload: a mediated child
populates **49 blobs / 268 KiB**, and on the next run `NODE_DEBUG_NATIVE=COMPILE_CACHE` reports
every one of capwall's ESM modules `accepted`, on 22, 24 and 26 alike. Two entries per module,
because the main thread and the loader thread each compile them.

`pnpm bench:startup --compile-cache`, 25 rounds, two reps per major, min estimator, quoting
**capwall's own cost** (the arm minus its matching bare-node control):

| Node | arm | no cache | warm cache | |
|---|---|---|---|---|
| 22.22.3 | `CAPWALL_ESM=0` | 121.3 / 136.4 ms | **105.2 / 120.2 ms** | −16.1 / −16.2 |
| | mediated, esm ON | 242.2 / 248.5 ms | 209.2 / 238.0 ms | −33.0 / −10.5 |
| 24.18.0 | `CAPWALL_ESM=0` | 125.1 / 129.7 ms | **100.7 / 110.4 ms** | −24.4 / −19.3 |
| | mediated, esm ON | 206.2 / 231.5 ms | 198.6 / 217.2 ms | −7.6 / −14.3 |
| 26.5.0 | `CAPWALL_ESM=0` | 127.7 / 134.5 ms | **114.2 / 103.1 ms** | −13.5 / −31.4 |
| | mediated, esm ON | 222.3 / 211.2 ms | 224.3 / 223.3 ms | +2.0 / +12.1 |

Read that table honestly, because half of it is noise:

- **The `CAPWALL_ESM=0` arm is the trustworthy row.** It moved the same direction in all six
  runs, on all three majors, by **13.5–31.4 ms**. That arm has no loader thread, so the only
  thing between the two columns is V8 compiling capwall's module graph.
- **The full mediated arm did not resolve on this box.** Same change, same runs: −33.0 to +12.1.
  The loader thread's own scheduling under loadavg 15 is larger than the effect being measured.
  The mechanism is not in doubt — the cache demonstrably hits on that thread too — but the
  whole-child figure is not something this machine can put a number on, and inventing one from
  the favourable half of the runs is exactly the estimator artifact § Methodology exists to stop.
- **The V8 component, measured directly** (a `vm.SourceTextModule` / `vm.Script` compile of every
  file in `core/dist` + `policy-schema/dist`, 38 files / 557 KiB, min of 15 ABBA blocks):

  | Node | compile, no cache | with `cachedData` | saved, per pass |
  |---|---|---|---|
  | 22.22.3 | 7.31 ms | 1.77 ms | 5.55 ms |
  | 24.18.0 | 7.72 ms | 1.69 ms | 6.03 ms |
  | 26.5.0 | 6.45 ms | 1.23 ms | 5.22 ms |

  That is the *floor*, not the ceiling: it caches only what a fresh compile eagerly produces
  (96 KiB of blobs), where a real `NODE_COMPILE_CACHE` run writes what the process actually
  compiled (268 KiB), lazily-compiled function bodies included, and pays it twice — main thread
  and loader thread.

**Why it is documentation and not a default.** Three properties of the API, none of them about
the measurement, and they answer #166's five bullets:

1. **Process-wide, with no way off.** There is no `disableCompileCache()`. To cover capwall's own
   graph it has to be on before capwall's first module compiles, and from that instant every
   module the *host application* compiles is serialized to disk too. capwall is injected into
   someone else's process through `NODE_OPTIONS`; writing that process's compiled code into a
   directory of capwall's choosing is not a call an injected security tool makes for the host.
2. **The cache I/O is invisible to capwall's own `fs` gate.** Verified: with `NODE_COMPILE_CACHE`
   set and a trace file attached, a mediated run records the fixture's `fs:read` and records
   **nothing at all** for the cache directory — the reads and writes happen natively, below the
   JS `fs` surface capwall mediates. capwall would be causing disk activity its own control
   cannot see or record.
3. **Integrity is against corruption, not against an adversary.** Node stores a hash of the
   payload in each blob's header and rejects a mismatch — verified by flipping bytes in a
   populated cache on 22, which yields `cache hash mismatch` and a clean recompile. That is
   Node's own non-cryptographic checksum over a file Node wrote: it stops bit rot, not someone
   with write access to the directory. The default location is 0700 and uid-suffixed on all three
   majors, which keeps that to the same-uid case — but it is a deserialize-and-execute path on
   the boot line of a supply-chain firewall, and it wants an operator's yes.

So the answer to "opt-in or default" is **neither: it is Node's switch, and it already works.**
`NODE_COMPILE_CACHE=<dir> capwall enforce -- node app.js` needs no capwall code, since the CLI
passes the environment through to the child. It is documented in `packages/core/README.md`
§ Environment variables and in `docs/node-api-dependencies.md` § The V8 compile cache, and it
closes #166. capwall's gates are unaffected by it: the whole suite and `bench.mjs`'s 21
self-checks are green with the cache enabled, writing 774 blobs.

### 2. `module.registerHooks()` — deliberately not here

Worth ~53 ms, tracked as **#152**, and out of scope on purpose. It is the ESM perimeter where
#59, #61 and #62 lived, and it needs its own PR with the full laundering-vector suite run against
both paths. Nothing in this section touches `loader/`. What it *does* leave behind is a measuring
device: `pnpm bench:startup` prices exactly the arm #152 changes, with the mediated-vs-`ESM=0`
gap already broken out, so that work does not have to build one first.

### 3. V8 across 22 → 24 → 26 — stack capture did not get cheaper, it got slightly dearer

**REJECTED, and in the opposite direction from the hypothesis.** capwall's hot path is
`Error.captureStackTrace` plus structured CallSite access, and the guess was that three majors of
V8 might have made it cheap enough that some constant tuned in 2024 (`FAST_PATH_FRAMES`,
`DEFAULT_MAX_FRAMES`) is now wrong in a recoverable direction. Measured with the three node
binaries themselves ABBA-interleaved round-robin — the same discipline, one level further up,
because otherwise this is a measurement of which version happened to run while the box was quiet:

| node / stack depth below the boundary | 1f | 3f | 5f | 6f | 8f | 25f |
|---|---|---|---|---|---|---|
| 22.22.3, 3 below | 4.91 | 7.57 | 9.82 | 9.83 | 12.10 | 13.31 |
| 22.22.3, 27 below | 5.18 | 7.84 | 10.93 | 11.41 | 13.85 | **34.02** |
| 24.18.0, 3 below | 4.93 | 8.04 | 10.11 | 10.50 | 12.97 | 13.67 |
| 24.18.0, 27 below | 5.50 | 8.48 | 11.14 | 12.50 | 15.08 | **38.09** |
| 26.5.0, 3 below | 4.88 | 7.67 | 10.93 | 10.96 | 12.63 | 13.97 |
| 26.5.0, 27 below | 5.64 | 8.76 | 10.79 | 11.93 | 16.40 | **39.51** |

µs per capture, min over 6 interleaved rounds. The Node 22 row reproduces § Stack depth's own
figures (~6.1 µs at 1 frame, ~7.6 at 3, ~12.2 at 6, ~37.8 at 25) closely enough to trust the
method.

Three readings, and none of them moves a constant:

- **The floor rose 9%** across three majors (5.18 → 5.64 µs at one frame from a deep stack), and
  **the deep 25-frame capture rose 16%** (34.0 → 39.5 µs). Newer V8 is not cheaper here.
- **The marginal frame got dearer too**: (25f − 3f) ÷ 22 frames is 1.19 µs on 22, 1.35 on 24,
  1.40 on 26. `FAST_PATH_FRAMES = 3` is therefore *better* justified than when it was chosen, not
  worse — and raising it to 5 would cost +3.1 / +2.7 / +2.0 µs on **every** mediated call for no
  coverage gain, since every surface but `dlopen` already sits 0 frames below its boundary and
  `dlopen` needs 7.
- **`DEFAULT_MAX_FRAMES = 25` stays.** Lowering it is a security change, not a perf one (a deeper
  owner falls to `<unknown>`), and raising it only costs on the slow path. Nothing in this table
  argues for either.

The one thing that *did* change is the case for #143 itself: the boundary-frame optimization is
worth more on 26 than it was on 22, because the frames it declines to materialize now cost more.

### 4. Newer built-ins that would replace hand-rolled work — three candidates, three rejections

Min over 12 blocks of 20 000 calls, per Node:

| candidate | capwall today | the built-in | verdict |
|---|---|---|---|
| `path.matchesGlob` vs `policy/glob.ts` | **99 / 153 / 153 ns** (22/24/26) | 13 650 / 11 575 / 11 368 ns | **REJECTED — 75–110x slower**, before the semantics even come up |
| `structuredClone` vs `shims/pin.ts` | 3 591 / 3 497 / 4 077 ns | 3 580 / 3 680 / 3 471 ns | **REJECTED — no speed to gain, and it is not the same operation** |
| `URL.parse` vs `new URL` in `try/catch` | valid 955 / 850 / 738 ns; **invalid 9 710 / 11 006 / 11 364 ns** | valid 1 044 / 849 / 792 ns; **invalid 288 / 260 / 254 ns** | **NOT TAKEN — see below** |

- **`path.matchesGlob` is the surprise.** It is two orders of magnitude slower than capwall's
  compiled-and-cached `RegExp`, which is enough on its own for a function on the `fs` guard's hot
  path. The semantic objection is the larger one and was the expected answer: it is a
  minimatch-flavoured dialect, considerably richer than the one `policy/glob.ts` documents, so
  swapping it in would silently *widen* every `fs` grant a policy author has written. Two
  independent reasons, and the fast one is not the one that matters.
- **`structuredClone` is not the same operation.** `pin.ts` exists to flatten own accessors to
  data properties *losslessly* — `Reflect.ownKeys` + `defineProperty`, so non-enumerable and
  symbol-keyed fields survive (#26/#56/#89). Measured: `structuredClone` **drops** both, and
  throws `DataCloneError` on a bag carrying a function — which `net` and `child_process` options
  routinely do (`lookup`, `createConnection`, `stdio`). It is also no faster. There is nothing
  here to trade.
- **`URL.parse` is 34–43x faster on the INVALID path only** (it returns `null` instead of
  constructing and throwing), and identical on the valid one. The invalid path exists in
  `shims/global-egress.ts` `targetFromHref` and two places in `shims/net.ts` — all of which reach
  it for input Node itself is about to reject, so the caller is already broken. Left alone: the
  `net.ts` sites have `catch` blocks covering more than the `new URL` call, and narrowing them is
  a behaviour change on the #26/#56/#99 pin path in exchange for ~10 µs on a path a working
  program does not take. Recorded so it is a decision rather than an oversight.

Nothing else came up. `Object.groupBy`, `Set.prototype.union`/`intersection`, `Array.prototype`
`findLast`/`toSorted`/`at` and the rest of the ES2024/2025 additions have no hand-rolled
equivalent in `packages/*/src` — the enforcement path does very little collection work by design.

### 5. undici / `globalThis.Request` materialization — re-checked, and the obvious fix is dead too

**REJECTED, and now with a proof rather than a reason.** § Startup records 21 ms for undici being
materialized by `global-egress.ts`'s capture of the real `Request.prototype.url` getter, and
concluded it cannot be deferred without reopening the #26/#56 TOCTOU window. Two things were
re-checked at the new floor:

- **No major makes it cheaper.** Touching `globalThis.Request` in an otherwise-empty process costs
  53 / 53 / 53 ms on 22 / 24 / 26 on this box (~21 ms idle, per § Startup). `Response`, `Headers`,
  `WebSocket` and `FormData` are the same slot; `globalThis.fetch` is **not** — reading it costs
  0.01 ms on every major, because Node's `fetch` global is a real function that pulls undici in
  when it is *called*. So the cost is specifically the `Request.prototype` capture, and it is
  unchanged from 22 to 26.
- **The lazy-interposition idea does not work, and this is the new part.** The obvious escape is
  to install capwall's *own* accessor on `globalThis.Request` at install time — early enough that
  nothing can tamper before it — and let it materialize undici and capture the pristine getter on
  the first read by anyone. That would close the TOCTOU window without paying 21 ms in a process
  that never touches `fetch`. It does not work: **`Object.defineProperty(globalThis, "Request", …)`
  itself materializes undici**, measured at 67 / 66 / 48 ms on 22 / 24 / 26. Every way of touching
  that slot — a read, a `getOwnPropertyDescriptor`, or a `defineProperty` over it — triggers the
  lazy initializer. There is no interposition that is cheaper than the capture it would defer.

One thing did fall out of re-checking it, and it is a defect rather than a lead:
**`CAPWALL_GLOBAL_EGRESS=0` does not avoid this cost.** The capture is an IIFE at module scope of
`global-egress.ts`, which is on capwall's static graph, so the 21 ms is paid whether or not the
guard is installed — measured at 188.98 vs 187.78 ms on 22 and 148.76 vs 159.36 ms on 26, i.e. no
difference at all. The switch removes the control and keeps its dominant startup cost. Filed as
**#170** rather than fixed here: moving the capture into `installGlobalEgressGuard()` is provably
window-free for the preload path (`install()` runs before the target's entry point) and widens the
window for an embedder who imports `@capwall/core` early and calls `install()` late, which is the
#26/#56/#80/#97 perimeter and deserves its own PR for the same reason #152 does.

### What none of this touches: the compile cache's ceiling is compile, and the cost is resolution

§ Startup attributes ~40 ms to "resolving + compiling ~33 modules". The measurement above splits
that: **compiling all of capwall's shipped JavaScript is 6.5–7.7 ms.** The rest is resolution and
per-module loader machinery, which no compile cache touches.

Priced directly — 35 trivial ES modules behind a barrel versus the identical code in one file, in
a cold process, min of 7:

| Node | 35 modules via a barrel | the same source, 1 module |
|---|---|---|
| 22.22.3 | 24.93 ms | 7.10 ms |
| 24.18.0 | 21.02 ms | 5.96 ms |
| 26.5.0 | 20.40 ms | 5.60 ms |

~15–18 ms, or ~450–500 µs per module, that exists only because the graph has 35 nodes in it.
capwall ships 35 on the main thread and ~10 more on the loader thread. That is the largest
remaining capwall-side term in § Startup after #78's capture and the undici materialization, and
unlike those two it is not bought by a guarantee — it is bought by the source layout. Bundling
`dist` would collect it, and is emphatically not a drive-by: `real-builtins.cts` has to stay a
separate CJS module for #78's proof to mean anything, and `test/esm-hook-graph.test.ts` holds the
loader thread's graph in place with a *static scan of the import graph* that a bundle would
invalidate. Filed as **#171** with these numbers rather than attempted.

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
| Node 22 in the CI container | 2.29 |
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
covers it on Node 22, 24 and 26. `CI_BENCH=0 pnpm ci:local` skips it.

## Layout

```
scripts/bench/
  bench.mjs                                          the per-CALL harness ("pnpm bench")
  startup.mjs                                        the per-PROCESS harness ("pnpm bench:startup")
  fixtures/node_modules/bench-dep/index.js           granted fixture dependency (CJS arms)
  fixtures/node_modules/bench-dep/esm.mjs            the ESM arm, imported under two URLs
  fixtures/node_modules/bench-dep-denied/index.js    granted-nothing twin (deny-path arms)
  fixtures/startup-app.cjs                           startup.mjs's target: the clock + the premise check
  README.md                                          this file
```
