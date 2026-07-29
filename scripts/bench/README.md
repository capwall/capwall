# capwall benchmarks

capwall's design target is **<1ms of added latency per intercepted call** — the same ballpark
NodeShield reported. `bench.mjs` is the harness that checks whether we hold that line.

```sh
pnpm install          # once
pnpm build            # bench.mjs imports the BUILT packages/core/dist, not src
pnpm bench            # the full run, ~20s
pnpm bench:gate       # the reduced run CI uses, ~10s
node scripts/bench/bench.mjs --json    # machine-readable
node scripts/bench/bench.mjs --no-esm  # skip the ESM arm
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
| ESM cold resolution (`registerHooks` `resolve`/`load`) | yes (#134) | `[G]` — a fresh `?n=` URL per iteration; paired against the same import with a NON-mediated specifier |
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
| ~~Node's loader-thread bootstrap~~ | ~~53~~ | **Gone — #152 moved the hooks to `module.registerHooks()`.** See § After #152 below; it took considerably more than the 53 ms with it. |
| `real-builtins.cts`'s twelve `require`s on the MAIN thread | 13 | #78. They must be eager and inside `index.js`'s static graph: that is the whole proof that they run against a pristine `Module._load` rather than capturing capwall's own shims. Narrowing helps a realm that needs two of them; it cannot help the realm that needs all twelve. |
| `globalThis.Request` → undici | 21 | `global-egress.ts` captures the real `Request.prototype.url` getter at module scope, and V8 materializes undici on the first *observation* of that global (even `getOwnPropertyDescriptor` triggers it — verified). The capture is load-bearing: it is what stops a `Request` with a shadowed `url` accessor — own OR on the prototype — reporting a granted destination while undici dials another (#26/#56). Deferring it to first `fetch()` would put that capture *after* dependencies have run, which is the window it exists to close. Note the guard itself is nearly free once undici is resident — `installGlobalEgressGuard` is ~1 ms — so this is the price of the TOCTOU capture, not of the guard. **Since #170 a process that has switched the guard OFF (`CAPWALL_GLOBAL_EGRESS=0`) no longer pays it** — see § 5. |
| zod on the MAIN thread | 4 (zod 3) / **~62** (zod 4) | `parsePolicy` is real validation of a real document, and the preload always parses one. See § zod 4 below for the measured breakdown of the increase and why none of it is recoverable without giving that sentence up. |
| the ESM shim registry being built eagerly | 3 | #150 opened by asking whether lazy shim construction was the win. **It is worth 3 ms.** `registerEsmHook` needs every specifier's export names before the hooks go live, so the registry cannot be lazy — and it turns out not to matter. Recorded because "we checked and it was small" is a result. |

### Before / after — #150 (narrowing the loader thread's graph)

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

**And, since #196, a mutation-sentinel preflight before that** — the same
`preflight({ kinds: ["src", "dist"] })` `bench.mjs` runs, which is what makes the #184 interlock
("`bench`, `bench:startup`, `canary` and `ci:local` refuse to start on a mutated tree") true of
this harness rather than only of the others. The premise check is not a substitute for it: it
probes the `fs` gate and nothing else, while the arm this harness exists to price is the ESM
perimeter, whose two files hold four catalogued `needsBuild: true` mutants. Demonstrated rather
than argued — with `esm-load-remediation-backstop` compiled into `dist`, the pre-#196 harness
printed `all 3 premise checks PASS` and a full table of numbers for a capwall whose `load`-level
re-mediation backstop had been deleted; the harness refuses outright and names the file and line.

Two measurement choices worth knowing before quoting a number out of it:

- **The clock is read inside the child**, on the first line of the target's entry point, not
  around `spawnSync` in the parent. Fork/exec, parent scheduling and teardown are hundreds of
  milliseconds of variance on a loaded box sitting on top of a ~200 ms signal. The parent-side
  figure is still recorded, and printed under `--verbose`, so the difference is visible rather
  than argued about.
- **`cpu` is the child's own `process.cpuUsage()`** at the same instant, which counts the ESM
  loader thread's work as well as the main thread's. On a mediated child `cpu > wall`, and the gap
  is that thread.
- **`--compare <other/dist/preload.js>` puts a SECOND BUILD in the same rounds** (#171). Both
  builds are premise-checked, and their arms alternate per sample rather than occupying separate
  blocks of wall-clock time — which is how #150 and #152 were measured, and which on a contended
  box lets the block structure outweigh the change. See § Bundling `dist` for what that cost.

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

One thing did fall out of re-checking it, and it was a defect rather than a lead:
**`CAPWALL_GLOBAL_EGRESS=0` did not avoid this cost.** The capture was an IIFE at module scope of
`global-egress.ts`, which is on capwall's static graph, so the 21 ms was paid whether or not the
guard was installed — measured at 188.98 vs 187.78 ms on 22 and 148.76 vs 159.36 ms on 26, i.e. no
difference at all. The switch removed the control and kept its dominant startup cost. Filed as
**#170**, and fixed there.

#### How #170 fixed it without deferring the capture

The obvious fix — move the capture into `installGlobalEgressGuard()`, where `ctx` says whether the
guard is wanted — is provably window-free for the preload path (`install()` runs before the
target's entry point) and **widens** the window for an embedder who imports `@capwall/core` early
and calls `install()` late. That is the #26/#56/#80/#97 perimeter, so it was not taken. Instead
the capture is conditional on something knowable at MODULE EVALUATION, which is as early as the
capture it replaces: `process.env.CAPWALL_GLOBAL_EGRESS`. Every configuration that does not
contradict itself is byte-identical to before; the table is in `shims/global-egress.ts` next to
the code.

Two undici materializations had to go, not one, and the second is the interesting half:

  1. the `Request.prototype.url` capture, above;
  2. **building the `http` shim.** `node:http` carries three members that are the same lazy
     undici binding — `WebSocket`, `CloseEvent`, `MessageEvent` — and `wrapHttpModule`'s copy loop
     read all of them. On the CJS path that charged 21 ms to the first `require("http")`; on the
     ESM path, which builds the whole shim registry eagerly inside `install()`, it charged it to
     **every mediated process**. So switching the guard off refunded nothing on the default
     configuration until this was fixed too. `shims/net.ts` now mirrors a getter-only member of
     the real namespace as a getter rather than flattening it to a value — which is also a more
     faithful shim, since `http.WebSocket` is getter-only on the real namespace and the copy was
     assignable. Reading the DESCRIPTOR does not trigger the binding (measured), which is what
     makes the shape test free; that is *not* true of `globalThis`, where even
     `getOwnPropertyDescriptor` materializes, and is why the global-scope capture had to be
     conditioned on the environment instead of probed for.

Measured after, on a 16-core box at load average 10 (min of 15 cold children per cell, ABBA'd,
`CAPWALL_MODE=enforce`), as the delta between the guard on and `CAPWALL_GLOBAL_EGRESS=0`:

| | guard on | `CAPWALL_GLOBAL_EGRESS=0` | delta |
|---|---|---|---|
| `CAPWALL_ESM=0` | 228–240 ms | 200–221 ms | **19–29 ms** |
| `CAPWALL_ESM=1` (default) | 238–249 ms | 212–220 ms | **25–29 ms** |

The absolute numbers are a busy box and are not comparable with § Startup's; the DELTA is the
result, and it was 0 before. `test/global-egress-capture.test.ts` gates it on
`process.moduleLoadList` rather than on a clock (AGENTS.md § 7), and two mutants in
`scripts/mutants.json` pin both halves.

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
`dist` would collect it. Filed as **#171** with these numbers rather than attempted; § Bundling
`dist` below is the answer, which is that it collects about what this predicts and is declined
anyway, for reasons that only showed up once a bundle actually ran.

## After #152 — `module.registerHooks()`, and the loader thread is gone

#150 shaved capwall's own graph off the loader thread. **#152 removed the thread.** The ESM path
now registers **synchronous, same-realm** `resolve`/`load` hooks with `module.registerHooks()`,
which Node ≥22.15 has and which is Node's named replacement for the DEP0205-deprecated
`module.register()` (see [`docs/node-api-dependencies.md`](../../docs/node-api-dependencies.md)).

Measured with **`pnpm bench:startup`** — the harness committed one PR earlier, for this — with the
two builds' `dist` trees swapped on disk between runs and the build order itself ABBA'd
(before / after / after / before), min-over-runs of the harness's own min-over-rounds. `wall` is
`performance.now()` on the first line of the child's entry point; `cpu` is the same instant's
`process.cpuUsage()`, which **counts the loader thread**, so the `cpu` column is where the thread
itself shows up.

**Idle 16-core, 20 rounds per build.**

| Node | arm | wall before | wall after | | cpu before | cpu after |
|---|---|---|---|---|---|---|
| 22.22.3 | mediated, esm ON | 273.4 ms | **178.8 ms** | **−94.6** | 337.7 ms | **227.0 ms** (−110.7) |
| | `CAPWALL_ESM=0` (control) | 161.3 | 171.0 | +9.7 | 200.3 | 216.2 |
| | bare node (control) | 42.7 | 44.7 | +2.0 | 39.8 | 41.1 |
| 24.18.0 | mediated, esm ON | 241.5 ms | **161.9 ms** | **−79.6** | 303.7 ms | **211.2 ms** (−92.5) |
| | `CAPWALL_ESM=0` (control) | 153.2 | 155.0 | +1.8 | 205.1 | 200.9 |
| | bare node (control) | 42.4 | 42.5 | +0.1 | 41.0 | 41.4 |
| 26.5.0 | mediated, esm ON | 224.2 ms | **141.0 ms** | **−83.2** | 280.9 ms | **182.6 ms** (−98.3) |
| | `CAPWALL_ESM=0` (control) | 140.0 | 137.3 | −2.7 | 183.2 | 177.9 |
| | bare node (control) | 37.7 | 36.8 | −0.9 | 38.1 | 38.0 |

**2 cores (`taskset -c 0,1`) — a GitHub hosted runner, 16 rounds per build.**

| Node | mediated esm ON, wall | | `CAPWALL_ESM=0` control | bare control |
|---|---|---|---|---|
| 22.22.3 | 227.4 → **137.8 ms** | **−89.6** | 138.7 → 136.0 (−2.7) | 30.0 → 36.1 (+6.1) |
| 24.18.0 | 211.7 → **139.0 ms** | **−72.7** | 129.7 → 138.8 (+9.1) | 32.8 → 35.5 (+2.7) |
| 26.5.0 | 211.9 → **142.9 ms** | **−69.0** | 137.1 → 138.8 (+1.7) | 33.5 → 33.1 (−0.4) |

**Under load (16 cores, 24 spinners, loadavg 15→47)** the direction is the same and the magnitudes
are not measurements: an earlier spawn-clocked run put mediated p50 at 1444 → 1051 (22),
1490 → 968 (24) and 1641 → 710 (26), but the `CAPWALL_ESM=0` control moved by +234 ms and +426 ms
on 24 and 26 — which by this document's own rule means the two arms differed in something other
than the change. Quoted only so the row is not silently omitted.

**The controls hold** in every clean row: `bare node` within ±6 ms and `CAPWALL_ESM=0` within
±10 ms, against an ~80–95 ms move on the arm under test. The two rows where a control drifts most
(Node 22 idle, Node 24 at two cores) drift *upward*, i.e. against the change, so they do not
manufacture the result.

### The number that matters most: esm ON now costs about what esm OFF costs

The gap between `mediated, esm ON` and `CAPWALL_ESM=0` — everything the ESM perimeter costs a
process — collapses:

| Node | before #152 | after #152 |
|---|---|---|
| 22.22.3 | 112.1 ms | **7.8 ms** |
| 24.18.0 | 88.3 ms | **6.9 ms** |
| 26.5.0 | 84.2 ms | **3.7 ms** |

The single largest item in the startup breakdown at the top of this section is gone, not reduced.
The `cpu` column says the same thing from the other side: a mediated child used to burn 60–65 ms
more CPU than wall-clock, which was the loader thread; it now burns ~40 ms more, the same as the
`CAPWALL_ESM=0` control.

### What got WORSE, and it is not nothing

**`registerHooks` hooks are consulted for `require()` as well as `import()`.**
`module.register()` hooks were not. So with ESM on, every CJS module load in the process now goes
through capwall's `resolve` and `load`. On the harness's tiny entry point that is unmeasurable;
on a large CJS tree it is not. Measured separately (not by `bench:startup`, whose target is fixed)
at two cores over `require("express")` — 123 modules — comparing `esm ON` against `CAPWALL_ESM=0`
in the same build:

| Node | esm ON − esm OFF, before #152 | after #152 |
|---|---|---|
| 22.22.3 | ~131 ms | **~11 ms** |
| 24.18.0 | ~130 ms | **~18 ms** |
| 26.5.0 | ~102 ms | **~24 ms** |

So roughly **0.1–0.2 ms per CJS module**, where before it was zero: a fixed per-process thread
cost has been traded for a per-module one. On that tree the trade is still strongly positive
(net −120 / −100 / −63 ms end to end), and it is module-load work rather than per-request work,
so the budget in AGENTS.md § 5 is untouched. But it scales with the size of the `require` graph
and it is largest on Node 26, which is where the smallest share of the win survives. An
application large enough for that to matter can turn the ESM perimeter off with `CAPWALL_ESM=0`,
at the price of un-mediated `import`.

**Every row of the per-call table above is unchanged**, as expected for a change that only moves
module loading: `pnpm bench:gate` PASS, ratio 1.04 (limit 7), 21/21 self-checks green.

### zod 4 — the +58 ms is module load, and it is not recoverable (#161)

zod 3.25.76 → 4.4.3 costs the main thread **+58 ms at p50**, on the one budget this section
exists for. It was taken anyway. This subsection is the measurement, so the trade is inspectable
rather than a shrug — and so nobody re-derives it from first principles the next time
`pnpm outdated` prints the row.

**Where it lives.** Cold `node` processes, ABBA-interleaved, ≥25 samples per arm, importing the
REAL `@capwall/policy-schema` barrel and then parsing the real policy file. The two arms differ
only in which `zod` the barrel resolves to.

| phase | zod 3.25.76 | zod 4.4.3 | delta |
|---|---|---|---|
| `import("@capwall/policy-schema")` — zod's module graph **plus** schema construction | 25.5 ms | 83.4 ms | **+57.9** |
| … of which zod's own module graph | ~20 | ~80 | **+60** |
| … of which building capwall's schema tree | ~5.6 | ~17.0 | **+11** |
| `parsePolicy(doc)` on the real policy | 5.77 ms | 5.87 ms | **+0.1 — none** |

So **the regression is entirely module load, and validation itself is free**. zod 4 parses this
document at exactly zod 3's speed; what changed is that `zod`'s ESM entry now evaluates ~79
modules where zod 3's evaluated ~10.

**Every cheaper door was measured, and none of them opens.** Same harness, import cost only:

| entry point | p50 | |
|---|---|---|
| `zod` (v3) | 19.4 ms | the baseline |
| `zod` (v4 classic) | 68.6 ms | what we now pay |
| `zod/mini` | 64.7 ms | −4 ms. Its win is minified bundle size after tree-shaking; Node evaluates the graph either way. Confirms #161. |
| `zod/v4/core` | 54.9 ms | −14 ms, and it would cost the entire inferred-type story — `z.infer` is what makes this package the single source of truth for both the schema and the TS types. Not worth 14 ms. |
| `require("zod")` (CJS) | 83.6 ms | **slower**, not faster: 79 CJS modules resolved synchronously. |

**Why it was not engineered around.** The preload validates a policy on the main thread before
the target's entry point, and that is not optional — an unvalidated policy file is a fail-open in
the component that decides what everything else may do. Three routes were considered and all
three buy the milliseconds with that sentence:

- *Lazy-load zod behind first validation.* Helps only the INERT preload (a stale `NODE_OPTIONS`
  in a shell, the case `preload.ts` deliberately handles by touching no files). Every mediated
  process parses, so the common case pays it anyway. Real but ~0% of the regression, and it would
  put an `await` into the most order-sensitive file in the repo for no gain.
- *Construct the schema tree on demand.* Same shape, same answer: the preload constructs it and
  then immediately parses with it. Worth 17 ms to an embedder who imports `@capwall/core` and
  never validates; worth nothing to a mediated process.
- *Trust a policy the parent already validated* — pass the parsed document to the child instead of
  re-reading and re-validating it. This is the one that would actually work, and it is refused:
  it makes `@capwall/core`'s guarantees depend on who launched the process.

**What it costs a whole mediated child.** Same discipline as the § Before/after table: ABBA
interleaved, ≥15 samples per arm, `bare node` and `CAPWALL_ESM=0` as controls. The child prints
`performance.now()` as its first statement, so the figure is everything the runtime and capwall
did before the application got control. The two arms are two `dist` trees differing only in
which `zod` `@capwall/policy-schema` resolves to.

| condition | child | zod 3 p50 | zod 4 p50 | |
|---|---|---|---|---|
| 16-core, Node 22 | mediated, esm ON | 283 ms | **334 ms** | +51 ms |
| | `CAPWALL_ESM=0` (control) | 167 ms | 228 ms | +62 ms |
| | bare node (control) | 44 ms | 44 ms | 0 — the noise floor |
| `docker --cpus=2`, Node 22 | mediated, esm ON | 347 ms | **402 ms** | +55 ms |
| | `CAPWALL_ESM=0` (control) | 204 ms | 263 ms | +59 ms |
| | bare node (control) | 49 ms | 49 ms | 0 |

**Read the `CAPWALL_ESM=0` row, not the headline.** It moves by the same amount as the mediated
row — which is the signature of a cost that is entirely on the MAIN thread, exactly where a
policy parse lives, and not on the loader thread #150 spent a change on. A version of this table
where `CAPWALL_ESM=0` had *not* moved would mean the two builds differed in something other than
zod.

**What did NOT move, and the check that says so.** zod is still absent from the ESM loader
thread's graph — `test/esm-hook-graph.test.ts`'s static scan and its runtime `moduleLoadList`
probe both pass unchanged against zod 4. #150's work holds; it just never made zod free on the
main thread, and never claimed to.

**One lever is left, and it is deliberately not pulled here.** Node's on-disk V8 compile cache
(`module.enableCompileCache()` / `NODE_COMPILE_CACHE`, available on the whole supported range)
recovers **~34 ms of zod 4's ~80 ms** on a warm cache (45.4 ms vs 79.7 ms p50, same harness) — and
~6 ms of zod 3's, so it narrows the gap rather than closing it. It also makes a security tool's
preload write bytecode into a cache directory in the target's environment, which is a decision
with a threat-model paragraph attached and not a line in a dependency bump. Filed separately.

## Bundling `dist` — the ~15 ms is real, and it is declined (#171)

§ What none of this touches prices capwall's 35-module main-thread graph at ~15–18 ms of pure
resolution, and says a bundle would collect it. **It does: measured at ~9–24 ms.** It is declined
anyway, and the reasons are not the two the issue predicted — they only appeared once a bundle was
actually built and run.

### The prototype, and what it recovered

`rollup` 4.62.3 (MIT, dev-only) over the built `packages/core/dist`, `real-builtins.cjs` and
`@capwall/policy-schema` external, two entry points. **capwall's 35 ES modules collapse to two
chunks**: `index.js` (33 modules, 499 KiB) and `preload.js` (2 modules, 13 KiB).

Measured with `pnpm bench:startup --compare <other>/dist/preload.js`, which this PR added for
exactly this and which is the reproducible half of the result:

```
node scripts/bench/startup.mjs --rounds 25 \
  --node ~/.nvm/versions/node/v24.18.0/bin/node \
  --compare packages/core/dist-bundled/preload.js
```

`--compare` puts both builds' mediated arms in the **same round**, so they alternate per sample
under the existing ABBA order and share the machine's mood. That matters more than it sounds:
#150 and #152 were measured by swapping the two builds' `dist` trees on disk between whole
harness runs, which leaves each build's samples contiguous in wall-clock time. Done that way here,
on a box at loadavg ~3.5, the `CAPWALL_ESM=0` arm moved by −6 ms on Node 22 and −18 ms on Node 24
for a change that is identical on both — i.e. the block structure was worth more than the signal.
Per-sample interleaving collapsed that spread. Min of 25 rounds, 5 arms, both builds premise-
checked independently.

| Node | arm | unbundled | bundled | Δ |
|---|---|---|---|---|
| 22.22.3 | mediated, esm ON — capwall's own cost | 149.8 ms | **125.5 ms** | **−24.3** |
| | `CAPWALL_ESM=0` | 148.3 | 133.1 | −15.1 |
| | bare node (control) | 35.7 ms absolute, both arms | | |
| 24.18.0 | mediated, esm ON — capwall's own cost | 156.4 ms | **139.8 ms** | **−16.6** |
| | `CAPWALL_ESM=0` | 152.7 | 142.1 | −10.6 |
| | bare node (control) | 38.2 ms absolute, both arms | | |
| 26.5.0 | mediated, esm ON — capwall's own cost | 147.6 ms | **138.7 ms** | **−8.9** |
| | `CAPWALL_ESM=0` | 140.0 | 128.0 | −12.0 |
| | bare node (control) | 36.5 ms absolute, both arms | | |

Read the two treatment rows together, per § zod 4's rule: this is a MAIN-thread change, so
`CAPWALL_ESM=0` is a second treatment arm and not a control — it must move by about the same
amount, and it does. `bare node` is the only control, and it is the same binary in both arms.
The six deltas average **−14.6 ms**, on a capwall cost of 140–156 ms: **~9%**, and squarely
inside the 15–18 ms § What none of this touches predicted from the synthetic barrel.

So the ceiling is confirmed. What follows is why it is not taken.

### Three things a bundle changes that no bundler flag controls

**1. Two path-derived security constants silently change meaning.** `CAPWALL_ROOT` is computed
twice — in `attribution/index.ts` and in `loader/module-read.ts` — as
`path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")`. Emitted at
`dist/attribution/index.js` that is `<package>/dist`. Emitted from a bundle at `dist/index.js` it
is `<package>` — one level up. Attribution then treats **every frame under the package root** as
capwall's own machinery and skips it; the #123 module-read trust root widens the same way. In this
repository that charges real dependencies to `<unknown>`, and **84 tests fail** with
`attribution hit the 25-frame budget and fell back to '<unknown>'`.

The fix is one character (`".."` → `"."` plus a bundler that knows it). The finding is not the fix:
**in the published layout the same change is silent**, because `node_modules/@capwall/core/..` has
nothing in it but capwall's own files, so the widened predicate never matches anything it should
not. It was caught here only because this repo happens to keep `test/fixtures/` one level above
`dist`. Nothing in the repo asserts either constant's value. A security predicate whose value is a
function of which directory the build tool put a file in is the "breaks nothing and fails nothing"
shape that #150's and #152's mutants exist for — and there is no mutant for this one because
until a bundler existed there was nothing that could move it.

**2. capwall generates source code containing a resolvable path, and that file therefore cannot be
bundled.** `loader/esm-hook.ts` computes

```js
const here = path.dirname(fileURLToPath(import.meta.url));
bridgeUrl: pathToFileURL(path.join(here, "esm-runtime.js")).href,
```

and writes `bridgeUrl` into the source of **every synthetic mediated-builtin module** the `load`
hook returns. Bundled, `here` is `dist` instead of `dist/loader`, so the first `import("node:dgram")`
dies with `ERR_MODULE_NOT_FOUND: .../dist/esm-runtime.js imported from capwall-esm:node:dgram`.
Measured, not reasoned about.

`esm-runtime.js` must therefore stay a separately emitted file at a stable path — **and must not
ALSO be inlined into the bundle**, because `pushEsmContext`/`popEsmContext` maintain a context
stack that the hook pushes onto and the synthetic module pops from. Two copies is not a slow ESM
perimeter, it is a split-brain one, and the missing-context direction is the permissive one. A
correct bundle needs `esm-runtime.js` as a third entry point and needs to get that right; nothing
would fail if it did not, which is the same objection as (1).

**3. `@capwall/policy-schema` cannot be inlined either.** The first prototype did inline it, and
`bench:startup`'s premise check killed the run:
`Cannot find package 'zod' imported from @capwall/core/dist/index.js`. Bundling a workspace
dependency hoists **its** dependencies into the bundling package's resolution scope, and under
pnpm's strict layout `@capwall/core` cannot see `zod` — it is `@capwall/policy-schema`'s
dependency. Making it work means declaring `zod` a direct runtime dependency of `@capwall/core`,
which changes the published dependency graph and the one-command licence audit
(`pnpm --filter '@capwall/*' licenses list --prod`). So the bundle can only ever collect capwall's
own 33 modules; policy-schema's 3 and zod's 79 stay where they are. The ~62 ms zod costs — **four
times what bundling recovers** — is untouched by any of this.

### And the ordinary work, for completeness

- **Source maps do not chain for free.** rollup does not read the input `.js.map` files, so the
  emitted map's `sources` are `../dist/*.js` — the `tsc` intermediate. Under `files: ["dist","src"]`
  with the per-module `.js` removed, that is **30 dangling references** and
  `scripts/check-tarball-sources.mjs` (#126) fails by construction. Fixable with a hand-written
  `load()` plugin that returns the sibling map, which is one more piece of custom machinery between
  `src/` and what ships.
- **#78's boundary changes from language-enforced to config-enforced.** Today `real-builtins.cts`
  cannot be inlined into ESM `tsc` output — the module systems are different and `tsc` emits two
  files. With a bundler it stays separate because one predicate in a build script says
  `external: id.endsWith(".cjs")`. (In the prototype it held: `import { realFs, … } from
  './real-builtins.cjs'` is the FIRST statement of both emitted chunks, hoisted above every other
  import, which is if anything a stronger ordering than today's. That is not the point — the point
  is that the guarantee now depends on a line nothing tests.) A landable PR needs a new gate over
  the *emitted* output, asserting the capture import is first and that no chunk statically imports
  a mediated builtin.
- **Two tests resolve deep `dist` paths** and would need re-pointing at `dist/index.js`:
  `test/esm-hook-graph.test.ts`'s fixture imports `dist/policy/load.js`, and
  `test/linked-packages.test.ts` resolves `dist/attribution/index.js`. Both are one-liners.
- **The `.d.ts` tree stays unbundled** (TS 7 ships no programmatic API, so there is no `.d.ts`
  bundler here), leaving `dist` with a per-module declaration tree whose sibling `.js` files no
  longer exist.

### The issue's own two collisions, corrected

#171 was filed against `test/esm-hook-graph.test.ts`'s **static scan of the loader thread's import
graph**. That scan no longer exists: #152/#173 moved the hooks to `module.registerHooks()`, which
runs them in this realm, and both scans — the zod ban and the narrow per-builtin captures — were
deleted with the thread they guarded. What is left in that file is #167's **zod-resolve budget**,
and a bundle does not move it: zod stays external, the count stays 180, and only the fixture's
`import` needs re-pointing. So one of the two stated blockers is stale, and the other (#78) turned
out to be the easy one.

### The decision

**DECLINED.** ~14 ms, ~9% of capwall's startup cost, in exchange for making three run-time
behaviours depend on which directory a build tool decided to put a file in — two of them security
predicates, and one of them silent in the published layout, where it matters and where no test
runs. Against that, the artifact itself: `dist` today is `tsc` output, near enough a 1:1
transliteration of the `src/` that ships beside it (#126), so an auditor can diff them by eye. A
bundle makes the executing artifact a machine-rewritten concatenation whose correspondence to
`src` can only be checked by trusting rollup or re-running it — in a tool whose entire argument is
that a build-time dependency is attack surface.

The largest remaining term is still zod, at ~62 ms, and none of this reaches it.

**If this is revisited**, the checklist is the six items above, and the first thing to do is not to
write a bundler config: it is to make `CAPWALL_ROOT` and `bridgeUrl` independent of the emitting
file's directory, and add a test that asserts each one's value. Both are worth doing on their own
merits — they are load-bearing constants with no coverage — and until they are, a bundle cannot be
proven safe rather than merely observed to pass.

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
- **`[G]` ESM cold resolve** — a cold module resolution is milliseconds with millisecond spread
  (it was a loader-thread round trip when this row was written; since #152 it is Node's own
  resolver on this thread, and the spread is the same order), and capwall's synthetic-module half
  is far under it, so the paired delta prints `≲` and is
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
