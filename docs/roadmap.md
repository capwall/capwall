# capwall roadmap

The authoritative build order. `AGENTS.md` § 4 mirrors this. **Do not start a step until the
previous step has passing tests and a clean typecheck** (`pnpm -r test && pnpm -r typecheck`).

> **This file is the single place milestone status is tracked.** Other docs point here rather
> than restating it — they drifted twice when they did not. As of now, **M1–M5 and S1–S4 are
> all done** (table at the bottom). "Done" means implemented and tested, not that capwall is
> a boundary: read [`threat-model.md`](./threat-model.md) for what the mediation is and is
> not worth.

## Principle: depth before breadth

Get the full **observe → policy → enforce** loop working end-to-end on **one capability
(`fs`)** before adding the other shims. A vertical slice that actually blocks a malicious
`fs` read is worth more than six half-wired shims.

## MVP

### M1 — `fs` vertical slice (observe)
- Patch CJS `require`/`Module._load` (`core/src/loader/require.ts`).
- Attribution: stack-walk → owning package (`core/src/attribution`), with module→package
  caching.
- `fs` shim (`core/src/shims/fs.ts`) wired behind **observe** mode: logs every fs read/write
  with the attributed package; blocks nothing.
- `examples/express-app` runs end-to-end under observe; its fs (and net) use is logged.
- **Done when:** express-app boots under `capwall observe`, fs activity is attributed and
  logged, tests + typecheck green.

### M2 — trace → `capabilities.json` (headline)
- `capwall observe` records observed capabilities and emits a starter `capabilities.json`
  (`cli/src/commands/observe.ts`, `gen-policy.ts`).
- Merge (not overwrite) on repeated runs.
- **Done when:** running observe on express-app writes a policy matching what it did.

### M3 — `enforce` mode
- `policy/evaluate.ts`: deny-by-default; throw on violation with a clear, attributed error.
- `examples/malicious-dep-demo` is **blocked in enforce**, **allowed (logged) in observe**.
- Regression test: a package not in policy is denied `fs` access in enforce mode.
- **Done when:** the malicious-dep-demo block works both ways and the regression test passes.

### M4 — remaining shims
- `net`/`http(s)`, `child_process`, `worker_threads`, `env`, `vm` shims, each following the
  attribute→evaluate→forward/log/throw pattern from `fs`.
- Extend policy generation and `explain` to cover them.

### M5 — ESM
- Loader hooks via `module.registerHooks()` (`core/src/loader/esm-hook.ts`); reach parity with the
  CJS path. Expect this to be genuinely hard (static imports resolve before hooks; immutable
  bindings) — see architecture.md Risks.

## Stretch (post-MVP — listed, not scheduled)

### S1 — SBOM / CBOM import
- `@capwall/sbom-import`: CycloneDX (and CBOM) → starter policy, NodeShield-compatible.
  Implemented — `sbomToPolicy()` / `parseCycloneDx()`, reading `capwall:*` component
  properties as the CBOM annotation convention. No runtime dependency (a CycloneDX SBOM is
  JSON). See `packages/sbom-import/README.md`.

### S2 — native-addon attribution
- Attribute (and gate) `.node` addon loads. Confinement remains a non-goal.
- Implemented as a `process.dlopen` patch (`core/src/loader/native.ts`) — the one JS-reachable
  chokepoint every addon load passes through, including a direct `process.dlopen` call and the
  `bindings`/`node-gyp-build`/`node-pre-gyp` resolver chains. The `native` grant is a boolean,
  not a path list, because addon paths are platform/arch/ABI build artifacts (see
  `docs/policy-format.md` § `native`). A load is charged to both the caller and the addon's
  owning package, so a shared resolver's grant is not a tree-wide skeleton key.

### S3 — CI observed-vs-declared diff
- Runs observe and diffs against the committed policy, flagging new capabilities a dependency
  started using (drift detection).
- Shipped as the **`capwall diff`** subcommand (`cli/src/commands/diff.ts`): exit 0 = no
  drift, 1 = drift, 2 = usage error / missing policy, plus `--json`. It gates
  `examples/express-app` in this repo (`packages/cli/test/express-app-policy.test.ts`).
  Usage: `docs/ci-local.md` § Drift detection in CI.

### S4 — full ESM parity & performance hardening
- Close remaining ESM gaps; benchmark and hold the **<1ms per intercepted call** target (see
  `scripts/bench/README.md`).
- `pnpm bench` measures every mediated surface — fs (including `glob`), egress (module and
  global), spawn, the env Proxy, attribution hits *and* misses, the install-chain parse, the
  `Module._load` chain, the ESM import path and hardened mode — as paired, ABBA-interleaved
  arms against the same call un-mediated, and verifies its own premises before it times
  anything.
- **The budget holds per intercepted call, and only per intercepted call.** Measured added
  latency is ~30–90 µs per interception. But a single JS call is not always a single
  interception: `{...process.env}` runs the env Proxy twice per key and costs ~2 ms on an 81-key
  environment — issue #133 got that down from ~4.4 ms by making the env traps capture 3 stack
  frames instead of 25, which is as far as it goes without weakening the gate, because both
  traps must still decide per key and a capture has a ~4 µs floor.
  `pnpm bench` prints those cases under `AMPLIFICATION` every
  run rather than folding them into a healthy-looking average — see `scripts/bench/README.md`
  § Where the budget does not hold. Any doc that states `<1ms/req` without the "per intercepted
  call" qualifier is overclaiming.
- `pnpm bench:gate` is the reduced run wired into CI and `pnpm ci:local`. It gates on three
  things: the 1 ms per-interception budget, the harness's own self-checks, and a **ratio**
  against a CPU calibration co-sampled in the same loop — the ratio is what actually catches a
  regression, because the 1 ms budget has 10–30x headroom and would not notice a 3x slowdown.
- The ESM residuals that are deliberately *not* closed are named in
  `docs/threat-model.md` § ESM known limits.

## Milestones summary

| Milestone | Deliverable | Gate | Status |
|---|---|---|---|
| M1 | fs observe slice + express-app | observe logs fs, tests green | ✅ done |
| M2 | trace → capabilities.json | policy emitted from a run | ✅ done |
| M3 | enforce mode | malicious-dep-demo blocked; deny-by-default test | ✅ done |
| M4 | all core shims | net/cp/worker/env/vm enforced | ✅ done |
| M5 | ESM parity | ESM path reaches CJS parity | ✅ done |
| S1 | SBOM/CBOM import | @capwall/sbom-import | ✅ done |
| S2 | native-addon attribution | `.node` loads attributed + gated | ✅ done |
| S3 | CI observed-vs-declared diff | `capwall diff` flags drift | ✅ done |
| S4 | perf benchmark | pnpm bench, <1ms per intercepted call validated across every mediated surface; `pnpm bench:gate` in CI | ✅ done |
