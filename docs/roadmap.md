# capwall roadmap

The authoritative build order. `AGENTS.md` § 4 mirrors this. **Do not start a step until the
previous step has passing tests and a clean typecheck** (`pnpm -r test && pnpm -r typecheck`).

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
- Loader hooks via `module.register` (`core/src/loader/esm-hook.ts`); reach parity with the
  CJS path. Expect this to be genuinely hard (static imports resolve before hooks; immutable
  bindings) — see architecture.md Risks.

## Stretch (post-MVP — listed, not scheduled)

### S1 — SBOM / CBOM import
- `@capwall/sbom-import`: CycloneDX (and CBOM) → starter policy, NodeShield-compatible.
  Currently a stub; see `packages/sbom-import/README.md`.

### S2 — native-addon attribution
- Attribute (and gate) `.node` addon loads. Confinement remains a non-goal.

### S3 — CI observed-vs-declared diff
- A CI action that runs observe and diffs against the committed policy, flagging new
  capabilities a dependency started using (drift detection).

### S4 — full ESM parity & performance hardening
- Close remaining ESM gaps; benchmark and hold the **<1ms/req** target (see
  `scripts/bench/README.md`).

## Milestones summary

| Milestone | Deliverable | Gate | Status |
|---|---|---|---|
| M1 | fs observe slice + express-app | observe logs fs, tests green | ✅ done |
| M2 | trace → capabilities.json | policy emitted from a run | ✅ done |
| M3 | enforce mode | malicious-dep-demo blocked; deny-by-default test | ✅ done |
| M4 | all core shims | net/cp/worker/env/vm enforced | ✅ done |
| M5 | ESM parity | ESM path reaches CJS parity | next |
| S1 | SBOM/CBOM import | @capwall/sbom-import | ✅ done |
| S4 | perf benchmark | pnpm bench, <1ms/req validated | ✅ done |
| S2,S3 | stretch | native-addon attr; drift diff | — |
