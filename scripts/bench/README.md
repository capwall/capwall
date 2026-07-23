# capwall benchmarks (stub)

capwall's design target is **<1ms per intercepted request** of overhead — the same ballpark
NodeShield reported. This directory will hold the harness that verifies we hold that line.
Not yet implemented.

## What to measure

- **Per-call overhead** on the hot path: `attribution` (stack capture + module→package
  resolution) + `policy/evaluate` (lookup + glob/host match), per intercepted core-API call.
  Attribution is expected to dominate.
- **Baseline vs shimmed** for each capability (fs read/write, net connect, env read), as
  absolute ns and as % over the unshimmed builtin.
- **End-to-end request latency** on `examples/express-app`: p50/p95/p99 with capwall off,
  in `observe`, and in `enforce`.
- **Cold vs warm** attribution: first resolution of a module→package vs a cache hit.

## Intended method

- Use `node --expose-gc` and a steady-state loop; discard warmup iterations.
- Prefer `process.hrtime.bigint()` for per-call timing; `mitata`/`tinybench` (permissive
  licenses only) for suites.
- Report median and tail, not just mean — tail matters for the per-request claim.
- Gate in CI (stretch S4): fail if median per-call overhead regresses past the <1ms target.

## Layout (planned)

```
scripts/bench/
  hot-path.bench.ts     per-call attribution + evaluate microbench
  express.bench.ts      end-to-end request latency on the example app
  README.md             (this file)
```
