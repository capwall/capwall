# @capwall/core

The capwall interception engine and policy evaluator. This is where module-load
interception, the capability shims, package attribution, and policy evaluation live.

> **Status (roadmap M1–M3 done):** the CJS require patch, stack-walk attribution, the `fs`
> shim, and policy load/evaluate are real and tested. The other shims (net, child_process,
> worker_threads, env, vm) and the ESM hook are still stubs marked `// TODO(capwall):`.
> See [`../../AGENTS.md`](../../AGENTS.md) and
> [`../../docs/architecture.md`](../../docs/architecture.md).

## API

```ts
import { install, loadPolicy } from "@capwall/core";

const policy = await loadPolicy("./capabilities.json", { projectRoot: process.cwd() });
const handle = install(policy, "observe", {
  projectRoot: process.cwd(),
  onDecision: (pkg, decision) => console.log(pkg, decision.reason),
}); // or "enforce"
// handle.uninstall() restores the loader (tests/teardown).
```

`install(policy, mode)` patches the CJS loader so subsequent `require("fs")` (and
`fs/promises`) return capwall's shim, which attributes each call to its owning package and
evaluates it against the policy. The CLI installs this automatically in child processes via
`@capwall/core/preload` (a `NODE_OPTIONS --import` entry configured by `CAPWALL_*` env vars).

## Configuration

### `install()` options

| Option | Default | What it does |
|---|---|---|
| `projectRoot` | `process.cwd()` | Root used to resolve relative policy globs and to tell app code from dependencies. |
| `onDecision` | no-op | Called on **every** decision (allowed and denied, both modes) — the observe log sink and the `gen-policy` trace source. |
| `env` | `true` | Gate `process.env` reads by dependencies against the `env` allowlist. |
| `esm` | `false` (`true` under the CLI) | Also register the ESM loader hook. |
| `attribution.maxFrames` | `25` | Frames the attribution stack walk may inspect — see below. |

### Environment variables (the preload channel)

The preload is configured only through env vars, because that is the only channel a
`--import` entry has. The CLI sets these for the target process; you can also set them
yourself when wiring the preload by hand.

| Variable | Default | What it does |
|---|---|---|
| `CAPWALL_MODE` | *(unset — capwall stays inert)* | `observe` or `enforce`. Required to activate. |
| `CAPWALL_POLICY_FILE` | *(none)* | Path to `capabilities.json`. Optional in observe; required in enforce (enforce with no policy denies everything). |
| `CAPWALL_TRACE_FILE` | *(none)* | Append the JSONL decision trace here, for `capwall gen-policy`. |
| `CAPWALL_PROJECT_ROOT` | `process.cwd()` | Project root for attribution and glob resolution. |
| `CAPWALL_ESM` | on | `0` disables the ESM loader hook (the CJS path is unaffected). |
| `CAPWALL_MAX_FRAMES` | `25` | Attribution frame budget — see below. |

### Attribution frame budget (`maxFrames` / `CAPWALL_MAX_FRAMES`)

Attribution walks the call stack for the nearest dependency frame and charges that package.
The walk inspects at most `maxFrames` frames. **If the owning dependency's frame sits deeper
than that** — long promise chains, deeply-nested or dynamically-compiled wrappers,
`async_hooks`-heavy frameworks — the walk runs out of budget and falls back to `<app>`, which
is a **mis-attribution**: the app is the trust root and usually holds broad grants, so a call
that should have been denied can be allowed (and, conversely, a dependency's granted call can
be denied under `<app>`'s deny-by-default).

```bash
CAPWALL_MAX_FRAMES=100 capwall enforce -- node ./src/server.js
```

```ts
install(policy, "enforce", { attribution: { maxFrames: 100 } });
```

Notes:

- The default is unchanged from capwall's original hard-coded value, so raising it is always
  an explicit decision.
- **Invalid values fail open**: anything that is not a positive integer is ignored with a
  warning on stderr and the default is used. capwall runs inside someone else's process and
  must not crash a host app over a config typo.
- Every mediated call pays for the walk, so a very large budget costs throughput (the
  <1ms/req target in [`../../AGENTS.md`](../../AGENTS.md) § 5). Raise it to fit your deepest
  real stack, not "just in case".
- When the walk *does* exhaust its budget, the decision handed to `onDecision` carries
  `attributionTruncated: true` and the preload prints a one-time stderr warning, so a capped
  `<app>` attribution is distinguishable from a genuine app-root call. Enforcement behavior is
  unchanged by the flag — it is observability, not a new deny path.

## Layout

```
src/index.ts            install(policy, mode) entry point
src/preload.ts          --import entry for child processes (CAPWALL_* env config)
src/loader/require.ts   CJS require/loader patch (live; fs only so far)
src/loader/esm-hook.ts  ESM module.register loader hook (stub, M5)
src/shims/fs.ts         fs shim (live); net/child_process/worker/env/vm are stubs (M4)
src/attribution/        stack-walk → owning package (nearest-package policy, memoized)
src/policy/*.ts         schema (re-export), load (glob normalization), evaluate, glob
test/                   evaluator, attribution, glob, and fixture-based e2e slice tests
```

## Build order

Follow [`../../docs/roadmap.md`](../../docs/roadmap.md): `fs` observe slice → trace→policy →
enforce → remaining shims → ESM.
