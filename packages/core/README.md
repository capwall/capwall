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
