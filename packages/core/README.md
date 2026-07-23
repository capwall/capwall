# @capwall/core

The capwall interception engine and policy evaluator. This is where module-load
interception, the capability shims, package attribution, and policy evaluation live.

> **Scaffold.** Only the policy evaluator has real, tested logic (deny-by-default). Loaders,
> shims, and attribution are stubs marked `// TODO(capwall):` with doc-comments on the
> intended approach. See [`../../AGENTS.md`](../../AGENTS.md) and
> [`../../docs/architecture.md`](../../docs/architecture.md).

## Intended API

```ts
import { install } from "@capwall/core";
import { loadPolicy } from "@capwall/core/policy";

const policy = await loadPolicy("./capabilities.json");
install(policy, "observe"); // or "enforce"
```

`install(policy, mode)` patches the loader and swaps capability-sensitive core modules for
shimmed versions, so subsequent `require`/`import` of `fs`, `net`, etc. go through capwall.

## Layout

```
src/index.ts            install(policy, mode) entry point
src/loader/require.ts   CJS require/loader patch
src/loader/esm-hook.ts  ESM module.register loader hook
src/shims/*.ts          fs, net, child_process, worker_threads, env, vm shims
src/attribution/        stack-walk → owning package (THE core research risk)
src/policy/*.ts         schema (re-export), load, evaluate (deny-by-default)
test/core.test.ts       passing smoke tests (extend, don't delete)
```

## Build order

Follow [`../../docs/roadmap.md`](../../docs/roadmap.md): `fs` observe slice → trace→policy →
enforce → remaining shims → ESM.
