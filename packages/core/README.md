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

### Install options

| Option | Default | What it does |
|---|---|---|
| `projectRoot` | `process.cwd()` | Root for attribution and relative policy globs. |
| `onDecision` | no-op | Called on every decision (allowed and denied) — the observe log / `gen-policy` trace sink. |
| `env` | `true` | Gate `process.env` reads by dependencies against the `env` allowlist. |
| `esm` | `false` (the CLI preload turns it on) | Also register the ESM loader hook. |
| `hardened` | `false` | **Opt-in.** Freeze the shim surfaces so a dependency cannot monkey-patch away mediation. **Breaks `graceful-fs`** — read before enabling. |

### Environment variables (the `@capwall/core/preload` entry)

| Variable | Meaning |
|---|---|
| `CAPWALL_MODE` | `observe` \| `enforce`. Required to activate; absent = inert. |
| `CAPWALL_POLICY_FILE` | Path to `capabilities.json` (optional in observe). |
| `CAPWALL_TRACE_FILE` | Where to append the JSONL decision trace. |
| `CAPWALL_PROJECT_ROOT` | Project root for attribution / glob resolution (default: cwd). |
| `CAPWALL_ESM` | `0` disables the ESM loader hook (default: on under the CLI). |
| `CAPWALL_HARDENED` | `1` enables hardened mode (default: off). |

### Hardened mode (`hardened: true` / `CAPWALL_HARDENED=1`)

capwall's shims are ordinary mutable objects by default, so a dependency can do
`fs.readFileSync = evil` (or `net.Socket.prototype.connect = evil`) and silently disable
enforcement **for the whole process**. Hardened mode `Object.freeze`s the surfaces capwall
created: each shim namespace (`fs`, `fs.promises`, `net`, `http`, `https`, `tls`, `http2`,
`dgram`, `child_process`, `worker_threads`, `vm`), the guarded wrapper functions on them, and
the guarded subclasses (`net.Socket`, `http.ClientRequest`, `http.Agent`, `tls.TLSSocket`,
`dgram.Socket`, `child_process.ChildProcess`) **plus their prototypes**.

It is opt-in for a blunt reason: **freezing `fs` breaks `graceful-fs`** — a transitive
dependency of npm, webpack, and much of the ecosystem — and every other legitimate `fs`
patcher, which fails to load with a `TypeError`. It also closes only the reassignment escape:
`process.getBuiltinModule("node:fs")`, `http.globalAgent.createConnection`, replacing
`process.env`, and the construct-trap `Proxy` class wrappers (`fs.ReadStream`, `vm.Script`,
`worker_threads.Worker`) are all unaffected. Read
[`docs/threat-model.md` § Hardened mode](../../docs/threat-model.md) for the full accounting
before turning it on, and roll it out under `observe` first.

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
