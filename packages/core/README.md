# @capwall/core

The capwall interception engine and policy evaluator. This is where module-load
interception, the capability shims, package attribution, and policy evaluation live.

> **Status:** everything in this package is implemented and tested — the CJS require patch,
> the ESM loader hook, stack-walk attribution, policy load/mode/evaluate, the `process.dlopen`
> native-addon gate, and every capability shim (`fs`; `net`/`http`/`https`/`tls`/`http2`/
> `dgram`; `child_process`; `worker_threads`; `vm`; `process.env`; plus `node:module`, which
> is mediated to protect the ESM path rather than as a policy capability). Per-milestone
> status lives in one place, [`../../docs/roadmap.md`](../../docs/roadmap.md); what the
> mediation is worth against which adversary lives in
> [`../../docs/threat-model.md`](../../docs/threat-model.md). See also
> [`../../AGENTS.md`](../../AGENTS.md) and
> [`../../docs/architecture.md`](../../docs/architecture.md).

## API

```ts
import { install, loadPolicy } from "@capwall/core";

const policy = await loadPolicy("./capabilities.json", { projectRoot: process.cwd() });
const handle = install(policy, "observe", {
  projectRoot: process.cwd(),
  onDecision: (pkg, decision) => console.log(pkg, decision.reason),
}); // or "enforce"
// handle.uninstall() removes the interception again — see the caveat below.
```

`install(policy, mode)` turns four things on: the CJS loader patch (so a subsequent
`require("fs")`, `require("node:net")`, … returns capwall's shim), the `process.dlopen`
native-addon gate, the `process.env` read guard, and — when `esm: true`, which the CLI
sets — the ESM loader hook, so `import` of a mediated builtin lands on the same shims. Each
shim attributes its calls to the owning package and evaluates them against the policy. The
CLI installs all of this automatically in child processes via `@capwall/core/preload` (a
`NODE_OPTIONS --import` entry configured by `CAPWALL_*` env vars).

`handle.uninstall()` is for tests and teardown, and is **best-effort on the ESM path only** —
Node cannot fully remove a registered loader hook, so teardown there is fail-closed rather
than reversible (see [`../../docs/threat-model.md`](../../docs/threat-model.md) § ESM known
limits).

## Configuration

### `install()` options

| Option | Default | What it does |
|---|---|---|
| `projectRoot` | `process.cwd()` | Root used to resolve relative policy globs and to tell app code from dependencies. |
| `onDecision` | no-op | Called on **every** decision (allowed and denied, both modes) — the observe log sink and the `gen-policy` trace source. |
| `env` | `true` | Gate `process.env` reads by dependencies against the `env` allowlist. |
| `esm` | `false` (`true` under the CLI) | Also register the ESM loader hook. |
| `attribution.maxFrames` | `25` | Frames the attribution stack walk may inspect — see below. |
| `hardened` | `false` | **Opt-in.** Freeze the shim surfaces so a dependency cannot monkey-patch away mediation. **Breaks `graceful-fs`** — see below. |

### Environment variables (the preload channel)

The preload is configured only through env vars, because that is the only channel a
`--import` entry has. The CLI sets these for the target process; you can also set them
yourself when wiring the preload by hand.

| Variable | Default | What it does |
|---|---|---|
| `CAPWALL_MODE` | *(unset)* | `observe` or `enforce`, and it outranks everything. When unset, the mode comes from the policy document's own `mode` field (that is what `capwall run` relies on); if neither declares one, capwall stays **inert**. An unrecognized value is inert too, not a fall-through. Full precedence table: [`docs/policy-format.md` § Enforcement mode](../../docs/policy-format.md#enforcement-mode). |
| `CAPWALL_POLICY_FILE` | *(none)* | Path to `capabilities.json`. Optional in observe; required in enforce (enforce with no policy denies everything). |
| `CAPWALL_TRACE_FILE` | *(none)* | Append the JSONL decision trace here, for `capwall gen-policy`. |
| `CAPWALL_PROJECT_ROOT` | `process.cwd()` | Project root for attribution and glob resolution. |
| `CAPWALL_ESM` | on | `0` disables the ESM loader hook (the CJS path is unaffected). |
| `CAPWALL_MAX_FRAMES` | `25` | Attribution frame budget — see below. |
| `CAPWALL_HARDENED` | off | `1` (exactly) enables hardened mode — see below. Any other value leaves it off. |
| `CAPWALL_ALLOW_LOADER_HOOKS` | off | `1` (exactly) lets a **dependency** call `module.register`/`registerHooks`, which is otherwise application-only (#61). Still warns loudly. See [`docs/threat-model.md` § Loader-hook registration](../../docs/threat-model.md). |

That is the complete list — capwall reads no other `CAPWALL_*` variable. Note that
`CAPWALL_*` keys are never gated or recorded by the `env` shim (they are capwall's own
plumbing, not the target's environment).

### Hardened mode (`hardened: true` / `CAPWALL_HARDENED=1`)

capwall's shims are ordinary mutable objects by default, so a dependency can do
`fs.readFileSync = evil` (or `net.Socket.prototype.connect = evil`) and silently disable
enforcement **for the whole process**, with no log line. Hardened mode `Object.freeze`s the
surfaces capwall created:

- every shim namespace (`fs`, `fs.promises`, `net`, `http`, `https`, `tls`, `http2`, `dgram`,
  `child_process`, `worker_threads`, `vm`);
- every guarded wrapper function on them (including `fs.realpath.native`);
- every guarded class **and its prototype** — `fs.ReadStream`/`WriteStream`, `net.Socket`,
  `tls.TLSSocket`, `http(s).ClientRequest`, `http(s).Agent`, `dgram.Socket`,
  `child_process.ChildProcess`, `vm.Script`/`SourceTextModule`/`SyntheticModule`,
  `worker_threads.Worker`;
- the guarded `send`/`connect` properties capwall installs for a `dgram` socket — pinned
  individually (a socket cannot be frozen; it needs its state).

All of it applies to `import` as well as `require`.

Real builtins are never frozen — that would be a process-global side effect outliving
`uninstall()`. Subclassing a guarded class (`class Mine extends fs.ReadStream {}`) still works.

```bash
CAPWALL_HARDENED=1 capwall enforce -- node ./src/server.js
```

It is opt-in for a blunt reason: **freezing `fs` breaks `graceful-fs`** — a transitive
dependency of npm, webpack, and much of the ecosystem — and every other legitimate `fs`
patcher, which fails to load with a `TypeError`. Note also that a blocked patch is **silent**
in sloppy-mode CJS (the write just no-ops; only `"use strict"` code sees the `TypeError`), and
that hardened mode closes only the reassignment escape: `process.getBuiltinModule("node:fs")`,
`http.globalAgent.createConnection` (issue #65), replacing `process.env`, and climbing past a
guarded prototype are all unaffected. Read
[`docs/threat-model.md` § Hardened mode](../../docs/threat-model.md) for the full accounting
before turning it on, and roll it out under `observe` first.

### Attribution frame budget (`maxFrames` / `CAPWALL_MAX_FRAMES`)

Attribution walks the call stack for the nearest dependency frame and charges that package.
The walk inspects at most `maxFrames` frames. **If the owning dependency's frame sits deeper
than that** — long promise chains, deeply-nested or dynamically-compiled wrappers,
`async_hooks`-heavy frameworks — the walk runs out of budget and falls back to `<unknown>`,
which is a **mis-attribution**: the call is denied by default in enforce even though a real,
possibly well-granted package owns it. (Before #60 it fell back to `<app>`, the trust root,
so the same mis-attribution could wrongly *allow* the call instead. Failing closed is the
better default, but it means a deep-stack framework can surface as unexplained denials —
raise the budget rather than granting `<unknown>`.)

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
  `<unknown>` attribution is distinguishable from any other unattributable call. The flag does
  not change the outcome — it tells you *which* knob fixes it (this budget), rather than the
  `<unknown>` grant.

## Policy principals

A grant is keyed by package name, or by one of two sentinels:

| Key | Meaning |
|---|---|
| `"<app>"` | the application's own code — a real source file not under `node_modules`. Exempt from the `process.env` and `dgram` gates (it is the trust root). |
| `"<unknown>"` | a call capwall could not attribute to any source file: no qualifying frame on the stack, or app code reached only through a `data:`/`eval`/bundled frame. **Not** exempt — deny-by-default in enforce, recorded in observe. |

`<unknown>` exists because "we could not attribute this" must not silently mean "this is the
app" (issue #60). Grant it only as narrowly as an `observe` run shows you need — Node's ESM
loader produces one unattributable `env` read per process, and `capwall observe` emits that
grant for you. See [`../../docs/threat-model.md`](../../docs/threat-model.md) § attribution
outcomes.

## Layout

```
src/index.ts               install(policy, mode, options) entry point + public re-exports
src/preload.ts             --import entry for child processes (CAPWALL_* env config)
src/errors.ts              CapabilityError
src/loader/require.ts      CJS require/Module._load patch; MEDIATED_MODULES lives here
src/loader/esm-hook.ts     ESM module.register() registration (main-thread side)
src/loader/esm-hooks.ts    the loader-thread resolve/load hooks themselves
src/loader/esm-runtime.ts  main-thread bridge the synthetic ESM modules re-export from
src/loader/native.ts       process.dlopen patch — the `native` .node load gate (S2)
src/shims/index.ts         registry assembly: specifier → shim module object
src/shims/runtime.ts       shared guard()/attribution plumbing every shim uses
src/shims/fs.ts            fs + fs/promises
src/shims/net.ts           net, http, https, tls, http2, dgram (six separate shims)
src/shims/child_process.ts child_process
src/shims/worker_threads.ts worker_threads
src/shims/vm.ts            vm
src/shims/env.ts           process.env read guard (a Proxy, not a require-routed module)
src/shims/module.ts        node:module — gates register/registerHooks (#61)
src/shims/harden.ts        opt-in hardened mode (freeze what capwall created)
src/attribution/           stack-walk → owning package (nearest-package policy, memoized)
src/policy/*.ts            load (glob normalization), mode (precedence), evaluate, glob
test/                      evaluator, attribution, shims, ESM, hardened, native, e2e slices
```

Policy types and the Zod schema are **not** here — they live in `@capwall/policy-schema` and
are imported from there directly.

## Roadmap

[`../../docs/roadmap.md`](../../docs/roadmap.md) is the authoritative build order and the one
place milestone status is tracked.
