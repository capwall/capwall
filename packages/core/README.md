# @capwall/core

The capwall interception engine and policy evaluator. This is where module-load
interception, the capability shims, package attribution, and policy evaluation live.

> **Status:** everything in this package is implemented and tested — the CJS require patch,
> the ESM loader hook, stack-walk attribution, policy load/mode/evaluate, the `process.dlopen`
> native-addon gate, the `Module.prototype._compile` gate, the `globalThis`
> `fetch`/`WebSocket`/`EventSource` guard, and every capability shim (`fs`;
> `net`/`http`/`https`/`tls`/`http2`/`dgram`; `child_process`; `worker_threads`; `vm`;
> `process.env`; plus `node:module`, whose loader-hook half
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

`install(policy, mode)` turns six things on:

1. the **CJS loader patch** — a subsequent `require("fs")`, `require("node:net")`, … returns
   capwall's shim, and a `require` of a file outside every `node_modules` tree takes an
   `fs.read` decision (#123, `loader/module-read.ts`);
2. the **`Module.prototype._compile` gate** (#93) — the `compile` capability, patched on the
   prototype rather than routed through the `node:module` shim, because `_compile` is read off
   the prototype and `process.getBuiltinModule("node:module")` reaches it either way;
3. the **`process.dlopen` native-addon gate** (#49);
4. the **`process.env` read guard** (a `Proxy`; skip it with `env: false`);
5. the **global egress guard** (#80) — `globalThis.fetch`/`WebSocket`/`EventSource` against the
   same `net` grant (skip it with `globalEgress: false`);
6. when `esm: true`, which the CLI sets — the **ESM loader hook**, so `import` of a mediated
   builtin lands on the same shims.

Plus a passive `Module._findPath` observer that records which `node_modules` entry a linked or
workspace package was resolved through, so it gets a principal of its own rather than being the
application (#127). It gates nothing.

Each shim attributes its calls to the owning package and evaluates them against the policy. The
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
| `env` | `true` | Gate `process.env` reads by dependencies against the `env` allowlist — the anti-exfiltration control. `false` leaves `process.env` un-proxied (for a workload that reads env in a hot loop and cannot pay the Proxy); `CAPWALL_ENV=0` is the same switch from the preload, and it warns. |
| `esm` | `false` (`true` under the CLI) | Also register the ESM loader hook. |
| `attribution.maxFrames` | `25` | Frames the attribution stack walk may inspect — see below. |
| `globalEgress` | `true` | Mediate `globalThis.fetch` / `WebSocket` / `EventSource` against the same `net` grant (#80). Writing to `globalThis` is the heaviest thing capwall does; set `false` if that write is unacceptable in your process. |
| `hardened` | `false` | **Opt-in.** Freeze the shim surfaces so a dependency cannot monkey-patch away mediation. Throws at `install()` if it cannot be applied (#97). **Breaks `graceful-fs`** — see below. |

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
| `CAPWALL_ENV` | on | `0` disables the `process.env` read guard (#125) — the CLI channel for `install()`'s `env: false`. **Warns on stderr when set**, because it makes every `env` grant in the policy unenforced and unrecorded while `enforce` keeps denying every other capability: the process looks guarded and is not. |
| `CAPWALL_GLOBAL_EGRESS` | on | `0` disables the global egress guard — `globalThis.fetch`/`WebSocket`/`EventSource` (#80). They are the one surface capwall reaches by writing to `globalThis`; the switch exists for a process where that write is unacceptable. Read at capwall's module evaluation, not just at install: setting it also skips the `Request.prototype.url` capture that materializes undici, which is ~21 ms of startup (#170). |
| `CAPWALL_MAX_FRAMES` | `25` | Attribution frame budget — see below. |
| `CAPWALL_HARDENED` | off | `1` (exactly) enables hardened mode — see below. Any other value leaves it off. |
| `CAPWALL_ALLOW_LOADER_HOOKS` | off | `1` (exactly) lets a **dependency** call `module.register`/`registerHooks`, which is otherwise application-only (#61). Still warns loudly. See [`docs/threat-model.md` § Loader-hook registration](../../docs/threat-model.md). |

That is the complete list — ten variables, and capwall reads no other `CAPWALL_*` one. The
same table lives in `src/preload.ts`'s header, which is the authority; if the two disagree,
`preload.ts` is right. Note that `CAPWALL_*` keys are never gated or recorded by the `env` shim
(they are capwall's own plumbing, not the target's environment).

#### `NODE_COMPILE_CACHE` — Node's, not capwall's, and worth setting

capwall costs a mediated process ~180 ms of startup, most of it module loading
([`scripts/bench/README.md` § Startup](../../scripts/bench/README.md)). Node's own on-disk V8
compile cache recovers a slice of that, and it needs no capwall code at all — the CLI passes the
environment through, so it applies to capwall's graph and the app's alike:

```sh
NODE_COMPILE_CACHE="$PWD/node_modules/.cache/node" capwall enforce -- node app.js
```

Measured across the three supported majors it is worth **~7–15 ms on Node 22 and ~15–35 ms on 24
and 26** off a mediated child, growing with the V8 in the release; the per-arm table is in
`scripts/bench/README.md` § The V8 compile cache, and `pnpm bench:startup --compile-cache`
re-derives it. capwall's gates are unaffected: the suite and the benchmark's 21 self-checks are
green with it on.

**capwall does not turn it on for you, and that is deliberate.** It is process-wide with no way
to switch off, so enabling it writes the *host application's* compiled code to disk as well as
capwall's — a side effect an injected security tool does not get to choose on the host's behalf.
Its reads and writes are also performed below the JS `fs` surface, so they are the one class of
disk activity capwall would be causing that its own `fs` gate cannot see or record. Both points,
and the cache-integrity question, are in
[`docs/node-api-dependencies.md` § The V8 compile cache](../../docs/node-api-dependencies.md).

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
  individually (a socket cannot be frozen; it needs its state);
- the guarded `createConnection` on the `http(s).globalAgent` view (#65/#88) — under hardened
  mode a write to it is refused outright rather than shadowed;
- the guarded global egress surfaces (#80) — `globalThis.fetch`/`WebSocket`/`EventSource` are
  installed **non-writable** (they stay `configurable`, so `uninstall()` can put the originals
  back).

All of it applies to `import` as well as `require`.

**It is a process-wide ratchet, not a per-install setting (#129).** Hardening engages the moment
**any** install asks for it and lifts only when capwall fully uninstalls. A later
`install({ hardened: false })` cannot downgrade a hardened install that is still active, and
passing `hardened: false` guarantees nothing about the surfaces you get if something else in the
process asked. It does not reach backwards either: `Object.freeze` is irreversible, so a shim a
module captured before the hardened install stays unfrozen. Install capwall early — that is what
the `--import` preload is for.

**If capwall cannot apply it, `install()` throws (issue #97).** After wiring everything up, a
hardened install verifies that the shim registries it just built really are frozen and that the
egress globals it just replaced really are non-writable; if any is not, the partial install is
rolled back and `install()` throws, naming the surface. A security option that is accepted and
silently inert is worse than one that is refused — `hardened: true` was exactly that on the ESM
path for many merges. The check inspects only surfaces capwall itself installed on paths that
call is mediating, so it never fires for an option capwall did honor.

Real builtins are never frozen — that would be a process-global side effect outliving
`uninstall()`. Subclassing a guarded class (`class Mine extends fs.ReadStream {}`) still works.

```bash
CAPWALL_HARDENED=1 capwall enforce -- node ./src/server.js
```

It is opt-in for a blunt reason: **freezing `fs` breaks `graceful-fs`** — a transitive
dependency of npm, webpack, and much of the ecosystem — and every other legitimate `fs`
patcher, which fails to load with a `TypeError`. Note also that a blocked patch is **silent**
in sloppy-mode CJS (the write just no-ops; only `"use strict"` code sees the `TypeError`), and
that hardened mode closes only the reassignment escape. Unaffected:
`process.getBuiltinModule("node:fs")` (a plain public API returning the real module — this alone
is why hardened mode is defense-in-depth and not a boundary); the **real**
`http(s).globalAgent` behind the guarded view, which is never frozen because freezing it wedges
the process's HTTP client (#88 — the *view's* `createConnection` is pinned, and the #65 bug
itself is closed); replacing `process.env` wholesale; `Object.defineProperty(globalThis, "fetch",
…)`; shadowing a guarded prototype method with an own property on an instance; and climbing past
a guarded prototype (`Object.getPrototypeOf(net.Socket.prototype).connect`). Read
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
| `"<app>"` | the application's own code — a real source file not under `node_modules`, inside the project root, with no opaque frame above it. The trust root, and exempt from **five** gates: `process.env` reads (`shims/env.ts`), `dgram` (`shims/net.ts`), loader-hook registration (`shims/module.ts`, #61), `Module.prototype._compile` (`shims/module.ts`, #93) and the module-load read gate (`loader/module-read.ts`, #123). `_compile` is the one to know: `compile` is identity-granting — a grant of every other grant — and `<app>` holds it without a grant. Not exempt from the `native` gate. |
| `"<unknown>"` | a call capwall could not attribute to any source file: no qualifying frame on the stack, or app code reached only through a `data:`/`eval`/bundled frame. **Not** exempt — deny-by-default in enforce, recorded in observe. |

`<unknown>` exists because "we could not attribute this" must not silently mean "this is the
app" (issue #60). Grant it only as narrowly as an `observe` run shows you need. Most policies
now need nothing here at all: the one line every generated policy used to carry
(`"env": ["WATCH_REPORT_DEPENDENCIES"]`) came from Node's own ESM loader, and env reads Node
initiates stopped being recorded in #119. See
[`../../docs/threat-model.md`](../../docs/threat-model.md) § attribution outcomes.

## Layout

```
src/index.ts               install(policy, mode, options) entry point + public re-exports
src/preload.ts             --import entry for child processes (CAPWALL_* env config)
src/errors.ts              CapabilityError
src/real-builtins.cts      the ONLY place capwall loads a real builtin — CJS on purpose, so the
                           ESM cache stays empty and the load-hook backstop can fire (#78)
src/lifecycle/process-patch.ts
                           the ONLY file allowed to write a process global; every process-level
                           patch is a refcounted relink chain (#107)
src/loader/require.ts      CJS require/Module._load patch; MEDIATED_MODULES lives here
src/loader/module-read.ts  the module system as a read channel: an fs.read decision on a
                           require/import of a file outside every node_modules tree (#123)
src/loader/live-context.ts the live install-context box every guard reads (#62/#87) + the
                           hardened ratchet and the per-hardened-ness shim registries (#129)
src/loader/esm-hook.ts     module.registerHooks() registration + teardown lifecycle
src/loader/esm-hooks.ts    the synchronous resolve/load hooks themselves
src/loader/esm-runtime.ts  main-thread bridge the synthetic ESM modules re-export from
src/loader/native.ts       process.dlopen patch — the `native` .node load gate (S2)
src/loader/linked-packages.ts
                           passive Module._findPath observer: which node_modules entry a linked
                           or workspace package was reached through (#127)
src/shims/index.ts         registry assembly: specifier → shim module object
src/shims/runtime.ts       shared guard()/attribution plumbing every shim uses
src/shims/fs.ts            fs + fs/promises
src/shims/net.ts           net, http, https, tls, http2, dgram (six separate shims)
src/shims/global-egress.ts globalThis fetch/WebSocket/EventSource — not a shim, a global (#80)
src/shims/child_process.ts child_process
src/shims/worker_threads.ts worker_threads
src/shims/vm.ts            vm
src/shims/env.ts           process.env read guard (a Proxy, not a require-routed module)
src/shims/module.ts        node:module — gates register/registerHooks (#61) AND
                           Module.prototype._compile, the `compile` capability (#93)
src/shims/pin.ts           flatten a caller's accessors to values before forwarding (#26/#56/#89)
src/shims/url-snapshot.ts  single-read destination derivation shared by net and global-egress
src/shims/harden.ts        opt-in hardened mode (freeze what capwall created)
src/attribution/index.ts   stack-walk → owning package (nearest-package policy, memoized)
src/attribution/link-map.ts  a link's source is its principal (#127)
src/policy/*.ts            load (glob normalization), mode (precedence), evaluate, glob, ipc
test/                      evaluator, attribution, shims, ESM, hardened, native, e2e slices
test/composition-matrix.test.ts     cross-subsystem pairs (the shared-state inventory is its header)
test/hardened-allowed.test.ts       hardened x granted x denied, every guarded surface
test/lifecycle-matrix.test.ts       install -> capture -> uninstall -> reinstall, every shim
test/install-option-parity.test.ts  {cjs, esm} x every install option
```

Policy types and the Zod schema are **not** here — they live in `@capwall/policy-schema` and
are imported from there directly.

## Roadmap

[`../../docs/roadmap.md`](../../docs/roadmap.md) is the authoritative build order and the one
place milestone status is tracked.
