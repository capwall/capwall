# capwall architecture

> Design doc. The full MVP + ESM (M1–M5) is implemented, as are the four stretch items
> (S1–S4). Build order and per-milestone status live in [`roadmap.md`](./roadmap.md); what
> that mediation is and is not worth is in [`threat-model.md`](./threat-model.md).

## Overview

capwall installs itself into a Node process (via `@capwall/core`'s `install(policy, mode)`,
typically launched by `@capwall/cli`) and mediates the capability-sensitive core surface.
Every intercepted call is attributed to an **owning package** and evaluated against that
package's slice of the policy.

```
                       ┌─────────────────────────────────────────┐
   require('fs')  ───▶ │  loader patch  (CJS require / ESM hook)  │
                       └───────────────┬─────────────────────────┘
                                       │ returns a shimmed module
                                       ▼
   fs.readFile(path)  ─▶  ┌────────────────────────┐
                          │  capability shim (fs)  │
                          └───────────┬────────────┘
                                      │ 1. who is calling?
                                      ▼
                          ┌────────────────────────┐
                          │  attribution           │  stack-walk → owning package
                          └───────────┬────────────┘
                                      │ 2. is (package, capability) allowed?
                                      ▼
                          ┌────────────────────────┐
                          │  policy/evaluate       │  observe → log, enforce → allow/throw
                          └────────────────────────┘
```

## Components

### Loader interception (`core/src/loader`)

- **CJS (`require.ts`)** — patch the module loader (`Module._load` /
  `Module.prototype.require`) so that when a package requires a capability-sensitive core
  module (`fs`, `net`, …), it receives capwall's **shimmed** version rather than the raw
  builtin. This is the primary, first-implemented path.
- **ESM (`esm-hook.ts` + `esm-hooks.ts` + `esm-runtime.ts`)** — implemented (M5). A
  `module.register()` hook on the loader thread (`esm-hooks.ts`) rewrites a mediated builtin
  specifier to a synthetic `capwall-esm:` module; its `load` returns generated source that
  re-exports the shim members from the main-thread bridge (`esm-runtime.ts`). The
  "static bindings are immutable" concern is sidestepped: because the hook supplies the module
  source up front, the binding is to the shim from the start — no post-hoc swap. Export names
  are enumerated on the main thread at registration and passed to the hook, so the loader
  thread never imports the real builtin (which would recurse). Covers static and dynamic
  `import`; attribution and `onDecision` run on the main thread exactly as for CJS.
  `esm-hooks.ts`'s `load` also **re-mediates** a raw `node:<mediated>` URL it is handed, the
  backstop for a resolution route capwall's `resolve` never saw — which only works because of
  the capture rule below.

### Real-builtin capture (`core/src/real-builtins.cts`)

Every real mediated builtin capwall holds is captured in this one file, and it is the only
CommonJS source file in the package. That is a security property rather than a style quirk
(#78): Node's ESM module cache is keyed by resolved URL, and a URL already in it is served from
cache **without the `load` hook chain being consulted at all**. A static
`import realFs from "node:fs"` in a shim therefore cached `node:fs` raw before
`module.register()` ran and left the re-mediation backstop above as dead code. A CommonJS
`require` populates the CJS cache and leaves the ESM cache untouched, and in a `.cjs` file
`require` is ambient — so the capture needs no ESM import of `node:module` either, which is
itself mediated.

The `require`s cannot loop through capwall's own `Module._load` patch: the file sits in
`index.js`'s **static** import graph, and ES module evaluation completes that graph before
`install()` — the only thing that patches `_load` — can be called. `test/real-builtins.test.ts`
holds both halves in place: a source scan that fails on any mediated-builtin import elsewhere in
`core/src` or any lazy route to this file, and a post-install identity check against
`process.getBuiltinModule`.

### Capability shims (`core/src/shims`)

One shim per core surface: `fs`; the six egress modules `net`, `http`, `https`, `tls`,
`http2`, `dgram` (all six evaluated against the one `net` capability — or, for a unix-socket /
named-pipe destination, the `ipc` capability keyed on the socket path (#72) — and all six
registered separately by `shims/net.ts`); `child_process`; `worker_threads`; `env` (a
`process.env` accessor guard); `vm`. Each shim wraps the real API; on every capability-sensitive call it
(1) asks `attribution` for the owning package, (2) asks `policy/evaluate` for a decision, then
(3) forwards to the real API, logs, or throws. Shims must preserve the real API's signatures
and error semantics so correct code is unaffected.

**Every egress module is shimmed separately, and this is load-bearing — do not assume one
covers another.** It is tempting to think shimming `net` gets `http`/`https` for free, since
they build on it. It does not, for two independent reasons:

1. capwall's require patch only sees `Module._load`-routed requires — that is, requires made
   by user and dependency code. Node's own HTTP client pulls in `net` through the **internal
   bootstrap loader**, which never reaches `Module._load`, so `http`'s internal use of `net`
   never passes through capwall's `net` shim.
2. Even if it did, a dependency could sidestep a `net`-only shim just by picking `tls`,
   `http2` or `dgram` instead.

So a new egress surface needs its **own** shim registration; inheriting coverage from a
lower-level module is the reasoning error that produces a real bypass. See
[`threat-model.md`](./threat-model.md) § per-capability notes, which states the same rule as
a security property.

`node:module` is also mediated: the shim gates `register`/`registerHooks` so a dependency cannot
install a loader hook ahead of capwall's and un-mediate the ESM path process-wide (#61). That
half is not a policy capability. Everything else on `node:module` passes through.

`Module.prototype._compile` is gated **separately, and not by that shim** (#93). It is the one
primitive that lets a caller choose what V8 reports as `getFileName()` on the frames of the code
it runs, which — since attribution names principals from frame file names — is the ability to
execute as an arbitrary principal, `<app>` included. The gate is a patch on `Module.prototype`
installed from `install()`, because `m._compile` is read off the prototype (the shim's `get` trap
never sees it) and because `process.getBuiltinModule("node:module")` returns the un-shimmed
module on Node ≥22. Node's own loader calls are recognized by their caller frame and never gated,
and a package compiling under its own name is not gated either; anything else needs the
identity-granting `compile` grant. See `shims/module.ts` § `installCompileGate`.

**The corollary of "one shim per module surface" is that non-module surfaces are outside the
mechanism.** `globalThis.fetch`, `globalThis.WebSocket` and `globalThis.EventSource` never
route through a module load, so no shim can ever see them. They are instead guarded on
`globalThis` itself (#80, `core/src/shims/global-egress.ts`), against the same `net` grant a
module-surface egress call is checked against — a dependency does not gain anything by
reaching for `fetch` instead of `http.request`. What that guard does and does not cover
(redirect hops, `init.dispatcher`) is in [`threat-model.md`](./threat-model.md) § Global
egress surfaces.

One capability is deliberately NOT a shim: `native` (`.node` addon loads, S2/#49) lives in
`core/src/loader/native.ts` and patches `process.dlopen`. There is no module to wrap — the
capability is the *load itself*, and `process.dlopen` is the one JS-reachable point every
addon load funnels through, whether it arrives via `require`, `createRequire` from ESM, a
`bindings`/`node-gyp-build` resolver, or a direct `process.dlopen(...)` call. It follows the
same attribute→evaluate→forward/throw sequence as the shims, but is module-system-independent
by construction. Gating only: capwall cannot confine an addon once it is loaded (see
`threat-model.md`).

### Process-patch lifecycle (`core/src/lifecycle/process-patch.ts`)

Five of capwall's controls are not module shims at all — they replace a **process-level
location**: `Module._load`, `process.dlopen`, `process.env`, `Module.prototype._compile`, and the
egress globals `fetch`/`WebSocket`/`EventSource`. Those five share one rule, and #107 made it
structural after #103 found three separate bugs that were all the same defect:

> **Every process-level patch capwall installs is a reference-counted relink chain, never a bare
> save/restore.**

A bare save/restore assumes capwall is the only patcher of that location and that teardown is
LIFO. Both assumptions stop being true the moment a second `install()` exists, and nothing in the
type system catches the assumption. What it produced: an out-of-order `uninstall()` that left
capwall's Proxy on `process.env` and capwall's wrapper on `globalThis.fetch` **permanently**
(reading the deny-all torn-down policy forever); a nested install that captured the first guard's
Proxy as the "un-proxied" environment and handed a *granted* `spawn` an empty child environment;
and an `uninstall()` that could throw and strand every patch after it in the teardown loop.

`lifecycle/process-patch.ts` provides the shape, in **two named primitives**, because the sites
genuinely differ on one axis:

- `defineRelinkedPatch` — **stacks**. Each install adds a link, every link's guard runs, and an
  out-of-LIFO-order removal relinks around the removed layer. `Module._load` and `process.dlopen`
  need this: two installs may hold different contexts.
- `defineSharedPatch` / `definePropertyPatch` — **exactly one patch per process, reference
  counted**; the count only decides *when* the original goes back. `Module.prototype._compile`
  requires this and breaks loudly under the other one (#100): it identifies Node's own loader by
  the caller frame one level up, so a second layer makes the inner patch see capwall's own frame
  and gate **every** `require` in the process. `process.env` and the egress globals require it
  too — a stacked Proxy double-gates and double-records every read.

Two names rather than one helper with a `{ stack: false }` flag, because a flag is what a future
patch site copies from its neighbour without reading.

Every handle is idempotent, order-independent, and **never throws** — teardown failures are
isolated so one unrestorable global cannot strand the other four patches. `definePropertyPatch`
additionally reads the location *exactly once, while the patch is provably inactive*, and hands
that value to the site: "the real underlying object" is not something a site has to get right, it
is the only value a site is ever given. That is what makes the empty-child-environment bug
structurally impossible rather than merely fixed.

**Adding a new process-level patch is enforced, not remembered.**
`test/process-patch-sites.test.ts` scans `packages/core/src` and fails on any write to
`process.*`, `globalThis.*`, a `Module` prototype or a local alias of one outside
`lifecycle/process-patch.ts`; asserts the registered sites match a reviewed inventory (which
records *which sites stack*); and runs every registered site through the nested / out-of-order /
double-uninstall lifecycle sequence automatically, so a new site is enrolled by the act of
registering.

### Attribution (`core/src/attribution`)

Maps "the code currently executing a shimmed call" to the **owning npm package**. The
implementation captures structured V8 CallSites (temporary `prepareStackTrace` swap, no
string parsing), skips capwall's own frames and Node internals, and resolves the first
remaining frame's file path to its **install chain**. Resolution of file-path → principal is
memoized (per project root).

**The install chain (#92).** The principal is every `node_modules/<name>` segment of the path
below the project root, joined by `>`: `lodash` for a top-level install, `webpack>lodash` for the
copy installed under `webpack`. A package-manager virtual store — pnpm's `.pnpm`, yarn Berry's
`.store` — is looked through, but only at the *first* link, so a `.pnpm` directory shipped inside
somebody's tarball stays in the chain rather than resetting it.

Reading only the *last* segment used to mean `node_modules/evil/node_modules/lodash/x.js` simply
*was* `lodash`, so a dependency could collect a granted package's capabilities by shipping a
directory with the right name (#92). capwall cannot distinguish that from the copy npm genuinely
nests to resolve a version conflict — nothing on disk distinguishes them — so it stops conflating
the two positions rather than guessing which is which. This changes what a policy key means; see
[`policy-format.md`](policy-format.md) § Package keys are install positions.

**Chosen attribution policy: nearest-package.** The package owning the frame closest to the
shimmed call is charged. Cheap (the walk stops at the first qualifying frame),
deterministic, and it matches the NodeShield model. Known blind spot, accepted and
documented in the threat model: calls funneled through a shared helper attribute to the
helper, so a malicious package can launder operations through a broadly-granted helper —
keep helper grants tight. A file under no `node_modules`, inside the project root, and with no
opaque frame above it on the stack attributes to the app sentinel `<app>`; the table below
states all three conditions, and they all matter (see #60 and #127).

**Frame budget.** The walk inspects at most `maxFrames` frames (default 25) to bound the
hot-path cost. If the owning dependency's frame sits deeper — long promise chains,
dynamically-compiled or deeply-nested wrappers, `async_hooks`-heavy frameworks — the walk
exhausts its budget and **mis-attributes** the call (issue #15), landing on `<unknown>` (before
#60, on `<app>`). The budget is configurable per install (`install(policy, mode, { attribution:
{ maxFrames } })`) and via `CAPWALL_MAX_FRAMES` for the preload; invalid values warn and fall
back to the default rather than throwing, because capwall must not crash a host process over a
config typo. A budget-exhausted fallback is distinguishable from any other unattributable call:
the decision carries `attributionTruncated: true` (the preload warns once on stderr), which is
the signal to raise the budget. See
[`../packages/core/README.md`](../packages/core/README.md) § Configuration.

**Three outcomes, not two (#60).** The walk returns a package name, `<app>`, or `<unknown>`:

| Outcome | When | Treated as |
|---|---|---|
| `<pkg>` | a frame under `node_modules/<pkg>`; a nested install is its chain, `<host>><pkg>` | that principal's grants |
| `<app>` | a real source file **not** under `node_modules`, inside the project root, with no opaque frame above it | the trust root — exempt from **five** gates: `process.env` reads, `dgram`, loader-hook registration (#61), `Module.prototype._compile` (#93, the identity-granting `compile` capability) and the module-load read gate (#123). Not exempt from the `native` gate. See [`threat-model.md`](threat-model.md) § Attribution outcomes, which enumerates them with their sites and says why `_compile` is the consequential one |
| `<unknown>` | no qualifying frame at all, or app code reached only through opaque code | an ordinary untrusted principal — deny-by-default in enforce, recorded in observe, grantable by an explicit `"<unknown>"` policy entry |

An **opaque** frame is user-controlled code with no filesystem identity: a `data:`/`blob:`
module, any `eval`/`new Function` frame, a bundler `sourceURL`, `node -e`/stdin. `node:*`
internals and native frames are *neutral* — skipped, as before. `<app>` is never inferred by
falling off the end of the walk, because `<app>` carries exemptions and "we could not tell"
must not inherit them.

Only a frame's `getFileName()` names a package — it is the one thing V8 reports from how the
code was **loaded** rather than from what the code **says about itself**. `eval`/`new Function`
frames were an exception between #60 and #84, resolved by parsing V8's `getEvalOrigin()`; a
nested `eval` turned out to put an attacker's `//# sourceURL=` inside the `eval at …` wrapper V8
synthesizes, letting a dependency name any package (see `docs/threat-model.md` § `eval` and
`new Function`). The origin is no longer read. A dependency's own synchronous `eval` is still
charged to it by name, via the ordinary frame beneath; detached eval'd code, and the app's own
`eval`, are `<unknown>`.

**This is THE core research risk.** See Risks below.

### Policy (`core/src/policy`)

The `Policy` / `PackagePolicy` types and the Zod schema live in `@capwall/policy-schema` and
are imported from there directly — core does not restate or re-export them.

- `load.ts` — read and validate `capabilities.json` against the schema; normalize globs.
- `mode.ts` — resolve the enforcement mode from `CAPWALL_MODE` and the policy's own `mode`
  (see `docs/policy-format.md` § Enforcement mode).
- `evaluate.ts` — the decision function: given `(package, capability, mode)`, return
  allow/deny (+ reason). **Deny-by-default** in `enforce`: absence of an entry means denied.
  In `observe`, nothing is denied; violations are recorded for policy generation.

### CLI (`@capwall/cli`)

- `observe` — launch the target with capwall in observe mode; record capabilities; on exit,
  emit/merge a starter `capabilities.json`.
- `enforce` — launch the target with capwall in enforce mode.
- `run` — launch the target in the mode the policy document declares (`mode`), for projects
  that want the committed file, not the command line, to be the authority.
- `diff` — run the target in observe mode, then report every observed capability the
  committed policy would deny in enforce mode (drift detection, roadmap S3). Exits 0 = no
  drift, 1 = drift, 2 = usage error / missing policy, and takes `--json`, so it can gate a
  merge. See [`ci-local.md`](./ci-local.md) § Drift detection.
- `gen-policy` — (re)generate a policy from a prior observe trace.
- `explain` — explain why a `(package, capability, target)` tuple would be allowed or denied.

## Observe / enforce lifecycle

```
  observe  ──────────────▶  capabilities.json  ──human review/tighten──▶  enforce
   (log every capability,      (starter policy,        (drop anything a         (deny-by-default,
    block nothing)              per package)            dep shouldn't need)       throw on violation)
```

`observe` is the on-ramp: it never breaks a running app, so teams can adopt capwall and see
what their dependency tree actually does before committing to enforcement. Staged rollout
(enforce a few trusted packages first, observe the rest) is the intended migration path.

## Risks / hard parts

The implementing agent should treat these as the real work, not incidentals:

- **ESM attribution & interception.** Static imports resolve before hooks run and bindings
  are immutable — the CJS module-swap trick does not port directly. *Addressed in M5* by
  having the hook supply the module source up front (see Loader interception above), so the
  binding is to the shim from the start. The residuals that remain — loader-hook chain
  ordering, pre-install capture, best-effort teardown — are enumerated in
  [`threat-model.md`](./threat-model.md) § ESM known limits.
- **Attribution through shared helpers (THE core risk).** When a call passes through a shared
  utility (`lodash`, a logger, a promise wrapper), the nearest `node_modules` frame may be
  the *helper*, not the package that *initiated* the operation. Stack-walking to find the
  "responsible" package is **fragile and costly**, and adversarially manipulable (a malicious
  package can arrange to call through a trusted helper to launder attribution). *Decided:*
  nearest-package (see Attribution above); the blind spots it keeps are written up in
  [`threat-model.md`](./threat-model.md) § attribution laundering. Still the core risk —
  deciding it did not remove it.
- **Policy-generation completeness.** A trace only covers exercised code paths. Unexercised
  error handlers, rare branches, and lazy requires will trip `enforce` mode later
  (false-positive fatigue). Mitigations: make "add a missing capability" a one-liner,
  support staged/partial enforcement, and merge (not overwrite) on repeated observe runs.
- **Performance (<1ms per intercepted call).** The S4 benchmark (`pnpm bench`) puts every
  mediated surface at ~30–90 µs of added latency per interception, well inside the budget. Two
  corrections to what this bullet used to say, both from the broadened harness:
  **(1) the cost is attribution-dominant after all, at realistic stack depths.** Issue #34's
  "roughly 50/50 between the stack walk and the wrapper's dispatch" was measured from a
  three-frame stack. Attribution materializes up to `maxFrames` (25) V8 CallSites per call, so
  the cost scales with the caller's depth: ~16 µs at depth 0, ~30 µs at the cap, which is ~70%
  of the added latency for a call made from a realistic stack. The walk is where the headroom
  is. **(2) the per-call budget does not hold where one JS call is many interceptions** —
  `{...process.env}` costs ~2 attributions per environment variable and measured ~4.4 ms on an
  81-key environment (issue #133). Cache module→package resolution aggressively (the path→package cache is
  worth ~50x cold-vs-warm); avoid allocations on the hot path; and read
  `scripts/bench/README.md` before quoting a headline figure.
- **Monkey-patch robustness.** capwall's shims are JS-level patches. Malicious code may try
  to un-patch them (grabbing the original builtin via internal caches / `process.binding`).
  We cannot fully prevent this without SES — document it (threat-model) and make un-patching
  at least awkward (install as early as possible). The freeze half of that is implemented as
  **opt-in hardened mode** (`install(…, { hardened: true })` / `CAPWALL_HARDENED=1`,
  `shims/harden.ts`): it freezes the shim namespaces, the guarded wrapper functions, and every
  guarded class + its prototype. It cannot be the default because freezing `fs` breaks
  `graceful-fs`; and it closes only the reassignment escape, not `process.getBuiltinModule`,
  `http.globalAgent` (#65), replacing `process.env`, or climbing past a guarded prototype.
  Note it depends on #64: while some class wrappers were construct-trap Proxies they could not
  be frozen at all, because `Object.freeze` on a Proxy forwards to its real-builtin target.
  Full accounting in threat-model.md § Hardened mode.
