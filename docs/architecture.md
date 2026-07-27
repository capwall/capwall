# capwall architecture

> Design doc. The CJS path with the `fs` shim (roadmap M1–M3) is implemented; the other
> the full MVP + ESM (M1–M5) is implemented. Build order lives in [`roadmap.md`](./roadmap.md).

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

### Capability shims (`core/src/shims`)

One shim per core surface: `fs`, `net` (covers `http`/`https` since they build on `net`),
`child_process`, `worker_threads`, `env` (a `process.env` accessor guard), `vm`. Each shim
wraps the real API; on every capability-sensitive call it (1) asks `attribution` for the
owning package, (2) asks `policy/evaluate` for a decision, then (3) forwards to the real API,
logs, or throws. Shims must preserve the real API's signatures and error semantics so
correct code is unaffected.

### Attribution (`core/src/attribution`)

Maps "the code currently executing a shimmed call" to the **owning npm package**. The
implementation captures structured V8 CallSites (temporary `prepareStackTrace` swap, no
string parsing), skips capwall's own frames and Node internals, and resolves the first
remaining frame's file path via its last `node_modules/<package>` path segment (pnpm's
`.pnpm` layout falls out for free). Resolution of file-path → package is memoized.

**Chosen attribution policy: nearest-package.** The package owning the frame closest to the
shimmed call is charged. Cheap (the walk stops at the first qualifying frame),
deterministic, and it matches the NodeShield model. Known blind spot, accepted and
documented in the threat model: calls funneled through a shared helper attribute to the
helper, so a malicious package can launder operations through a broadly-granted helper —
keep helper grants tight. Files not under any `node_modules` attribute to the app sentinel
`<app>`.

**This is THE core research risk.** See Risks below.

### Policy (`core/src/policy`)

- `schema.ts` — the in-memory `Policy` / `PackagePolicy` / `Capability` types (re-exported
  from `@capwall/policy-schema`).
- `load.ts` — read and validate `capabilities.json` against the schema; normalize globs.
- `evaluate.ts` — the decision function: given `(package, capability, mode)`, return
  allow/deny (+ reason). **Deny-by-default** in `enforce`: absence of an entry means denied.
  In `observe`, nothing is denied; violations are recorded for policy generation.

### CLI (`@capwall/cli`)

- `observe` — launch the target with capwall in observe mode; record capabilities; on exit,
  emit/merge a starter `capabilities.json`.
- `enforce` — launch the target with capwall in enforce mode.
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
  are immutable — the CJS module-swap trick does not port directly. CJS-first; ESM
  fast-follow. Expect partial parity initially.
- **Attribution through shared helpers (THE core risk).** When a call passes through a shared
  utility (`lodash`, a logger, a promise wrapper), the nearest `node_modules` frame may be
  the *helper*, not the package that *initiated* the operation. Stack-walking to find the
  "responsible" package is **fragile and costly**, and adversarially manipulable (a malicious
  package can arrange to call through a trusted helper to launder attribution). Decide and
  document the attribution policy (nearest-package vs first-non-core vs
  initiating-app-boundary) and its known blind spots.
- **Policy-generation completeness.** A trace only covers exercised code paths. Unexercised
  error handlers, rare branches, and lazy requires will trip `enforce` mode later
  (false-positive fatigue). Mitigations: make "add a missing capability" a one-liner,
  support staged/partial enforcement, and merge (not overwrite) on repeated observe runs.
- **Performance (<1ms/req).** Attribution stack-walking is the hot cost. Cache
  module→package resolution aggressively; consider capturing only the minimal stack depth
  needed; avoid allocations on the hot path.
- **Monkey-patch robustness.** capwall's shims are JS-level patches. Malicious code may try
  to un-patch them (grabbing the original builtin via internal caches / `process.binding`).
  We cannot fully prevent this without SES — document it (threat-model) and make un-patching
  at least awkward (install as early as possible). The freeze half of that is implemented as
  **opt-in hardened mode** (`install(…, { hardened: true })` / `CAPWALL_HARDENED=1`,
  `shims/harden.ts`): it freezes the shim namespaces, the guarded wrapper functions, and the
  guarded subclasses + their prototypes. It cannot be the default because freezing `fs` breaks
  `graceful-fs`; and it closes only the reassignment escape, not `process.getBuiltinModule` or
  the construct-trap `Proxy` class wrappers (freezing a Proxy would freeze the real builtin
  target). Full accounting in threat-model.md § Hardened mode.
