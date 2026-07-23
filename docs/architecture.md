# capwall architecture

> Scaffold-stage design doc. The engine is stubbed; this describes the intended shape and
> the hard problems the implementing agent must solve. Build order lives in
> [`roadmap.md`](./roadmap.md).

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
- **ESM (`esm-hook.ts`)** — register a loader via `module.register()` and use `resolve`/
  `load` hooks. **Hard part:** static `import` specifiers are resolved before user code runs,
  and bindings are live/immutable, so the CJS "swap the returned module" trick does not
  translate cleanly. ESM is a fast-follow after the CJS path is solid (roadmap step 5).

### Capability shims (`core/src/shims`)

One shim per core surface: `fs`, `net` (covers `http`/`https` since they build on `net`),
`child_process`, `worker_threads`, `env` (a `process.env` accessor guard), `vm`. Each shim
wraps the real API; on every capability-sensitive call it (1) asks `attribution` for the
owning package, (2) asks `policy/evaluate` for a decision, then (3) forwards to the real API,
logs, or throws. Shims must preserve the real API's signatures and error semantics so
correct code is unaffected.

### Attribution (`core/src/attribution`)

Maps "the code currently executing a shimmed call" to the **owning npm package**. The
approach: capture a stack trace, walk frames to the first frame whose file path resolves
into a `node_modules/<package>` (or workspace package) directory, and return that package's
name. Resolution of file-path → package is cached.

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
  at least awkward (freeze our shim references where possible, install as early as possible).
