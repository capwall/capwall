# The Node.js APIs capwall is built on

This document is the source of truth for **which Node.js APIs capwall's mechanism depends on,
what their supported status actually is, and what capwall loses if any of them goes away.** It
sits alongside [`threat-model.md`](threat-model.md) and is held to the same rule: overclaiming
here is a bug.

## One-sentence summary

**capwall's enforcement mechanism rests on a small set of Node.js module-system internals that
are undocumented and unsupported, plus one documented release-candidate API.** It works on every
current Node release, it is written defensively against their churn, and it has no supported
substitute for most of them. Until #152 the "one documented API" row was `module.register()`,
which was formally deprecated with removal announced; the ESM path is now on its named successor.

That is not a disclaimer bolted on for form. It is the central engineering fact about this
project, and a security tool whose mechanism rests on internals should say so out loud rather
than let a reader infer stability from the fact that it works.

## How to read the status column

Node's own vocabulary, used precisely:

| Status | Meaning |
|---|---|
| **documented, stable** | in `doc/api/`, Stability 2. Node's compatibility rules apply. |
| **documented, RC / experimental** | in `doc/api/`, Stability 1.x. May change in a minor. |
| **runtime-deprecated (DEP####)** | emits a `DeprecationWarning` on use; throws under `--throw-deprecation`. Removal follows. |
| **docs-only deprecated (DEP####)** | marked deprecated in the docs; no warning at runtime. |
| **undocumented** | **not in `doc/api/` at all.** No DEP code, no deprecation, and *no support commitment either*. Node may change or remove it in any release without a deprecation cycle, and has. |

The last row is the one to be careful about, because "no DEP code" reads like "fine" and is not
the same claim. `Module._load` has never had a deprecation code; it is also not public API. The
honest status is **widely depended upon, unsupported**, and the precedent for what that is worth
is `Module._debug()` — an undocumented `Module._*` internal that went to Runtime deprecation in
Node 9 and was **removed outright in Node 25** (DEP0077, Type: End-of-Life; Node's own entry
notes it "was never documented as an officially supported API").

## The inventory

Verified by running each API against real binaries — Node **20.19.4, 22.23.1, 24.18.0 and
26.5.0** — and by reading Node's shipped `lib/` out of each of them, not from memory or from a
changelog summary. See § Reproducing the measurement.

| API | What capwall uses it for | Status (22 / 24 / 26) | Supported replacement | What breaks if it goes |
|---|---|---|---|---|
| `Module._load` | The CJS interception point. Patched so a mediated builtin SPECIFIER returns a shim. Since #177 it no longer takes the #123 module-read decision — that moved to `Module.prototype.load`, because everything `_load` could say about the file a load opens it had to reconstruct from arguments the caller supplies. `loader/require.ts` | **Undocumented**, no DEP code, present and writable on all four | `module.registerHooks()` — see § The one migration that matters | **The entire CJS path.** Every capability on `require` |
| `Module.prototype.load` | The #123 module-read gate (#177), at the point Node commits to a filename: `Module._load` has finished resolving and calls this with the result, which then picks the extension handler that opens the file. Every CJS route passes through it, including `new Module(f).load(f)`, which never enters `Module._load`. `loader/require.ts` | **Undocumented**, no DEP code. `(filename)` on 20/22/23/24/26 — the most stable signature of any internal in this table | a `registerHooks` `resolve` hook, which sees the resolution but not the commitment | **The module-read gate (#123).** `fs.read` via `require` is un-gated again |
| `Module._resolveFilename` | **No longer used** (#178). It was called (not patched) to re-derive which file a load would open; that re-resolution was driven by `Module._load`'s caller-supplied argument list and was steerable. `Module._findPath` below is a separate, passive use | **Undocumented**, no DEP code, `(request, parent, isMain, options)` on all four | n/a | Nothing — capwall no longer depends on it |
| `Module._findPath` | Passive observer: records symlinked `node_modules` entries at resolution time so a linked workspace package gets an identity (#127). `loader/linked-packages.ts` | **Undocumented**, no DEP code. Signature **changed**: gained `conditions` after 20 | Partial — a `resolve` hook sees the specifier and parent but not Node's ordered search-path list | Linked/workspace dependencies lose their identity and fall back to the out-of-project rule. Not a gate; degrades attribution, denies nothing |
| `Module.prototype._compile` | The `compile` capability gate (#93) — the primitive that lets a caller choose what V8 reports as `getFileName()`, i.e. execute as an arbitrary principal. `shims/module.ts` | **Undocumented**, no DEP code. Signature **changed** in 22.18 (gained `format`) — this is #128 | **None** | **The `compile` capability dies.** Identity forgery via a chosen filename becomes ungated again |
| `Module._extensions[".node"]` | Not patched — it is the *reason* `process.dlopen` is the right hook. Body confirmed as `process.dlopen(module, path.toNamespacedPath(filename))` on 20.20 / 22.22 / 22.23 / 24.18 / 26.5 | **Docs-only deprecated** as `require.extensions` (**DEP0039**, since v0.10.6 — `require.extensions === Module._extensions`, verified on all four); `Module._extensions` itself undocumented | none | Nothing directly — capwall does not depend on it, by design |
| `process.dlopen` | The native-addon load gate (`native`, #49). The single JS-reachable chokepoint every `.node` load funnels through. `loader/native.ts` | **Undocumented**, no DEP code. Own writable+configurable property of `process` on all four; `.length` is 0 (C++ binding) | **None** | **The `native` capability dies.** A dependency can load arbitrary compiled code un-gated, which makes every other control moot |
| `module.registerHooks()` | Registers capwall's `resolve`/`load` hooks (M5, moved here by #152). Also **gated** (#61) so a dependency cannot register a hook ahead of capwall's. `loader/esm-hook.ts`, `shims/module.ts` | **Documented, Stability 1.2 (Release candidate).** Present on 22.15+/23.5+, i.e. every runtime in the support range | n/a — this *is* the replacement | **The entire ESM path.** `import` of a mediated builtin is un-mediated |
| `module.register()` | **Not used by capwall since #152.** Still **gated** (#61) — a dependency must not register a hook ahead of capwall's through either API. `shims/module.ts` | **Deprecated. Stability 0.** Docs-only in v25.9.0, **Runtime deprecation (DEP0205) in v26.0.0.** Removal announced | `module.registerHooks()` | Nothing. The #61 gate keeps covering it for as long as Node ships it |
| `Error.prepareStackTrace` + `Error.captureStackTrace` + structured CallSites | **All of attribution**, plus the `compile` gate's one-frame loader check and the "initiated by Node?" discriminator (#119). `attribution/index.ts`, `shims/module.ts` | **V8, not Node.** `prepareStackTrace` is non-standard and unspecified; `captureStackTrace` is at **TC39 Stage 2** (`proposal-error-capturestacktrace`, which does *not* specify `prepareStackTrace`). Writable on all four | none | **Everything.** capwall answers exactly one question — whose code is calling — and this is how |
| `Error.stackTraceLimit` | Bounds the frame budget; the #143 optimization depends on the limit applying *after* `captureStackTrace`'s boundary skip | **V8, non-standard.** Writable on all four | none | The frame budget and the #143 cost reduction; attribution still works |
| `globalThis.fetch` / `WebSocket` / `EventSource` | The global egress guard (#80). `shims/global-egress.ts` | `fetch` documented+stable on all four; `WebSocket` global from 22; **`EventSource` is still flag-only (`--experimental-eventsource`) on 26.5** | n/a — these are the API | Egress via globals is un-gated. Each guard installs only if the global exists, so a flag-only API is picked up when the flag is on and nothing is invented when it is not |
| `globalThis.localStorage` / `Storage.prototype` / `process.execArgv` | The Web Storage guard (#156): `localStorage`'s six members take an `fs` read/write decision on the file `--localstorage-file` names, which Node otherwise reads and writes below the `fs` shim. The whole object is replaced rather than the prototype's methods, because **`Storage.prototype.length` is a non-configurable getter on 26.5.0** (measured) and `length` is a read of the file's state. `process.execArgv` (plus `NODE_OPTIONS`, in Node's own precedence order) is how the backing path is recovered. `shims/web-storage.ts` | **Documented, experimental.** Web Storage exists only on **Node ≥26** and only behind `--localstorage-file`; absent on 22 and 24, so the guard registers no patch site there at all. Availability is probed with `Object.keys(globalThis)` and never by reading the property, because a read on an unflagged Node 26 emits `ExperimentalWarning` on the same stderr as capwall's DENY lines. `process.execArgv` is documented and stable | n/a — these are the API | `localStorage` becomes an un-gated route to `fs` bytes again, on Node ≥26 with the flag. Nothing on 22 or 24, where the surface does not exist |
| `process.moduleLoadList` | ONE narrow question, on the fail-safe side: has anything in this realm materialized undici yet (#170)? `internal/deps/undici/undici` enters the list at the instant `globalThis.Request` is first read and not before — merely reading `globalThis.fetch` does NOT put it there. It decides whether capwall WARNS that a deferred `Request.prototype.url` capture is unprovable; it never decides whether capwall guards. `shims/global-egress.ts` (also used by `test/fixtures/startup-graph.mjs`) | **Undocumented**, no DEP code. An own array on `process`, populated by the bootstrap, on 22.22.3 / 24.18.0 / 26.5.0 | none | Nothing that gates anything. Anything unrecognizable — a Node that drops the array, a dependency that replaced it — reads as "already materialized", i.e. as doubt, so the fallback is the noisy one |
| `process.binding()` | **Not used.** Named in the threat model as an escape route capwall does not claim to stop | **Docs-only deprecated, DEP0111** (supports `--pending-deprecation`); unavailable under the permission model | `process.getBuiltinModule()` for the module cases | Nothing. Confirmed by a `--pending-deprecation` run of the whole suite: the only DEP0111 warnings come from `@vitest/snapshot`, a dev dependency |
| `Module._cache`, `require.extensions` | **Not used.** Referenced only in comments explaining why the shim is a `Proxy` over the real `Module` class | `require.extensions`: docs-only deprecated, **DEP0039** | n/a | Nothing |
| `module.enableCompileCache()` / `NODE_COMPILE_CACHE` | **Not used, deliberately.** Evaluated for startup and declined — see § The V8 compile cache below, and `scripts/bench/README.md` § The V8 compile cache | **Documented, Stability 1.2 (Release candidate)** on all three supported majors (env var since 22.1, function since 22.8) | n/a | Nothing. It is an operator's switch, and it works on capwall today with no capwall code at all |

Two things capwall depends on that are ordinary public API and therefore not in this table:
`module.createRequire()` (Stability 2) and `require()` inside `real-builtins.cts`.

## Direction of travel, per API

### `module.register()` — the only scheduled removal, and capwall is off it (#152, #153)

**Resolved.** capwall's ESM path moved to `module.registerHooks()`; `module.register()` no longer
appears anywhere in `packages/*/src` except in the #61 gate's list of APIs a dependency may not
call. The rest of this section is kept because it is the record of *why*, and because the gate
still has to know about the API.

This was the one item on the list with an announced end. Node 25.9.0 marked it Stability 0; Node
26.0.0 made it a **Runtime** deprecation, DEP0205; and the entry says, in Node's own words, that
it "will be removed in a future version of Node.js". Node's stated reason is not cosmetic:

> Supporting async hooks has proven to be complex, involving worker threads orchestration, and
> there are issues that have proven unresolveable.

Measured on the real binary, not inferred. On **Node 26.5.0**, a capwall-mediated process **before
#152**:

- printed, on **stderr, on every run**:

  ```
  (node:…) [DEP0205] DeprecationWarning: `module.register()` is deprecated. Use `module.registerHooks()` instead.
  ```

- and, under `--throw-deprecation`, **failed to start at all** — `install()` threw from
  `registerEsmHook` with `code: 'DEP0205'`, exit 1, and the mediated app never ran.

**After #152, on the same 26.5.0 binary, over the same app:** `capwall enforce` prints nothing on
stderr and exits 0, and `NODE_OPTIONS=--throw-deprecation capwall enforce` runs the app and exits
0. Both are asserted rather than left to a one-off check —
`packages/core/test/esm-hook-graph.test.ts` requires a mediated child's stderr to be **exactly
empty**, which is stronger than a `not.toContain("DEP0205")` and also catches the next warning.

Both matter more for capwall than they would for a library. capwall's stderr is where `DENY`
lines live; a tool that unconditionally prints a Node deprecation warning there is training its
operator to skim the channel that carries its output. And `--throw-deprecation` is an ordinary
thing for a careful CI to set.

Node 26 becomes LTS in October 2026. The migration was tracked in **issue #152** (which found it
first from the other direction — `module.register()` was ~93 ms of capwall's ~180 ms startup, of
which ~53 ms was Node bootstrapping a loader thread) and **issue #153**, the currency half; both
are closed by the same change. Nothing in this repository ever suppressed the warning: the honest
signal is the accurate one, and the fix was to stop calling the deprecated API.

### `Module._load` — no deprecation, and no stable shape either

`Module._load` has no DEP code and is not going anywhere soon; it is also not public API, and its
**call arity has oscillated**, which is the practical exposure rather than removal. Read off the
live function on each binary:

| Node | declared signature | arguments actually passed |
|---|---|---|
| 20.19.4 | `(request, parent, isMain)` | 3 |
| 22.23.1 | `(request, parent, isMain, options = kEmptyObject)` | 4 |
| 23.9.0 | `(request, parent, isMain)` | 3 |
| 24.5.0 | `(request, parent, isMain)` | 3 |
| 24.18.0 | `(request, parent, isMain, internalOptions = kEmptyObject)` | 4 |
| 26.5.0 | `(request, parent, isMain, internalOptions = kEmptyObject)` | 4 |

A fourth parameter appeared in 22, vanished for 23 and early 24, and came back **in a 24 minor**
under a different name carrying a different payload — `{ shouldSkipModuleHooks }` on 22,
`{ requireResolveOptions, shouldSkipModuleHooks }` on 24.18+. `Module._load.length` reports **3
on every one of them**, because `.length` stops at the first defaulted parameter. That is #135's
finding, and it is now known to be worse than #135 recorded: the shape is not merely
under-reported, it is *unstable within a major*.

capwall's wrapper is variadic and forwards `Reflect.apply(link.next, this, args)`, so none of
this required a code change. The second-order consequence did — see § What this audit changed.

### `Module._findPath` — moved once, silently

`(request, paths, isMain)` on 20.19.4; `(request, paths, isMain, conditions = getCjsConditions())`
on 22.23.1, 24.18.0 and 26.5.0, with four arguments passed on every call. `.length` is 3 on all
four. The observer in `loader/linked-packages.ts` was written variadic on the #128 rule and so
absorbed the change without noticing it; `test/primitive-arity.test.ts` now holds that property
in place rather than leaving it to habit.

### `Module.prototype._compile` — stable shape since 22.18, and the one with no replacement

`(content, filename, format)` on all four majors measured, including 20.19.4 (the `format`
parameter was backported). This is the shape #128 found the hard way when 22.18 added `format`
and a fixed-arity wrapper dropped it, handing raw TypeScript to `wrapSafe`.

There is **no supported replacement**, and this is worth being blunt about: `_compile` is not a
convenience. It is the one primitive that lets a caller choose what V8 reports as `getFileName()`
on the frames of the code it runs, which — since capwall names principals from frame file names —
is the ability to execute as an arbitrary principal. If Node removed it, the `compile` capability
would not be re-implementable on top of anything else Node offers. A `registerHooks` `load` hook
sees module *loads*, not a direct call to the compile primitive, which is precisely the
adversarial shape #93 is about. Node has no current plan to remove it. `Module._debug()` is the
precedent for what that assurance is worth.

### `process.dlopen` — no deprecation, and the gate got *more* coverage without changing

Plain writable, configurable own property of `process` on all four. `.length` is 0 because it is a
C++ binding, so its true arity is not readable from JS at all — a further reason the wrapper
forwards `args` rather than a written-out parameter list.

The audit turned up a change in the *routes* that reach it, in capwall's favour. `loader/native.ts`
used to state that a bare `import("./foo.node")` needed no coverage because Node rejects it with
`ERR_UNKNOWN_FILE_EXTENSION`. That is now true only of 20, 22 and unflagged ≤24: Node 24.18 grew
`--experimental-addon-modules`, which maps `.node` to `format: "addon"` in the ESM
`extensionFormatMap`, and **on Node 26.5 the import resolves with no flag at all**. The gate held
through both changes with no code change, because Node's `addon` translator returns
`createCJSNoSourceModuleWrap(...)` — it does not read the file as source, it routes the load back
through the CJS `.node` extension and therefore back through `process.dlopen`. Verified end to
end: under a deny-all policy, `import("./x.node")` raises capwall's `CapabilityError` for the
`native` capability on 24.18 with the flag and on 26.5 without it.

A gate hooked on `Module._extensions` or on the `require` specifier would have silently stopped
covering ESM at Node 26. That is the argument for hooking the chokepoint rather than the loader,
and it is now a measured one rather than a design intention.

### `Error.prepareStackTrace` / `captureStackTrace` — non-standard, and the whole thing rests here

Neither is a Node API; both are V8's. `Error.prepareStackTrace` and the structured `CallSite`
objects it yields are non-standard, unspecified, and documented only in V8's own stack-trace API
page. `Error.captureStackTrace` is at **TC39 Stage 2** (`tc39/proposal-error-capturestacktrace`)
— but that proposal covers only the *capture* half and **does not specify `prepareStackTrace`**,
which it mentions only to explain why V8 defers formatting. So the half of the pair that is being
standardized is the half capwall could most easily live without; the half it cannot live without
— structured CallSites, reached by swapping `prepareStackTrace` — has no standardization path at
all.

Every CallSite method capwall reads (`getFileName`, `isEval`, `getFunctionName`,
`isNative`, `getScriptNameOrSourceURL`) is present on all four majors, and `prepareStackTrace`,
`captureStackTrace` and `stackTraceLimit` are writable and configurable on all four.

There is nothing to migrate to and nothing to feature-detect against. The security consequence of
their being writable is not new and is already the threat model's opening section — see
[`threat-model.md`](threat-model.md) § The one assumption every control rests on. The *currency*
consequence is separate and belongs here: **a V8 change to the shape of a CallSite, or to when
`stackTraceLimit` is applied relative to the `captureStackTrace` boundary skip, would change
attribution's answers or its cost without any deprecation warning at all.** The #143 optimization
depends on that ordering specifically.

### `globalThis.EventSource` — guarded, and still not present

`EventSource` requires `--experimental-eventsource` on **every** major measured, up to and
including 26.5.0. The guard is therefore inert by default on every shipping Node, by design:
`shims/global-egress.ts` installs each guard only if the global is actually present, so the
coverage appears when the flag does. `test/global-egress-inventory.test.ts` is what catches a new
global egress API arriving in a minor.

### The V8 compile cache — available, effective, and still not capwall's to turn on

`module.enableCompileCache()` and its `NODE_COMPILE_CACHE` env channel are the obvious answer to
the ~40 ms capwall's own module graph costs at startup, and they work: measured on a mediated
child, the cache is populated with **49 blobs / 268 KiB** and every one of capwall's ESM modules
is reported `accepted` on the next run, on 22, 24 and 26 alike. The saving is real and grows with
the V8 in the release — the numbers are in `scripts/bench/README.md` § The V8 compile cache.

It is listed here as an API capwall deliberately does **not** rest on, for three reasons that are
properties of the API rather than of the measurement:

1. **It is process-wide and cannot be scoped or switched off.** There is no
   `disableCompileCache()`. To cover capwall's own graph it must be enabled before capwall's
   first module compiles, and from that moment every module the *host application* compiles is
   serialized to disk too. capwall is injected into someone else's process through
   `NODE_OPTIONS`; writing that process's compiled code to a directory of capwall's choosing is
   not a decision an injected security tool gets to take on the host's behalf.
2. **The cache I/O is invisible to capwall's own `fs` gate.** Verified: with
   `NODE_COMPILE_CACHE` set and a trace file attached, a mediated run records the fixture's
   `fs:read` and records **nothing at all** for the cache directory. The reads and writes are
   performed natively, below the JS `fs` surface capwall mediates, so capwall would be causing
   disk activity that its own control can neither see nor record.
3. **Integrity is against corruption, not against an adversary.** Node stores a hash of the
   payload in each blob's header and rejects a mismatch — verified by flipping bytes in a
   populated cache on 22, which produces `cache hash mismatch` and a clean recompile. That hash
   is Node's own non-cryptographic checksum over a file Node itself wrote, so it stops bit rot
   and does not stop anyone who can write the directory. The default location
   (`os.tmpdir()/node-compile-cache/<version>-<arch>-<hash>-<uid>`, mode 0700, uid-suffixed on
   all three majors) keeps that to the same-uid case, which is already lost — but it is a
   directory capwall would be *creating*, and putting a deserialize-and-execute path on the
   critical boot line of a supply-chain firewall wants an operator's yes, not a default.

None of this is an argument against **using** it: `NODE_COMPILE_CACHE=<dir> capwall enforce -- …`
needs no capwall code, since the CLI passes the environment through to the child. capwall's gates
are unaffected by it — the whole suite and the benchmark's 21 self-checks are green with the cache
enabled. That is the recommendation, and it is documented rather than defaulted.

## The one migration that mattered — done (#152)

`module.registerHooks()` is the supported successor to `module.register()`, and the ESM path is
on it. Measured on 22.23.1 / 24.18.0 / 26.5.0 when this was written, and re-measured on 22.22.3 /
24.18.0 / 26.5.0 when it landed, it is also more than a like-for-like replacement: **a synchronous
`registerHooks` `load` hook intercepts `require()` as well as `import()`, including builtins, and
can replace a builtin's source for both.** Verified — a `load` hook returning
`{ format: "commonjs", source: "module.exports={SHIMMED:true}", shortCircuit: true }` for
`node:fs` is observed by `require("node:fs")` and by `await import("node:fs")` alike.

So the API Node offers as the replacement for `module.register()` is *also* the first **documented**
thing to exist in the space capwall's `Module._load` patch occupies — builtin-specifier
interception on `require`.

### Could it SUBSUME the `Module._load` patch? Assessed, and the answer is no — not yet

This is the tempting version of the migration and #152 deliberately did not attempt it. The
assessment, so the next person does not have to redo it:

**What a `registerHooks` `load` hook would cover.** Returning
`{ format: "commonjs", source, shortCircuit: true }` for a mediated builtin specifier does reach
`require()`, on 22/24/26. That is genuinely the same ground `Module._load`'s specifier
interception occupies, and it is documented where `_load` is not.

**Four things it would not cover, and they are most of what `loader/require.ts` is for.**

1. **The filename Node is actually about to open.** The #123 module-read gate has to decide on
   that file, and since #178 it takes it from `Module.prototype.load(filename)` — the point Node
   has already decided, with no second resolution of its own. (This item used to argue from a
   `Module._resolveFilename` call inside the `Module._load` wrapper; that call, and the double
   resolve it performed, are deleted — see § Superseded by #178, which is the reason. The
   conclusion is unchanged and the argument is stronger for it.) A `resolve` hook does learn a
   filename, but it learns it for the load Node is performing at a point *before* `load` runs, and
   the CJS half must not then decide the same load twice; the arbitration between the two is what
   `loader/module-read.ts` § WHICH OF THE GATES DECIDES A GIVEN LOAD exists to state.
2. **The subject.** The CJS gate's subject is a **stack walk**, precisely because
   `createRequire()` lets a caller choose the `parent.filename` a hook would be handed. A
   `registerHooks` hook runs in capwall's realm now, so a walk is *possible* there — but at
   resolution time the stack is Node's loader machinery, and getting the importer out of it
   reliably is a different problem from the one attribution solves today.
3. **`Module._findPath`.** #127's link observer needs Node's *ordered search-path list* to give a
   symlinked workspace package an identity. A `resolve` hook does not receive it.
4. **`Module.prototype._compile` and `process.dlopen`.** Untouched by any hook, and the `native`
   gate is the capability that subsumes the rest.

**And two things that would get worse.** A hook chain is *composable and process-wide*, so moving
CJS interception into it would put the whole `require` path behind the same chain-ordering
exposure #61 gates against — today the `Module._load` patch is **outside** the hook system
entirely and a hostile hook cannot displace it, which is why the CJS path held while the ESM path
needed #59/#61/#78. And a hook never sees the requires Node's own internal bootstrap makes, the
same blind spot `_load` has (the reason each egress module is shimmed separately —
[`architecture.md`](architecture.md) § Capability shims).

**Verdict: not a replacement, a second layer at best.** The honest framing is that
`registerHooks` is the *documented* successor for the ESM path and a *possible* defence-in-depth
addition on the CJS path — never a reason to remove the `Module._load` patch, which is both
outermost and the only site that sees a caller's own resolve options. Filed as a follow-up rather
than done here.

### What the migration cost, stated plainly

- `registerHooks` is Stability **1.2 (Release candidate)**, not stable. It can change in a minor.
  That is still a strict improvement on Stability 0 with removal announced.
- **The hooks are now consulted for every `require()` in the process**, which is work that did not
  exist before — `module.register()` hooks never saw `require`. Measured on a 123-module
  `express` tree at 2 cores: with ESM on, module loading costs **~11 ms (Node 22) / ~18 ms (24) /
  ~24 ms (26)** more than with `CAPWALL_ESM=0`, where on a tiny entry point the difference is
  4–8 ms. Net the change is still **−63 to −120 ms** on that tree, because the loader thread it
  removed cost far more. See `scripts/bench/README.md` § After #152.
- It brings one thing capwall used to document as impossible: a `deregister()` that actually
  removes the hooks. `docs/threat-model.md` § ESM known limits used to carry the ESM/CJS teardown
  asymmetry as a named limitation; it no longer does.

## What this audit changed (2026-07)

### A live bypass of the #123 module-read gate on Node ≥24.18

`loader/require.ts` re-runs `Module._resolveFilename` before delegating, so the module-read gate
knows which file a load will open. It did that by forwarding `Module._load`'s **own argument list
verbatim**, on the stated reasoning that the two take the same arguments. They do not, and Node
24.18 made the difference observable:

- On **Node 22**, `_load` calls `resolveForCJSWithHooks(request, parent, isMain,
  options.shouldSkipModuleHooks)`, whose default impl calls `Module._resolveFilename(specifier,
  parent, isMain)` — with **no options argument at all**.
- On **Node ≥24.18 / 26**, `_load`'s fourth argument is `CJSModuleLoadInternalOptions`, and
  `resolveForCJSWithHooks` destructures `{ requireResolveOptions, shouldSkipModuleHooks }` and
  passes **`requireResolveOptions`** — that field, not the bag — to `Module._resolveFilename`.

capwall passed the bag. `Module._resolveFilename` found no `paths` in it, resolution failed,
`resolveQuietly` returned `null`, and the gate read that as "nothing to decide".

Measured, with a clean A/B against the same tree. On Node 24.18.0 and 26.5.0, a dependency
calling

```js
Module._load("./secrets.json", parent, false, { requireResolveOptions: { paths: ["/somewhere"] } })
```

under a **deny-all `enforce` policy** received the file contents and produced **zero decisions** —
no throw, no `DENY` line, nothing for `observe` or `capwall diff` to see. The three-argument
spelling of the identical read was denied and logged correctly, which is exactly what kept it
invisible. Node 22 and earlier reject the four-argument form outright, so it never showed on the
CI matrix.

Fixed at the time by mirroring Node's own unwrapping (`resolveOptionsFrom` in `loader/require.ts`).
Covered by `test/module-read.test.ts` § "every spelling of `Module._load` reaches the same
decision", which **feature-detects** the four-argument form at runtime rather than version-gating
it — because the history above shows any `major >= N` test would have been wrong for two of the
five majors. Both new rows fail against the pre-fix tree on 24.18 and 26.5 and skip on 20/22.
**That fix has since been superseded — see the subsection at the end of this section.**

Note what this says about the CI matrix, because it is the uncomfortable part: **the defect could
not be observed on either Node in `ci.yml`.** It was introduced by a Node minor on a major the
matrix does not cover, and no test capwall could have written on Node 20 or 22 would have caught
it. That is a coverage argument, not a test-quality argument, and it is filed as **issue #154**.
It is also why no mutant was added to `scripts/mutants.json` for `resolveOptionsFrom`: on Node
20/22 the mutation is behaviourally identical to the original, so the mutant would report
`SURVIVED` on the repo's own gate for a reason that is not a hole in the tests.

### Documentation corrections in the source

Four comments asserted version facts that had stopped being true. All were *comments* — the code
was already variadic and correct — but a stale claim about a Node internal is how the next
fixed-arity wrapper gets written:

- `loader/require.ts` said the four-argument `_load` was the shape "on Node ≥22". It is the shape
  on 22 and on ≥24.18, and was not the shape on 23 or early 24.
- `loader/linked-packages.ts` said `Module._findPath`'s "current signature is
  `(request, paths, isMain)`". It gained `conditions` after Node 20.
- `loader/native.ts` said a bare `import("./foo.node")` is rejected by Node. It resolves on 26.5
  unflagged, and the gate covers it — for a reason worth writing down.
- `test/primitive-arity.test.ts` repeated the "Node ≥22 really is four arguments" claim.

### New coverage

- `test/primitive-arity.test.ts` gained a `Module._findPath` row — the third wrapper site over a
  Node internal and the one whose parameter list has already moved. Asserted arity-agnostically,
  spanning counts Node has used, has stopped using, and has never used. It fails if the site is
  changed to a fixed three-argument forward.
- `test/module-read.test.ts` gained the two rows described above.
- `test/native.test.ts` gained the ESM `.node` import route, which had no coverage because it did
  not exist when the gate was written. Feature-detected in the child rather than version-gated,
  and on a runtime where the route does not exist it asserts **Node's own
  `ERR_UNKNOWN_FILE_EXTENSION`** rather than skipping — a row that reports green by doing nothing
  is the #112 failure mode.

### Superseded by #178 — and the reason is the most useful thing in this document

Everything above stands as a record of what was measured. The **fix** did not survive review.

`resolveOptionsFrom` classified `Module._load`'s fourth argument by the fields it **has** — unwrap
`requireResolveOptions`, pass through an object carrying `paths`/`conditions`, contribute nothing
otherwise — rather than by a Node version, on the reasoning that a Node which hands `_load` the
resolve options directly again is a live possibility and dropping a `paths` on the floor would put
the gate back to deciding about a file Node is not opening.

**The fields are the attacker's.** #178 turned that classifier into a steering wheel: a
dependency passing `{ paths: [<some node_modules dir>] }` sent capwall's re-resolution to a
graph-exempt decoy — no decision — while Node, which reads `paths` off `_load`'s fourth argument
on no released version, opened the real file. That construction worked on **22, 24 and 26**. A
getter showed the bag was read twice by capwall and a third time by Node, so it could answer the
two differently. The forward-compatibility branch, written to prevent the gate deciding about a
file Node is not opening, is what made it do exactly that on every Node that exists.

The durable fix was not a better classifier and not a snapshot of the bag. It was to **stop taking
the decision from a second resolution at all**: the gate moved to `Module.prototype.load`, which
Node calls with the filename it resolved. `resolveOptionsFrom`, `resolveQuietly` and the double
resolve this section measured are all deleted — see `docs/threat-model.md` § The module system as
a read channel, and issues #177/#178/#179/#180.

Three things in this document are worth re-reading with that outcome in mind:

- The mutant paragraph above says no mutant was added for `resolveOptionsFrom` because on 20/22
  the mutation is behaviourally identical. That was true, and it also meant the repo's strongest
  gate had nothing to say about a function whose behaviour on the floor was a live bypass. The
  four mutants that replaced it (`module-read-gate-at-proto-load`,
  `module-read-ignores-node-main-marking`, `esm-gate-declines-every-require-resolution`,
  `module-read-host-root-only-from-parentless-resolution`) all pin properties that are observable
  on **every** supported Node, because the design no longer has a behaviour that varies by one.
- **#154's coverage argument was right and insufficient.** The matrix now covers 24 and 26, which
  is what #154 asked for — and #178's construction A was reachable on 22 the whole time. A wider
  matrix finds defects that a Node version exposes; it does nothing for a defect that is exposed
  by an argument the caller controls.
- The rule this section was written to establish — *a DERIVED argument is not a forwarded one*
  (#128 one level up) — is still right. It just has a sharper form: **a re-resolution is a second
  opinion, and a second opinion the attacker parameterises is worthless.** Where a gate needs to
  know what a primitive is about to do, take it from the point the primitive has already decided.

## Reproducing the measurement

Nothing in this document was taken from a changelog summary or from memory. The method, so it can
be repeated when Node 27 lands:

1. **Read the internals off a real binary.** For each Node under test, dump Node's shipped `lib/`
   with `process.binding("natives")` and read the actual implementation of
   `Module._load`, `Module._findPath`, `Module._resolveFilename`, `Module.prototype._compile`,
   `Module._extensions[".node"]` and `resolveForCJSWithHooks` in
   `internal/modules/cjs/loader.js`. A declared signature is not the same fact as the arity Node
   passes — instrument each function and count `arguments.length` during a real `require`.
2. **Read the deprecation source, not the rendered page.** `doc/api/deprecations.md` and
   `doc/api/module.md` from the release branch carry the YAML `changes:` blocks with exact
   versions and the `Type:` line. The rendered HTML flattens histories and is easy to misread.
3. **Run the suite under `--pending-deprecation`.** It surfaces docs-only deprecations the suite
   otherwise swallows. Add `--trace-deprecation` to find the caller: that is how DEP0111 here was
   traced to `@vitest/snapshot` rather than to capwall.
4. **Run the CLI end to end under `--throw-deprecation`** on each major. A runtime deprecation is
   an availability bug for a preload, not a warning.
5. **Do not treat "no DEP code" as "supported."** Check whether the API appears in `doc/api/` at
   all.

## Assessment

Being direct, because the rest of this document is detail:

**capwall's exposure to Node internal churn is real, structural, and currently well-managed
rather than reduced — though #152 reduced it by exactly one item.** Of the seven things that make
capwall work, five are undocumented Node internals with no support commitment (`Module._load`,
`Module.prototype.load`, `_findPath`, `Module.prototype._compile`, `process.dlopen` — this list
read `_resolveFilename` rather than `Module.prototype.load` until #178 deleted the last call to
it), one is
**documented but at Stability 1.2, release candidate** (`module.registerHooks()`), and one is not
a Node API at all (V8's `prepareStackTrace` / CallSites, which is all of attribution). Exactly
zero are documented *and stable*. That middle row was `module.register()` — Stability 0, removal
announced — until #152.

Four of them have moved under the project already, and the tempo is roughly one per major:
`Module.prototype._compile` gained `format` in 22.18 (#128, which broke every TypeScript user);
`Module._load`'s arity turned out to be under-reported by `.length` (#135); `Module._findPath`
gained `conditions` after 20 and nobody noticed until this audit; and `Module._load`'s fourth
argument changed payload in **24.18**, which produced a live, unrecorded enforcement gap on the
current active LTS. `process.dlopen` did not change, but the set of routes reaching it did.

What keeps that manageable is a discipline rather than a design: every wrapper over a Node
primitive forwards `Reflect.apply(real, this, args)` and states no arity, and every version claim
is measured against a binary rather than asserted. That discipline absorbed the `_findPath`
change and the `--experimental-addon-modules` change with no code change at all. Where it was not
applied — a *derived* argument rather than a forwarded one — is exactly where the gap opened.

What is not managed, and cannot be from inside this repository:

- **`Module.prototype._compile` and `process.dlopen` have no replacement.** If either is removed,
  the `compile` and `native` capabilities do not degrade — they cease to exist, and there is
  nothing to build them on. `native` is the more serious of the two, because it is the capability
  that subsumes the rest.
- **Attribution has no standardization path.** `Error.prepareStackTrace` and structured CallSites
  are V8-specific and unspecified, and the TC39 proposal in this area explicitly declines to
  specify the part capwall uses.
- **The CI matrix has to cover every major those internals ship in.** The ≥24.18 gap found in
  this audit could not be observed on the Node 20/22 matrix `ci.yml` ran at the time. That is why
  the matrix is now **22, 24 and 26** (issue #154, and the floor move that followed).

The direction of travel is, unusually, favourable, and #152 is the first instalment of it:
`module.registerHooks()` is the only documented API Node has offered in the space capwall's
loader interception occupies, and the ESM path is now on it — from "deprecated with removal
announced" to "documented, release candidate", with a loader thread, a `MessageChannel` policy
copy and ~100 ms of startup retired on the way. It did **not** subsume the `Module._load` patch
and should not be expected to; see § The one migration that mattered for the four things it does
not cover and the two that would get worse. `_compile`, `dlopen` and attribution stay exactly
where they are, and this document exists so that nobody has to discover that for themselves.
