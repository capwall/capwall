# capwall threat model

This document is the source of truth for **what capwall protects against and what it does
not.** Read it before relying on capwall. If you change the engine, keep this document in
sync — overclaiming here is a security bug.

## One-sentence summary

capwall is **pragmatic, runtime, per-package defense-in-depth against opportunistic
supply-chain malware.** It is **not** a formal sandbox and does not withstand a determined
in-process attacker.

## Implementation status (keep in sync with the roadmap)

As of roadmap **M5**, all core capability surfaces are mediated on **both the CJS `require`
path and the ESM `import` path**: `fs`, `net`/`http`/`https`/`tls`/`http2`/`dgram`,
`child_process`, `worker_threads`, `vm`, and `process.env`. ESM interception uses a
`module.register()` loader hook (`loader/esm-hook.ts` + `esm-hooks.ts` + `esm-runtime.ts`)
that rewrites mediated builtin specifiers to a synthetic module re-exporting the same shims
the CJS path uses; it covers **static AND dynamic** `import` (`import { readFile } from
"node:fs"` and `await import("node:fs")`), attributing to the importing package exactly like
CJS. It is **on by default** under the CLI preload (disable with `CAPWALL_ESM=0`).

The shims are handed out **mutable by default** (so `graceful-fs` and friends keep working);
`install(policy, mode, { hardened: true })` / `CAPWALL_HARDENED=1` freezes them instead —
**off by default**, see § Hardened mode for what that does and does not buy.

**ESM known limits** (documented, not silent):
- A module that captured a raw builtin **before** capwall installed is not re-bound (same as
  CJS — install via the `--import` preload so capwall registers first).
- The set of mediated specifiers is fixed at install time; a mediated builtin not in the shim
  registry is not intercepted (the registry covers the capabilities above).
- Unregistering the ESM hook is best-effort (Node cannot fully remove a registered hook);
  after `uninstall()` a re-import of a mediated builtin throws a visible error rather than
  silently returning the raw builtin (fail-closed).
- `process.env` is not import-routed; its Proxy guard (installed by `install()`) covers both
  module systems already.

Per-capability notes:

- **`fs`** — path-taking read/write families (sync, callback, `fs.promises`) plus the
  path-taking stream constructors (`ReadStream`/`WriteStream` and their `File*Stream`
  aliases). Purely fd-based operations (`fs.read`, `fs.write`, `ftruncate`, …) are not
  mediated — consistent with the fd-escape exclusion below.
- **`net`/`http`/`https`/`tls`/`http2`/`dgram`** — **egress only**. Mediated: `net.connect`/
  `createConnection` **and** `new net.Socket().connect()`; `http(s).request`/`get` **and**
  `new http.ClientRequest()`; `tls.connect` and `new tls.TLSSocket().connect()`;
  `http2.connect`; and `dgram` socket `send`/`connect` (UDP). Each core egress module is
  shimmed separately on purpose: capwall's require patch only affects `Module._load`-routed
  requires (user/dependency code); Node's own HTTP client loads `net` through the internal
  bootstrap loader, which never hits `Module._load`, so one module's shim never covers
  another — and a dependency could otherwise bypass the control simply by choosing `tls`
  (or `dgram`) over `net`. Inbound `server.listen` is not gated (capwall mediates who a
  package may *reach*, not that it may serve). IPC/unix-socket connects have no host:port and
  are approximated coarsely as `{ host: "<ipc>", port: 0 }`. Capability-bearing classes
  (`net.Socket`, `tls.TLSSocket`, `http.ClientRequest`, `http.Agent`, `dgram.Socket`) are
  guarded via a **guarded subclass** whose prototype method (or constructor) runs the check,
  so `new Cls()`, `(instance).constructor`, and `Cls.prototype.method.call(...)` are all
  covered (a construct-trap Proxy would not be). **Not covered:** `dns` lookups (a lookup
  moves no payload; DNS tunneling is a determined-attacker technique out of scope); reaching
  the real prototype by climbing past the guarded subclass (two levels from an instance,
  `Object.getPrototypeOf(Object.getPrototypeOf(sock)).connect`, or equivalently one hop from
  the class object, `net.Socket.prototype.__proto__.connect` — the same class as the general
  shim un-patching residual, in-process code deliberately climbing above the guard); and a
  getter-based TOCTOU on `{host,port}` options for a
  package that *already holds a narrow net grant* (the derived target is read separately from
  the value Node connects to — tracked as #26). These are documented residuals, not silent
  gaps.
- **`child_process`, `worker_threads`, `vm`** — boolean **gates** (may this package spawn /
  start a worker / use `vm` at all). Gating, not confinement: capwall does not constrain what
  the subprocess/worker/vm-context does once started (see § gating vs confinement).
- **`process.env`** — a read allowlist enforced via a `Proxy` on `process.env` (`get` **and**
  `getOwnPropertyDescriptor` traps, so `Object.getOwnPropertyDescriptor(process.env, k).value`
  cannot leak a value a direct read denies). Only reads attributed to a **dependency** are
  gated; reads attributed to `<app>` (application code AND Node-internal frames, which
  attribute to `<app>` because internal frames are skipped) pass through — gating them would
  break Node startup for no gain, since the app is the trust root. `CAPWALL_*` keys (capwall's
  own preload plumbing) are never gated or recorded. When a package **spawns a child**, Node
  reads `process.env` to build the child's environment block; those reads are exempted (the
  child_process shim suspends the env gate around the spawn) so an allowed spawn inherits a
  real environment rather than an empty one. A denied env read is a **soft deny**: it returns
  `undefined` (hiding the value) rather than throwing, so a benign dependency probing an
  optional var is not crashed. The denial is still recorded and logged. **Key NAMES stay
  enumerable** to a denied dependency (`Object.keys`, `in`, `for..in`); only VALUES are hidden
  — names are not the secret, and hiding them would break feature-detection.

**Behavior change vs. real `fs` (operational note).** In `enforce` mode a denial is delivered
via the SAME channel the real `fs` API would use for that call, not always a synchronous
throw — chosen specifically so idiomatic (try/catch-free) code is not crashed by an uncaught
exception it would never see from real `fs`:

- **`*Sync` methods** (`readFileSync`, …) throw `CapabilityError` synchronously — matches
  real sync `fs`.
- **`fs.promises` methods** reject with `CapabilityError` — matches the real promise API.
- **Callback-style async methods** (`readFile`, `mkdir`, `access`, `rm`, …) invoke the
  caller's own callback as `cb(err)` on `process.nextTick`, exactly as a real async `fs`
  error would arrive, instead of throwing. If the call is missing a callback (a mis-call),
  the shim falls back to a synchronous throw, matching real Node's behavior for the same
  mis-call.
- **`createReadStream`/`createWriteStream`** return a minimal stream (with `.path` set) that
  holds the `CapabilityError` and emits `'error'` with it **as soon as an `'error'` listener
  is attached** to the stream — not on a fixed timer — so a handler attached synchronously,
  on a microtask, on `setImmediate`, or on `setTimeout(0)` is always caught (fix #40; this
  closes the earlier parity gap, where a fixed `setImmediate` delivery could fire before a
  handler attached on a later macrotask, producing an uncaught `'error'` even though the
  consumer did handle errors). A sync throw here would still be a bypass-shaped surprise,
  since `fs.createReadStream(p).on('error', h)` is the idiomatic pattern and never throws
  synchronously in real Node either. If `'error'` is never listened for at all, a safety net
  still delivers the denial after two event-loop phases, so an unhandled denial ultimately
  crashes the process — same as real `fs` would for an unhandled async error — rather than
  silently hanging forever. This is **fail-closed** either way — the read/write never happens.
- **`watch`/`watchFile`** and the `ReadStream`/`WriteStream` **class constructors**
  (`new fs.ReadStream(deniedPath)`) throw synchronously on denial. `fs.watch` and a real
  stream constructor also throw synchronously on a bad argument, so those match. `fs.watchFile`
  is the exception: real `watchFile` does NOT throw (it calls its listener with zeroed stats),
  so the shim's sync throw there is a deliberate loud-failure choice — `watchFile`'s listener
  is `(curr, prev)`, not error-first, so there is no faithful channel to deliver the denial
  through.
- **Buffer path arguments** are decoded with `latin1` (byte-exact — fix #19) before the policy
  check, so the checked path matches the bytes forwarded to real `fs` even for non-UTF-8
  bytes. Trade-off: a **valid non-ASCII UTF-8 path passed as a Buffer** decodes to a different
  (latin1) string than the UTF-8 string a policy glob is authored in, so it may **false-deny**
  (fail-closed — never a false-allow). Uncommon (needs a non-ASCII filename supplied as a
  Buffer); the encoding strategy is tracked for reconsideration (issue).
- **`exists`/`existsSync`** remain the bespoke non-throwing existence probes: a denial reads
  as "does not exist" (`false` / `cb(false)`), never an error at all.

This is unchanged in spirit from before — enforce mode still fails loudly and a policy gap
still surfaces as a real error, not a silent allow — only the DELIVERY CHANNEL now matches
what the real `fs` API would use for that call shape. This is most likely to matter during
the observe→tighten→enforce rollout while a policy is still incomplete; run `observe` until
coverage is stable before flipping to `enforce`. Path matching is POSIX-oriented
(`/`-separated); Windows drive-letter paths are not matched by relative grants yet.

## Adversary we are designed to stop

**Opportunistic, worm-style supply-chain malware** delivered through a compromised npm
dependency. Concretely, the class exemplified by:

- **Shai-Hulud** (Nov 2025) — a self-propagating npm worm.
- **Glassworm** (2026) — malware that runs at **both** the lifecycle-script (install) phase
  **and** the application-runtime phase.

The critical observation: these payloads execute at **application runtime**, not only at
install. Install-time defenses — lockfile pinning, `--ignore-scripts`, registry scanners,
socket brokers — never see the runtime phase, where credential theft, wallet drain, and
lateral movement actually happen. capwall lives in the running process and mediates that
phase.

Such malware is typically **opportunistic**: it tries to read `process.env`, open a socket
to an exfiltration host, spawn a shell, or write to a persistence path. It does **not** go
out of its way to break out of a capability shim. That is exactly the behavior capwall's
per-package capability policy catches: a logger that suddenly opens a network socket, or a
string-formatting helper that reads environment secrets, is a policy violation.

## What capwall stops

When a package's declared capabilities are tight, capwall denies (in `enforce` mode) or logs
(in `observe` mode) attempts by that package to:

- Read/write files outside its allowed path globs (`fs`).
- Open network connections to hosts/ports outside its allowlist (`net`, `http(s)`).
- Spawn subprocesses when `child_process` is not permitted (**gating** the spawn).
- Spin up `worker_threads` when not permitted.
- Read `process.env` keys outside its allowlist (e.g. exfiltrating `AWS_SECRET_ACCESS_KEY`
  from a package with no reason to see it).
- Use `vm` when not permitted.

The **trace→policy DX** makes those policies practical to author: run once in `observe`,
emit a starter policy scoped to what each package *actually* did, tighten it, enforce.

## What capwall does NOT stop (out of scope for confinement)

capwall does **not** harden JavaScript primordials (that is SES's job — see below). Without
frozen primordials, a **determined in-process attacker** can defeat it via, among others:

- **Prototype pollution** and **shared mutable primordials** — mutating
  `Object.prototype`/`Array.prototype`/etc. to influence code in other packages, or to
  tamper with capwall's own bookkeeping.
- **Un-patching the shims** — reaching for the original, un-wrapped core module reference and
  calling it directly. This is **cheap, not exotic**: capwall returns a plain, mutable shim
  object (deliberately un-frozen, so legitimate `fs` monkey-patchers such as `graceful-fs`
  keep working — the no-SES-tax tradeoff). A dependency can reassign the shim's methods, or
  reach the raw builtin through channels capwall does not mediate. Both the CJS `require` and
  the ESM `import` paths ARE mediated (M4/M5), so `require("node:fs")` and
  `import … from "node:fs"` both return the shim — but capwall does not chase every reflective
  escape hatch, and at least one is a **plain public API**: `process.getBuiltinModule("node:fs")`
  (Node ≥22) returns the real, un-shimmed module, as does `process.binding`, internal module
  caches, or a builtin loaded from a context capwall has not patched. `getBuiltinModule` is
  path-independent (it defeats the CJS patch identically), so this is not specific to ESM. The
  shim is a **shared, process-wide singleton**, so a single dependency that does un-patch it
  **silently disables enforcement for every other package and the app**, not just for itself,
  with no log line. Treat capwall's mediation as effective only against packages that do not
  go looking for the raw builtin. **Opt-in hardened mode (#17) closes the reassignment half of
  this** — see § Hardened mode below for exactly how much, and how little, that buys.
- **fd / symlink escapes** — using an already-open file descriptor, or a symlink, to reach a
  path outside the allowed globs.
- **`vm` / `eval` / `node:sqlite`** and similar reflective or alternate-execution surfaces
  that can sidestep the shimmed API.
- **Attribution laundering** — capwall attributes each call to the **nearest** package frame
  on the stack (see `core/src/attribution`). A malicious package that arranges for its
  operation to be *executed by* a trusted helper's code (passing a path to a logger that
  writes it, scheduling work a broadly-granted package performs) is charged to the helper.
  Keep helper grants tight; broad grants are laundering targets.
- **Native `.node` addons** — arbitrary compiled code; capwall can gate *whether* an addon
  loads but cannot confine what it does once loaded.
- **Subprocess internals** — capwall can gate *whether* a `child_process` spawn happens, but
  once a child process runs it is outside capwall's process and outside its confinement.

**Gating vs confinement.** For native addons and subprocesses, capwall provides **gating**
(a policy decision about whether they are allowed to start) but **not confinement** (control
over what they do after starting). Do not treat a gated-but-allowed addon or subprocess as
confined.

## Hardened mode (opt-in, off by default) — issue #17

`install(policy, mode, { hardened: true })`, or `CAPWALL_HARDENED=1` for the CLI preload,
freezes the capability surfaces capwall hands to dependencies. It exists because the default
shim is a plain mutable object, so `fs.readFileSync = evil` is a one-line, un-logged removal
of enforcement **for the whole process** (the bullet above). Hardened mode is **off by
default and must stay off by default** — see the graceful-fs cost below.

**What it freezes** (only objects capwall itself created — never a builtin):

- Every shim **namespace** handed to a dependency: `fs`, `fs.promises`, `net`, `http`,
  `https`, `tls`, `http2`, `dgram`, `child_process`, `worker_threads`, `vm`. So
  `fs.readFileSync = evil`, `delete fs.readFileSync`, and
  `Object.defineProperty(fs, "readFileSync", …)` all fail.
- Every guarded **wrapper function** on those namespaces, including wrappers hanging off
  other wrappers (`fs.realpath.native`).
- Every guarded **subclass** capwall builds for a capability-bearing class — `net.Socket`,
  `tls.TLSSocket`, `http.ClientRequest`, `http.Agent`, `dgram.Socket`,
  `child_process.ChildProcess` — **and its prototype**. The prototype freeze is the one that
  matters: `net.Socket.prototype.connect = evil` is otherwise the same one-line un-guard as
  above, one level down.
- The guarded `send`/`connect` own-properties capwall installs on a `dgram` socket instance
  (made non-writable/non-configurable; the socket itself is not frozen — it needs its state).

**Observable behavior of a blocked patch.** Freezing does not raise an alarm. A write to a
frozen object **throws a `TypeError` only under `"use strict"`**; in sloppy-mode CJS — which
is what most published packages still are — it **silently no-ops**. There is no capwall log
line for a blocked patch attempt. The guarantee is only that the original guarded method is
still installed and still enforcing afterwards.

**What it does NOT protect against.** Hardened mode raises the cost of un-patching. It is not
a sandbox and it closes none of the following, all verified against a hardened install:

- **`process.getBuiltinModule("node:fs")`** (Node ≥22) — a plain public API returning the
  real, un-shimmed module. Also `process.binding`, internal module caches, and builtins loaded
  from a context capwall has not patched. These never touch a shim object, so freezing shim
  objects is irrelevant to them. **This alone makes hardened mode defense-in-depth, not a
  boundary.**
- **The construct-trap `Proxy` class wrappers** — `fs.ReadStream`/`WriteStream` (and the
  `File*Stream` aliases), `vm.Script`/`SourceTextModule`/`SyntheticModule`, and
  `worker_threads.Worker` are guarded by a `Proxy` over the real class, not by a guarded
  subclass. `Object.freeze` on a Proxy forwards to its **target**, so freezing them would
  freeze the real builtin class process-wide — a global side effect capwall refuses to take.
  They are therefore left unfrozen, and `new (fs.ReadStream.prototype.constructor)(path)`
  reaches the real, unguarded class in hardened mode exactly as it does without it.
- **`http.globalAgent` / `https.globalAgent`** — the shim's `Agent` **class** is guarded, but
  `globalAgent` is a real `Agent` instance passed through untouched, so
  `http.globalAgent.createConnection({host, port})` is un-gated egress with or without
  hardened mode.
- **Replacing `process.env` wholesale** — the env read allowlist is a `Proxy` over the live
  `process.env`, not a capwall-created namespace. Freezing it would break `process.env.X = y`
  for the whole process and freeze the real environment object, so it is left alone;
  `process.env = {…}` still un-gates env reads.
- **Prototype pollution / primordials / fd + symlink escapes / `eval` / native addons /
  subprocess internals** — unchanged. Hardening primordials is SES's job.
- **Climbing past a guarded subclass** — `Object.getPrototypeOf(net.Socket.prototype).connect`
  still reaches the real method. Freezing capwall's subclass says nothing about the real class
  above it.

**Cost: it breaks `graceful-fs`, and therefore anything that depends on it.** `graceful-fs` is
a transitive dependency of npm, webpack, and a large fraction of the ecosystem, and it patches
`fs`'s methods at load time. Against a frozen `fs` that patch throws a `TypeError` (its
sources are strict-mode), so the dependent package fails to load. The same applies to every
other legitimate `fs` monkey-patcher. Enabling hardened mode is a deliberate trade: you lose
`graceful-fs`-class compatibility — the no-SES-tax property that is capwall's whole adoption
argument — and gain the closure of the reassignment escape only. Try it in `observe` mode
first; a load-time `TypeError` from a patcher is what failure looks like.

## Comparison to other threat models

### vs SES / hardened primordials (LavaMoat, Endo)

SES freezes the primordials and runs each package in a compartment, so prototype pollution
and primordial-tampering attacks in the list above are largely **in scope** for SES to stop.
capwall accepts those as **out of scope** in exchange for **no SES tax**: no broken packages
from frozen intrinsics, no uneven ESM/native-addon story, near-zero adoption friction.
capwall offers *weaker isolation, dramatically lower friction*. For a hostile,
break-out-motivated adversary, prefer SES; for containing opportunistic supply-chain malware
in an existing Node service with minimal changes, capwall is the pragmatic choice. The two
are composable.

### vs Node's `--permission` model

Node's built-in permission model is **process-global**: one `--allow-fs-read` set applies to
the entire process, so you cannot say "express may read `./views`, but this transitive dep
may read nothing." capwall's contribution is exactly the **per-package** dimension. Node's
model, being enforced deeper (in the runtime, not via JS shims), is harder to un-patch —
another reason capwall is defense-in-depth *alongside* it, not a replacement.

### vs scanners (guarddog, Socket)

Scanners try to **detect** a malicious package before or as it enters your tree. capwall
assumes detection failed and a bad package is present, then **contains what it can do at
runtime.** Complementary layers, not competitors.

## Residual risk statement

Deploying capwall in `enforce` mode meaningfully raises the cost of opportunistic
supply-chain malware and gives you a per-package audit trail. It does **not** provide a
security boundary against a determined, capwall-aware in-process attacker. Treat it as one
layer of defense-in-depth, alongside dependency review, lockfile pinning, least-privilege
process/OS sandboxing (containers, seccomp), and secret hygiene.
