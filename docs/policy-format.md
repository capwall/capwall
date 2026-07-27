# capwall policy format (`capabilities.json`)

The policy is a single JSON file (conventionally `capabilities.json` at the project root)
mapping each **package** to the capabilities it is allowed to use. It is deliberately compact
— NodeShield-style, a handful of entries per dependency. The machine-readable JSON Schema is
[`packages/policy-schema/schema.json`](../packages/policy-schema/schema.json); the TypeScript
types are exported from `@capwall/policy-schema`.

## Top-level shape

```jsonc
{
  "$schema": "./packages/policy-schema/schema.json",
  "version": 1,               // policy format version
  "mode": "enforce",          // optional: "observe" | "enforce" — see § Enforcement mode
  "default": { /* PackagePolicy applied to any package with no explicit entry */ },
  "packages": {
    "<package-name>": { /* PackagePolicy */ }
  }
}
```

- **Deny-by-default.** In `enforce` mode, a package with no entry falls back to `default`;
  the recommended `default` grants nothing (see `capabilities.example.json`).

## Enforcement mode

`mode` is **optional**. It declares the mode capwall runs the target under when the caller
did not name one — which is what `capwall run` is for:

```bash
capwall run -- node ./src/server.js     # mode comes from capabilities.json
```

That is the point of committing it: the mode lives in a reviewed file next to the grants it
applies to, and promoting a project from on-ramp to enforcement is a one-word diff rather than
a change to whatever invokes capwall.

Precedence, highest first (implemented in `core/src/policy/mode.ts`, tested in
`core/test/mode.test.ts`):

| # | Source | When it applies |
|---|---|---|
| 1 | `CAPWALL_MODE` env var | Always wins. `capwall observe`, `capwall enforce` and `capwall diff` set it, so those subcommands ignore the file's `mode` by design. |
| 2 | the file's `mode` | Used when nothing set `CAPWALL_MODE` — `capwall run`, or a bare `NODE_OPTIONS=--import @capwall/core/preload`. |
| 3 | neither | capwall stays **inert**: no interception, nothing logged, nothing blocked. |

Consequences worth knowing:

- A policy that **omits** `mode` cannot switch capwall on. Omitted and `"observe"` are
  different: `"observe"` means "mediate and log", omitted means "I am not deciding".
- Because rule 1 is unconditional, `capwall observe -- …` on a policy declaring
  `"mode": "enforce"` runs in **observe** — nothing is blocked. That is the safe direction and
  it is deliberate (observe is how you regenerate a policy), but do not read a committed
  `"mode": "enforce"` as proof that every capwall invocation enforces. Use `capwall run` if
  you want the file to be the authority.
- An unrecognized `CAPWALL_MODE` (a typo) is inert rather than falling back to the file.
  `capwall run` refuses to launch in that case instead of running the target unmediated.

### Two sentinel keys

Besides real package names, `packages` accepts two sentinels:

| Key | Charged when | Notes |
|---|---|---|
| `"<app>"` | the call came from the application's own code — a real source file not under `node_modules` | the trust root; also exempt from the `process.env` and `dgram` gates, so entries here only matter for `fs`, `net`, `child_process`, `worker_threads`, `vm` |
| `"<unknown>"` | capwall could not attribute the call to any source file | e.g. a `data:` URL module, `eval`'d code with no trustworthy origin, or a native function invoked straight from a timer |

`<unknown>` is gated like any dependency — deny-by-default in `enforce` — so a legitimate
setup that produces path-less frames needs an explicit grant. Node's own ESM loader reads
`WATCH_REPORT_DEPENDENCIES` from such a stack, so most projects end up with:

```jsonc
"<unknown>": { "env": ["WATCH_REPORT_DEPENDENCIES"] }
```

`capwall observe` writes that for you. **Keep it narrow.** A broad `<unknown>` grant applies
to every call capwall cannot attribute, which includes a dependency deliberately running its
payload from a path-less frame — the fail-open that
[`threat-model.md`](threat-model.md) § attribution laundering describes. The preload prints a
warning at startup when a policy grants `<unknown>`.

Stated plainly, because it is the whole point of the sentinel: before issue #60, "capwall
could not attribute this call" and "this is the application" were the same value, so
unattributable calls silently inherited `<app>`'s exemptions from the `process.env` and
`dgram` gates. Splitting `<unknown>` out closed that. **Writing `"<unknown>": { "env": ["*"] }`
— or any comparably wide grant — re-opens it by hand**, for every call capwall cannot place.
List the observed keys instead.

A third place `<unknown>` shows up is `native`: a `.node` file that lives under neither
`node_modules` nor the project root (a temp dir, a download cache) is owned by `<unknown>`,
so `<app>`'s grants do not cover it. See § `native` below.

## `PackagePolicy`

Every field is optional; an omitted capability means **not granted**.

```jsonc
{
  "fs":  { "read": ["<glob>", ...], "write": ["<glob>", ...] },
  "net": { "hosts": ["<host-pattern>", ...], "ports": [<number> | "*", ...] },
  "ipc": { "paths": ["<socket-glob>", ...] },   // unix sockets / Windows named pipes
  "child_process": false,     // boolean gate: may this package spawn subprocesses?
  "worker_threads": false,    // boolean gate: may this package start worker threads?
  "env": ["<KEY>", "<KEY>", ...],   // allowlist of process.env keys it may read
  "vm": false,                // boolean gate: may this package use node:vm?
  "native": false             // boolean gate: may this package load a .node addon?
}
```

### `fs` — file read/write

Path globs, resolved relative to the project root. Grants are additive.

```jsonc
"fs": {
  "read":  ["./config/**", "./views/**"],
  "write": ["./logs/**"]
}
```

- `read` / `write` are evaluated independently (a read-only package gets `write: []`).
- Globs follow standard `**` / `*` semantics. A missing array means no access of that kind.
- **Note (see threat-model):** already-open fds and symlink tricks can escape path
  confinement; globs bound *ordinary* access, not a determined attacker.

### `net` — network egress

```jsonc
"net": {
  "hosts": ["api.example.com", "*.internal"],   // see the pattern table below
  "ports": [443, 3000]                          // empty/omitted = no port allowed
}
```

#### `hosts` patterns

An entry is an **exact hostname**, the single literal **`"*"`** (any host), or a **wildcard
pattern**. An empty list denies all hosts.

| entry | meaning |
|---|---|
| `api.example.com` | that host, exactly |
| `*` | any host at all, IP literals included |
| `*.internal` | exactly **one** label in front of `.internal` |
| `**.internal` | **one or more** labels in front of `.internal` |
| `api-*.internal` | `*` may sit inside a label |

The rules the table implies, spelled out because a host allowlist is worth predicting exactly:

- **`*` never crosses a dot**, the same way the `fs` matcher's `*` never crosses a `/`. So
  `*.internal` matches `api.internal` and `db.internal`, but **not** `a.b.internal` (that is
  two labels) and **not** `evil-internal` (the dot is part of the pattern). This is the
  wildcard-certificate rule from RFC 6125 — deliberately the rule you already know from TLS
  certificates and DNS, rather than a new one.
- **Neither wildcard matches the apex.** `*.internal` and `**.internal` both leave `internal`
  itself ungranted; list it separately if you mean it. (`fs`'s `dir/**` *does* match `dir`,
  because `mkdirSync("./logs")` needs it. Hostnames read right-to-left and the ergonomics do
  not transfer, so the two differ on purpose.)
- **A wildcard never matches an IP address.** `*.1.1` does not match `1.1.1.1`; an address's
  dots are not name boundaries. Patterns that look like an attempt at one — an all-numeric
  rightmost label, or any `:` — are **rejected at load time** rather than accepted and left
  never to fire. List addresses exactly.
- **Matching is case-insensitive over ASCII A–Z only.** `API.Example.com` and
  `api.example.com` are the same host, so they match interchangeably. Non-ASCII case is *not*
  folded: full Unicode folding maps distinct characters onto ASCII ones (U+212A KELVIN SIGN
  lowercases to `k`), which would let a non-ASCII host satisfy an ASCII grant.
- **No IDNA/punycode conversion.** Node's URL-based egress (`fetch`, `http.request(url)`,
  `http2.connect`) hands capwall an already-punycoded hostname, so that is what a policy must
  list — `xn--mnchen-3ya.de`, which is also what `capwall observe` records. A raw
  `net.connect({host: "münchen.de"})` is not converted by Node either, and capwall matches it
  literally. capwall matches what Node dials.
- **A malformed pattern is a load-time error**, not an entry that quietly matches nothing:
  an empty label (`*.internal.`, `*..internal`), a `**` that is not the whole first label
  (`a.**.b`, `**foo.internal`), or a wildcard inside an IP literal. This is the actual defect
  behind issue #83 — the docs advertised `"*.internal"`, the evaluator did exact equality, and
  the mismatch surfaced as unexplained `enforce` denials some distance from the policy line.
- Exact entries are **unchanged** by all of the above: a policy that only lists concrete
  hostnames matches exactly what it did before, and no previously-accepted exact entry is now
  rejected.

An IPv6 literal is written **unbracketed** — `"::1"`, not `"[::1]"` — because that is the
form Node actually dials (it strips the brackets a URL keeps on `.hostname` before handing
the address to `net`/`dns`), and therefore the form capwall observes and matches. A URL like
`http://[::1]:8080/` matches a `"::1"` host entry.

`capwall observe` always records **concrete** hostnames; wildcards are a hand-tightening step.

#### other `net` notes
- `ports` is an allowlist of numeric ports. A literal `"*"` entry grants **any** port —
  use it for a dependency that connects to a dynamically-assigned (ephemeral) port, where a
  concrete observed port would not match on the next run. `capwall observe` records concrete
  ports; add the `"*"` by hand when you know a target is dynamic.
- Covers the `net`, `http`, `https`, `tls`, `http2` and `dgram` **module** surfaces (egress), and
  Node's **global** egress APIs — `fetch`, `WebSocket` and `EventSource` (#80). Deliberately ONE
  grant for both: a dependency dialing `example.com:443` holds the same authority whether it got
  there through `http.request` or through `fetch`, and a separate capability would let a policy
  grant one and not the other by accident. A `fetch` with no explicit port is recorded at its
  scheme default (443 for `https:`/`wss:`, 80 for `http:`/`ws:`).
- **Redirects are guarded, but only after the request goes out.** `fetch` follows a 3xx inside
  Node's HTTP stack, where capwall has no hook. The final origin is evaluated and recorded, and in
  `enforce` a hop to a host the package is not granted rejects the call — but the request has
  already been sent. If a granted host may redirect elsewhere, grant the redirect target too;
  `capwall observe` records it for you. See `docs/threat-model.md` § global egress residuals.
- `data:` and `blob:` URLs are not gated at all — they resolve in-process and move no bytes.
- A unix-domain-socket / named-pipe connect has no host:port pair and is **not** a `net` grant.
  It is its own capability — see [`ipc`](#ipc--unix-sockets-and-named-pipes) below.

### `ipc` — unix sockets and named pipes

```jsonc
"ipc": {
  "paths": ["/var/run/myapp/api.sock", "./run/*.sock"]
}
```

Every IPC destination — `net.connect({path})`, `http.request({socketPath})`, `tls.connect`,
`http2` over a pipe — is gated against this list, by **socket path**. Omitted or empty means no
IPC at all.

- `paths` entries are globs, matched by the **same matcher `fs` grants use**: `*` within one
  path segment, `**` across segments, `dir/**` covering `dir` itself. Relative patterns resolve
  against the project root, exactly like `fs` globs, and Windows drive letters work the same way.
- **Windows named pipes** are supported. Write them however you like — `"\\\\.\\pipe\\myapp-*"`,
  `"//./pipe/myapp-*"` — both name the same pipe, and both match a pipe capwall observed under
  either spelling. The pipe **name** is matched case-sensitively (the same call the `fs` matcher
  makes for everything but the drive letter: a spurious deny is a smaller mistake than a
  silently widened grant — widen with `*` if you need it).
- `<tmp>` and `<home>` are **placeholders**, expanded against the machine that loads the policy
  (`os.tmpdir()`, `os.homedir()`). `capwall observe` emits them so a socket in `/tmp` on Linux CI
  and one in `/var/folders/…` on a maintainer's mac are the same grant. See § Generating a policy.
- An IPC connect whose destination capwall could not read off the call is recorded as
  `<unknown>`, which only an all-paths grant (`"*"` / `"**"`) covers. Fail-closed.

#### Backward compatibility with `<ipc>`

Before this capability existed, **every** socket and pipe was the single pseudo-target
`<ipc>:0`, granted as `"net": {"hosts": ["<ipc>"], "ports": [0]}`. That shape **still works and
still means every socket and pipe on the machine** — including the Docker socket, the systemd
journal socket and an SSH agent socket. It is honored unchanged rather than reinterpreted,
because a policy that silently becomes more restrictive on upgrade breaks a working deployment
just as surely as one that silently becomes more permissive.

It is nonetheless the coarse form, and `capwall observe` no longer emits it. **Prefer
`ipc.paths`**; treat a remaining `<ipc>` host entry as "grants all local IPC" when you review a
policy, and narrow it. A `net.hosts` wildcard (`"*.internal"`) never grants IPC — only the
literal `"<ipc>"` or `"*"` host does, and only on port `0` or `"*"`, exactly as before.

### `child_process`, `worker_threads`, `vm` — boolean gates

```jsonc
"child_process": true,
"worker_threads": false,
"vm": false
```

These are **gates**, not confinement (see threat-model § gating vs confinement): `true`
allows the package to spawn/spin-up/eval; capwall does **not** confine what the resulting
subprocess, worker, or vm context then does.

### `native` — native (`.node`) addon load gate

```jsonc
"native": true    // may this package load compiled code into the process?
```

A boolean gate on a **load-time decision**: may this package `dlopen` a native addon at all.
It is the highest-consequence grant in the format, because a native addon is not one more
capability — it is the capability that makes the others moot. Compiled code in the process has
raw libc: it opens files, opens sockets and reads the environment without touching a single
shimmed JS builtin. Granting `native` to a package means every other limit in its entry stops
being a limit *for that package*.

**capwall gates the load; it does not confine the addon.** There is no sandbox here and none
is planned — see [`threat-model.md`](threat-model.md) § Native `.node` addons.

#### Why a boolean and not a path list

`fs` grants name paths, so the obvious question is why `native` does not. Because an addon's
path is a build artifact, not a property of the package:

| how it was built | where the `.node` lives |
|---|---|
| compiled locally by `node-gyp` | `build/Release/<name>.node` |
| prebuilt, `node-gyp-build`/`prebuildify` | `prebuilds/<platform>-<arch>/<name>.node`, sometimes ABI-suffixed (`node.abi115.node`) |
| `node-pre-gyp` | `lib/binding/<napi_vN>-<platform>-<arch>/<name>.node` |

An `observe` run on a linux/x64 laptop records exactly one of those. On a maintainer's arm64
mac, or after a Node major bump changes the ABI tag, the recorded path does not exist and the
grant does not match — a policy that only enforces on the machine that generated it. That is
the same non-reproducibility that made concrete `net.ports` useless for ephemeral ports
(issue #27) and host-specific `env` keys useless across machines (issue #57), and the fix
there was a wildcard. A path list here would be a list of `"*"`s.

It would also buy no containment even if it did reproduce: a package that ships
`build/Release/a.node` can ship `b.node` in the same release. Constraining *which* file inside
a package may load only constrains a party that was never adversarial. The question worth
answering — and the only one a load-time gate can answer — is whether this package may bring
compiled code into the process at all.

The addon path is still **recorded**: `capwall observe` logs it, the trace carries it, and
`capwall diff` prints it (`native ./node_modules/foo/build/Release/foo.node`). You see which
addon loaded; you decide at package granularity.

#### Two packages are charged for one load

Almost no native package `require`s its own `.node` directly. They go through a shared
resolver — `bindings`, `node-gyp-build`, `@mapbox/node-pre-gyp` — and the first two call
`require` from *their own* source file. Under capwall's usual nearest-frame attribution the
load would be charged to the resolver, so an `observe` run would emit
`"node-gyp-build": { "native": true }`: one grant that every native package in the tree then
loads through, handed to you by the tool.

So a `.node` load is charged to **both** the caller (nearest package frame) and the addon's
**owner** — the principal the `.node` file itself belongs to:

| where the addon file is | owner |
|---|---|
| under `node_modules/<pkg>/…` | `<pkg>` |
| under the project root, outside `node_modules` (e.g. `./build/Release/`) | `<app>` — the project's own build output |
| anywhere else (a temp dir, a cache dir, a downloaded payload) | `<unknown>` — deny-by-default like any other principal |

That third row matters: charging a `.node` written to a temp dir to `<app>` would hand it the
trust root's grants, which is the same fail-open issue #60 closed for the stack walk. A stray
addon is `<unknown>`, so granting `<app>` does not cover it.

Both subjects must be granted or the load is denied. In the common case they are the same package and
there is one grant; where a resolver is involved you will see two, and `observe` emits both,
so the round-trip still needs no hand editing:

```jsonc
"packages": {
  "node-gyp-build": { "native": true },   // the resolver may perform loads
  "better-sqlite3": { "native": true }    // ...and this package's addon may be loaded
}
```

Read the resolver's grant as "this helper is allowed to be a native loader" — on its own it
unlocks nothing, because the owner still has to be granted separately.

#### A denied load throws

Unlike a denied `env` read (a soft deny returning `undefined`), a denied `.node` load throws
`CapabilityError` synchronously, matching the other boolean gates and matching real Node,
which also throws synchronously when `dlopen` fails. The resolver wrappers `require` inside a
`try`/`catch`, so they see a denial as "this candidate did not load" and move on to the next
one — but a package with no fallback will fail to initialize, and that usually means the app
crashes at startup. That is the intended failure mode: handing back an addon-less module
object would turn a policy gap into a mysterious error far from its cause. Run `observe` until
coverage is stable before flipping to `enforce`.

**Upgrading an existing policy.** `native` is deny-by-default like every other capability, and
a `capabilities.json` generated before it existed contains no `native` entries — so a tree with
native dependencies (`bcrypt`, `better-sqlite3`, `sharp`, `esbuild`…) that enforced cleanly
before will start failing at startup. Re-run `capwall observe`, or `capwall diff`, to see which
packages need the grant before flipping back to `enforce`. This is the same upgrade step every
new capability has required (compare the `env` shim landing in M4 — issue #57).

### `env` — environment-variable read allowlist

```jsonc
"env": ["NODE_ENV", "PORT"]   // or ["*"] to allow all keys (discouraged)
```

An allowlist of `process.env` keys the package may read. This is the anti-exfiltration
control: a package with `"env": ["NODE_ENV"]` reading `AWS_SECRET_ACCESS_KEY` is a violation.

Scope, precisely:

- **Reads only.** `env` grants nothing about writes; `process.env.K = v`, `delete process.env.K`
  and `Object.defineProperty(process.env, …)` are unmediated for every package (see
  [threat-model](./threat-model.md) for why, and the residual it leaves).
- **Values only, not names.** A denied read is a *soft deny*: the value comes back `undefined`
  rather than throwing, so a dependency probing an optional var is not crashed. Key **names**
  stay visible — `"K" in process.env`, `Object.keys(process.env)`, `for..in` and
  `Object.getOwnPropertyNames` are ungated, and are **not** recorded in `observe` either. Only
  operations that actually yield a value (`process.env.K`, `JSON.stringify(process.env)`,
  `{...process.env}`, `Object.entries`) are gated and recorded. That is why a package that
  enumerates the environment — `debug` does — generates a policy listing only the keys it really
  reads, and that policy is the same on every machine (#67).

Matching is **exact string equality**, or the single literal `"*"`. There are no prefix or
glob forms — `"DEBUG_*"` matches a key literally named `DEBUG_*`, nothing else. (`fs.read`/
`fs.write`, `net.hosts` and `ipc.paths` *do* glob; `env` does not. An environment variable name
is not a hierarchy, so there is no separator for a wildcard to respect and no shape of grant a
prefix would express safely.)

A denied env read is still logged and still shows up in `capwall diff`. See
`docs/threat-model.md`.

#### When `["*"]` is the right call — and what it costs

`["*"]` grants a package **every** environment variable, including ones that do not exist
yet. Read that as: *this package may read every secret this process is ever given.* `env` is
the primary exfiltration surface for the token-theft worms capwall exists to slow down
(Shai-Hulud reads `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*` straight out of `process.env`), so a
`"*"` grant is the single largest capability you can hand a dependency in this format. Treat
it the way you would treat `"net": { "hosts": ["*"] }` — occasionally correct, never casual.

**Try these first, in order:**

1. **List the concrete keys.** Most packages read a handful (`NODE_ENV`, `NO_DEPRECATION`).
   `capwall observe` records them for you; keep the ones that come from the package's own
   source, drop the rest.
2. **Check whether the keys are actually stable.** Re-run `observe` in a different shell
   (`env -i PATH=$PATH HOME=$HOME …`) and diff the two policies. Keys that appear in both
   are the package's real needs; keys that appear in only one are your host leaking in.
3. **Ask whether the package belongs in the production tree at all.** A dependency that
   needs unrestricted env access is a dependency you are choosing to trust completely. Moving
   it to `devDependencies`, or dropping it, is a stronger control than any policy entry.

**Reach for `["*"]` only when the key set is not a property of the package's code.** Note
that *enumeration is no longer such a case*. A package that does

```js
Object.keys(process.env).filter((key) => /^debug_/i.test(key))
```

used to be recorded as reading *every variable present on the machine* — `SSH_AUTH_SOCK` on a
laptop, `GITHUB_TOKEN` in CI — because the enumeration was mediated key-by-key, and no finite
list was correct on the next machine. That was a shim limitation, and it is fixed (issue #67):
enumerating key *names* is not a value read, so only the keys a package really reads are
recorded and the generated list is the same on every machine.
[`../examples/express-app/README.md`](../examples/express-app/README.md) walks the case that
motivated it — `debug`, which went from a bare `"*"` back to five concrete keys.

What is left in this category is a package whose key set genuinely varies at runtime — one
that derives variable names from user input or from a remote config. If you cannot point at
the lines of the package's own source that name the keys, `"*"` may be the honest answer.

**What you give up, stated plainly:** capwall stops reporting env drift for that package
forever. If a future version of it starts reading `AWS_SECRET_ACCESS_KEY`, `capwall diff`
will not flag it and `capwall enforce` will not deny it — the grant already covers keys that
did not exist when you wrote it. You keep the package's `fs`, `net`, `child_process` and
`worker_threads` limits, which is what still makes reading a secret hard to *act on*: with
`"net": { "hosts": [] }` the package can see a token but has nowhere to send it. That
containment is the reason a `"*"` env grant is survivable, not a reason it is free.

**Scope it narrowly.** Put `["*"]` on the one package that needs it, never in `default` —
a `default` of `{ "env": ["*"] }` silently grants it to every unlisted package, which is the
opposite of deny-by-default. Because `capabilities.json` is strict JSON with no comment
field, record *why* in the project's README or policy review notes; a bare `"*"` in a diff is
indistinguishable from a careless one.

## Worked example

```jsonc
{
  "version": 1,
  "mode": "enforce",
  "default": {
    "fs": { "read": [], "write": [] },
    "net": { "hosts": [], "ports": [] },
    "ipc": { "paths": [] },
    "child_process": false,
    "worker_threads": false,
    "env": [],
    "vm": false,
    "native": false
  },
  "packages": {
    "express": {
      "net": { "hosts": ["*"], "ports": [3000, 8080] },
      "fs":  { "read": ["./views/**", "./public/**"], "write": [] },
      "env": ["NODE_ENV", "PORT"]
    },
    "pino": {
      "fs":  { "read": [], "write": ["./logs/**"] },
      "env": ["NODE_ENV"]
    },
    "internal-client": {
      "net": { "hosts": ["*.internal"], "ports": [443] },
      "ipc": { "paths": ["/var/run/myapp/api.sock"] }
    }
  }
}
```

Here every package other than `express` and `pino` inherits `default` (nothing). `pino` may
write logs but not read arbitrary files or reach the network; `express` may serve on two
ports and read its view/static dirs. See [`../capabilities.example.json`](../capabilities.example.json)
for the committed example.

## Generating a policy

Do not hand-write from scratch. Run `capwall observe -- <your start command>` to emit a
starter `capabilities.json` scoped to what each package actually did, then **tighten** it (in
particular, narrow `"*"` hosts and remove capabilities that only appeared in incidental code
paths). Re-running `observe` merges into the existing file rather than overwriting it.

The output of `observe` is a **starting point, not the answer.** It records what happened on
*your* machine in *that* run, and two categories of entry will not reproduce elsewhere:

- **Ephemeral values** — a dynamically-assigned port, or an env key that only exists in your
  shell. Replace them with `"*"` (see `net.ports` above and `env` above) or delete them.
- **Incidental code paths** — a capability used once during a code path you happened to
  exercise. Keep it only if it is a real requirement.

Socket paths (`ipc.paths`) get a little help with this. `observe` writes one of three shapes,
most portable first: a `./relative` path when the socket is inside the project root; `<tmp>/…`
or `<home>/…` when it is under the temp or home directory (expanded per-machine at load time);
otherwise the literal path. What it will **not** do is guess which segment of
`/tmp/app-a91f3/api.sock` is random — capwall cannot know, and quietly emitting a wider grant
than the run actually justified is precisely what you are reading this file to catch. Widen
volatile segments yourself with `*` (a `/run/user/<uid>/…` socket is the other common case).

Host names (`net.hosts`) are recorded concretely; if a dependency legitimately talks to a whole
internal domain, replace the observed hosts with `"*.internal"` / `"**.internal"` by hand rather
than reaching for `"*"`.

Because the merge is additive, a re-run will happily append fresh host-specific noise on top
of grants you deliberately widened (a `"*"` env grant does not stop concrete keys from being
merged in beside it). When you have a reviewed policy you want to keep, observe into a
scratch file and diff by hand:

```bash
capwall observe -o /tmp/observed.json -- node src/server.js
diff <(jq -S . capabilities.json) <(jq -S . /tmp/observed.json)
```

Once the policy is committed, `capwall diff -- <your start command>` is the ongoing check: it
exits non-zero when a run uses a capability the committed policy does not grant. Wiring that
into CI is what keeps a policy from silently going stale as dependencies change (this repo
gates `examples/express-app` that way — `packages/cli/test/express-app-policy.test.ts`).
