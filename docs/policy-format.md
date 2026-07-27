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

## `PackagePolicy`

Every field is optional; an omitted capability means **not granted**.

```jsonc
{
  "fs":  { "read": ["<glob>", ...], "write": ["<glob>", ...] },
  "net": { "hosts": ["<host|glob>", ...], "ports": [<number>, ...] },
  "child_process": false,     // boolean gate: may this package spawn subprocesses?
  "worker_threads": false,    // boolean gate: may this package start worker threads?
  "env": ["<KEY>", "<KEY>", ...],   // allowlist of process.env keys it may read
  "vm": false                 // boolean gate: may this package use node:vm?
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
  "hosts": ["api.example.com", "*.internal", "*"],  // "*" = any host
  "ports": [443, 3000]                              // empty/omitted = no port allowed
}
```

- `hosts` matches hostnames (glob `*` supported); an empty list denies all hosts.
- An IPv6 literal is written **unbracketed** — `"::1"`, not `"[::1]"` — because that is the
  form Node actually dials (it strips the brackets a URL keeps on `.hostname` before handing
  the address to `net`/`dns`), and therefore the form capwall observes and matches. A URL like
  `http://[::1]:8080/` matches a `"::1"` host entry.
- A unix-domain-socket / named-pipe connect (`net.connect({path})`, `http.request({socketPath})`,
  `http2` over a pipe) has no host:port pair and is recorded coarsely as the pseudo-target
  `<ipc>` on port `0`. Granting `{"hosts": ["<ipc>"], "ports": [0]}` therefore grants **every**
  local socket, not one — see the IPC note in `docs/threat-model.md`.
- `ports` is an allowlist of numeric ports. A literal `"*"` entry grants **any** port —
  use it for a dependency that connects to a dynamically-assigned (ephemeral) port, where a
  concrete observed port would not match on the next run. `capwall observe` records concrete
  ports; add the `"*"` by hand when you know a target is dynamic.
- Covers `net`, `http`, `https`, `tls`, `http2`, and `dgram` (egress).

### `child_process`, `worker_threads`, `vm` — boolean gates

```jsonc
"child_process": true,
"worker_threads": false,
"vm": false
```

These are **gates**, not confinement (see threat-model § gating vs confinement): `true`
allows the package to spawn/spin-up/eval; capwall does **not** confine what the resulting
subprocess, worker, or vm context then does.

### `env` — environment-variable read allowlist

```jsonc
"env": ["NODE_ENV", "PORT"]   // or ["*"] to allow all keys (discouraged)
```

An allowlist of `process.env` keys the package may read. This is the anti-exfiltration
control: a package with `"env": ["NODE_ENV"]` reading `AWS_SECRET_ACCESS_KEY` is a violation.

Matching is **exact string equality**, or the single literal `"*"`. There are no prefix or
glob forms — `"DEBUG_*"` matches a key literally named `DEBUG_*`, nothing else.

A denied env read is a **soft deny**: the value comes back `undefined` rather than throwing,
so a dependency probing an optional variable degrades instead of crashing. The denial is
still logged and still shows up in `capwall diff`. See `docs/threat-model.md`.

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

**Reach for `["*"]` only when the key set is not a property of the package's code.** The
concrete case in this repo is `debug` (pulled in transitively by `express`), which does:

```js
Object.keys(process.env).filter((key) => /^debug_/i.test(key))
```

That enumeration is mediated key-by-key, so `debug` is recorded as reading *every variable
present on the machine* — `SSH_AUTH_SOCK` on a laptop, `GITHUB_TOKEN` in CI, `PYENV_ROOT`
wherever. No finite list is correct on the next machine, which makes a key-by-key grant
non-reproducible in exactly the way ephemeral ports were for `net.ports` (issue #27). See
[`../examples/express-app/README.md`](../examples/express-app/README.md) for the worked case.
(That enumeration is recorded as a value read at all is arguably a shim limitation rather
than a fact of life — issue #67. If it changes, packages that only *enumerate* will stop
needing `"*"`, and these grants should be narrowed again.)

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
    "child_process": false,
    "worker_threads": false,
    "env": [],
    "vm": false
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
