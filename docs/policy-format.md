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
  "mode": "enforce",          // default mode: "observe" | "enforce" (CLI flag overrides)
  "default": { /* PackagePolicy applied to any package with no explicit entry */ },
  "packages": {
    "<package-name>": { /* PackagePolicy */ }
  }
}
```

- **Deny-by-default.** In `enforce` mode, a package with no entry falls back to `default`;
  the recommended `default` grants nothing (see `capabilities.example.json`).
- `mode` in the file is the default; the CLI (`capwall observe|enforce`) overrides it.

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
