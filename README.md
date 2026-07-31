# capwall

**A runtime, per-package capability firewall for Node.js.** Record what each dependency
actually does, review it, then enforce it — so a compromised package cannot quietly start
reading your credentials.

---

## The problem

Your date-formatting library can read `~/.aws/credentials` and POST it to an attacker's
server. So can your colour-string helper, your CLI-spinner package, and every transitive
dependency you have never heard of that came in behind them. Node gives every package in
`node_modules` the same authority your application has: the whole filesystem, every socket,
every environment variable, arbitrary subprocesses. There is no notion of *"this package was
only ever supposed to parse dates."*

That is not hypothetical any more. Worms like **Shai-Hulud** (Nov 2025) and **Glassworm**
(2026) run their payload at **application runtime**, not just in an install script — which is
the phase lockfile pinning, `--ignore-scripts` and registry scanners never see. By the time
the payload runs, the interesting damage (credential exfiltration, wallet theft, lateral
movement) is a plain `fs.readFileSync` and a plain `fetch`.

capwall sits inside the running process, attributes every capability-sensitive call to the
**package that made it**, and checks it against that package's policy. A logging library that
suddenly opens a socket, or a string helper that reads `process.env`, is a policy violation —
logged in `observe` mode, denied in `enforce` mode.

## The loop

You do not write the policy. You **record** it, read it, and commit it.

```bash
# 1. OBSERVE — run your app or test suite. Nothing is blocked. capwall records what
#    every package actually did and writes a starter policy.
capwall observe -- node ./src/server.js
#   → [capwall] observed 6 capability event(s) across 4 package(s); wrote capabilities.json
#   → [capwall] review/tighten it, then run: capwall enforce -- node ./src/server.js

# 2. REVIEW — open capabilities.json. It is short, and it is the point (see below).
#    Delete anything a dependency has no business doing.

# 3. COMMIT it. It is now a reviewed artifact in your repo, like a lockfile.

# 4. ENFORCE — anything not in the policy is denied by default and throws.
capwall enforce -- node ./src/server.js

# 5. KEEP IT HONEST IN CI — re-observe and fail the build if a dependency started
#    using a capability it never used before. Exit 0 = no drift, 1 = drift.
capwall diff -- node ./src/server.js
```

### The artifact

This is a real `capabilities.json`, emitted by step 1 against
[`examples/express-app`](./examples/express-app) — an Express 5 server that appends to a log
file and reads a little environment (line-wrapped here for width):

```json
{
  "version": 1,
  "mode": "observe",
  "default": {},
  "packages": {
    "<app>": {
      "fs": { "read": [], "write": ["./logs", "./logs/requests.log"] }
    },
    "debug": { "env": ["DEBUG"] },
    "depd": { "env": ["NO_DEPRECATION", "TRACE_DEPRECATION"] },
    "express": { "env": ["NODE_ENV"] }
  }
}
```

Four entries. That is the whole authority the process needs, written down where a human can
read it in ten seconds — and a diff will show you the day it changes. Every omitted field is a
denial: `express` may read one environment variable and *nothing else* — no files, no sockets,
no subprocesses. `<app>` is your own code, the trust root; a key like `webpack>lodash` names
the copy of `lodash` installed under `webpack`, which is a different principal from the
top-level `lodash` ([`docs/policy-format.md`](./docs/policy-format.md) § Package keys).

Then you set `"mode": "enforce"` and commit. `capwall run` takes the mode from the file, so
promoting a project from observe to enforce is a one-word diff in a reviewed artifact rather
than a change to how CI invokes the tool.

### What enforcement looks like

[`examples/malicious-dep-demo`](./examples/malicious-dep-demo) vendors an inert fixture
dependency that behaves like a Shai-Hulud-class payload — it reads
`process.env.AWS_SECRET_ACCESS_KEY` and a credentials file. Under a policy that grants it
nothing:

```
$ capwall enforce -- node src/index.js
[capwall] enforce: DENY 'sneaky-dep' env:AWS_SECRET_ACCESS_KEY (not in policy; deny-by-default)
[sneaky-dep] read process.env.AWS_SECRET_ACCESS_KEY => undefined (INERT)
[capwall] enforce: DENY 'sneaky-dep' fs:read .../sneaky-dep/fake-secret.txt (not in policy; deny-by-default)
[demo] BLOCKED by capwall: enforce: DENY 'sneaky-dep' fs:read ... (not in policy; deny-by-default)
$ echo $?
1
```

(Paths abbreviated; capwall prints them absolute.)

The env read is **soft-denied** — capwall returns `undefined`, so the value is never revealed,
without crashing the caller. The file read is **hard-denied**: it throws before any bytes are
read. Both are logged.

And in CI, `capwall diff` names the drift and exits non-zero:

```
[capwall] diff: DRIFT — 2 observed capability event(s) not granted by capabilities.json
  sneaky-dep  env AWS_SECRET_ACCESS_KEY (not granted)
  sneaky-dep  fs:read .../sneaky-dep/fake-secret.txt (not granted)
```

---

## Install

```bash
npm i -D @capwall/cli          # or: pnpm add -D @capwall/cli
npx capwall observe -- node your-app.js
```

That is the whole install. Everything above runs against it.

### Or from a clone

Requirements: **Node ≥ 22.15** (tested on 22, 24 and 26) and **pnpm ≥ 11** — required, not a
preference. capwall is a pnpm workspace with no npm `workspaces` field, so `npm install` at the
clone root would succeed while linking none of the four packages; a root `preinstall` guard
refuses it with an explanation.

```bash
corepack enable                                # provides the pnpm this repo pins
git clone https://github.com/capwall/capwall.git ~/src/capwall
cd ~/src/capwall && pnpm install && pnpm build

# The CLI is then ~/src/capwall/packages/cli/dist/index.js. Run it by path, or alias it:
alias capwall='node ~/src/capwall/packages/cli/dist/index.js'
```

Then `cd` back to **your** project — capwall treats its own working directory as the project
root. Full command reference, flags and exit codes: [`docs/cli.md`](./docs/cli.md).

---

## Honest scope — read this before you rely on it

capwall is **pragmatic defense-in-depth, not a formal sandbox.** Overclaiming here would be a
security bug, so:

**A determined in-process attacker can defeat it.** Without SES's frozen primordials,
prototype pollution, fd/symlink escapes, un-patching the shims, `node:sqlite`/`vm`/`eval`,
native `.node` addons and spawned-subprocess internals are all available. The sharpest form:
capwall decides **who is calling** by asking V8 for the stack, so replacing
`Error.captureStackTrace` — one line, self-restoring, and **not** mitigated by hardened mode —
lets a caller mint any principal in the policy. Every gate is a decision about a principal, so
that one assumption bounds all of them. capwall's job is to stop **opportunistic, worm-style
supply-chain malware** that runs at application runtime and does not go out of its way to break
out of a capability shim.

**Gated is not confined.** Native addons and subprocesses can be gated (*whether* they run) but
not confined (*what they do* once running). A `"native": true` grant is a load-time decision
with no confinement whatsoever — compiled code in the process reaches files, sockets and the
environment without touching a shimmed JS builtin. Read it as trusting that package completely.

**Package identity is a position in the dependency tree, not a verified fact.** A principal is
where a frame's file sits: `lodash` for the top-level install, `webpack>lodash` for the copy
nested under `webpack`. That stops one package impersonating another's *position*, but capwall
does not verify what is installed at a position — a typosquat, a compromised publish, or
anything that can write into `node_modules` still answers to that name. The `compile` and `vm`
grants are identity-granting in the same spirit: a package holding either can execute as any
principal in the policy.

**Global egress is covered, with named residuals.** `globalThis.fetch`, `WebSocket` and
`EventSource` never route through a module load, so they are replaced on `globalThis` and
checked against the same `net` grant as `http.request`. Four things that guard does not do: a
redirect hop is guarded only *after* the request has gone out (undici follows it internally);
`init.dispatcher` lets a caller supply the code that opens the socket; a dependency that
captured `fetch` before capwall installed holds the raw function; and the replaced global stays
writable unless hardened mode is on — and even then `Object.defineProperty(globalThis, "fetch",
…)` is open, the unavoidable price of a global `uninstall()` can put back.

The full accounting — every residual, and the comparison to the SES and Node-permission threat
models — is [`docs/threat-model.md`](./docs/threat-model.md). Read it before relying on capwall
for anything.

---

## What capwall mediates

Nine capability kinds, per package, on both the CJS `require` and the ESM `import` paths:
**`fs`** (including a `require`/`import` of a file outside every `node_modules` tree), **`net`**
(`net`/`http`/`https`/`tls`/`http2`/`dgram` *and* global `fetch`/`WebSocket`/`EventSource`),
**`ipc`** (unix sockets and named pipes), **`env`** (`process.env` reads), **`child_process`**,
**`worker_threads`**, **`vm`**, **`native`** (`.node` addon loads) and **`compile`**. On Node ≥26
behind `--localstorage-file`, `localStorage` takes an `fs` decision on its backing file — no new
capability kind, because the API a package used to reach a file is not a separate authority.
Field-by-field: [`docs/policy-format.md`](./docs/policy-format.md).

Each of the six egress modules is shimmed **separately**; one never covers another, and that is
a security property rather than a style choice ([`docs/architecture.md`](./docs/architecture.md)
§ Capability shims).

## How it compares

| Tool | Boundary / mechanism | Granularity | Runtime enforcement | SES / primordial tax |
|---|---|---|---|---|
| **capwall** | module-load + core-API shims (non-SES, out-of-band) | **per-package** | **yes** (observe → enforce) | **no** |
| **LavaMoat** | SES compartments, hardened primordials | per-package | yes | **yes** |
| **Node `--permission`** | process-level flag | **process-global** | yes | no |
| **Socket Firewall / socket.dev** | install-time + registry signals | per-package (install) | mostly install-time | no |
| **guarddog (Datadog)** | static/heuristic package scanner | per-package (scan) | **no** | no |

The scanners *detect* a bad package before it lands; capwall assumes one got through. Against
Node's [`--permission`](https://nodejs.org/api/permissions.html) the difference is granularity:
*express* and *some-transitive-dep-you've-never-heard-of* get different capability sets in the
same process. Against LavaMoat it is adoption cost — capwall intercepts at the module-load and
core-API boundary instead of hardening every primordial, trading isolation strength for
near-zero friction.

The mechanism is not novel; the ergonomics are. KTH-LangSec's **NodeShield** prototype (CCS
2025, ["Runtime Enforcement of Security-Enhanced SBOMs for
Node.js"](https://doi.org/10.1145/3719027.3765136)) demonstrated per-package enforcement that is
non-SES, out-of-band and "vanilla Node compatible" — but it is a dead single-commit prototype
with no DX. The observe→review→enforce loop is what capwall adds.

---

## Documentation

| | |
|---|---|
| [`docs/cli.md`](./docs/cli.md) | every command, flag and exit code |
| [`docs/policy-format.md`](./docs/policy-format.md) | `capabilities.json` field by field; package keys; mode precedence |
| [`docs/threat-model.md`](./docs/threat-model.md) | what the mediation is and is not worth — every residual, named |
| [`docs/architecture.md`](./docs/architecture.md) | interception, attribution, the patch lifecycle |
| [`docs/node-api-dependencies.md`](./docs/node-api-dependencies.md) | the unsupported Node internals capwall rests on, measured per major |
| [`docs/ci-local.md`](./docs/ci-local.md) | reproducing the CI matrix locally; drift detection in CI |
| [`docs/roadmap.md`](./docs/roadmap.md) | build order, and the one place milestone status is tracked |
| [`docs/releasing.md`](./docs/releasing.md) | the publish runbook, and what is (and is not) in the release |
| [`SECURITY.md`](./SECURITY.md) | how to report a bypass **privately**, what is in scope, and which residuals are already documented |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | pnpm is required, `pnpm ci:local` is the gate, and commit messages write the changelog |
| [`packages/core/README.md`](./packages/core/README.md) | the `install()` API, hardened mode, and the complete `CAPWALL_*` table |
| [`scripts/bench/README.md`](./scripts/bench/README.md) | the performance numbers, and where the per-call budget does not hold |

Four packages: `@capwall/core` (interception engine + policy evaluator), `@capwall/cli` (the
`capwall` command), `@capwall/policy-schema` (the schema, TS types and `schema.json`) and
`@capwall/sbom-import` (CycloneDX/CBOM → starter policy). Two runnable fixtures:
[`examples/express-app`](./examples/express-app) and
[`examples/malicious-dep-demo`](./examples/malicious-dep-demo).

## License

[MIT](./LICENSE) © 2026 William Zujkowski.

capwall deliberately avoids non-compete / source-available (e.g. PolyForm) code so it stays
freely adoptable. See [`AGENTS.md`](./AGENTS.md) § Conventions.
