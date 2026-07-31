# capwall CLI reference

`@capwall/cli` is the primary way to drive the observe→enforce loop. Six commands, all of which
run your target in a **child process** with `@capwall/core/preload` injected through
`NODE_OPTIONS=--import`, so capwall installs before the target's entry point and before any
dependency can capture a raw builtin.

> Install with `npm i -D @capwall/cli` — see the root [README](../README.md) § Install. To run
> it from a clone instead: `node <clone>/packages/cli/dist/index.js …` after
> `pnpm install && pnpm build`, or alias it.

The **project root is the CLI's working directory** — relative policy globs and dependency-vs-app
attribution are resolved against it.

## Commands

```
capwall observe   -- <cmd...>   run <cmd> in observe mode; record every capability and
                                emit/merge a starter capabilities.json (nothing is blocked)
capwall enforce   -- <cmd...>   run <cmd> in enforce mode; deny-by-default, throw on any
                                capability not in the policy
capwall run       -- <cmd...>   run <cmd> in the mode the policy file itself declares
capwall diff      -- <cmd...>   observe <cmd>, then report drift against the committed policy
capwall gen-policy --from <trace.jsonl> [-o <file>]
                                (re)generate a policy from a prior observe trace
capwall explain <package> <capability> [target]
                                explain why a tuple would be allowed or denied
capwall --version               print the CLI version AND the @capwall/core version it injects
```

`capwall <command> --help` prints the same detail per command.

### `observe` — the on-ramp

```
capwall observe [-o <capabilities.json>] -- <command...>
```

Runs the command with capwall in observe mode: every capability-sensitive call is attributed and
logged, **nothing is blocked**, and on exit the observed set is merged into the policy file
(default `./capabilities.json`). Re-runs **merge**, they do not overwrite — so you can build a
policy up across several runs (unit tests, integration tests, a manual exercise of the app).

Output on exit names the counts and the file, and differs on whether the file already existed:

```
[capwall] observed 6 capability event(s) across 4 package(s); wrote capabilities.json
[capwall] review/tighten it, then run: capwall enforce -- node src/server.js
```

A generated policy is a **draft, not a shippable artifact.** Its `env` entries in particular are
host-specific: a package that merely enumerates `process.env` is recorded as reading every key
the machine has. Review before committing — that is step 2 of the loop, not a departure from it.

### `enforce`

```
capwall enforce [--policy <capabilities.json>] -- <command...>
```

Deny-by-default against the policy file (default `./capabilities.json`). Absence of an entry is a
denial. Most denials throw a `CapabilityError` before the operation happens; `process.env` reads
are **soft-denied** — the read returns `undefined`, so the value is never revealed to the
dependency, without crashing it. Every decision is logged either way.

Enforce with no policy file denies everything, which is a valid but rarely useful configuration.

### `run` — let the committed file decide

```
capwall run [--policy <capabilities.json>] -- <command...>
```

Runs in the mode the policy document's own `"mode"` field declares, rather than one named on the
command line, so promoting a project from observe to enforce is a one-word diff in a reviewed
file. **Refuses if the policy declares no mode.** An explicit `CAPWALL_MODE` in the environment
still overrides it.

### `diff` — the CI-facing command

```
capwall diff [--policy <capabilities.json>] [--strict] [--json] -- <command...>
```

Runs the command in observe mode, then diffs what it actually did against the committed policy.
Drift is reported in **both directions**:

- **observed-but-not-granted** — a dependency using a capability the policy does not grant. This
  is the one that catches a compromised dependency that started doing something new.
- **declared-but-never-matched** — a `packages` key that names no principal that ran, so the
  grant does nothing. Usually a typo in the `outer>inner` chain grammar.

| flag | effect |
|---|---|
| `--policy`, `-p <file>` | policy to diff against (default `./capabilities.json`) |
| `--strict` | **also** exit 1 when a policy key matched no package in this run |
| `--json` | emit the drift as a single compact JSON array of `{pkg, kind, detail}` |

Exit codes: **0** = no drift, **1** = drift found, **2** = usage error or missing policy file.

`--json` writes its array as the **last** line of stdout — the target's own stdout is inherited
and may precede it, so parse the last line. Unmatched keys are reported on stderr in every mode;
the array is the stable, documented contract.

Example, against a dependency granted nothing:

```
[capwall] diff: DRIFT — 2 observed capability event(s) not granted by capabilities.json
  sneaky-dep  env AWS_SECRET_ACCESS_KEY (not granted)
  sneaky-dep  fs:read .../sneaky-dep/fake-secret.txt (not granted)
```

See [`ci-local.md`](./ci-local.md) § Drift detection in CI for wiring it into a pipeline.

### `gen-policy`

```
capwall gen-policy --from <trace.jsonl> [-o <capabilities.json>]
```

Aggregates a capwall observe trace (the JSONL written to `CAPWALL_TRACE_FILE`) into a policy
file, merging with the existing file if present. `observe` does this for you at exit; this
command is for the case where you captured a trace separately, or want to re-aggregate one.

### `explain`

```
capwall explain [--policy <file>] <package> <capability> [target]
```

Answers why a `(package, capability, target)` tuple would be allowed or denied under the current
policy — without running anything.

```
capwall explain pino fs:write ./logs/app.log
capwall explain some-dep ipc /var/run/docker.sock
capwall explain express net localhost:3000
capwall explain sneaky-dep env AWS_SECRET_ACCESS_KEY
capwall explain better-sqlite3 native
capwall explain webpack>lodash fs:read ./package.json
capwall explain ts-node compile
```

Capabilities and their targets: `fs:read <path>`, `fs:write <path>`, `net <host:port>`,
`ipc <socket-path>`, `env <KEY>`, `child_process`, `worker_threads`, `vm`,
`native [addon-path]`, `compile [filename]`.

`native` and `compile` grants are **booleans**, so their optional targets are echoed in the
answer for readability only and do not change the verdict.

`<package>` is the principal attribution reports, which for a package installed under another is
its **install chain** — `webpack>lodash`, not `lodash` (see
[`policy-format.md`](./policy-format.md) § Package keys are install positions).

**Two things `explain` cannot tell you.** It takes `<package>` literally and cannot know whether
any code actually runs as that principal — it says so in a note on every answer. And it evaluates
the **policy document**, not the gates, so it does **not** model the five `<app>` exemptions:
`capwall explain "<app>" compile` answers `DENY` and exits 1, while `<app>` in fact holds
`compile` at runtime without a grant. For `<app>`, read the answer as "what the policy says"
rather than "what will happen".

### `--version`

```
capwall 0.1.0
@capwall/core 0.1.0 (injected into the target process)
```

Two versions because they are two questions: the CLI runs your target in a **child** process with
core preloaded via `NODE_OPTIONS`, so "which core actually enforced this" is not answered by
"which capwall did I type".

## Common flags

| flag | commands |
|---|---|
| `-p`, `--policy <path>` | `enforce`, `run`, `diff`, `explain` |
| `-o`, `--out <path>` | `observe`, `gen-policy` |

Both default to `./capabilities.json`.

## Which command sets the mode

`observe`, `enforce` and `diff` name the mode themselves — they set `CAPWALL_MODE`, which
outranks everything. `run` takes it from the policy document. The full precedence table is in
[`policy-format.md` § Enforcement mode](./policy-format.md#enforcement-mode).

## Generated policies point at the schema

`observe` and `gen-policy` write a `"$schema"` key into a policy they create, so the file you are
then told to hand-edit gets editor validation and completion — which is where it pays for itself,
given the `outer>inner` package-key grammar. The pointer is
`./node_modules/@capwall/policy-schema/schema.json`, and it is written **only when that path
actually exists**: a dangling `$schema` shows up as a diagnostic on line 2 of a file capwall just
wrote, which is worse than none. An existing `$schema` is never rewritten.

## Configuring the injected core

The CLI configures the child process entirely through `CAPWALL_*` environment variables, because
that is the only channel a `--import` entry has. It sets the mode, policy path, trace path and
project root for you; the remaining switches — `CAPWALL_ESM`, `CAPWALL_ENV`,
`CAPWALL_GLOBAL_EGRESS`, `CAPWALL_MAX_FRAMES`, `CAPWALL_HARDENED`,
`CAPWALL_ALLOW_LOADER_HOOKS` — are yours to set, and pass straight through:

```bash
CAPWALL_HARDENED=1 capwall enforce -- node ./src/server.js
```

The complete table, with defaults and what each one weakens, is in
[`../packages/core/README.md`](../packages/core/README.md) § Environment variables. It is not
restated here on purpose: `packages/core/src/preload.ts`'s header is the authority, and
`packages/core/test/capwall-env-table.test.ts` holds exactly one prose copy of it in step with
the source. A third copy would be a third thing to drift.
