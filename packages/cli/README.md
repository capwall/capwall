# @capwall/cli

The `capwall` command-line interface — the primary way users drive the observe→enforce loop.

> **Status:** all **six** commands are implemented and work for every capability, on both the
> CJS `require` and the ESM `import` paths. `observe`/`enforce`/`run`/`diff` launch the target
> with `@capwall/core/preload` injected via `NODE_OPTIONS --import`. Milestone status is
> tracked in one place, [`docs/roadmap.md`](https://github.com/capwall/capwall/blob/main/docs/roadmap.md).
>
> ```bash
> npm i -D @capwall/cli      # or: pnpm add -D @capwall/cli
> npx capwall observe -- node your-app.js
> ```
>
> Requires **Node ≥ 22.15** (tested on 22, 24 and 26). See the root
> [README](https://github.com/capwall/capwall#readme) for the full observe → review →
> enforce loop.

## Commands

```
capwall observe   -- <cmd...>   Run <cmd> with capwall in observe mode; record every
                                capability and emit/merge a starter capabilities.json.
                                (Nothing is blocked.) — HEADLINE feature.

capwall enforce   -- <cmd...>   Run <cmd> with capwall in enforce mode; deny-by-default,
                                throw on any capability not in the policy.

capwall run       -- <cmd...>   Run <cmd> in the mode the policy file itself declares (its
                                "mode" field). Refuses if the policy declares none.

capwall diff      -- <cmd...>   Observe <cmd>, then report capabilities the committed policy
                                would DENY in enforce mode (CI drift check).

capwall gen-policy [--from <trace>] [-o capabilities.json]
                                (Re)generate a policy from a prior observe trace.

capwall explain <package> <capability> [target]
                                Explain why a (package, capability, target) tuple would be
                                allowed or denied under the current policy.

capwall --version               Print this CLI's version AND the @capwall/core version it
                (-V, -v)        would inject. Those are two questions: the CLI runs the
                                target in a CHILD process with core preloaded via
                                NODE_OPTIONS, so "which core actually enforced this" is not
                                answered by "which capwall did I type".
```

Common flags: `-p, --policy <path>` for `enforce`/`run`/`diff`/`explain` and `-o, --out <path>`
for `observe`/`gen-policy` (both default to `./capabilities.json`). `diff` also takes
`--json`, which writes the drift as a compact JSON array of `{pkg, kind, detail}` as the
**last** line of stdout (the target's own stdout is inherited and may precede it), and
`--strict`, which additionally exits 1 when a policy key matched no package in this run. The
project root is the CLI's working directory.

`diff` is the CI-facing command: exit **0** = no drift, **1** = drift found, **2** = usage
error or missing policy file. It reports drift in **both** directions (#118) —
observed-but-not-granted, and declared-but-never-matched. See [`docs/ci-local.md` § Drift
detection in CI](https://github.com/capwall/capwall/blob/main/docs/ci-local.md).

**The full reference — every flag, exit code and `explain` capability spelling — is
[`docs/cli.md`](https://github.com/capwall/capwall/blob/main/docs/cli.md).** This README is the orientation.

`observe`, `enforce` and `diff` name the mode themselves (they set `CAPWALL_MODE`, which
outranks everything); `run` takes it from the policy document. Full precedence table:
[`docs/policy-format.md` § Enforcement mode](https://github.com/capwall/capwall/blob/main/docs/policy-format.md#enforcement-mode).

## Generated policies point at the schema

`observe` and `gen-policy` write a `"$schema"` key into a policy they create, so the file you
are then told to hand-edit gets editor validation and completion — which is where it pays for
itself, given the `outer>inner` package-key grammar. The pointer is
`./node_modules/@capwall/policy-schema/schema.json`, and it is written **only when that path
actually exists**: a dangling `$schema` shows up as a diagnostic on line 2 of a file capwall
just wrote, which is worse than none. An existing `$schema` is never rewritten.
