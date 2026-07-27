# @capwall/cli

The `capwall` command-line interface — the primary way users drive the observe→enforce loop.

> **Status:** all **six** commands are implemented and work for every capability, on both the
> CJS `require` and the ESM `import` paths. `observe`/`enforce`/`run`/`diff` launch the target
> with `@capwall/core/preload` injected via `NODE_OPTIONS --import`. Milestone status is
> tracked in one place, [`../../docs/roadmap.md`](../../docs/roadmap.md).
>
> Not published to npm yet (version `0.0.0`) — run it as
> `node <clone>/packages/cli/dist/index.js` after `pnpm install && pnpm build`. See the root
> [`README.md`](../../README.md) § Quickstart.

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
```

Common flags: `-p, --policy <path>` for `enforce`/`run`/`diff`/`explain` and `-o, --out <path>`
for `observe`/`gen-policy` (both default to `./capabilities.json`). `diff` also takes
`--json`, which writes the drift as a compact JSON array of `{pkg, kind, detail}` as the
**last** line of stdout (the target's own stdout is inherited and may precede it). The project
root is the CLI's working directory.

`diff` is the CI-facing command: exit **0** = no drift, **1** = drift found, **2** = usage
error or missing policy file. See [`docs/ci-local.md` § Drift detection in
CI](../../docs/ci-local.md).

`observe`, `enforce` and `diff` name the mode themselves (they set `CAPWALL_MODE`, which
outranks everything); `run` takes it from the policy document. Full precedence table:
[`docs/policy-format.md` § Enforcement mode](../../docs/policy-format.md#enforcement-mode).
