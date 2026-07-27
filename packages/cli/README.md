# @capwall/cli

The `capwall` command-line interface — the primary way users drive the observe→enforce loop.

> **Status (roadmap M1–M3 done):** all four commands work for the `fs` capability on the
> CJS path. `observe`/`enforce` launch the target with `@capwall/core/preload` injected via
> `NODE_OPTIONS --import`. See [`../../docs/roadmap.md`](../../docs/roadmap.md).

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
for `observe`/`gen-policy` (both default to `./capabilities.json`). The project root is the
CLI's working directory.

`observe`, `enforce` and `diff` name the mode themselves (they set `CAPWALL_MODE`, which
outranks everything); `run` takes it from the policy document. Full precedence table:
[`docs/policy-format.md` § Enforcement mode](../../docs/policy-format.md#enforcement-mode).
