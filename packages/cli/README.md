# @capwall/cli

The `capwall` command-line interface — the primary way users drive the observe→enforce loop.

> **Scaffold.** Each command parses its args and prints its intended behavior plus
> "not yet implemented". See [`../../docs/roadmap.md`](../../docs/roadmap.md).

## Commands

```
capwall observe   -- <cmd...>   Run <cmd> with capwall in observe mode; record every
                                capability and emit/merge a starter capabilities.json.
                                (Nothing is blocked.) — HEADLINE feature.

capwall enforce   -- <cmd...>   Run <cmd> with capwall in enforce mode; deny-by-default,
                                throw on any capability not in the policy.

capwall gen-policy [--from <trace>] [-o capabilities.json]
                                (Re)generate a policy from a prior observe trace.

capwall explain <package> <capability> [target]
                                Explain why a (package, capability, target) tuple would be
                                allowed or denied under the current policy.
```

Common flags (intended): `-p, --policy <path>` (default `./capabilities.json`),
`-o, --out <path>`, `--project-root <path>`.
