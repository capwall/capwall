# @capwall/policy-schema

The single source of truth for the shape of a capwall `capabilities.json`: a **Zod schema**,
the **TypeScript types** inferred from it, and the **JSON Schema** (`schema.json`) that gives
your editor validation and completion while you hand-edit a policy.

`@capwall/core` imports these types directly and never restates them; the CLI validates every
user-supplied policy file against `PolicySchema`. The authoritative field-by-field
documentation is [`docs/policy-format.md`](https://github.com/williamzujkowski/capwall/blob/main/docs/policy-format.md)
— this README is the orientation, not the reference.

> **Not published to npm yet** (staged at `0.1.0`, in lockstep with the other three
> packages — see [`docs/releasing.md`](https://github.com/williamzujkowski/capwall/blob/main/docs/releasing.md)).
> See the root
> [README](https://github.com/williamzujkowski/capwall#readme) § Install for the
> run-from-a-clone path.

## Point your editor at the schema

Add `$schema` as the first key of your policy. `capwall observe` writes this line for you when
the path resolves:

```jsonc
{
  "$schema": "./node_modules/@capwall/policy-schema/schema.json",
  "version": 1,
  "mode": "enforce",
  "default": {},
  "packages": {
    "pino": { "fs": { "read": [], "write": ["./logs/**"] } },
    "got":  { "net": { "hosts": ["api.example.com"], "ports": [443] } }
  }
}
```

Inside a capwall checkout the same file lives at `./packages/policy-schema/schema.json`.

## The shape, in one screen

| Key | Meaning |
|---|---|
| `version` | policy format version — `1` |
| `mode` | optional `"observe"` \| `"enforce"`. What `capwall run` reads; an explicit CLI mode or `CAPWALL_MODE` outranks it |
| `default` | a `PackagePolicy` applied to any package with no explicit entry. **Grant nothing here** — that is what deny-by-default means |
| `packages` | package key → `PackagePolicy` |

A `PackagePolicy` has one optional field per capability. Every omitted field is a denial:

| Field | Type | Notes |
|---|---|---|
| `fs` | `{ read: string[], write: string[] }` | path globs, resolved against the project root |
| `net` | `{ hosts: string[], ports: (number \| "*")[] }` | egress. `"*"`, `"*.internal"` and `"**.internal"` are the host wildcards; a wildcard never matches an IP literal |
| `ipc` | `{ paths: string[] }` | unix sockets / named pipes, matched by the same glob matcher `fs` uses |
| `env` | `string[]` | a **read** allowlist of `process.env` keys. Writes are not mediated |
| `child_process` | `boolean` | gate on spawning, not confinement of the child |
| `worker_threads` | `boolean` | gate only |
| `vm` | `boolean` | **identity-granting** — `vm` lets a package choose the filename its frames report |
| `native` | `boolean` | may this package load a `.node` addon. A load-time gate with **no confinement whatsoever** |
| `compile` | `boolean` | `Module.prototype._compile` under another package's filename. **Identity-granting — a grant of every other grant.** Grant it to the one build/instrumentation tool that needs it |

## Package keys are install positions

This is the part worth reading twice, because it is where a hand-written policy most often
silently fails to apply.

A key names a **position in the dependency tree**, not just a name. `lodash` is the top-level
install; `webpack>lodash` is the copy nested under `webpack`. They are different principals and
the first does not cover the second (issue #92 — otherwise any package could collect a granted
package's capabilities by vendoring a directory with the right name).

Two wildcard forms widen a leaf, and they are **not** interchangeable:

| Key | Matches |
|---|---|
| `lodash` | the top-level install only |
| `*>lodash` | an install nested **exactly one level** (`webpack>lodash`) — *not* `webpack>babel>lodash` |
| `**>lodash` | an install nested at **any depth** |

A `*` must be the whole first link of a chain; `sneak*` is rejected at load time with an error
saying so, rather than silently matching nothing. Whether a *well-formed* key matches anything
is a runtime fact, so `capwall observe` and `capwall diff` report keys that granted nothing in
a run and suggest the chain you probably meant (#118 — `unmatchedPackageKeys` here is what they
use, deliberately sharing `packageKeyMatches` with the enforcer so the two cannot disagree).

Two sentinel keys complete the set: `"<app>"` (the application's own code — the trust root) and
`"<unknown>"` (a call capwall could not attribute to any source file — an ordinary
deny-by-default principal, deliberately not an exemption). Both are documented in
[`docs/policy-format.md`](https://github.com/williamzujkowski/capwall/blob/main/docs/policy-format.md)
§ Two sentinel keys.

## API

```ts
import { parsePolicy, type Policy, type PackagePolicy } from "@capwall/policy-schema";

const policy: Policy = parsePolicy(JSON.parse(raw)); // throws a ZodError on invalid input
```

Also exported: `PolicySchema` / `PackagePolicySchema` and friends (the Zod objects themselves),
the host-pattern grammar (`validateHostPattern`, `matchesHostPattern`, `isIpLiteral`,
`ANY_HOST`), and the package-key grammar (`validatePackageKey`, `widenedPackageKeys`,
`packageKeyMatches`, `unmatchedPackageKeys`, `CHAIN_SEP`).

`parsePolicy` validates and applies defaults. It does **not** normalize globs against a project
root — that is `loadPolicy` in `@capwall/core`, because normalization needs a root and this
package deliberately knows nothing about the filesystem.

## Layout

```
src/index.ts        the Zod schema + inferred TS types (the source of truth)
src/host.ts         net host-pattern grammar and its validator
src/package-key.ts  package-key grammar: install chains, `*>` / `**>` widening, sentinels
schema.json         the JSON Schema, kept in sync with src/index.ts by hand
```

## License

[MIT](https://github.com/williamzujkowski/capwall/blob/main/LICENSE) © 2026 William Zujkowski.
