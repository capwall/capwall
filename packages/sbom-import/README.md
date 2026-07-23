# @capwall/sbom-import

Imports a CycloneDX SBOM (JSON) — and, when present, CBOM-style capability annotations on
its components — and produces a starter capwall `capabilities.json`, in the spirit of
NodeShield's "security-enhanced SBOM" input. Same review-then-enforce loop as the
`observe`-trace path: this package gets you a schema-valid skeleton, you tighten it before
switching to `enforce`.

Roadmap: S1 (see `docs/roadmap.md`). No new runtime dependency — CycloneDX SBOMs are just
JSON; the parser is `JSON.parse` + defensive shape-checking (see AGENTS.md § 5).

## API

```ts
import { sbomToPolicy, parseCycloneDx } from "@capwall/sbom-import";

// sbom is `unknown` — untrusted input, validated defensively.
const policy = sbomToPolicy(sbom, { mode: "observe" });
// policy is a schema-valid @capwall/policy-schema Policy (emitted via parsePolicy()).

// Lower-level: just parse components + their derived grants, without assembling a policy.
const components = parseCycloneDx(sbom);
```

- `sbomToPolicy(sbom: unknown, opts?): Policy` — one `packages[name]` entry per CycloneDX
  component, sorted by name for stable diffs. `opts.mode` ("observe" | "enforce", default
  "observe") sets the emitted policy's mode. `opts.warnings` (a `string[]`, mutated in
  place) collects malformed-input warnings; malformed SBOM input is **never** thrown for —
  a bad top-level document yields an empty policy, a bad individual component is skipped.
  The output always passes `parsePolicy()`.
- `parseCycloneDx(json: unknown, warnings?: string[]): Component[]` — the parsing step on
  its own: `{ name, version?, purl?, bomRef?, grant }` per component, where `grant` is the
  `PackagePolicy` derived from that component's `capwall:*` CBOM properties (`{}` if none).

## CBOM annotation convention

CycloneDX components may carry an arbitrary `properties: [{ name, value }]` array — a
standard CycloneDX extensibility point. We read `capwall:*`-prefixed properties off that
array as a lightweight capability bill-of-materials (CBOM):

| property name             | value format                           | maps to          |
|----------------------------|-----------------------------------------|-------------------|
| `capwall:fs:read`          | comma-separated globs                   | `fs.read`         |
| `capwall:fs:write`         | comma-separated globs                   | `fs.write`        |
| `capwall:net:hosts`        | comma-separated hostnames/globs         | `net.hosts`       |
| `capwall:net:ports`        | comma-separated integers                | `net.ports`       |
| `capwall:child_process`    | `"true"` / `"false"`                    | `child_process`   |
| `capwall:worker_threads`   | `"true"` / `"false"`                    | `worker_threads`  |
| `capwall:vm`                | `"true"` / `"false"`                   | `vm`              |
| `capwall:env`               | comma-separated env key names, or `*`  | `env`             |

A property name may repeat (values from repeated properties concatenate); a single value
may itself be a comma-separated list. Example component:

```jsonc
{
  "type": "library",
  "name": "express",
  "purl": "pkg:npm/express@4.19.2",
  "properties": [
    { "name": "capwall:fs:read", "value": "./views/**,./public/**" },
    { "name": "capwall:net:hosts", "value": "*" },
    { "name": "capwall:net:ports", "value": "3000,8080" },
    { "name": "capwall:env", "value": "NODE_ENV,PORT" }
  ]
}
```

Unrecognized `capwall:*` property names and malformed values (e.g. a non-numeric port) are
ignored with a collected warning, not an error. Non-`capwall:` properties are ignored
silently — they're not ours. A component with no `capwall:*` properties gets an **empty
grant `{}`** — the safe deny-by-default scaffold, same as any package `capwall observe`
never saw active.

This is a first-cut convention scoped to what `PackagePolicy` (`@capwall/policy-schema`)
can express. It deliberately does not attempt to parse the heavier, still-evolving OWASP
CycloneDX ML-BOM/CBOM `evidence` block — a future iteration could add that as an additional
annotation source without changing this one or the public API.

## Compatibility

Stays compatible with NodeShield's SBOM-driven policy notion (see the CCS 2025 paper, DOI
10.1145/3719027.3765136) so existing security-enhanced SBOMs can seed a capwall policy, and
with the general CycloneDX component shape so a plain CycloneDX SBOM (no capwall
annotations at all) still imports cleanly — it just produces all-empty grants for you to
fill in.

See [`../../docs/roadmap.md`](../../docs/roadmap.md) § S1 and
[`../../docs/policy-format.md`](../../docs/policy-format.md) for the policy shape.
