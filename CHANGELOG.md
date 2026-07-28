# Changelog

All notable changes to capwall. The four packages (`@capwall/policy-schema`, `@capwall/core`,
`@capwall/sbom-import`, `@capwall/cli`) release in **lockstep at one version**, so this is one
file, not four. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning:
[semver](https://semver.org/), with the pre-1.0 rule that a **minor bump may break** — see
[`docs/releasing.md`](docs/releasing.md).

Written by hand. There is no changelog generator in this repo and there should not be one: the
entries worth reading are the ones that say what a change means for someone running capwall,
and a tool that reads commit subjects cannot write those.

**If you change behaviour, add a line under `[Unreleased]` in the same PR.** Use
`Added` / `Changed` / `Deprecated` / `Removed` / `Fixed` / `Security`. `Security` is not
optional here: "capwall stopped mediating X" is a security regression for every user, and it
has to be findable without reading the diff.

> The `"version": 1` field inside `capabilities.json` is the **policy format** version. It is
> independent of the package version and does not move with it. A capwall `0.2.0` still reads
> `"version": 1` policies.

## [Unreleased]

### Security

- **Closed an unrecorded route around the module-read gate (#123) on Node ≥24.18.** capwall
  re-resolves every `require` of a path specifier so the gate knows which file the load will
  open, and it did that by forwarding `Module._load`'s own argument list to
  `Module._resolveFilename`. Node 24.18 changed `_load`'s fourth argument into an internal
  options bag whose `requireResolveOptions` field is what Node itself passes down, so capwall's
  re-resolution failed and the gate silently declined. Measured on Node 24.18.0 and 26.5.0: a
  dependency calling `Module._load(spec, parent, false, { requireResolveOptions: { paths: […] } })`
  under a **deny-all `enforce` policy** read the file and produced **zero decisions** — nothing
  thrown, nothing on stderr, nothing for `observe` or `capwall diff`. The ordinary three-argument
  spelling of the same read was denied correctly, which is what kept it invisible. Node 20 and 22
  reject the form outright and were never affected.

### Added

- **[`docs/node-api-dependencies.md`](docs/node-api-dependencies.md)** — one row per Node API
  capwall's mechanism depends on: what it is used for, its real status on Node 22/24/26, the
  supported replacement if any, and which capability dies without it. Measured against real
  binaries rather than changelogs. It records, among other things, that
  **`module.register()` — capwall's entire ESM path — is runtime-deprecated in Node 26 (DEP0205)
  with removal announced** (#153), and that `Module.prototype._compile` and `process.dlopen` have
  no replacement at all, so the `compile` and `native` capabilities would simply cease to exist
  if either were removed.

### Fixed

- Four source comments asserted Node version facts that had stopped being true —
  `Module._load`'s argument count (which has oscillated 3→4→3→4 across 20/22/23/24.5/24.18/26),
  `Module._findPath`'s signature (it gained `conditions` after Node 20), and the claim that a bare
  `import("./x.node")` is rejected by Node (it resolves unflagged on Node 26, and capwall's
  `process.dlopen` gate covers it — verified end to end). The code was already variadic and
  correct in each case; the comments are what a future fixed-arity wrapper would have been written
  from. `test/primitive-arity.test.ts` now covers `Module._findPath` as well.

## [0.1.0] - unreleased

First public release. Nothing was published before this, so everything below is new; the
entries are grouped by what the thing does rather than by what changed.

### Added

- **`fs`, `net`/`http(s)`, `child_process`, `worker_threads`, `vm`, `env` and `dgram`
  mediation**, per-package, on both the CJS and the ESM load path. Every intercepted call is
  attributed to the package that made it and evaluated against `capabilities.json`.
- **Attribution by install chain, not by name.** A package is identified by where it is
  installed (`express>debug` is the copy of `debug` under `express`), so a vendored
  `node_modules/<granted-pkg>/` directory cannot borrow that package's grants.
- **`capwall observe`** — run a command, record what every package actually did, write a
  starter `capabilities.json`. Merges on re-run rather than overwriting.
- **`capwall enforce`** — deny-by-default; a call outside the policy throws with the package,
  the capability and the target named.
- **`capwall run`** — read the committed policy and honour its `mode` field.
- **`capwall diff`** — observed-vs-declared drift detection for CI. Exit 0 clean, 1 drift,
  2 usage error; `--json` for machine consumption.
- **`capwall gen-policy`** and **`capwall explain`** — generate a policy from a trace, and
  explain why a specific call would be allowed or denied.
- **`capwall --version`** — prints the CLI version *and* the `@capwall/core` version it would
  inject, because the core runs in a different process and the two can differ.
- **Global egress mediation** — `globalThis.fetch`, `WebSocket` and `EventSource`, not just
  the `node:http`/`node:net` module surface.
- **Native addon (`.node`) attribution and gating** via a `process.dlopen` patch, charged to
  both the caller and the addon's owning package.
- **Hardened mode** (opt-in) — the installed shims are frozen, and a later non-hardened
  install cannot downgrade them.
- **`@capwall/policy-schema`** — the `capabilities.json` schema as Zod plus a published
  `schema.json` for editors and CI.
- **`@capwall/sbom-import`** — CycloneDX/CBOM → starter policy. **Not published in 0.1.0**;
  see *Not shipped* below.
- **`pnpm bench`** — measures added latency on every mediated surface as paired,
  ABBA-interleaved arms, and reports call shapes that amplify one JS call into many
  interceptions instead of hiding them in an average.

### Changed

- **Breaking, relative to any pre-release clone:** a bare `"lodash"` key in `packages` grants
  the **top-level install only**. Before, it matched every copy of `lodash` anywhere in the
  tree. To grant a nested copy, name its chain (`"express>lodash"`) or use a wildcard. Policies
  written against the old semantics grant strictly less than they used to, so they fail closed
  — you will see denials in `enforce`, not silent allows. (#92, #100)
- Policy `mode` is read rather than merely parsed and documented.

### Security

The pre-release audit closed a set of attribution and mediation bypasses. Each one let a
dependency with no grants act as if it had them, which is the failure this tool exists to
prevent — they are listed because "capwall did not mediate X" is the class of thing a user
needs to be able to search for.

- `Module.prototype._compile` with a caller-chosen filename forged the attributed package.
  `_compile` is now itself a capability. (#93)
- Nested `eval` plus a `//# sourceURL` comment forged `getEvalOrigin()`; that signal is no
  longer trusted. (#84, #91)
- A `data:` URL ESM module made attribution fail **open** to `<app>`, the trust root.
  Unattributable calls now fail closed to `<unknown>`. (#60, #76)
- `require()`/`import()` of a `.json` or `.ts` file was an un-gated, unlogged file read.
  (#120, #123)
- An ESM dependency could `module.registerHooks()` ahead of capwall and un-mediate
  `node:fs`/`node:child_process` process-wide; the subpath-imports map (`{"#x": "fs"}`)
  laundered a dependency straight past the resolve hook. (#59, #61, #74)
- `http(s).globalAgent` was a real Agent copied verbatim — un-gated egress. Its guarded view
  now traps writes and freezes. (#65, #88)
- A `child_process` grant suspended the env gate **process-wide** for the duration of a spawn,
  so a package granted only `child_process` read every env value, unlogged. The suspension is
  now scoped to the keys being passed. (#89)
- `options.path`/`socketPath` accessors survived argument pinning, escalating a TCP grant to
  an arbitrary unix socket. (#56)
- Construct-trap `Proxy` classes (`fs.ReadStream`, `vm.Script`, `worker_threads.Worker`) were
  bypassable via `.prototype.constructor`; they are guarded subclasses now. (#64, #70)
- Repeated argument-normalization gaps — numeric-string ports, latin1 byte paths, URL objects,
  `fs.glob` on Node 22, `TLSSocket#connect`, duck-typed `isURL`, http2 object authority — each
  of which skipped a gate entirely. Shim argument handling now mirrors Node's own
  normalization rather than approximating it. (#99, #104, #105, #106, #108)
- A `..` written as a glob expansion (`[.][.]`, `..{,}`) walked past the path prefix check.
  (#120)

### Packaging

- All four packages ship their TypeScript **sources** alongside `dist`, so the published
  source maps resolve and the code that mediates your process is readable from
  `node_modules`. (#126)
- Tarballs are built with `pnpm pack` and uploaded with `npm publish <tarball>`; a `prepack`
  guard refuses `npm pack`, which would ship an unresolvable `workspace:*` specifier. (#116)
- LICENSE and repository metadata in every tarball. (#130)

### Not shipped in 0.1.0

- **`@capwall/sbom-import` is held back from the registry.** It is built, tested and released
  in-repo at the same version as the rest, but nothing consumes it: no CLI subcommand exposes
  it, so publishing it would put a package on npm with no entry point, republished on every
  lockstep release forever. It publishes in the release that adds its CLI consumer. See
  [`docs/releasing.md`](docs/releasing.md) § What is published.
- **Provenance attestations**, if `0.1.0` has to be published manually — provenance requires a
  trusted CI publisher and GitHub Actions is billing-blocked (#3). See `docs/releasing.md`.

[Unreleased]: https://github.com/williamzujkowski/capwall/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/williamzujkowski/capwall/releases/tag/v0.1.0
