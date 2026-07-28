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

### Changed

- **The ESM path no longer uses `module.register()`** (issues #152, #153). capwall's `resolve` and
  `load` hooks are now registered with **`module.registerHooks()`** — synchronous, and running in
  capwall's own realm rather than on Node's separate module-customization thread. Four things
  change for anyone running capwall:

  - **Node 26 no longer prints a deprecation warning on every mediated run, and
    `--throw-deprecation` no longer stops the application starting.** `module.register()` is
    Stability 0 and runtime-deprecated as **DEP0205** since Node 26.0.0, with removal announced;
    under `NODE_OPTIONS=--throw-deprecation` `install()` threw and the mediated app never ran at
    all. Both are fixed, verified on a real 26.5.0 binary.
  - **A mediated process starts ~70–95 ms faster.** Measured with `pnpm bench:startup` on
    22.22.3 / 24.18.0 / 26.5.0, ABBA-interleaved with the two builds' `dist` trees swapped between
    runs: **−94.6 / −79.6 / −83.2 ms** idle and **−89.6 / −72.7 / −69.0 ms** at two cores, with
    `bare node` and `CAPWALL_ESM=0` moving ≤10 ms as controls. Turning the ESM perimeter on now
    costs 4–8 ms, where it cost 84–112 ms. Full tables in
    [`scripts/bench/README.md`](scripts/bench/README.md) § After #152.
  - **ESM teardown is real.** `registerHooks()` returns a `deregister()`, which the last
    `uninstall()` calls. A mediated builtin that was **never imported** before teardown now
    reaches the real builtin on a fresh `import`, exactly as a fresh `require` does on the CJS
    path, instead of throwing "capwall is no longer installed". A specifier a module had **already
    imported** still denies under the deny-all torn-down policy — that is the property that
    matters and it is unchanged. This removes the last place `docs/threat-model.md` documented the
    two module systems behaving differently on `uninstall()`.
  - **A dependency's `module.register()` can no longer get ahead of capwall in the hook chain**
    (#61). Node runs the synchronous hook chain entirely before the asynchronous one, and capwall
    is now in the synchronous one. A dependency using `module.registerHooks()` still can — that
    remains the named residual, and the `load`-level re-mediation backstop still catches it for all
    twelve mediated builtins.

  **One thing costs more.** `registerHooks` hooks are consulted for `require()` as well as
  `import()`, which `module.register()` hooks were not. With ESM on, module loading over a large
  CJS tree now costs ~0.1–0.2 ms per module more than with `CAPWALL_ESM=0` — about 11 ms (Node 22)
  to 24 ms (Node 26) over `require("express")`'s 123 modules, against ~130 ms before. Net still a
  large win; it is module-load work, not per-request work.

### Removed

- **Node 20 support.** It went end-of-life on 2026-04-30. `engines` is now `>=22.15.0` in all
  four manifests, and the CI matrix is **22, 24 and 26**.

  The floor is `22.15`, not `22.0`, on purpose: `module.registerHooks()` landed in 22.15, and
  capwall wants it available **without a version gate** (issue #152 — Node 26 has since
  deprecated `module.register()` in its favour, DEP0205). If you are on Node 20, upgrade to 24
  (the active LTS, supported to 2028-04-30).

### Added

- **Node 24 and Node 26 are tested.** 24 is the active LTS; 26 becomes LTS on 2026-10-28 and is
  carried early so breakage surfaces before it is everyone's runtime.
- **Web Storage is classified.** Node 26 introduced `Storage`/`localStorage`/`sessionStorage`,
  `Temporal`, `ErrorEvent` and `QuotaExceededError` as globals. All six were reviewed and are
  **inert for egress** — none can originate a network request. `localStorage` is separately
  documented as a **known, un-mediated, flag-gated file channel**: with `--localstorage-file`,
  Node's internal read/write of that one file happens below the `fs` shim. See
  `docs/threat-model.md` § Web Storage, tracked as #156.
- **A startup-graph budget on the main thread** (#167), in `test/esm-hook-graph.test.ts`. #150 had
  guarded the blocking `module.register()` graph; nothing guarded the graph the main thread
  evaluates before the target's entry point, where the policy is parsed — which is how zod 4's
  ~58 ms arrived with `test`, `bench:gate`, `mutation:gate` and `ci:local` on three Node versions
  all green. #152 — the first entry under `[Unreleased]` — later removed the loader thread and
  #150's scans with it, so as shipped this budget is the whole of the startup-graph coverage
  rather than half of it.

  It gates a **module count, not a time**: AGENTS.md § 7 forbids a wall-clock threshold, and
  startup has no co-sampled reference for `bench.mjs`'s ratio trick. The count is immune to
  machine speed and is what actually moved — zod's graph went from **19 resolves to 180** across
  the upgrade. Measured identical on 22, 24 and 26, and byte-stable across runs. The ceiling has
  headroom so a zod patch release cannot turn CI red on its own (`ci.yml` installs with
  `--frozen-lockfile=false`), and the headroom is **derived** — 15 ms at the measured ~0.34 ms per
  resolve — rather than picked. A self-check pins the ceiling to the observed floor in both
  directions, so raising one without re-deriving the other fails.

### Changed

- **Tests that used to skip on Node 20 now run everywhere**: the `fs.glob` family (seven
  `describe` blocks, previously behind a `HAS_GLOB` predicate), `globalThis.WebSocket` and the
  `node:http` `WebSocket` re-export, `WebSocket` under hardened mode, and — the security-relevant
  one — the `module.registerHooks()` laundering cases in `esm.test.ts` (#61's synchronous-chain
  gate and #78's backstop), which now assert the *guarded* outcome on every leg instead of
  accepting `UNSUPPORTED` on one.
- `@types/node` moved from v20 to v22, removing several hand-written declarations for APIs the
  v20 types did not know about.
- `.devcontainer/ci.Dockerfile` installs corepack from npm when the base image lacks it — Node
  unbundled corepack in 25, so `node:26` images have none.
- **`zod` 3.25.76 → 4.4.3** (#161). capwall's only runtime dependency, still MIT, still with no
  runtime dependencies of its own. No source changes and no behaviour change to policy
  validation: every API `@capwall/policy-schema` uses survives, and #138's structural error
  formatting is unaffected.

  **It costs ~58 ms of startup, per mediated process, and that was accepted rather than
  engineered around.** The cost is entirely zod's module graph — ~79 ES modules where zod 3
  evaluated ~10 — plus ~11 ms building the schema tree. *Parsing is exactly as fast as before*
  (5.87 ms vs 5.77 ms on the real policy file). Every cheaper route was measured: `zod/mini` is
  4 ms better, `zod/v4/core` 14 ms better at the cost of the inferred types, and the CJS entry is
  *slower*. The remaining routes all buy the milliseconds by not validating the policy at
  startup, which is a fail-open in the component that decides what everything else may do. The
  full breakdown, the harness and the one lever left unpulled are in
  `scripts/bench/README.md` § zod 4. One clause of this entry did not survive the release it is
  in: as written it added that zod was still absent from the **ESM loader thread's** graph and
  that #150's guard passed unchanged. #152 — the first entry under `[Unreleased]` — removed that
  thread, and #150's static scans with it. The cost and the decision are unchanged: zod reaches
  every mediated process through `index.ts`'s re-export of `loadPolicyFromObject`, not through the
  hook module, and what watches it now is #167's module-count ceiling above.

  One thing to know if you write a test against it: zod's own default message text changed
  (`"Required"` → `"Invalid input: expected string, received undefined"`). Nothing asserts on it
  today.
- **TypeScript 5.9.3 → 7.0.2** (#160), the Go rewrite. One config line: `types: ["node"]` in
  `tsconfig.base.json`, because TS 7 defaults `types` to `[]` where 5.x auto-included every
  `@types/*` in scope. No source changes. Emit was diffed against 5.9.3 across all four packages:
  **16 differing files out of ~200 — 15 source maps and one `.d.ts` whose only change is the key
  order of an emitted enum object type.** `scripts/check-tarball-sources.mjs` is green on all four
  packed tarballs (98 maps, 0 dangling), and the new maps were spot-checked against source lines
  rather than only for existence. Note TS 7.0 ships **no programmatic API** (`import ts from
  "typescript"` yields `{version, versionMajorMinor}`); nothing here uses it, but it forecloses a
  `.d.ts` validation gate until 7.1.
- **pnpm 10.33.0 → 11.17.0** (#162), now that the `>=22.15.0` floor satisfies pnpm 11's
  `engines.node: >=22.13`. `packageManager`, both workflows' `pnpm/action-setup` pin,
  `.devcontainer/devcontainer.json` and README § Prerequisites all move together. The lockfile
  format is **unchanged** (`lockfileVersion: '9.0'`), verified by a from-scratch resolve with
  both `node_modules` and `pnpm-lock.yaml` deleted.

  **The install-script setting changed spelling and behaviour**, which is the thing #162 said to
  re-check by running it. pnpm 11 removed `ignoredBuiltDependencies` (with
  `onlyBuiltDependencies`, `onlyBuiltDependenciesFile`, `neverBuiltDependencies` and
  `ignoreDepScripts`) in favour of one `allowBuilds` map of name → boolean — and unlike pnpm 10
  it does **not** go quiet on a `false`: it **fails** the install with `ERR_PNPM_IGNORED_BUILDS`,
  exit 1, until every package carrying a build script has an explicit decision. pnpm 10 printed a
  warning above the summary; pnpm 11 will not let you scroll past it.

  This composes with #165, which had just emptied the list because vite 8 removed `esbuild` — the
  last install script in the tree — entirely. So the end state is that **neither setting appears
  in `pnpm-workspace.yaml` at all**: there is nothing to declare, and the first dependency that
  brings a script in fails the install rather than logging. An empty `allowBuilds: {}` was
  considered and rejected as the same "refers to nothing" defect #165 removed. Verified in a
  clean `node:22` container against a cold store: silent, exit 0, and pnpm does not rewrite the
  file. README § Prerequisites describes the new failure instead of the old silence.

  Both pnpm guards were re-verified under 11: `npm install` at the clone root still fails loudly
  (#122) and `npm pack` is still refused (#116).
- **`@types/node` stays at `^22.15.0`** (#163), matching the Node floor rather than tracking
  `latest`. Evaluated and deliberately declined: `@types/node`'s major tracks a Node major, so
  `^24` or `^26` would let `tsc` accept APIs the minimum supported runtime does not have,
  silently, in a codebase whose entire job is calling Node internals that move between majors.
  The rule is "types major == floor major", and the floor is 22.15. Demonstrated rather than
  asserted: `new URLPattern({pathname:"/x"})` compiles clean under `@types/node` `^24` and `^26`
  and is correctly rejected under `^22`, while `globalThis.URLPattern` is `undefined` on Node
  22.22. (The rule is directional, not airtight — DefinitelyTyped backports some globals across
  lines, so `^22` already types `localStorage`, which Node 22 also does not have. It moves the
  hazard, it does not remove it.)

### Known gaps (unchanged by this release)

- `EventSource` is still behind `--experimental-eventsource` on **22, 24 and 26**, so the
  in-process suites skip it; it is covered by `test/global-egress-flagged.test.ts`, which spawns
  a child with the flag.
- `vm.SourceTextModule`/`SyntheticModule` are still behind `--experimental-vm-modules` on all
  three, and vitest is never handed that flag. The gate is asserted only where the classes are
  absent. This is a real hole, not a version artifact.

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

  **That last sentence is also why the fix needed coverage it did not have** (#176). The two
  end-to-end regression rows can only run where `Module._load` honours the four-argument form, so
  on Node **22.15 — the declared `engines` floor** — they feature-detect and skip, and `pnpm test`
  exercised none of the fix on the version adopters are told to run. The classification rule is a
  pure function of the argument list and is deliberately not version-keyed, so it is now asserted
  directly on every runtime, and the catalog has a `module-read-resolve-options-unwrapped` mutant
  that fails on 22 as well as on 24 and 26.

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
