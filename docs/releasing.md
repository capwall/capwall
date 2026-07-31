# Releasing capwall

How the four packages get to npm, and — kept deliberately separate below — the steps only a
person with account access can do.

`@capwall/policy-schema`, `@capwall/core` and `@capwall/cli` are published, at both `0.1.0` and
`0.1.1`. `@capwall/sbom-import` is built, tested and versioned in lockstep with the other four
but deliberately not published — see § What is published. `0.1.0` was the first release and set
the precedents: **npm's unpublish window is 72 hours and narrow even inside it**, so a broken
first version sits in the `@capwall` namespace forever, which is why it was rehearsed end to end
before being cut rather than trusted on the first try.

**There are two publish paths in this file and they are not interchangeable.** The OIDC path
(release-please → tag → `release.yml` → `npm publish --provenance`) is described first and is
the norm from `0.1.1` onwards — it is what actually published `0.1.1`, via a manual
`workflow_dispatch` rather than the tag alone (§ How a release happens explains why, and issue
#207 tracks the open decision about it). § THE FIRST MANUAL PUBLISH below is what published
`0.1.0` — a paste-ready sequence run from a workstation with a granular token, rehearsed end to
end against the real tarballs before it was used for real. Read that section for the historical
record of how `0.1.0` shipped, and as the manual fallback if trusted publishing ever needs to be
bootstrapped again; the OIDC path above it is the one to use for the next release.

Everything a machine can check about a release is checked by
`scripts/check-release-versions.mjs` (lockstep, pins, publish set, changelog, shipped READMEs, and that
release-please's own config still says what this file says it says) and
`scripts/check-tarball-sources.mjs` (what is actually inside the tarballs). Both run in the
release workflow before anything is uploaded. Read them; they carry the reasoning inline.

---

## The two things that make this repo unusual

**1. `pnpm` packs, `npm` publishes.** Three of the four packages depend on a sibling with pnpm's
`workspace:*` protocol — `cli` on `core` and `policy-schema`, `core` on `policy-schema`,
`sbom-import` on `policy-schema`; `policy-schema` itself has no workspace dependency, only
`zod`. Only pnpm rewrites that protocol to a concrete version when it builds a
tarball. `npm pack` copies the string verbatim, so an `npm publish` run from a package
directory uploads a manifest reading `"@capwall/core": "workspace:*"` — which no registry can
resolve and every consumer's install rejects with `Unsupported URL Type "workspace:"`
(issue #116).

But `pnpm publish` has no `--provenance` flag and no OIDC support, so it cannot do trusted
publishing. So the release does both halves:

```bash
pnpm pack                                              # correct tarball: workspace:* -> 0.1.0
npm publish ./<tarball> --provenance --access public   # trusted publishing + provenance
```

**The leading `./` is not optional.** `npm publish dist-tarballs/x.tgz` is parsed as the
GitHub shorthand `<user>/<repo>`, not as a file, and dies with:

```
npm error command git --no-replace-objects ls-remote ssh://git@github.com/dist-tarballs/capwall-policy-schema-0.0.0.tgz.git
npm error ERROR: Repository not found.
```

(Captured before the manifests were staged, hence `0.0.0`; the tarball naming convention
`capwall-<pkg>-<version>.tgz` is the part that matters, and it is what the publish loop below
globs on.)

Only `./dist-tarballs/x.tgz` or an absolute path works.

`npm publish <tarball>` uploads a finished archive without re-reading the workspace manifest,
so the rewrite survives and the attestation still gets attached. Do not collapse these into
one command — each half does something the other cannot.

A `prepack` guard (`scripts/assert-pnpm-pack.mjs`) makes the wrong path fail loudly rather
than silently producing a broken artifact:

```
$ cd packages/cli && npm pack
  capwall: refusing to pack with npm.

  This package depends on its siblings with pnpm's `workspace:*` protocol.
  npm copies that string into the tarball verbatim, producing a package that
  cannot be installed from a registry — and npm publishes are effectively permanent.

  Use pnpm instead:

      pnpm pack                                          # one package
      pnpm -r --filter './packages/*' pack               # all of them

  Then PUBLISH the tarball with npm, not with pnpm — pnpm publish has no
  --provenance flag and no OIDC support, so it cannot do trusted publishing:

      npm publish ./<tarball> --provenance --access public

  See docs/releasing.md (the authority for a release) and issue #116.
npm error code 1
```

**The guard's advice used to end with `pnpm -r publish --access public`, and that conflicted
with this document — a real conflict, not a wording slip.** `pnpm publish` has no `--provenance`
flag and no OIDC support, so it cannot do trusted publishing; both statements were true of the
tools, and they told the operator opposite things at the one moment they are reading a failure
message. **This document is the authority for a release — pack with pnpm, publish the tarball
with npm**, and the guard now says so too. `pnpm publish` is fine for a scratch registry or a
`--dry-run`, and nowhere else. (An earlier revision of this doc elided those two lines with
`...`, so a reader never saw the disagreement; it is recorded here rather than quietly
re-elided, because the fix was to the message and not to the doc.)

Its sibling `scripts/assert-pnpm-install.mjs` is the root `preinstall` guard and refuses
`npm install` at the repository root for the same family of reasons (#122). Neither guard moved
when release-please arrived, and release-please never runs either — it edits `version` fields and
`CHANGELOG.md` and nothing else.

**2. The workflow filename is part of the trust configuration.** npm trusted publishing binds
a package to a repository *and a specific workflow filename*. Renaming
`.github/workflows/release.yml`, or moving the publish step elsewhere, breaks publishing for
all four packages until each one is reconfigured by hand on npmjs.com.

That is why `release-please.yml` opens the release PR and creates the tag but publishes
nothing. The two workflows are separate on purpose and the seam between them is the tag.

---

## How a release happens

```
  conventional commits on main
            │
            ▼
  .github/workflows/release-please.yml     ← opens/updates ONE release PR:
            │                                 five package.json versions + CHANGELOG.md
            │                                 + .release-please-manifest.json
      (a human merges it)
            │
            ▼
       tag  v0.2.0                          ← created by release-please, not by hand
            │
            ▼
  .github/workflows/release.yml            ← the OIDC publish path. Unchanged.
            │                                 verify matrix → pnpm pack → assertions →
            ▼                                 npm publish --provenance
     three packages on npm
```

**The tag does not reliably start `release.yml` by itself.** A tag created by a workflow using
the default `GITHUB_TOKEN` — which is what release-please uses unless `RELEASE_PLEASE_TOKEN` is
configured (§ HUMAN CHECKLIST step 5) — does not trigger other workflows; this is documented
GitHub behavior, not a bug here. `v0.1.1` needed a manual `workflow_dispatch` for exactly this
reason: merging the release PR created the tag, but `release.yml` did not start on its own, and
had to be run by hand. See § HUMAN CHECKLIST step 17 for the operational detail, and issue #207,
which tracks the open decision of whether to close this gap (adding the token) or keep the
manual dispatch as the accepted norm — it has not been decided either way yet.

Nobody edits a version by hand any more, and nobody writes a changelog entry by hand any more.
The commit message *is* the changelog entry, which is why
`.github/workflows/commit-conventions.yml` refuses a pull request whose title does not parse as a
conventional commit — see § Conventional commits below.

### The configuration, and the three parts of it that are load-bearing

`release-please-config.json` + `.release-please-manifest.json` (manifest mode). JSON takes no
comments, so the reasoning lives here and `scripts/check-release-versions.mjs` check 6 refuses a
config that has drifted away from it.

**1. There is exactly ONE release-please package — the repository root — and it writes all five
versions.** The four `packages/*/package.json` files are updated through the root package's
`extra-files`:

```json
{ "type": "json", "path": "packages/core/package.json", "jsonpath": "$.version" }
```

so lockstep is *structural*: there is one version number, written five times. There is no
mechanism by which the packages can disagree, which is the only property worth having here — see
§ Lockstep below for why a resolver that gets to pick a core version is the thing being bought
off.

**This is not the shape the release-please documentation reaches for, and the obvious one was
tried first and rejected on evidence.** The documented way to link a monorepo is five packages
plus the `linked-versions` plugin, and it does not work for this repository. `linked-versions`
groups strategies by **component**, and a strategy configured with
`"include-component-in-tag": false` — which is what produces a bare `vX.Y.Z` tag rather than
`capwall-vX.Y.Z` — reports an **empty** component, which the plugin skips:

```js
const component = await strategy.getComponent();   // '' when include-component-in-tag is false
if (!component) continue;                          // …so the root is never in the group
```

The root would therefore have been versioned on its own, next to a group of four. Most of the
time that coincides, because the root's path (`"."`) sees every commit in the repository. It stops
coinciding the moment a releasable commit touches nothing under `packages/` — a
`fix(tooling): …` against `scripts/`, which this repo does routinely — and then the root bumps and
the four packages do not. Verified by running `release-please release-pr --dry-run` against this
branch: `Found 4 group components for capwall`, not five.

Nothing catches that until the release, so the shape was changed rather than guarded.
`check-release-versions.mjs` check 6 now refuses a config with more than one package, or with
`include-component-in-tag` turned on, or with a `packages/` directory missing from `extra-files`.

**2. One tag, and it is `vX.Y.Z`.** `release.yml` listens on `v*`. Five packages would mean five
tags (`core-v0.2.0`, `cli-v0.2.0`, …) and five publish runs racing each other; one root package
with `"include-component-in-tag": false` means one. Verified against the resolved config, not
inferred: the tag the configured strategy would create is `v0.2.0`.

The root package also owns `CHANGELOG.md`, and because its path is `"."` it sees every commit in
the repository, which is what makes one file the whole story.

The visible consequence is that the private root `package.json` now carries the release version
instead of `0.0.0`. It is never published (`"private": true`); it is the release's identity, and
`check-release-versions.mjs` holds it in lockstep with the other four.

One cosmetic consequence, dealt with in advance: release-please's `extra-files` JSON updater
re-serialises the file it edits, so `"files": ["dist", "src"]` becomes three lines. That
reformatting was applied to all four manifests in the commit that adopted release-please, so the
first release PR is a one-line diff per file rather than four rewritten manifests. It is
idempotent from there — verified by running the updater three times.

**3. `"bump-minor-pre-major": true` is not a style preference.** release-please's default is
`false`, and on a `0.x` version that means a `feat!:` or a `BREAKING CHANGE:` footer cuts
**`1.0.0`** — automatically, in a PR that looks like every other release PR. § Why `0.1.0` below
is an argument that `1.0.0` is a promise this project cannot yet keep; this one flag is what
stops release-please making that promise on its behalf. With it set, the pre-1.0 rule this repo
already documents is what actually happens:

| commit | 0.1.0 → |
|---|---|
| `fix:` / `security:` / anything else | `0.1.1` |
| `feat:` | `0.2.0` |
| `feat!:` or `BREAKING CHANGE:` | `0.2.0` |

**`bootstrap-sha` is the seam, and it is a date-stamped fact rather than a setting to tune.** No
tag exists yet, so without it release-please would walk the entire history and regenerate a
changelog for 73 pre-adoption commits on top of the hand-written one. It points at the `main` this
branch was rebased onto — the last commit whose changes are described by the hand-written
`[Unreleased]` / `[0.1.0]` sections. Anything merged after it is release-please's. If a batch of
PRs lands between this being written and this being merged, they will have hand-written
`[Unreleased]` entries *and* generated ones; that duplication is bounded to the transition and is
cheaper than moving the seam and losing entries.

**What is deliberately NOT in the config:** the `node-workspace` plugin. It rewrites internal
dependency specifiers to concrete versions, which would replace every `workspace:*` with
something pnpm did not write at pack time — the #116 failure, reintroduced from the release
config rather than from a manifest. `check-release-versions.mjs` refuses it.

**release-please knows nothing about the publish set, and must not.** See § What is published.

### Conventional commits

`scripts/check-commit-messages.mjs` holds the rules and the reasoning;
`.github/workflows/commit-conventions.yml` runs it on every pull request, against **both** the PR
title and the individual commits — one implementation, two strings that can be wrong. There is
deliberately **no husky / `commit-msg` hook** — a local hook is opt-in per clone, does not survive
`--no-verify` or a merge performed in the GitHub UI, and would be a second set of rules that can
disagree with the one that decides the release.

The PR title is the important one: this repository squash-merges, so the title is the subject
that reaches `main` and the string release-please reads.

**The accepted types are read out of `release-please-config.json`, not restated in the script.**
That file's `changelog-sections` is what decides whether a type means anything, so a list written
down a second time could drift from it — and the drift would look like working right up until a
release quietly dropped a change. It is also why `security:` works with no special case anywhere:
it is in the config, so it is in the grammar. `packages/core/test/commit-messages.test.ts` proves
the binding rather than asserting it, by adding an invented type to a throwaway config and
checking the validator accepts it there and nowhere else.

**Nothing is capped.** No subject length (the longest in this history is 189 characters, because
it names every issue the change closes), no body or footer line length (bodies here paste
measurements, tables and fenced code), no scope enumeration (an allow-list would reject the first
correctly-scoped commit for a surface that does not exist yet).

**It replaced commitlint, and the reason was weight, not quality.** commitlint's closure is 68
packages — 27% of a 253-package dev tree, measured from a clean resolve with `node_modules` *and*
the lockfile deleted, since pnpm otherwise keeps what is already installed and the drop is
invisible — to check that a string starts with a known word. For a tool whose entire pitch is that
a dependency tree is a liability you cannot see, that was a cost with no technical justification.
It was **not** a licence problem (the `argparse` transitive is pure JavaScript; `Python-2.0` is the
permissive PSF licence, not the dead runtime) and not a maintenance problem. The script's header
records that, so it does not get re-litigated as one.

**The commits job walks `base..head`, never the whole history.** Six commits already on `main`
predate this gate and do not parse — `node scripts/check-commit-messages.mjs --all` names them:
`fs:`, `bench:`, `release:` and three compound types (`docs+cli:`, `docs+hygiene:`,
`docs+hygiene+test:`). Each was a change that happened and a changelog line that did not, which is
the evidence the gate is worth having; none can be fixed without rewriting published history, and
a gate that is always red is a gate that gets switched off.

Locally: `pnpm lint:commits` runs the same script over `origin/main..HEAD`, with no install step
because there is nothing to install. `commit-conventions.yml` enforces the same rules in Actions
on every pull request now; running it locally first is what catches a bad title before that
round trip.

---

## Versioning

**Lockstep, semver, starting at `0.1.0`.** release-please's `linked-versions` plugin produces it
and `scripts/check-release-versions.mjs` verifies it before anything is packed.

### Why `0.1.0` and not a number that looks more finished

The roadmap is complete (M1–M5, S1–S4) and the tool works end-to-end, which is an argument for
a bigger opening number. It loses to three others:

- **The policy format broke recently.** A bare `"lodash"` key now grants the top-level install
  only, where it used to match every copy in the tree (#92/#100). `ipc.paths` arrived in #72,
  `net.hosts` globs in #83. The format has never been through outside hands.
- **`1.0.0` is a promise you would immediately break.** The next policy-format change would
  force `2.0.0` on a tool with no installed base, which reads as churn rather than stability.
  Pre-1.0 semver exists precisely for this: `0.y.z` says the surface may still move, and a
  **minor** bump is allowed to carry a breaking change. Given how much has moved recently,
  that is the property worth having. `"bump-minor-pre-major": true` is where that rule is now
  encoded rather than remembered.
- **`0.9.0` is a claim about the near future, not the present.** It says "1.0 is next", which
  nothing supports. Padding a version number is an unearned maturity signal, which is a
  strange thing for a security tool to emit; the README and the threat model are where
  maturity gets argued, honestly and in detail.

`0.1.0` also leaves room. Breaking policy-format changes become `0.2.0`, `0.3.0` — cheap and
semver-legal. Starting at `0.9.0` leaves one such change before the number corners you.

### Lockstep, and the cost of it

All packages carry the same version and are released together — including any held back from
the registry, which stay in lockstep in-repo so the release that finally publishes them does
not have to reason about a gap.

- `@capwall/cli` does not merely call `@capwall/core`, it injects it into a *different
  process* via `NODE_OPTIONS=--import`. A mismatched core is a silently differently-behaving
  firewall.
- Same argument for `@capwall/policy-schema`: `core`'s evaluator and `cli`'s generator must
  agree byte-for-byte on what a policy key means. A range would let a resolver seat one copy
  under `core` and another under `cli` in the same tree, and the failure mode is a policy that
  generates one way and evaluates another.

**The trade, stated plainly.** Lockstep plus exact pinning means every release touches every
package, so `@capwall/policy-schema@0.1.1` can be byte-identical to `0.1.0` and still get
published. Version numbers stop being a claim that something changed, and a one-line fix in
`core` costs three registry publishes instead of one. Independent versions would avoid that,
at the price of making "which core does this CLI want?" a real question with a range for an
answer — and for a firewall injected into another process, a resolver being free to pick is
exactly the freedom being bought off. Redundant publishes are cheap; an ambiguous enforcement
version is not.

**Exact pins between the packages** is the same decision at dependency level, and it is what
pnpm's `workspace:*` rewrite produces (`"@capwall/core": "0.1.0"`, not `^0.1.0`). A patch to
`@capwall/core` must not be able to change what an already-installed `@capwall/cli` enforces.
Caret ranges are right for third-party deps — `zod` is the only one. Writing a caret on an
internal dep by hand is one of the mistakes `check-release-versions.mjs` catches; enabling
release-please's `node-workspace` plugin is the other.

The `capabilities.json` `"version": 1` field is **independent** of the package version and does
not move with it — a capwall `0.2.0` still reads `"version": 1` policies. This is stated at the
top of `CHANGELOG.md` too, because otherwise the first `0.2.0` makes someone bump their policy.

## What is published

**`@capwall/policy-schema`, `@capwall/core` and `@capwall/cli` are on the registry**, at both
`0.1.0` and `0.1.1`. This table is the declared *publish set*. `npm view @capwall/sbom-import` is
still a 404 — held back deliberately, not because nothing has shipped yet.

| package | in the publish set | why |
|---|---|---|
| `@capwall/policy-schema` | yes | the schema every consumer validates against |
| `@capwall/core` | yes | the enforcement engine |
| `@capwall/cli` | yes | the entry point everyone actually installs |
| `@capwall/sbom-import` | **held back** | see below |

`@capwall/sbom-import` (roadmap S1) is built, tested, versioned in lockstep and released
in-repo, but does **not** go to the registry. No CLI subcommand exposes it; it is
reachable only as a library that nothing in the product imports. Publishing it would put a
package on npm with no entry point and — because of lockstep — republish it on every release
forever, adding permanent registry surface and a provenance attestation for something with no
consumer. The one argument that would justify shipping it anyway, reserving the name against
squatters, does not apply: owning the `@capwall` org on npm already reserves every
`@capwall/*` name.

Holding it back costs nothing — it stays in the repo, in CI, in the tests — and it turns into a
real release note when a `capwall`-side consumer lands, which is a better announcement than a
library nobody can reach. Its first published version will be whatever release adds that
consumer, not `0.1.0`; that is normal and needs no apology in the changelog.

**release-please does not know this and is not told.** It versions all five components
identically, because holding a package back from the *registry* is not the same as holding it
back from the *release* — a held-back package that has quietly stopped building or packing is a
nasty surprise on the release that finally publishes it. The publish set lives in
`scripts/check-release-versions.mjs` (`--publish-list`) and `release.yml` reads it from there, so
there is one list rather than two that can disagree:

```bash
node scripts/check-release-versions.mjs --publish-list   # the authoritative list
```

The guard also refuses to let a published package depend on a held-back one — pnpm would rewrite
the specifier to a version that is not on the registry and the tarball would be uninstallable
for everyone.

To publish it, add it to `PUBLISHED` in that one file and configure its trusted publisher on
npmjs.com (§ HUMAN CHECKLIST step C). Nothing in `release-please-config.json` changes.

## Source maps — the tarballs ship `src/` (#126)

`"files": ["dist", "src"]` in `cli`, `core` and `sbom-import`; `["dist", "src", "schema.json"]`
in `policy-schema`, where `schema.json` is load-bearing — it is the file a generated policy's
`$schema` pointer resolves to. **The published packages contain their TypeScript sources.** That is a decision, not an oversight, and it is worth understanding
before anyone "trims" the tarball.

`tsconfig.base.json` sets `sourceMap` and `declarationMap`, so the build emits a `.js.map`
and a `.d.ts.map` beside every output file, and each one names its input as `../src/x.ts`.
Shipping only `dist` meant every map in `@capwall/core` resolved to nothing — 68 of them today
(`find packages/core/dist -name '*.map' | wc -l`; it was 66 when #126 was written, and the count
moves with the source file count, so re-derive it rather than quoting one) — 22% of the
tarball delivering no function, and `.d.ts.map` in particular being *worse* than no map,
because "go to definition" follows it to a file that is not there instead of falling back to
the real `.d.ts`.

The two honest fixes were "ship the sources" and "ship neither". Sources won:

- **`inlineSources` is not a third option.** It embeds sources in `.js.map` only; tsc never
  writes `sourcesContent` into a `.d.ts.map` (verified against tsc 5.9; the repo now builds on
  TypeScript 7 and this has not been re-verified there). It would fix stack traces under
  `--enable-source-maps` and leave the go-to-definition case exactly as broken.
- **Auditability is the product.** capwall's pitch is supply-chain trust. `npm i -D
  @capwall/cli` and you can read every line that mediates your `fs` calls, and diff the
  shipped `dist` against the shipped `src`, without cloning anything. A security tool that
  ships only minified-by-omission output is asking for a trust it will not extend.
- **The cost is small in absolute terms.** At the time of #126, all four tarballs together went
  from 327 kB to 511 kB compressed (+56%), and `@capwall/core` from 262 kB to 425 kB. Those are a
  point-in-time measurement, not a standing figure — the map count has moved since (68, was 66),
  so pack and measure before quoting them. Either way this is a devDependency installed once per
  project, not something on a hot path.

`scripts/check-tarball-sources.mjs` enforces it, and the release workflow runs it on the
packed tarballs before anything is uploaded. To check by hand:

```bash
for p in policy-schema core sbom-import cli; do
  (cd "packages/$p" && pnpm pack --pack-destination ../../dist-tarballs)
done
node scripts/check-tarball-sources.mjs dist-tarballs/*.tgz
```

## Changelog

One `CHANGELOG.md` at the repo root. **release-please writes it, from the commit messages**, and
inserts each new section directly above the previous one — the file's header block and every
existing section are left byte-for-byte alone (verified by running release-please's changelog
updater against this repository's actual `CHANGELOG.md`).

- **Do not hand-edit `CHANGELOG.md` in a feature PR.** Anything written there will be above
  whatever release-please generates, unattributed, and will read as a second changelog. Put the
  sentence in the commit subject instead — it is the same sentence, in the place that ships it.
- **`security:` is a first-class type**, mapped to a `### Security` section that sorts above
  everything else. "capwall stopped mediating X" is a security-relevant regression for every
  user and has to be findable without reading the diff. It bumps the patch, so a security fix can
  never be a release that looks like it changed nothing.
- `feat` → `Added`, `fix` → `Fixed`, `perf` → `Performance`, `refactor` → `Changed`,
  `revert` → `Reverted`. `docs`, `test`, `build`, `ci`, `chore` and `style` are hidden: they still
  bump the patch, they just do not fill the file with entries no user can act on.

**The sections up to and including `0.1.0` are the hand-written ones and stay that way.** Two of
them exist — `## [Unreleased]` and `## [0.1.0] - unreleased` — because `0.1.0` was staged by hand
before any of this existed and has never been published. Whoever cuts the first release folds the
first into the second; from the release after that, the file is generated and there is no
`[Unreleased]` section at all.

**What was given up.** The previous revision of this file argued that a generated changelog is
worse, because "the entries worth reading say what a change means for someone running capwall,
and nothing that reads commit subjects can write those". That argument was not wrong, and it has
not been refuted — it has been answered differently: the commit subject is now the thing that has
to be worth reading, and `commit-conventions.yml` is what stops a PR whose subject is not. The
property actually being bought is that the changelog **cannot be forgotten**, which was the
characteristic failure of the hand-written one and the reason
`check-release-versions.mjs` had to guard against it at tag time.

`check-release-versions.mjs` still fails if there is no `## [<version>]` section, and — once a tag
is being released — if that heading carries no ISO date. It accepts both spellings, so it works
across the two halves of the file.

---

## What has to be true before the first publish

Blocking — a broken or dangerous first artifact:

| | |
|---|---|
| #116 | `npm pack` ships `workspace:*`. **Fixed**: `prepack` guard + the pack-with-pnpm workflow. |
| #113 | Repo was private. Trusted publishing requires a public repo; the README's only install path was a clone. **Fixed and closed**: the repo was transferred to `capwall/capwall` and made public. |
| #115 | No versions, no CHANGELOG, no publish set. **Fixed**: all packages staged at `0.1.0`, `CHANGELOG.md` written, publish set declared once; all enforced by `check-release-versions.mjs`, and versions now owned by release-please. |
| #126 | Maps shipped without sources. **Fixed**: `"files": ["dist", "src"]`, enforced by `check-tarball-sources.mjs`. Done before the first publish on purpose — `files` decides what a reader can audit, and changing it later silently changes that answer. |
| #3 | Actions was billing-blocked. OIDC publishing *runs in Actions*, so this gated the whole path — **and it gated release-please too**, which is a workflow like any other. **Fixed and closed**: making the repo public (#113) gives it unlimited standard-runner minutes, which is what unblocked this — nobody had to "restore billing" as a separate step. |

Not blocking, and all four have since **landed** rather than waiting for `0.1.1`: #124
(`packages/policy-schema/README.md` exists; `cli/src/trace.ts` writes the `$schema` pointer),
#119 (env reads Node initiates are no longer recorded), #118 (`capwall observe`/`diff` report
unmatched policy keys, and `diff --strict` fails on them), #122 (the root `preinstall` guard
refuses an `npm install`). Nothing on this list is outstanding for `0.1.0`.

## What CI running now proves

Stated plainly, because "the release config is verified" is exactly the claim that must not be
overstated — and because "Actions ran" is a different, narrower claim than "the pinned SHAs are
the right ones" (see ci.yml's header). This section records both: what was checked locally before
`0.1.0` ever shipped, and what running for real in Actions has since confirmed or, in one case,
disproved a hope rather than a claim.

What **was** verified, locally, against release-please 17.6.0 (the version bundled by
`googleapis/release-please-action@v5.0.0`):

- the config parses and resolves, run as a real `release-please release-pr --dry-run` against this
  branch: one PR, titled `chore(<branch>): release 0.2.0`, updating `CHANGELOG.md`,
  `.release-please-manifest.json` and all **five** `package.json` files from `0.1.0` to `0.2.0`;
- the `linked-versions` shape was tried, dry-run, and found to leave the root component out of the
  group (`Found 4 group components`, not five) — which is why the config has the shape it has;
- the tag the configured strategy would create is `vX.Y.Z`, and there is only one of them;
- `bump-minor-pre-major: true` keeps a breaking change at a minor while the major is 0 — and
  without it, the same commit cuts `1.0.0`;
- a `security:` commit lands in a `### Security` section and bumps the patch;
- release-please's changelog updater leaves this repository's existing `CHANGELOG.md` untouched
  and inserts above the first section;
- **the whole chain joins up**: release-please's updaters were applied to a copy of this tree for
  a `0.2.0` release and `check-release-versions.mjs v0.2.0` — the exact command `release.yml` runs
  before packing — passes on the result, and still fails for `v0.3.0`;
- `check-commit-messages.mjs` accepts and rejects the intended messages, including every type the
  release config declares, `!`, `BREAKING CHANGE:` footers, merge/revert/release-please subjects,
  and the six real historical subjects that parse as nothing
  (`packages/core/test/commit-messages.test.ts`, 36 cases, in `pnpm test`);
- `check-release-versions.mjs` fails on each of: a lockstep break, a caret internal dep, a
  drifted release-please manifest, a package on disk that is missing from the release config, a
  removed `linked-versions` plugin, an added `node-workspace` plugin, a shipped README with a
  link that climbs out of its package, and — only when a tag is supplied — a shipped README that
  still says the package is unpublished.

And what a full **publish rehearsal** verified against the real `0.1.0` tarballs — every shell
step in `release.yml`'s `publish` job, run verbatim outside Actions:

- all four packages pack with `pnpm pack`; `workspace:*` is rewritten to the exact pin `0.1.0`
  in `core` and `cli`, and no `workspace:` string survives into any tarball;
- `check-tarball-sources.mjs` reports **0 dangling** across 96 maps (68 core, 20 cli, 6
  policy-schema, 2 sbom-import), and every tarball carries `dist/`, `src/`, `LICENSE` and
  `README.md`; `policy-schema` also carries `schema.json`;
- **nothing leaks.** `files` is an allowlist, so the 79 committed `node_modules/` fixture files
  under `packages/*/test/` and `examples/malicious-dep-demo/` cannot reach a tarball, and do not;
- `npm publish --dry-run ./<tarball> --access public` succeeds for all three, each reporting
  *"with tag latest and public access"* — `publishConfig.access` is doing its job;
- the missing-`./` failure reproduces exactly as documented: exit **128**, `git ls-remote
  ssh://git@github.com/dist-tarballs/capwall-cli-0.1.0.tgz.git`;
- the tarballs install into a bare `npm init -y` directory in dependency order and `npx capwall`
  drives the whole documented loop — `observe` writes a `capabilities.json` whose `$schema`
  resolves, `enforce` denies an ungranted `fs:read`, `diff` reports no drift, `explain` answers
  both ways;
- **the ESM path works from the tarball layout**, not just CJS: an `.mjs` entry importing two
  ESM-only dependencies attributes `env:XDG_*` to `env-paths` under `observe` and is denied under
  `enforce`. `esm-runtime.js` ships beside `esm-hook.js`, so the bridge URL resolves, and
  `CAPWALL_ROOT` narrows to `<pkg>/dist` rather than widening (#171);
- publishing out of order is a real failure and not a stylistic one: with only the `cli` tarball
  available, `npm i` dies with `404 '@capwall/core@0.1.0' is not in this registry`.

All six of the following were, at one point, items that could not be verified without pushing to
GitHub and running Actions. They have now been checked for real, not dry-run:

1. **That `release-please.yml` opens a PR at all.** Verified: it opened release PR #206 on
   `main`. The action's permissions and the repository's "Allow GitHub Actions to create and
   approve pull requests" setting do let it write.
2. **That the tag actually starts `release.yml`.** **Disproved, as predicted.** This was
   documented as the one step with a known failure mode — a tag pushed with the default
   `GITHUB_TOKEN` does not trigger other workflows, by design — and that is exactly what
   happened: merging PR #206 created tag `v0.1.1`, and `release.yml` did not start on its own.
   The release went out via a manual `workflow_dispatch` instead. Whether to close this gap with
   a `RELEASE_PLEASE_TOKEN` (checklist step 5) or keep the manual dispatch as the accepted norm
   is the open decision tracked in issue #207 — see § How a release happens.
3. **The pinned action SHAs.** Now exercised: `ci.yml` is green on the full Node 22/24/26 matrix
   on `main` and on a release-please PR branch; `release-please.yml` ran on `main` (PR #206, tag
   `v0.1.1`); `commit-conventions.yml` ran on a PR branch; `release.yml`'s verify (22/24/26) and
   publish jobs both went green (run 30600809316). That proves these pins resolve and the actions
   work end to end — it does not prove the SHAs are the only right choice, or that a moved tag on
   one of them is impossible (see ci.yml's header).
4. **Everything downstream of the tag.** Verified by the same run: OIDC trusted publishing
   worked, provenance was attached, and the `verify` matrix ran in Actions rather than only in
   `pnpm ci:local`. `release.yml` published `@capwall/policy-schema`, `@capwall/core` and
   `@capwall/cli` at `0.1.1`.
5. **`--provenance` itself.** Verified by the real publish, not just the dry run that could not
   reach this step: `npm audit signatures` reports verified signatures and verified attestations
   for `0.1.1`, and the attestation binds to
   `git+https://github.com/capwall/capwall@refs/tags/v0.1.1`, built by
   `.github/workflows/release.yml` on a GitHub-hosted runner. `0.1.0` — published manually, see
   § THE FIRST MANUAL PUBLISH — carries no such attestation; the contrast is the proof that this
   step is doing something real rather than always no-op succeeding.
6. **`actions/upload-artifact`.** Exercised as part of the same green `release.yml` run; it had
   no local equivalent to rehearse it with beforehand.

---

## Ordering constraint (read before scheduling anything)

npm trusted publishing runs **inside GitHub Actions**. The steps were strictly ordered and the
middle one could not be skipped — this is the order it actually happened in, and the order to
repeat for `@capwall/sbom-import` whenever it joins the publish set:

1. **Actions unblocked** — the repo was transferred to `capwall/capwall` and made public; public
   repos get unlimited standard-runner minutes, so the billing block (#3, closed) no longer
   applied. Nothing else in this list works without it, including release-please.
2. **Repo made public** (#113, closed).
3. **These workflows merged to `main`** — the trusted-publisher form on npmjs.com asks for a
   workflow filename, so `release.yml` had to exist and be on the default branch first.
4. **Human configured the trusted publisher, per package, on npmjs.com** — see the checklist.
5. **Merge the release PR → tag → publish.** In practice the tag alone did not start
   `release.yml` — see § How a release happens and issue #207 — so this step needed a manual
   `workflow_dispatch`.

---

# THE FIRST MANUAL PUBLISH (granular token, no Actions)

**This is what actually published `0.1.0`.** Everything from § How a release happens down to
here describes the OIDC path, which is the norm from `0.1.1` onwards and is what published it —
through `release.yml`, via trusted publishing, with SLSA provenance attached. This section is the
one-time route that was used for `0.1.0`, kept here as the record of how it shipped and as the
manual fallback if trusted publishing ever needs to be bootstrapped again — a new package joining
the publish set, a lost credential, or Actions itself being unavailable.

Why it existed: step 4 of the ordering constraint needs the package to *already exist* on npm for
some flows, and Actions was billing-blocked (issue #3, closed) at the time. So `0.1.0` was
published manually from a workstation with a granular access token, trusted publishing was then
configured (§ HUMAN CHECKLIST C), and every release from `0.1.1` on has run through release-please
and Actions.

This is also the path that cuts `v0.1.0` itself. `.release-please-manifest.json` says `0.1.0`, so
release-please treats it as the baseline and proposes `0.1.1` / `0.2.0` for the *next* release —
it will not cut `0.1.0`, and it should not: that entry in `CHANGELOG.md` is hand-written and
better than anything a generator would produce for 73 commits of pre-adoption history.

## The token, and exactly what it needs

npmjs.com → avatar → **Access Tokens** → *Generate New Token* → **Granular Access Token**.

| Field | Value | Why |
|---|---|---|
| Expiration | 7 days, or the shortest the form offers | It is used once, on one afternoon, and then deleted (checklist step 20). A 90-day token on a laptop is the standing credential capwall exists to argue against. |
| Packages and scopes → Permissions | **Read and write** | Anything less cannot create a package. |
| Packages and scopes → *Select packages* | **the `@capwall` scope**, not individual packages | None of the three packages exist yet, so there is nothing to select by name. Scope-level write is what lets a token create the first version. |
| Organizations | **Read and write** *only if* the `@capwall` org still needs creating | Publishing into an org that already exists needs no org permission. Prefer creating the org in the web UI (checklist step 11) and leaving this at *No access*. |

Then put it somewhere that dies with the terminal, rather than in `~/.npmrc` where `npm config
set` would leave it forever:

```bash
export NPM_CONFIG_USERCONFIG="$(mktemp)"
printf '//registry.npmjs.org/:_authToken=%s\n' 'npm_…' > "$NPM_CONFIG_USERCONFIG"
npm whoami                                 # must print your username, not an error
# ...and when you are done, before closing the terminal:
#   rm -f "$NPM_CONFIG_USERCONFIG"
```

**`export NPM_CONFIG_TOKEN=…` does not work** — it looks like it should, and npm ignores it.
Verified during the rehearsal against an unreachable local registry: with the temp-`.npmrc`
form npm gets as far as `ECONNREFUSED` (auth accepted, transport failed), and with
`NPM_CONFIG_TOKEN` it stops at `ENEEDAUTH: This command requires you to be logged in`. `npm
login` also works and is fine; it just writes to `~/.npmrc`, so remember step 20.

**If the account requires 2FA for writes** (it should — checklist step 10), expect npm to accept
the token without prompting for an OTP: a write-scoped granular token is the credential class
that exists so CI and scripts can publish, which is exactly why the expiry is short and why step
20 deletes it. If npm *does* prompt, answer it — do not go and loosen the 2FA setting. *Neither
branch was verified during the rehearsal; no token was created.*

## The sequence

Run it top to bottom in a clean clone of `main` at the commit you intend to release. Every
command below was executed during the rehearsal against the real `0.1.0` tarballs — the ones
that reach the registry with `--dry-run`, everything else for real.

```bash
# ── 0. Preconditions ─────────────────────────────────────────────────────────────────────
npm install -g npm@latest                  # trusted publishing / --provenance track npm, not Node
node --version                             # use Node 24 — the version release.yml packs on
git status --porcelain                     # must be empty; you are about to ship this tree

# ── 1. Fold and date CHANGELOG.md ────────────────────────────────────────────────────────
# CHANGELOG.md carries BOTH `## [Unreleased]` and `## [0.1.0] - unreleased`. Fold the first
# into the second and replace `unreleased` with today's date (§ Changelog, checklist step 15).
# Until you do, the next command FAILS — by design:
#   release check failed: CHANGELOG.md's '## [0.1.0] - unreleased' carries no ISO date.

# ── 2. Rewrite the shipped READMEs ───────────────────────────────────────────────────────
# npmjs.com renders package/README.md on the package page, and a README can only be changed by
# publishing a NEW VERSION. `packages/cli/README.md` and `packages/policy-schema/README.md` each
# open with a "Not published to npm yet — run it from a clone" note that is false the instant it
# is published, and it is the first paragraph every evaluator reads. Replace both with the
# `npm i -D @capwall/cli` install path. This is checklist step 21 moved BEFORE the publish,
# because after the publish it costs a 0.1.1.
#
# You cannot forget: check-release-versions.mjs check 7 fails on that sentence WHEN A TAG IS
# SUPPLIED — which is the next command, and the one release.yml runs. It also refuses any
# `](../..)` link in a shipped README, always, because those 404 on npmjs.com.

# ── 3. Build and verify ──────────────────────────────────────────────────────────────────
pnpm install --frozen-lockfile
pnpm build
pnpm typecheck && pnpm test && pnpm lint
node scripts/check-release-versions.mjs v0.1.0

# ── 4. Pack — with pnpm, never npm (#116) ────────────────────────────────────────────────
# Pack ALL FOUR. @capwall/sbom-import is not published, but the assertions below need it: a
# held-back package that has quietly stopped packing is a nasty surprise on the release that
# finally publishes it.
rm -rf dist-tarballs && mkdir -p dist-tarballs
for d in packages/*/; do (cd "$d" && pnpm pack --pack-destination ../../dist-tarballs); done
ls -l dist-tarballs

# ── 5. Open the tarballs before anything leaves the machine ──────────────────────────────
node scripts/check-tarball-sources.mjs dist-tarballs/*.tgz
for t in dist-tarballs/*.tgz; do
  tar xzOf "$t" package/package.json | grep -q '"workspace:' \
    && { echo "FAIL: $t still contains a workspace: specifier"; break; }
done
# Expect an EXACT pin written by pnpm — `"@capwall/policy-schema": "0.1.0"`, never `^0.1.0`:
tar xzOf dist-tarballs/capwall-core-0.1.0.tgz package/package.json | grep '@capwall/'
tar xzOf dist-tarballs/capwall-cli-0.1.0.tgz  package/package.json | grep '@capwall/'

# This one must print NOTHING. `files: ["dist","src"]` is an allowlist, so the 79 committed
# node_modules fixtures under packages/*/test/ and examples/malicious-dep-demo/ cannot reach a
# tarball — but the fixtures are git-tracked, so confirm it rather than reasoning about it.
for t in dist-tarballs/*.tgz; do tar tzf "$t" | grep -E 'node_modules|/test/|fixture'; done

# ── 6. Dry-run each publish ──────────────────────────────────────────────────────────────
# THE LEADING `./` IS NOT OPTIONAL. `npm publish dist-tarballs/x.tgz` is parsed as the GitHub
# shorthand <user>/<repo> and exits 128 on a `git ls-remote` of
# ssh://git@github.com/dist-tarballs/capwall-cli-0.1.0.tgz.git.
# NOTE: no --provenance. It requires a trusted CI publisher; see § What a manual publish loses.
for p in $(node scripts/check-release-versions.mjs --publish-list); do
  npm publish ./dist-tarballs/capwall-$p-*.tgz --access public --dry-run
done
# Each must end `Publishing to https://registry.npmjs.org/ with tag latest and public access`.
# "public access" comes from publishConfig.access in the manifest; a scoped package without it
# is rejected as restricted on a free org.

# ── 7. Publish, ONE AT A TIME, IN THIS ORDER, verifying between each ─────────────────────
npm publish ./dist-tarballs/capwall-policy-schema-0.1.0.tgz --access public
npm view @capwall/policy-schema version                 # -> 0.1.0
npm view @capwall/policy-schema dist.tarball

npm publish ./dist-tarballs/capwall-core-0.1.0.tgz --access public
npm view @capwall/core version                          # -> 0.1.0
npm view @capwall/core dependencies                     # -> { '@capwall/policy-schema': '0.1.0' }

npm publish ./dist-tarballs/capwall-cli-0.1.0.tgz --access public
npm view @capwall/cli version                           # -> 0.1.0
npm view @capwall/cli dependencies                      # -> both siblings at exactly 0.1.0
npm view @capwall/cli bin                               # -> { capwall: './dist/index.js' }

# ── 8. Tag, so release-please's baseline matches the registry ────────────────────────────
git tag v0.1.0 && git push origin v0.1.0
```

### Why the order is not a preference

pnpm rewrote `workspace:*` to an **exact** pin, so the published `@capwall/cli@0.1.0` names
`"@capwall/core": "0.1.0"` and nothing else can satisfy it. Publishing `cli` first leaves a
window — minutes, or hours if a publish fails — in which `npm i -D @capwall/cli` is a hard error
for everyone. Rehearsed, in an empty directory, with only the `cli` tarball available:

```
npm error code E404
npm error 404 '@capwall/core@0.1.0' is not in this registry.
```

npm does not *enforce* the order (it does not resolve dependencies at publish time), which is
precisely why nothing but this list will catch it. Publish the leaf first and the tree is
consistent at every intermediate moment.

### Then verify it as a stranger, from the registry

Do this before announcing anything. It is the only check that exercises what a user actually
gets rather than what the workspace contains:

```bash
mkdir /tmp/capwall-smoke && cd /tmp/capwall-smoke && npm init -y
npm i -D @capwall/cli express                       # one install; the siblings come with it
npx capwall --version                               # -> capwall 0.1.0 / @capwall/core 0.1.0
echo 'const fs=require("node:fs");require("express");fs.writeFileSync("out.txt","ok");' > app.js
npx capwall observe -- node app.js
cat capabilities.json                               # $schema must point at a file that EXISTS
npx capwall enforce -- node app.js
npx capwall diff    -- node app.js                  # -> "no drift"

# The ESM path is separate machinery (the loader hook, the synthetic-module bridge, and the
# .cts real-builtins capture) and packing can disturb the file layout all three depend on (#171).
# Exercise a dependency that uses `import`, not just require:
npm i env-paths
printf 'import fs from "node:fs";\nimport p from "env-paths";\np("x");\nfs.writeFileSync("e.txt","ok");\n' > esm.mjs
npx capwall observe -- node esm.mjs                 # must attribute env:XDG_* to 'env-paths'

# And the claim docs/ makes to anyone deciding whether to trust this (#126):
ls node_modules/@capwall/core/src/shims/fs.ts
ls node_modules/@capwall/policy-schema/schema.json
```

`Unsupported URL Type "workspace:"` at `npm i` is the #116 failure and means the version is
unusable. (`workspace:`, the pnpm protocol — an earlier revision of this line said `workflow:`,
which npm never prints, so grepping for it found nothing.)

## What a manual publish loses, and whether to buy it back

**One thing: the provenance attestation.** `--provenance` requires a trusted CI publisher —
npm reads an OIDC token that only GitHub Actions can mint — so a workstation publish cannot
attach one however the flag is spelled. `0.1.0` therefore carries no attestation — confirmed:
`npm audit signatures` does not vouch for it — and "the supply-chain firewall shipped without
provenance" is a fair thing for a reviewer to notice about that one version. A manual publish
also puts a write-capable credential on a laptop, which is the other half of the same argument.

Nothing else is lost. The tarball bytes are identical either way — the same `pnpm pack` produces
them, and `npm publish <tarball>` uploads a finished archive without re-reading anything.
Provenance is metadata *about* the upload, not a property of what is in it.

**Do not republish a patch to gain it.** A `0.1.1` whose only change is "published from CI this
time" is a version number that means nothing, on a package with no installed base, and it makes
the registry's first two entries a story about the publisher rather than about capwall. The
honest sequence is: publish `0.1.0` manually, configure the trusted publishers (§ HUMAN CHECKLIST
C) while it is fresh, and let the first real change — whatever it is — be `0.1.1` **with**
provenance through Actions. Every version anyone actually installs will be attested; exactly one
early version will not, and `CHANGELOG.md` can say so in a line.

**This is exactly what happened.** `0.1.0` was published manually and carries no attestation;
`0.1.1` was published from CI via OIDC trusted publishing and does — the attestation binds to
`git+https://github.com/capwall/capwall@refs/tags/v0.1.1`, built by
`.github/workflows/release.yml` on a GitHub-hosted runner, and `npm audit signatures` reports
verified signatures and verified attestations for it. Exactly one early version carries no
provenance, as predicted; every version from `0.1.1` on does.

---

# HUMAN CHECKLIST

Everything below needs account access. Nothing above this line does. Work top to bottom.

### A. GitHub — one time

1. **Actions billing.** **Done, and not by restoring anything.** The repo was transferred to
   `capwall/capwall` and made public (step 2); public repos get unlimited standard-runner
   minutes, so the billing block (issue #3, closed) no longer applies — there was no separate
   "restore billing" action to take. Until that transfer happened, no workflow ran at all: no CI,
   no release-please PR, no OIDC publish.
2. **Make the repository public.** **Done** — the repo is `capwall/capwall`, public. Settings →
   General → Danger Zone → Change visibility → Public. The tree is MIT and the "malicious"
   fixtures only `console.log`, but **re-run the licence audit rather than trusting this line**
   if the dependency tree has moved since: it once read "all 123 dependencies are
   MIT/ISC/BSD-3-Clause/Apache-2.0" and the lockfile has since grown past 180 entries (vitest 4 /
   vite 8). The rule is not one blanket gate — it is scoped by whether the dependency ships:
   ```bash
   pnpm --filter '@capwall/*' licenses list --prod   # runtime closure: MIT/BSD/Apache-2.0 only
   pnpm licenses list                                # whole tree: no non-compete / source-available, at ANY depth
   ```
   Weak copyleft (MPL-2.0) is acceptable in devDependencies and is present today — vite 8 hard-
   depends on `lightningcss`. See `AGENTS.md` § 5 for the three rules and the accepted trade-off.
3. **Enable private vulnerability reporting.** Settings → Code security → *Private vulnerability
   reporting* → Enable. `SECURITY.md` names this as the reporting channel, and without it the
   only route a reporter has is a public issue — which, for a bypass, is a zero-day with a
   README.
4. **Set the merge strategy to squash, and only squash.** Settings → General → Pull Requests:
   tick *Allow squash merging*, untick *merge commits* and *rebase merging*, and set the squash
   commit message default to **"Pull request title and description"**. Everything about
   conventional commits assumes the PR title becomes the subject on `main`; a merge commit would
   put `Merge pull request #N from …` there instead, and release-please would see nothing.
5. **Create `RELEASE_PLEASE_TOKEN`.** *This is the one step whose absence fails silently.* A tag
   pushed by a workflow using the default `GITHUB_TOKEN` **does not trigger other workflows**, so
   release-please would tag `v0.2.0` and `release.yml` would never start — no publish, no error,
   nothing red.
   - Create a **fine-grained personal access token** (or a GitHub App installation token) scoped
     to this repository with **Contents: Read and write** and **Pull requests: Read and write**.
   - Settings → Secrets and variables → Actions → *New repository secret*, named exactly
     `RELEASE_PLEASE_TOKEN`.
   - Without it, `release-please.yml` still works and says so in its job summary; the tag just has
     to be re-pushed by a human, or `release.yml` run by hand with `dry_run = false`.
   - **Confirmed by `v0.1.1`:** the tag alone did not start `release.yml` — the release needed a
     manual `workflow_dispatch` (§ HUMAN CHECKLIST step 17). Whether to add this token, versus
     keeping the manual dispatch as the accepted norm, is the open decision tracked in issue
     #207; it has not been decided either way yet.
6. **Allow Actions to open pull requests.** Settings → Actions → General → Workflow permissions →
   tick *Allow GitHub Actions to create and approve pull requests*. release-please cannot open the
   release PR otherwise. (A `RELEASE_PLEASE_TOKEN` from step 5 sidesteps this, but tick it anyway
   so the fallback path works.)
7. **Protect `main` and turn `CODEOWNERS` into a gate.** Settings → Rules/Branches → require a
   pull request before merging, and tick **Require review from Code Owners**. `.github/CODEOWNERS`
   only *requests* review until that box is ticked, and the paths it lists are the ones where an
   unreviewed change publishes something irreversible (`release.yml`, the release config, the
   version and tarball guards) or quietly changes what capwall claims to protect
   (`docs/threat-model.md`, `SECURITY.md`).
8. **Merge these workflows** to `main`. `release.yml` must be on the default branch before
   section C — the trusted-publisher form on npmjs.com asks for a workflow filename.
9. *(Optional but recommended.)* Settings → Environments → **New environment** named exactly
   `npm-publish`, and add yourself as a required reviewer. This turns every publish into a
   button you press, which is worth having in front of an action that cannot be undone. The
   workflow already references this environment; if you skip this step GitHub creates it
   implicitly with no protection and publishing still works.

### B. npm — reserve the scope

10. Sign in at npmjs.com with **2FA enabled** (authenticator or hardware key, not SMS).
11. **Create the `@capwall` organisation**: npmjs.com → your avatar → *Add organization* →
   name `capwall`, free plan. The free plan only allows *public* packages, which is what you
   want. Do this before the repo goes public — an unclaimed scope on a public security repo
   is squattable.
   - If the name is taken, **stop and file an issue** — the scope appears in every package
     name and in `docs/`, and renaming is not a decision to make at the console.

### C. npm — configure trusted publishing, per package

Do this **three times**, once for each of `@capwall/policy-schema`, `@capwall/core`,
`@capwall/cli` — the packages that are actually published. `@capwall/sbom-import` is held back
from `0.1.0` (see § What is published), so it has no registry entry to configure yet; do this
for it on the release that first publishes it.

```bash
node scripts/check-release-versions.mjs --publish-list   # the authoritative list
```

12. Package page → **Settings** → **Trusted Publisher** → *GitHub Actions*, and enter:

    | Field | Value |
    |---|---|
    | Organization or user | `capwall` |
    | Repository | `capwall` |
    | Workflow filename | `release.yml` |
    | Environment | `npm-publish` if you created it in step 9, otherwise leave blank |

    The workflow filename is the bare name, not a path. It must match
    `.github/workflows/release.yml` exactly — **not** `release-please.yml`, which publishes
    nothing.

    **The organisation is `capwall`, the GitHub org the repository moved to — not the personal
    account it was created under.** npm binds a trusted publisher to a literal `<owner>/<repo>`
    and to nothing else: GitHub's post-transfer redirect moves *browsers*, not the OIDC subject
    claim, so a publisher still bound to the old owner does not error, it simply never matches
    and every publish falls back to asking for a token. That is the quiet failure this table
    exists to prevent, and `packages/core/test/repo-identity.test.ts` now checks these two rows
    against the root manifest's `repository.url` so the next rename cannot leave them behind.

13. On the same settings page set **Publishing access** to *Require two-factor authentication
    or an automation token*. Do **not** leave a long-lived automation token in repository
    secrets once trusted publishing works — the whole point of OIDC is that there is no
    standing credential to steal.

> If a package does not exist on the registry yet, npm may not offer the Trusted Publisher
> form. That is the chicken-and-egg § THE FIRST MANUAL PUBLISH above solves: publish `0.1.0`
> from a workstation with a granular token, then come back and do steps 12–13 for each package.

### D. Cutting a release

> **Cutting `0.1.0` by hand instead?** Steps 14–19 describe the OIDC path and need Actions.
> Go to § THE FIRST MANUAL PUBLISH and run that sequence; it covers steps 15 and 19 itself, and
> steps 16–18 do not apply. Come back to section C afterwards — the trusted-publisher form
> appears once the packages exist.

14. **Nothing to prepare.** Merge PRs with conventional titles; release-please keeps a release PR
    open and up to date on every push to `main`. Read it: it names the version and shows the
    CHANGELOG diff.
15. **Only for a hand-cut `v0.1.0`: fold `[Unreleased]` in, then date the entry.**
    `CHANGELOG.md` carries **both** a populated `## [Unreleased]` section and the
    `## [0.1.0] - unreleased` heading below it — everything merged since that entry was first
    written lives in the former, so dating the `0.1.0` heading alone would ship a release whose
    changelog omits all of it. Fold `[Unreleased]`'s entries into the `0.1.0` section and
    replace `unreleased` with today's date. Then verify — the check refuses an undated heading
    when a tag is supplied, which is the whole point:
    ```bash
    node scripts/check-release-versions.mjs v0.1.0
    ```
    Every release after that is generated; there is no `[Unreleased]` section to fold.
16. **Rehearse, before the first real one.** Actions → *Release* → *Run workflow*, leaving
    **Dry run = true**. This runs the full matrix, packs with pnpm, asserts no `workspace:` string
    survived, asserts every source map resolves inside its own tarball, and calls
    `npm publish --dry-run` for the published set only. Nothing is uploaded. Download the
    `capwall-tarballs` artifact and look inside if you want to be sure — note it contains a
    `@capwall/sbom-import` tarball that is packed for verification and deliberately **not**
    published.
17. **Merge the release PR.** release-please tags `vX.Y.Z` and creates the GitHub release from the
    generated notes. Watch the Actions tab: `release.yml` must start within about a minute. **If
    it does not, step 5 was skipped** — re-push the tag by hand
    (`git push --delete origin vX.Y.Z && git tag -f vX.Y.Z <sha> && git push origin vX.Y.Z`) or run
    *Release* by hand with `dry_run = false`.
18. If you created the `npm-publish` environment, approve the run when GitHub asks.
19. **Verify the result** before announcing anything:
    ```bash
    npm view @capwall/cli version
    npm view @capwall/cli dist.tarball
    # provenance should be present:
    npm audit signatures --registry https://registry.npmjs.org
    ```
    Then the real test — install it as a stranger would, in an empty directory:
    ```bash
    mkdir /tmp/capwall-smoke && cd /tmp/capwall-smoke && npm init -y
    npm i -D @capwall/cli express
    echo 'const fs=require("node:fs");require("express");fs.writeFileSync("out.txt","ok");' > app.js
    npx capwall observe -- node app.js
    npx capwall enforce -- node app.js
    ```
    If `npm i` fails with `Unsupported URL Type "workspace:"` the guard was bypassed somehow —
    that is the #116 failure, and it means the version is unusable. (`workspace:`, the pnpm
    protocol — an earlier revision of this line said `workflow:`, which npm never prints, so
    grepping for it found nothing.)

    Then confirm the sources really shipped, because it is the claim `docs/` now makes to
    anyone deciding whether to trust this:
    ```bash
    ls node_modules/@capwall/core/src/shims/fs.ts
    ```

### E. Afterwards

20. Delete any granular access token used for a manual first publish.
21. Update the **root** `README.md`: replace the "nothing is published" note and the from-clone
    quickstart with `npm i -D @capwall/cli`, keeping the clone path as the contributor route.
    The root README is not in any tarball, so this one really is an afterwards job.
    **`packages/policy-schema/README.md` and `packages/cli/README.md` are not** — they ship
    inside the tarballs and are what npmjs.com renders on the package page, and a README on the
    registry can only be changed by publishing a new version. Both carry a "Not published to npm
    yet — run it from a clone" note that is false the moment it is published. Rewrite them
    **before** packing (§ THE FIRST MANUAL PUBLISH step 2, or a PR merged before the release
    PR). Doing it here instead costs a `0.1.1` whose only content is a paragraph.
22. Nothing to do to `CHANGELOG.md`. There is no `[Unreleased]` section to reopen — release-please
    creates the next section when the next releasable commit lands.
