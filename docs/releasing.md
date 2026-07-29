# Releasing capwall

How the four packages get to npm, and — kept deliberately separate below — the steps only a
person with account access can do.

Nothing has been published yet. The manifests are staged at `0.1.0` and `CHANGELOG.md` carries
its entry, but neither `@capwall/cli` nor `@capwall/core` exists on the registry. The first
release is therefore the one that sets all the precedents, and it is the one that cannot be
undone: **npm's unpublish window is 72 hours and narrow even inside it.** A broken first
version sits in the `@capwall` namespace forever, which is a poor opening argument for a
supply-chain security tool.

Everything a machine can check about a release is checked by
`scripts/check-release-versions.mjs` (lockstep, pins, publish set, changelog, and that
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

`commitlint.config.js` holds the rules; `.github/workflows/commit-conventions.yml` runs them on
every pull request, against **both** the PR title and the individual commits. There is
deliberately **no husky / `commit-msg` hook** — a local hook is opt-in per clone, does not survive
`--no-verify` or a merge performed in the GitHub UI, and would be a second set of rules that can
disagree with the one that decides the release.

The PR title is the important one: this repository squash-merges, so the title is the subject
that reaches `main` and the string release-please reads.

Three deviations from `@commitlint/config-conventional`, each with its reasoning in the config
file: a `security` type is added (mapped to a `### Security` changelog section, because "capwall
stopped mediating X" has always had to be findable without reading the diff), and
`header-max-length` / `body-max-line-length` are **off** rather than raised, because this repo's
subjects name every issue a change closes and its bodies paste measurements and code.

Locally: `pnpm lint:commits` runs the same commitlint over `origin/main..HEAD`. Given #3 that is
the only place these rules are actually enforced today.

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

**Nothing is on the registry yet.** This table is the declared *publish set* — which packages
`0.1.0` will upload when it is cut — not a statement of what npm currently serves. `npm view
@capwall/cli` is a 404 today.

| package | in the publish set | why |
|---|---|---|
| `@capwall/policy-schema` | yes | the schema every consumer validates against |
| `@capwall/core` | yes | the enforcement engine |
| `@capwall/cli` | yes | the entry point everyone actually installs |
| `@capwall/sbom-import` | **held back** | see below |

`@capwall/sbom-import` (roadmap S1) is built, tested, versioned in lockstep and released
in-repo, but does **not** go to the registry in `0.1.0`. No CLI subcommand exposes it; it is
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
| #113 | Repo is private. Trusted publishing requires a public repo; the README's only install path is a clone. |
| #115 | No versions, no CHANGELOG, no publish set. **Fixed**: all packages staged at `0.1.0`, `CHANGELOG.md` written, publish set declared once; all enforced by `check-release-versions.mjs`, and versions now owned by release-please. |
| #126 | Maps shipped without sources. **Fixed**: `"files": ["dist", "src"]`, enforced by `check-tarball-sources.mjs`. Done before the first publish on purpose — `files` decides what a reader can audit, and changing it later silently changes that answer. |
| #3 | Actions is billing-blocked. OIDC publishing *runs in Actions*, so this gates the whole path — **and it gates release-please too**, which is a workflow like any other. |

Not blocking, and all four have since **landed** rather than waiting for `0.1.1`: #124
(`packages/policy-schema/README.md` exists; `cli/src/trace.ts` writes the `$schema` pointer),
#119 (env reads Node initiates are no longer recorded), #118 (`capwall observe`/`diff` report
unmatched policy keys, and `diff --strict` fails on them), #122 (the root `preinstall` guard
refuses an `npm install`). Nothing on this list is outstanding for `0.1.0`.

## What is still unverified until #3 is resolved

Stated plainly, because "the release config is verified" is exactly the claim that must not be
overstated. What **was** verified, locally, against release-please 17.6.0 (the version bundled by
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
- `commitlint` accepts and rejects the intended messages (`pnpm lint:commits`);
- `check-release-versions.mjs` fails on each of: a lockstep break, a caret internal dep, a
  drifted release-please manifest, a package on disk that is missing from the release config, a
  removed `linked-versions` plugin, an added `node-workspace` plugin.

What **cannot** be verified without pushing to GitHub and running Actions:

1. **That `release-please.yml` opens a PR at all.** A dry run proves what release-please would
   compute; it does not prove that the action's permissions (`contents: write`,
   `pull-requests: write`) and the repository's "Allow GitHub Actions to create and approve pull
   requests" setting let it write. Proof: the first push to `main` after this merges should
   produce a release PR (or the "no releasable commits" summary line).
2. **That the tag actually starts `release.yml`.** This is the one with a known failure mode: a
   tag pushed with the default `GITHUB_TOKEN` **does not trigger other workflows**, by design.
   Proof: after the first release PR is merged, `release.yml` appears in the Actions tab within a
   minute. If it does not, the `RELEASE_PLEASE_TOKEN` secret is missing — checklist step 5.
3. **The pinned action SHAs.** `googleapis/release-please-action@v5.0.0` has never run here, for
   the same reason every other pin in `ci.yml` has never run (see its header).
4. **Everything downstream of the tag** that was already unverified: OIDC trusted publishing,
   provenance attachment, and the `verify` matrix in Actions rather than in `pnpm ci:local`.

---

## Ordering constraint (read before scheduling anything)

npm trusted publishing runs **inside GitHub Actions**, which is currently billing-blocked
(#3). The steps are strictly ordered and the middle one cannot be skipped:

1. **Actions billing restored** (#3) — nothing else in this list works without it, including
   release-please.
2. **Repo made public** (#113).
3. **These workflows merged to `main`** — the trusted-publisher form on npmjs.com asks for a
   workflow filename, so `release.yml` has to exist and be on the default branch first.
4. **Human configures the trusted publisher, per package, on npmjs.com** — see the checklist.
5. **Merge the release PR → tag → publish.**

### Alternative: first publish with a granular token, then move to OIDC

Because step 4 requires the package to *already exist* on npm for some flows, and because
#3 may take a while, there is a legitimate shortcut: publish `0.1.0` manually from a
workstation with a granular access token, then configure trusted publishing and let every
release after that run through release-please and Actions.

This is also the path that cuts `v0.1.0` itself. `.release-please-manifest.json` says `0.1.0`, so
release-please treats it as the baseline and proposes `0.1.1` / `0.2.0` for the *next* release —
it will not cut `0.1.0`, and it should not: that entry in `CHANGELOG.md` is hand-written and
better than anything a generator would produce for 73 commits of pre-adoption history.

**Which Node and npm.** The workflow verifies on the full **22 / 24 / 26** matrix but packs and
publishes on **Node 24**, and it upgrades npm to `@latest` first — deliberately, and not because
Node 24's bundled npm is too old to work. Trusted publishing and `--provenance` track npm's own
releases, so a manual publish should do the same rather than trusting whatever npm your Node
shipped with:

```bash
npm install -g npm@latest        # trusted publishing / --provenance track npm, not Node
pnpm install --frozen-lockfile && pnpm build

# Date the 0.1.0 heading in CHANGELOG.md first (see § Changelog), then:
node scripts/check-release-versions.mjs v0.1.0

# Pack everything (the assertions below need something to inspect)...
for d in packages/*/; do (cd "$d" && pnpm pack --pack-destination ../../dist-tarballs); done
node scripts/check-tarball-sources.mjs dist-tarballs/*.tgz

# ...but publish only the declared set, in the declared order.
for p in $(node scripts/check-release-versions.mjs --publish-list); do
  npm publish ./dist-tarballs/capwall-$p-*.tgz --access public   # no --provenance outside CI
done

git tag v0.1.0 && git push origin v0.1.0   # so release-please's baseline matches the registry
```

**Recommendation: wait for OIDC if #3 will be resolved in days; take the token path if it
will be weeks.** The trade is real and worth naming. A manual publish cannot attach a
provenance attestation — provenance requires a trusted CI publisher — so `0.1.0` would ship
without one, and "the supply-chain firewall shipped without provenance" is a fair thing for a
reviewer to notice. It also puts a long-lived credential on a laptop, which is the exact
threat model capwall exists to talk about. Neither is fatal, and `0.1.1` would carry
provenance either way, but if the wait is short the OIDC path is strictly better.

---

# HUMAN CHECKLIST

Everything below needs account access. Nothing above this line does. Work top to bottom.

### A. GitHub — one time

1. **Restore Actions billing** (issue #3). Settings → Billing. Until this is done, no workflow
   runs at all: no CI, no release-please PR, no OIDC publish.
2. **Make the repository public.** Settings → General → Danger Zone → Change visibility →
   Public. The tree is MIT and the "malicious" fixtures only `console.log`, but **re-run the
   licence audit rather than trusting this line**: it once read "all 123 dependencies are
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
    | Organization or user | `williamzujkowski` |
    | Repository | `capwall` |
    | Workflow filename | `release.yml` |
    | Environment | `npm-publish` if you created it in step 9, otherwise leave blank |

    The workflow filename is the bare name, not a path. It must match
    `.github/workflows/release.yml` exactly — **not** `release-please.yml`, which publishes
    nothing.

13. On the same settings page set **Publishing access** to *Require two-factor authentication
    or an automation token*. Do **not** leave a long-lived automation token in repository
    secrets once trusted publishing works — the whole point of OIDC is that there is no
    standing credential to steal.

> If a package does not exist on the registry yet, npm may not offer the Trusted Publisher
> form. That is the chicken-and-egg the "granular token" alternative above solves: publish
> `0.1.0` manually, then come back and do steps 12–13 for each package.

### D. Cutting a release

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
21. Update the README: replace the "nothing is published" note and the from-clone quickstart
    with `npm i -D @capwall/cli`, keeping the clone path as the contributor route. Also update
    `packages/policy-schema/README.md` and `packages/cli/README.md`, which each carry their own
    "not published yet" note.
22. Nothing to do to `CHANGELOG.md`. There is no `[Unreleased]` section to reopen — release-please
    creates the next section when the next releasable commit lands.
