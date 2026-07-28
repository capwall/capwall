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
`scripts/check-release-versions.mjs` (versions, pins, publish set, changelog) and
`scripts/check-tarball-sources.mjs` (what is actually inside the tarballs). Both run in the
release workflow before anything is uploaded. Read them; they carry the reasoning inline.

---

## The two things that make this repo unusual

**1. `pnpm` packs, `npm` publishes.** The four packages depend on each other with pnpm's
`workspace:*` protocol. Only pnpm rewrites that to a concrete version when it builds a
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
  ...
npm error command failed
```

**2. The workflow filename is part of the trust configuration.** npm trusted publishing binds
a package to a repository *and a specific workflow filename*. Renaming
`.github/workflows/release.yml`, or moving the publish step elsewhere, breaks publishing for
all four packages until each one is reconfigured by hand on npmjs.com.

---

## Versioning

**Lockstep, semver, starting at `0.1.0`.** `scripts/check-release-versions.mjs` enforces all
of it and the release workflow runs it before packing.

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
  that is the property worth having.
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
internal dep by hand is the mistake `check-release-versions.mjs` catches.

The `capabilities.json` `"version": 1` field is **independent** of the package version and does
not move with it — a capwall `0.2.0` still reads `"version": 1` policies. This is stated at the
top of `CHANGELOG.md` too, because otherwise the first `0.2.0` makes someone bump their policy.

## What is published

| package | published | why |
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

The publish set lives in `scripts/check-release-versions.mjs` (`--publish-list`) and the
workflow reads it from there, so there is one list rather than two that can disagree. The
guard also refuses to let a published package depend on a held-back one — pnpm would rewrite
the specifier to a version that is not on the registry and the tarball would be uninstallable
for everyone.

## Source maps — the tarballs ship `src/` (#126)

`"files": ["dist", "src"]` in all four manifests. **The published packages contain their
TypeScript sources.** That is a decision, not an oversight, and it is worth understanding
before anyone "trims" the tarball.

`tsconfig.base.json` sets `sourceMap` and `declarationMap`, so the build emits a `.js.map`
and a `.d.ts.map` beside every output file, and each one names its input as `../src/x.ts`.
Shipping only `dist` meant all 66 maps in `@capwall/core` resolved to nothing — 22% of the
tarball delivering no function, and `.d.ts.map` in particular being *worse* than no map,
because "go to definition" follows it to a file that is not there instead of falling back to
the real `.d.ts`.

The two honest fixes were "ship the sources" and "ship neither". Sources won:

- **`inlineSources` is not a third option.** It embeds sources in `.js.map` only; tsc never
  writes `sourcesContent` into a `.d.ts.map` (verified against tsc 5.9). It would fix stack
  traces under `--enable-source-maps` and leave the go-to-definition case exactly as broken.
- **Auditability is the product.** capwall's pitch is supply-chain trust. `npm i -D
  @capwall/cli` and you can read every line that mediates your `fs` calls, and diff the
  shipped `dist` against the shipped `src`, without cloning anything. A security tool that
  ships only minified-by-omission output is asking for a trust it will not extend.
- **The cost is small in absolute terms.** All four tarballs together went from 327 kB to
  511 kB compressed (+56%); `@capwall/core` went from 262 kB to 425 kB. This is a
  devDependency installed once per project, not something on a hot path.

`scripts/check-tarball-sources.mjs` enforces it, and the release workflow runs it on the
packed tarballs before anything is uploaded. To check by hand:

```bash
for p in policy-schema core sbom-import cli; do
  (cd "packages/$p" && pnpm pack --pack-destination ../../dist-tarballs)
done
node scripts/check-tarball-sources.mjs dist-tarballs/*.tgz
```

## Changelog

One `CHANGELOG.md` at the repo root, [Keep a Changelog](https://keepachangelog.com/) format,
hand-written. **No generator**, deliberately: the entries worth reading say what a change means
for someone running capwall, and nothing that reads commit subjects can write those. A scheme
that needs tooling nobody runs produces a changelog nobody trusts.

- PRs that change behaviour add a line under `## [Unreleased]`, using
  `Added` / `Changed` / `Deprecated` / `Removed` / `Fixed` / `Security`.
- A `Security` heading is not optional here — "capwall stopped mediating X" is a
  security-relevant regression for every user and has to be findable without reading the diff.
- Cut a release by renaming `[Unreleased]` to `[X.Y.Z] - unreleased`, then replacing
  `unreleased` with the ISO date on the day you tag.

`check-release-versions.mjs` fails if there is no `## [<version>]` section, and — once a tag is
being released — fails if that heading still says `unreleased` instead of a `YYYY-MM-DD` date.
Forgetting the changelog at the moment it matters is the characteristic failure of a
hand-written one, so it is the one part not left to discipline.

---

## What has to be true before the first publish

Blocking — a broken or dangerous first artifact:

| | |
|---|---|
| #116 | `npm pack` ships `workspace:*`. **Fixed**: `prepack` guard + the pack-with-pnpm workflow. |
| #113 | Repo is private. Trusted publishing requires a public repo; the README's only install path is a clone. |
| #115 | No versions, no CHANGELOG, no publish set. **Fixed**: all packages staged at `0.1.0`, `CHANGELOG.md` written, publish set declared once; all enforced by `check-release-versions.mjs`. |
| #126 | Maps shipped without sources. **Fixed**: `"files": ["dist", "src"]`, enforced by `check-tarball-sources.mjs`. Done before the first publish on purpose — `files` decides what a reader can audit, and changing it later silently changes that answer. |
| #3 | Actions is billing-blocked. OIDC publishing *runs in Actions*, so this gates the whole path. |
| LICENSE | Now shipped in all four tarballs. |

Not blocking — ship in `0.1.1`: #124 (README for `policy-schema`),
#119 (`WATCH_REPORT_DEPENDENCIES` noise), #118 (silent unmatched policy keys),
#122 (pnpm prerequisite).

---

## Ordering constraint (read before scheduling anything)

npm trusted publishing runs **inside GitHub Actions**, which is currently billing-blocked
(#3). The steps are strictly ordered and the middle one cannot be skipped:

1. **Actions billing restored** (#3) — nothing else in this list works without it.
2. **Repo made public** (#113).
3. **This workflow merged to `main`** — the trusted-publisher form on npmjs.com asks for a
   workflow filename, so the file has to exist and be on the default branch first.
4. **Human configures the trusted publisher, per package, on npmjs.com** — see the checklist.
5. **Tag → publish.**

### Alternative: first publish with a granular token, then move to OIDC

Because step 4 requires the package to *already exist* on npm for some flows, and because
#3 may take a while, there is a legitimate shortcut: publish `0.1.0` manually from a
workstation with a granular access token, then configure trusted publishing and let every
release after that run through Actions.

```bash
pnpm install --frozen-lockfile && pnpm build
node scripts/check-release-versions.mjs v0.1.0

# Pack everything (the assertions below need something to inspect)...
for d in packages/*/; do (cd "$d" && pnpm pack --pack-destination ../../dist-tarballs); done
node scripts/check-tarball-sources.mjs dist-tarballs/*.tgz

# ...but publish only the declared set, in the declared order.
for p in $(node scripts/check-release-versions.mjs --publish-list); do
  npm publish ./dist-tarballs/capwall-$p-*.tgz --access public   # no --provenance outside CI
done
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

1. **Restore Actions billing** (issue #3). Settings → Billing. Until this is done, no OIDC
   publish can run at all.
2. **Make the repository public.** Settings → General → Danger Zone → Change visibility →
   Public. (Checked already: the tree is MIT, all 123 dependencies are
   MIT/ISC/BSD-3-Clause/Apache-2.0, and the "malicious" fixtures only `console.log`.)
3. **Merge the release workflow** to `main`. It must be on the default branch before step C.
4. *(Optional but recommended.)* Settings → Environments → **New environment** named exactly
   `npm-publish`, and add yourself as a required reviewer. This turns every publish into a
   button you press, which is worth having in front of an action that cannot be undone. The
   workflow already references this environment; if you skip this step GitHub creates it
   implicitly with no protection and publishing still works.

### B. npm — reserve the scope

5. Sign in at npmjs.com with **2FA enabled** (authenticator or hardware key, not SMS).
6. **Create the `@capwall` organisation**: npmjs.com → your avatar → *Add organization* →
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

7. Package page → **Settings** → **Trusted Publisher** → *GitHub Actions*, and enter:

   | Field | Value |
   |---|---|
   | Organization or user | `williamzujkowski` |
   | Repository | `capwall` |
   | Workflow filename | `release.yml` |
   | Environment | `npm-publish` if you created it in step 4, otherwise leave blank |

   The workflow filename is the bare name, not a path. It must match
   `.github/workflows/release.yml` exactly.

8. On the same settings page set **Publishing access** to *Require two-factor authentication
   or an automation token*. Do **not** leave a long-lived automation token in repository
   secrets once trusted publishing works — the whole point of OIDC is that there is no
   standing credential to steal.

> If a package does not exist on the registry yet, npm may not offer the Trusted Publisher
> form. That is the chicken-and-egg the "granular token" alternative above solves: publish
> `0.1.0` manually, then come back and do steps 7–8 for each package.

### D. Cutting a release

9. **Date the changelog entry.** For `0.1.0` the manifests are already staged and
   `CHANGELOG.md` already has its entry, so the only edit left is replacing `unreleased` with
   today's date on the `## [0.1.0] -` heading. (For later releases: bump every
   `packages/*/package.json` to the same value and rename `[Unreleased]` first.) Then verify —
   the check refuses an undated heading when a tag is supplied, which is the whole point:
   ```bash
   node scripts/check-release-versions.mjs v0.1.0
   ```
10. **Rehearse.** Actions → *Release* → *Run workflow*, leaving **Dry run = true**. This runs
    the full matrix, packs with pnpm, asserts no `workspace:` string survived, asserts every
    source map resolves inside its own tarball, and calls `npm publish --dry-run` for the
    published set only. Nothing is uploaded. Download the `capwall-tarballs` artifact and look
    inside if you want to be sure — note it contains a `@capwall/sbom-import` tarball that is
    packed for verification and deliberately **not** published.
11. Merge the version bump, then tag and push:
    ```bash
    git tag v0.1.0 && git push origin v0.1.0
    ```
12. If you created the `npm-publish` environment, approve the run when GitHub asks.
13. **Verify the result** before announcing anything:
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
    If `npm i` fails with `Unsupported URL Type "workflow:"` the guard was bypassed somehow —
    that is the #116 failure, and it means the version is unusable.

    Then confirm the sources really shipped, because it is the claim `docs/` now makes to
    anyone deciding whether to trust this:
    ```bash
    ls node_modules/@capwall/core/src/shims/fs.ts
    ```
14. Create the GitHub release from the tag, body pointing at the `CHANGELOG.md` entry.

### E. Afterwards

15. Delete any granular access token used for a manual first publish.
16. Update the README: replace the "nothing is published" note and the from-clone quickstart
    with `npm i -D @capwall/cli`, keeping the clone path as the contributor route. Also update
    `packages/policy-schema/README.md` and `packages/cli/README.md`, which each carry their own
    "not published yet" note.
17. Open the `[Unreleased]` section in `CHANGELOG.md` for the next cycle.
