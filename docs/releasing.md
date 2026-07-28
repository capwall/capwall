# Releasing capwall

How the four packages get to npm, and — kept deliberately separate below — the steps only a
person with account access can do.

Nothing has been published yet. Every package is at `0.0.0` and neither `@capwall/cli` nor
`@capwall/core` exists on the registry. The first release is therefore the one that sets all
the precedents, and it is the one that cannot be undone: **npm's unpublish window is 72 hours
and narrow even inside it.** A broken first version sits in the `@capwall` namespace forever,
which is a poor opening argument for a supply-chain security tool.

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

**Lockstep, semver, starting at `0.1.0`.** `scripts/check-release-versions.mjs` enforces
lockstep and refuses to publish `0.0.0`; the release workflow runs it before packing.

- **Lockstep** because the four packages are one product on one cadence. `@capwall/cli` does
  not merely call `@capwall/core`, it injects it into a *different process* via
  `NODE_OPTIONS=--import` — a mismatched core is a silently differently-behaving firewall.
  Same argument for `@capwall/policy-schema`: `core`'s evaluator and `cli`'s generator must
  agree byte-for-byte on what a policy key means, and a range would let a resolver seat two
  different copies in one tree.
- **Exact pins between the four**, which is what pnpm's `workspace:*` rewrite produces
  (`"@capwall/core": "0.1.0"`, not `^0.1.0`). Caret ranges for third-party deps — `zod` is
  the only one.
- **`0.x`, not `1.0.0`.** `1.0.0` is a compatibility promise, and the policy format is still
  moving: `packages` key semantics changed in #92, `ipc.paths` arrived in #72, `net.hosts`
  globs in #83. Stay on `0.x` until the format has been through outside hands.
- The `capabilities.json` `"version": 1` field is **independent** of the package version and
  does not move with it.

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

One `CHANGELOG.md` at the repo root, Keep-a-Changelog format, with an `## [Unreleased]`
section that PRs add to. A `Security` heading is not optional here — "capwall stopped
mediating X" is a security-relevant regression and has to be findable. Cut a release by
renaming `[Unreleased]` to `[0.1.0] - YYYY-MM-DD`.

---

## What has to be true before the first publish

Blocking — a broken or dangerous first artifact:

| | |
|---|---|
| #116 | `npm pack` ships `workspace:*`. **Fixed**: `prepack` guard + the pack-with-pnpm workflow. |
| #113 | Repo is private. Trusted publishing requires a public repo; the README's only install path is a clone. |
| #115 | Versions are `0.0.0`, no CHANGELOG. Enforced by `check-release-versions.mjs`. |
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
node scripts/check-release-versions.mjs
for p in policy-schema core sbom-import cli; do
  (cd "packages/$p" && pnpm pack --pack-destination ../../dist-tarballs)
done
for p in policy-schema core sbom-import cli; do
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

Do this **four times**, once for each of `@capwall/policy-schema`, `@capwall/core`,
`@capwall/sbom-import`, `@capwall/cli`.

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

9. Set the version in all four `packages/*/package.json` to the same value, and update
   `CHANGELOG.md`. Verify locally:
   ```bash
   node scripts/check-release-versions.mjs v0.1.0
   ```
10. **Rehearse.** Actions → *Release* → *Run workflow*, leaving **Dry run = true**. This runs
    the full matrix, packs with pnpm, asserts no `workspace:` string survived, and calls
    `npm publish --dry-run`. Nothing is uploaded. Download the `capwall-tarballs` artifact and
    look inside if you want to be sure.
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
14. Create the GitHub release from the tag, body pointing at the `CHANGELOG.md` entry.

### E. Afterwards

15. Delete any granular access token used for a manual first publish.
16. Update the README: replace the "nothing is published" note and the from-clone quickstart
    with `npm i -D @capwall/cli`, keeping the clone path as the contributor route.
