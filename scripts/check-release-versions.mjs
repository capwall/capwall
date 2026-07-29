/**
 * Pre-publish guard: everything about a release that can be checked from the repo, checked
 * before the first byte reaches the registry.
 *
 * WHY. Publishing is not atomic and it is not reversible. `.github/workflows/release.yml`
 * pushes tarballs one at a time; npm's unpublish window is 72 hours and narrow inside it. If
 * the third publish fails because one manifest is at a different version, the registry is left
 * half-released and the only way out is a new version number. Checking first costs nothing;
 * checking after is not a thing you can do.
 *
 * WHAT THIS SCRIPT NO LONGER DOES, because release-please took it over (see docs/releasing.md
 * § How a release happens):
 *
 *   - IT NO LONGER TELLS ANYONE TO BUMP A MANIFEST BY HAND. release-please writes all five
 *     `version` fields and `.release-please-manifest.json` in its release PR.
 *   - The `0.0.0` placeholder rule is gone with the workflow that needed it. There is no longer a
 *     hand-staged version waiting to be filled in; the manifest file is the current version and
 *     release-please computes the next one from the commits.
 *   - The changelog "you forgot to replace `unreleased` with a date" rule is gone. release-please
 *     dates the heading when it writes it. What survives is the weaker, still-useful assertion
 *     that a dated section for THIS version exists at all — which is what catches a tag pushed
 *     for a version release-please never released.
 *
 * WHAT IT STILL ENFORCES, and the decision behind each (issue #115, docs/releasing.md):
 *
 *   1. LOCKSTEP, VERIFIED RATHER THAN ASSUMED. All four package manifests, the private root
 *      manifest and `.release-please-manifest.json` carry the same version — including the
 *      package that is not published (see 4). release-please PRODUCES this by writing all five
 *      from one root component (check 6); a package added to `packages/` and not to the release
 *      config, or a hand edit, lands here rather than on the registry. The four packages are one
 *      product on one cadence: `@capwall/cli` does not merely call `@capwall/core`, it injects it
 *      into a *different process* via NODE_OPTIONS, so a mismatched core is a silently
 *      differently-behaving firewall.
 *
 *   2. EXACT PINS BETWEEN THE FOUR, expressed as `workspace:*`, which pnpm rewrites to the
 *      concrete version at pack time (`"@capwall/core": "0.1.0"`, not `^0.1.0`). A range would
 *      let a resolver seat one `@capwall/policy-schema` under `core` and a different one under
 *      `cli` in the same tree, and the failure mode is a policy that generates one way and
 *      evaluates another. Writing a caret here by hand is one way to break it; adding
 *      release-please's `node-workspace` plugin is the other, and check 6 refuses that at the
 *      config rather than waiting for the tarball. Caret ranges are correct for third-party
 *      deps; `zod` is the only one.
 *
 *   3. NO PUBLISHED PACKAGE MAY DEPEND ON A HELD-BACK ONE. Cheap check, unrecoverable
 *      failure: pnpm would rewrite the specifier to a version that is not on the registry and
 *      the published package would be uninstallable for everyone.
 *
 *   4. THE PUBLISH SET IS DECLARED HERE, once, and the workflow asks for it (`--publish-list`)
 *      rather than repeating it. release-please knows nothing about it and must not:
 *      `@capwall/sbom-import` is deliberately not published yet — no CLI subcommand exposes it,
 *      so it would land on npm as an unreachable library and be republished on every lockstep
 *      release forever — while still being versioned, packed and verified like the rest.
 *
 *   5. A DATED CHANGELOG SECTION EXISTS FOR THIS VERSION. Accepts both spellings: release-please
 *      writes `## [0.2.0](https://.../compare/v0.1.0...v0.2.0) (2026-08-01)`, the hand-written
 *      sections up to 0.1.0 read `## [0.1.0] - 2026-08-01`.
 *
 *   7. THE SHIPPED READMEs ARE FIT TO BE THE PACKAGE PAGE. `files` includes `README.md`, so each
 *      published package's README is what npmjs.com renders, and a README on the registry can
 *      only be changed by publishing a NEW VERSION — there is no edit button. Two mistakes are
 *      therefore permanent under a version number and are checked here:
 *
 *        a. RELATIVE LINKS OUT OF THE PACKAGE (`](../../docs/x.md)`). They resolve on GitHub and
 *           404 on npmjs.com, which renders the README at a URL that has no repository above it.
 *           Checked always — there is no state of the world in which one of these works.
 *        b. A "NOT PUBLISHED YET" NOTE. True today, self-refuting the instant it is published,
 *           and the first paragraph an evaluator reads on the package page. Checked ONLY when a
 *           tag is supplied, exactly like the changelog-date rule above: the note is honest
 *           right up until the release that makes it false, so the gate belongs at the moment of
 *           irreversibility and not before it.
 *
 *      Found by the 0.1.0 publish rehearsal: `@capwall/core` shipped 7 dead links and
 *      `@capwall/cli` 5, and `cli`/`policy-schema` both opened with "Not published to npm yet —
 *      run it from a clone". None of it is catchable by build, test, typecheck or lint.
 *
 *   6. RELEASE-PLEASE'S OWN CONFIGURATION STILL HAS THE SHAPE LOCKSTEP DEPENDS ON. One package
 *      (`"."`), a bare `vX.Y.Z` tag, every directory under `packages/` listed in that package's
 *      `extra-files`, and no `node-workspace` plugin. A package added to the workspace but not to
 *      the release config would sit at a stale version forever with every other gate green —
 *      which is exactly the shape of defect that only shows up on a release, i.e. the moment it
 *      cannot be undone.
 *
 * Usage:
 *   node scripts/check-release-versions.mjs [v1.2.3]   run the checks; tag is optional and,
 *                                                      when empty (a workflow_dispatch run),
 *                                                      the changelog date is not required
 *   node scripts/check-release-versions.mjs --publish-list
 *                                                      print the publish order, one name per
 *                                                      line, and exit
 */

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Every package in the workspace, in dependency order. All of them stay in version lockstep. */
const PACKAGES = ["policy-schema", "core", "sbom-import", "cli"];

/**
 * The subset that goes to the registry, in publish order: policy-schema -> core -> cli.
 * npm does not require the order (a version that does not exist yet is not checked at publish
 * time), but it keeps the registry consistent at every intermediate moment if a later publish
 * fails.
 */
const PUBLISHED = ["policy-schema", "core", "cli"];

/** Held back, with the reason, so the next person does not have to go and find it. */
const HELD_BACK = {
  "sbom-import":
    "no CLI subcommand exposes it; it would publish as an unreachable library and be " +
    "republished on every lockstep release. Publishes with its CLI consumer.",
};

if (process.argv[2] === "--publish-list") {
  process.stdout.write(PUBLISHED.join("\n") + "\n");
  process.exit(0);
}

const readJson = (...parts) => JSON.parse(readFileSync(join(ROOT, ...parts), "utf8"));

const manifests = new Map();
for (const p of PACKAGES) {
  manifests.set(p, readJson("packages", p, "package.json"));
}
const rootManifest = readJson("package.json");

const errors = [];

// --- 1. lockstep -------------------------------------------------------------------------
// The private root manifest is in here because release-please's root component is what carries
// the `vX.Y.Z` tag and the CHANGELOG; its version is not cosmetic, it is the release's identity.
const versioned = [
  [rootManifest.name, rootManifest.version],
  ...[...manifests.values()].map((m) => [m.name, m.version]),
];
const distinct = new Set(versioned.map(([, v]) => v));
if (distinct.size !== 1) {
  errors.push(
    `the workspace is not in version lockstep:\n` +
      versioned.map(([n, v]) => `    ${n.padEnd(24)} ${v}`).join("\n") +
      `\n    Held-back packages stay in lockstep too — see docs/releasing.md § What is published.` +
      `\n    release-please's linked-versions plugin produces this; if it has drifted, the config` +
      `\n    is wrong rather than the manifests.`,
  );
}

const version = manifests.get("core").version;

// --- 2 & 3. internal dependency specifiers -----------------------------------------------
const internal = new Set([...manifests.values()].map((m) => m.name));
const heldNames = new Set(Object.keys(HELD_BACK).map((p) => manifests.get(p).name));

for (const [dir, manifest] of manifests) {
  for (const [dep, spec] of Object.entries(manifest.dependencies ?? {})) {
    if (!internal.has(dep)) continue;
    if (spec !== "workspace:*") {
      errors.push(
        `${manifest.name} declares ${dep} as '${spec}', not 'workspace:*'.\n` +
          `    The four packages pin each other EXACTLY. pnpm rewrites 'workspace:*' to the\n` +
          `    concrete version at pack time; anything else publishes a range, and a range lets\n` +
          `    a resolver seat two different copies of ${dep} in one tree.`,
      );
    }
    if (PUBLISHED.includes(dir) && heldNames.has(dep)) {
      errors.push(
        `${manifest.name} is published but depends on ${dep}, which is held back.\n` +
          `    The published tarball would name a version that is not on the registry and would\n` +
          `    be uninstallable. Publish ${dep} or drop the dependency.`,
      );
    }
  }
}

// --- 5. changelog ------------------------------------------------------------------------
const tag = (process.argv[2] ?? "").trim();

let changelog = "";
try {
  changelog = readFileSync(join(ROOT, "CHANGELOG.md"), "utf8");
} catch {
  errors.push(`CHANGELOG.md is missing from the repository root.`);
}

if (changelog !== "") {
  // Two spellings are accepted, because both are in the file: release-please writes
  // `## [0.2.0](https://.../compare/v0.1.0...v0.2.0) (2026-08-01)`, and the hand-written
  // sections up to 0.1.0 read `## [0.1.0] - 2026-08-01`. Scanned line by line rather than built
  // into a RegExp, so a version string never has to be escaped into a pattern.
  const prefix = `## [${version}]`;
  const line = changelog.split("\n").find((l) => l.startsWith(prefix));
  if (line === undefined) {
    errors.push(
      `CHANGELOG.md has no '## [${version}]' section.\n` +
        `    release-please writes one into the release PR. If this fails on a tag, the tag was\n` +
        `    not created from a merged release PR.`,
    );
  } else if (tag !== "" && !/\d{4}-\d{2}-\d{2}/.test(line)) {
    errors.push(
      `CHANGELOG.md's '${line.trim()}' carries no ISO date.\n` +
        `    A tagged release needs a real date (YYYY-MM-DD) on that heading.`,
    );
  }
}

// --- 7. the shipped READMEs are fit to be the package page --------------------------------
// Only the PUBLISHED set: a held-back package's README reaches nobody.
for (const p of PUBLISHED) {
  const rel = `packages/${p}/README.md`;
  let readme;
  try {
    readme = readFileSync(join(ROOT, "packages", p, "README.md"), "utf8");
  } catch {
    errors.push(
      `${rel} is missing. It is in that package's "files", so npm would render an empty page.`,
    );
    continue;
  }

  // (a) always: a link that climbs out of the package resolves nowhere on npmjs.com.
  const escaping = [...readme.matchAll(/\]\((\.\.\/[^)]*)\)/g)].map((m) => m[1]);
  if (escaping.length > 0) {
    const shown = [...new Set(escaping)].slice(0, 4);
    errors.push(
      `${rel} has ${escaping.length} link(s) that climb out of the package: ${shown.join(", ")}` +
        `${escaping.length > shown.length ? ", ..." : ""}\n` +
        `    npmjs.com renders this file with no repository above it, so each one 404s there\n` +
        `    while still working on GitHub. Use an absolute URL:\n` +
        `    https://github.com/williamzujkowski/capwall/blob/main/<path>`,
    );
  }

  // (b) only when cutting a release: a note saying the package is unpublished, published.
  if (tag !== "" && /not published to npm yet/i.test(readme)) {
    errors.push(
      `${rel} still says "Not published to npm yet", and you are cutting ${tag}.\n` +
        `    That sentence is what npmjs.com will show as the package page's opening paragraph,\n` +
        `    and a README can only be corrected by publishing another version. Replace it with\n` +
        `    the install path before packing — see docs/releasing.md § THE FIRST MANUAL PUBLISH.`,
    );
  }
}

// --- 6. release-please configuration agrees with this file --------------------------------
// release-please owns the numbers; this owns the shape. A package that exists on disk but not in
// the release config is versioned by nobody, and nothing else in the repo would notice.
let rpConfig = null;
let rpManifest = null;
try {
  rpConfig = readJson("release-please-config.json");
} catch {
  errors.push(`release-please-config.json is missing or unparseable.`);
}
try {
  rpManifest = readJson(".release-please-manifest.json");
} catch {
  errors.push(`.release-please-manifest.json is missing or unparseable.`);
}

if (rpConfig !== null && rpManifest !== null) {
  const configured = Object.keys(rpConfig.packages ?? {});

  // ONE release-please package, the repository root. This is the shape that makes lockstep
  // structural instead of conditional. release-please's `linked-versions` plugin is the
  // documented way to link a monorepo, and it was tried first — it cannot include a component
  // whose tag is a bare `vX.Y.Z`, because `include-component-in-tag: false` makes the strategy
  // report an EMPTY component and the plugin skips those. The root would then have been versioned
  // on its own, and a commit touching only `scripts/` or `docs/` (`fix(tooling): ...`, which this
  // repo does routinely) would have bumped the root and nothing else. See docs/releasing.md.
  if (configured.length !== 1 || configured[0] !== ".") {
    errors.push(
      `release-please-config.json must declare exactly one package, '.'; it declares\n` +
        `    ${JSON.stringify(configured)}.\n` +
        `    Per-package entries mean per-package versions and per-package tags: release.yml\n` +
        `    listens on 'v*' and would see one tag per package, each starting its own publish.`,
    );
  }
  if (rpConfig.packages?.["."]?.["include-component-in-tag"] === true) {
    errors.push(
      `release-please-config.json sets 'include-component-in-tag' on '.'.\n` +
        `    The tag would become '<component>-vX.Y.Z', which release.yml's 'v*' trigger never\n` +
        `    matches — the release would tag and then silently publish nothing.`,
    );
  }
  if (Object.keys(rpManifest).length !== 1 || rpManifest["."] !== version) {
    errors.push(
      `.release-please-manifest.json should be exactly {".": "${version}"}; it is\n` +
        `    ${JSON.stringify(rpManifest)}.`,
    );
  }

  // Every package directory that exists on disk must be in the root package's `extra-files`.
  // Read the workspace from disk, not from PACKAGES: the failure being caught is "a fifth
  // package was added", and a list in this file would be just as easy to forget as the config.
  const extraFiles = rpConfig.packages?.["."]?.["extra-files"] ?? [];
  const updated = new Set(
    extraFiles
      .filter((f) => f?.type === "json" && f?.jsonpath === "$.version")
      .map((f) => f.path),
  );
  const onDisk = readdirSync(join(ROOT, "packages"), { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
  for (const p of onDisk) {
    if (!updated.has(`packages/${p}/package.json`)) {
      errors.push(
        `release-please-config.json does not update packages/${p}/package.json.\n` +
          `    Add { "type": "json", "path": "packages/${p}/package.json", "jsonpath": "$.version" }\n` +
          `    to the root package's extra-files. A package missing there is never bumped: it sits\n` +
          `    at a stale version through every release with all the other gates green.`,
      );
    }
  }
  for (const path of updated) {
    if (!onDisk.some((p) => path === `packages/${p}/package.json`)) {
      errors.push(
        `release-please-config.json updates '${path}', which is not a workspace package.\n` +
          `    A stale extra-files entry fails the release PR on a file that no longer exists.`,
      );
    }
  }

  const hasNodeWorkspace = (rpConfig.plugins ?? []).some(
    (p) => p === "node-workspace" || p?.type === "node-workspace",
  );
  if (hasNodeWorkspace) {
    errors.push(
      `release-please-config.json enables the 'node-workspace' plugin. Remove it.\n` +
        `    It rewrites internal dependency specifiers to concrete versions, which would replace\n` +
        `    every 'workspace:*' with a range or a pin written by something other than pnpm's pack\n` +
        `    step — the #116 failure, reintroduced from the release config.`,
    );
  }
}

// --- tag agreement -----------------------------------------------------------------------
if (tag !== "") {
  if (!/^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(tag)) {
    errors.push(`tag '${tag}' is not of the form vMAJOR.MINOR.PATCH[-prerelease]`);
  } else if (tag.slice(1) !== version) {
    errors.push(`tag '${tag}' does not match the manifest version '${version}'`);
  }
}

if (errors.length > 0) {
  for (const e of errors) process.stderr.write(`\n  release check failed: ${e}\n`);
  process.stderr.write("\n");
  process.exit(1);
}

process.stdout.write(
  `release check: all ${PACKAGES.length} packages at ${version}${tag ? ` (tag ${tag})` : ""}\n` +
    `  publishing: ${PUBLISHED.map((p) => `@capwall/${p}`).join(", ")}\n` +
    `  held back:  ${Object.keys(HELD_BACK).map((p) => `@capwall/${p}`).join(", ") || "(none)"}\n`,
);
