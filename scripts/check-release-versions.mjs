/**
 * Pre-publish guard: everything about a release that can be checked from the repo, checked
 * before the first byte reaches the registry.
 *
 * WHY. Publishing is not atomic and it is not reversible. `.github/workflows/release.yml`
 * pushes tarballs one at a time; npm's unpublish window is 72 hours and narrow inside it. If
 * the third publish fails because someone bumped three manifests and forgot the fourth, the
 * registry is left half-released and the only way out is a new version number. Checking first
 * costs nothing; checking after is not a thing you can do.
 *
 * WHAT IT ENFORCES, and the decision behind each (issue #115, docs/releasing.md):
 *
 *   1. LOCKSTEP. All four manifests carry the same version — including the one that is not
 *      published (see 4). The four packages are one product on one cadence; `@capwall/cli`
 *      does not merely call `@capwall/core`, it injects it into a *different process* via
 *      NODE_OPTIONS, so a mismatched core is a silently differently-behaving firewall.
 *
 *   2. EXACT PINS BETWEEN THE FOUR, expressed as `workspace:*`, which pnpm rewrites to the
 *      concrete version at pack time (`"@capwall/core": "0.1.0"`, not `^0.1.0`). A range would
 *      let a resolver seat one `@capwall/policy-schema` under `core` and a different one under
 *      `cli` in the same tree, and the failure mode is a policy that generates one way and
 *      evaluates another. Writing a caret here by hand is the mistake this catches. Caret
 *      ranges are correct for third-party deps; `zod` is the only one.
 *
 *   3. NO PUBLISHED PACKAGE MAY DEPEND ON A HELD-BACK ONE. Cheap check, unrecoverable
 *      failure: pnpm would rewrite the specifier to a version that is not on the registry and
 *      the published package would be uninstallable for everyone.
 *
 *   4. THE PUBLISH SET IS DECLARED HERE, once, and the workflow asks for it (`--publish-list`)
 *      rather than repeating it. `@capwall/sbom-import` is deliberately not published yet —
 *      no CLI subcommand exposes it, so it would land on npm as an unreachable library and be
 *      republished on every lockstep release forever.
 *
 *   5. A CHANGELOG ENTRY EXISTS FOR THIS VERSION, and when an actual tag is being released,
 *      it carries a real date rather than the `unreleased` placeholder. A hand-written
 *      changelog's characteristic failure is being forgotten at the moment it matters.
 *
 *   6. NOT 0.0.0 — the unreleased placeholder.
 *
 * Usage:
 *   node scripts/check-release-versions.mjs [v1.2.3]   run the checks; tag is optional and,
 *                                                      when empty (a workflow_dispatch run),
 *                                                      only the date check is relaxed
 *   node scripts/check-release-versions.mjs --publish-list
 *                                                      print the publish order, one name per
 *                                                      line, and exit
 */

import { readFileSync } from "node:fs";
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

const manifests = new Map();
for (const p of PACKAGES) {
  manifests.set(p, JSON.parse(readFileSync(join(ROOT, "packages", p, "package.json"), "utf8")));
}

const errors = [];

// --- 1. lockstep -------------------------------------------------------------------------
const distinct = new Set([...manifests.values()].map((m) => m.version));
if (distinct.size !== 1) {
  errors.push(
    `the four packages are not in version lockstep:\n` +
      [...manifests.values()].map((m) => `    ${m.name.padEnd(24)} ${m.version}`).join("\n") +
      `\n    Held-back packages stay in lockstep too — see docs/releasing.md § What is published.`,
  );
}

const version = manifests.get("core").version;

// --- 6. not the placeholder --------------------------------------------------------------
if (version === "0.0.0") {
  errors.push(
    `refusing to publish version 0.0.0 — this is the unreleased placeholder.\n` +
      `    Set a real version in all four manifests first (see docs/releasing.md).`,
  );
}

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
  // `## [0.1.0] - 2026-08-01` or `## [0.1.0] - unreleased`. Scanned line by line rather than
  // built into a RegExp, so a version string never has to be escaped into a pattern.
  const prefix = `## [${version}]`;
  const line = changelog.split("\n").find((l) => l.startsWith(prefix));
  const heading = line === undefined ? null : /^-\s*(\S+)/.exec(line.slice(prefix.length).trim());
  if (heading === null) {
    errors.push(
      `CHANGELOG.md has no '## [${version}] - ...' section.\n` +
        `    Every released version gets an entry, written by hand, before it is tagged.`,
    );
  } else if (tag !== "" && !/^\d{4}-\d{2}-\d{2}$/.test(heading[1])) {
    errors.push(
      `CHANGELOG.md still says '## [${version}] - ${heading[1]}'.\n` +
        `    A tagged release needs a real ISO date (YYYY-MM-DD) on that heading.`,
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
