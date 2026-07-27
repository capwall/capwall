/**
 * Pre-publish guard: the four packages must be in version lockstep, and must match the tag.
 *
 * WHY. Publishing is not atomic. `.github/workflows/release.yml` pushes four tarballs one at
 * a time, and there is no rollback — if the third fails because someone bumped three
 * manifests and forgot the fourth, the registry is left with a half-released version and the
 * only way out is a new version number. Checking first costs nothing; checking after is not
 * a thing you can do.
 *
 * Lockstep is a deliberate policy, not an accident of the monorepo: the four packages are one
 * product, they pin each other exactly (pnpm rewrites `workspace:*` to the concrete version
 * at pack time), and `@capwall/cli` injects `@capwall/core` into a *different process* via
 * NODE_OPTIONS — a mismatched core is a silently differently-behaving firewall. See issue
 * #115 for the full argument.
 *
 * Usage:  node scripts/check-release-versions.mjs [v1.2.3]
 * The tag argument is optional; when empty (a `workflow_dispatch` run) only lockstep is
 * checked.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGES = ["policy-schema", "core", "sbom-import", "cli"];

const versions = new Map();
for (const p of PACKAGES) {
  const manifest = JSON.parse(readFileSync(join(ROOT, "packages", p, "package.json"), "utf8"));
  versions.set(manifest.name, manifest.version);
}

const errors = [];

const distinct = new Set(versions.values());
if (distinct.size !== 1) {
  errors.push(
    `the four packages are not in version lockstep:\n` +
      [...versions].map(([n, v]) => `    ${n.padEnd(24)} ${v}`).join("\n"),
  );
}

const version = versions.get("@capwall/core");

if (version === "0.0.0") {
  errors.push(
    `refusing to publish version 0.0.0 — this is the unreleased placeholder.\n` +
      `    Set a real version in all four manifests first (see docs/releasing.md).`,
  );
}

const tag = (process.argv[2] ?? "").trim();
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

process.stdout.write(`release check: all four packages at ${version}${tag ? ` (tag ${tag})` : ""}\n`);
