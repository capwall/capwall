/**
 * Post-release guard: did every tagged release actually reach npm?
 *
 * WHY THIS EXISTS. `.github/workflows/release.yml` fires on `push: tags: v*`, but a tag created
 * with the default `GITHUB_TOKEN` — which is what release-please uses unless
 * `RELEASE_PLEASE_TOKEN` is configured — does not trigger other workflows. This is deliberate
 * GitHub behaviour to prevent workflow recursion, not a bug here; it is documented in advance in
 * release.yml's header note 5 and docs/releasing.md § HUMAN CHECKLIST step 17, and it is tracked
 * as issue #207.
 *
 * It happened for real on `v0.1.1`: release-please merged the release PR, created the tag, and
 * cut the GitHub release. `release.yml` never started on its own. Nothing reached npm until
 * someone ran `gh workflow run release.yml --ref v0.1.1 -f dry_run=false` by hand.
 *
 * THE DANGER IS NOT THE MANUAL STEP. IT IS THAT THE FAILURE IS SILENT AND LOOKS LIKE SUCCESS.
 * The tag exists. The GitHub Release exists. CHANGELOG.md is dated. Every gate this repo already
 * runs — `check-release-versions.mjs`, `check-tarball-sources.mjs` — is green, because both check
 * state that exists whether or not `npm publish` ever ran. Only the registry knows, and nobody
 * looks at the registry unless something makes them look. This script is what looks.
 *
 * WHAT IT CHECKS, IN BOTH DIRECTIONS. The publish set is read from
 * `check-release-versions.mjs --publish-list` — not repeated here. That file's point 4 is
 * explicit that the publish set is declared once; a second hardcoded list here is exactly the
 * kind of copy that silently disagrees with the original the day someone adds a package.
 *
 *   TAG -> REGISTRY: for every `vX.Y.Z` tag, does that version exist on npm? This catches the
 *   release that silently never shipped, described above.
 *
 *   REGISTRY -> TAG: for every version on npm, is there a tag that accounts for it? This is the
 *   more security-relevant direction and it is NOT symmetric with the first. A version on the
 *   registry that no tag in this repository explains is the exact shape of a publish nobody
 *   here authorised — a leaked or stolen npm token used from someone's workstation, which is
 *   precisely the supply-chain compromise capwall exists to talk about. It is also what an
 *   honest manual publish looks like, which is the point: the two are indistinguishable from
 *   the registry alone, so the untagged version has to be reconciled either way.
 *
 * Checking only TAG -> REGISTRY would be a fail-open guard: it can only ever look at versions
 * someone already told it about. AGENTS.md § 6 names fail-open design as this project's dominant
 * bug class, recurring four times independently (#26/#56, #60, #59/#61, #177/#178). The question
 * to ask of any guard here is "what happens to an input nobody enumerated?", and for a
 * tag-driven check the answer was: it is invisible.
 *
 * THREE DISTINGUISHABLE OUTCOMES, NOT TWO:
 *
 *   - MISSING: the package exists on the registry but the tagged version does not. This is the
 *     `v0.1.1` failure mode exactly, and it is what this script exists to catch.
 *   - GONE: the package does not exist on the registry AT ALL. This is a much stranger state
 *     than a missing version — either the very first publish of that package never happened, or
 *     the publish set here has drifted from what `release.yml` actually publishes (for example,
 *     `@capwall/sbom-import` is deliberately held back and must never be queried — see
 *     docs/releasing.md § What is published). Reported separately so it can never be misread as
 *     "just one version behind."
 *   - UNTAGGED: the registry has a version that no `vX.Y.Z` tag in this repository accounts for.
 *     See the REGISTRY -> TAG note above for why this is the direction that matters most.
 *   - INCONCLUSIVE: the registry could not be reached, timed out, or answered with something
 *     other than 200/404. This is NOT evidence of anything. Reading it as "not published" would
 *     make this guard cry wolf on every transient DNS blip; reading it as "fine" would make the
 *     guard a no-op on the one day the registry is unreachable while a release silently failed.
 *     It is reported with its own message and its own exit code so neither misreading is
 *     possible from the output alone.
 *
 * WHY ONE FETCH PER PACKAGE, NOT ONE PER TAG. The registry's abbreviated packument
 * (`Accept: application/vnd.npm.install-v1+json`) lists every published version of a package in
 * one small response. Fetching it once per package in the publish set and checking every tag
 * against the resulting set is cheaper than one request per tag per package, and it gives the
 * GONE/MISSING distinction for free: the per-version endpoint
 * (`registry.npmjs.org/<pkg>/<version>`) 404s identically whether the package never existed or
 * only that version doesn't, which is exactly the distinction this script has to make.
 *
 * Usage:
 *   node scripts/check-release-published.mjs            human-readable report
 *   node scripts/check-release-published.mjs --json      same checks, machine-readable report
 *
 * Exit codes:
 *   0   every tag is on the registry, and every published version is accounted for by a tag
 *   1   a tag -> package@version is MISSING, a package is GONE, or a published version is UNTAGGED
 *   2   nothing failed harder than an INCONCLUSIVE registry query
 *
 * Zero dependencies: Node 22 ships a global `fetch` and `AbortSignal.timeout`.
 */

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const REGISTRY = "https://registry.npmjs.org";
const FETCH_TIMEOUT_MS = 10_000;

/**
 * Versions on the registry that are known to have no tag, with the reason, so the REGISTRY -> TAG
 * direction does not report a settled historical fact as an open finding every single day.
 *
 * This is an ATTESTED RECORD, NOT A RULE. Nothing may be added here to silence a finding. An
 * entry is a claim that someone identified exactly which source produced an untagged published
 * version and wrote down how they know. If you cannot say how you know, the honest state is a
 * failing check.
 *
 * `0.1.0` was published by hand from a workstation on 2026-07-30, before the release-please tag
 * path had ever run, so no tag was ever created for it. The source is commit 2eee187: the
 * `packages/cli/README.md` inside the published `@capwall/cli@0.1.0` tarball matches that commit
 * byte-for-byte and differs from both its parent and its child, and 2eee187 was `main` at the
 * time of the publish. npm recorded no `gitHead` for it — `pnpm pack` does not write one and
 * `npm publish <tarball>` does not add one — so the tarball content IS the evidence.
 *
 * The intended end state is to delete this entry by tagging `v0.1.0` at 2eee187, which cannot be
 * done safely until `release.yml` skips versions already on the registry instead of failing on
 * them. Tracked in issue #209.
 */
const UNTAGGED_BY_RECORD = new Map([["0.1.0", "published manually from 2eee187; see #209"]]);

const jsonMode = process.argv.includes("--json");

// --- 1. the publish set, read from the one place it is declared --------------------------
const publishList = spawnSync(
  process.execPath,
  [join(ROOT, "scripts", "check-release-versions.mjs"), "--publish-list"],
  { encoding: "utf8" },
);
if (publishList.status !== 0) {
  process.stderr.write(
    `check-release-published: could not read the publish set ` +
      `(check-release-versions.mjs --publish-list exited ${publishList.status})\n` +
      (publishList.stderr ?? ""),
  );
  process.exit(1);
}
const publishSet = publishList.stdout
  .split("\n")
  .map((l) => l.trim())
  .filter((l) => l !== "")
  .map((short) => `@capwall/${short}`);

if (publishSet.length === 0) {
  process.stderr.write("check-release-published: the publish set is empty; nothing to check\n");
  process.exit(1);
}

// --- 2. release tags in the repository ----------------------------------------------------
// Needs full tag history to see anything — a shallow checkout (the CI default) has none.
const tagList = spawnSync("git", ["tag", "--list", "v*"], { cwd: ROOT, encoding: "utf8" });
if (tagList.status !== 0) {
  process.stderr.write(
    `check-release-published: 'git tag --list' exited ${tagList.status}\n${tagList.stderr ?? ""}`,
  );
  process.exit(1);
}

// Same shape check-release-versions.mjs applies to a tag it is handed, so a tag that would fail
// that check is not silently treated as a release here either. Anything else that starts with
// `v` (there is nothing today, but nothing stops someone pushing `vNext` as a marker tag) is
// skipped and reported, not treated as an error — it is not a release tag, whatever it is for.
const TAG_RE = /^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
const allTags = tagList.stdout
  .split("\n")
  .map((l) => l.trim())
  .filter((l) => l !== "");
const tags = allTags.filter((t) => TAG_RE.test(t));
const skippedTags = allTags.filter((t) => !TAG_RE.test(t));

if (tags.length === 0) {
  process.stdout.write("check-release-published: no 'vX.Y.Z' tags in the repository; nothing to check\n");
  process.exit(0);
}

// --- 3. one packument fetch per package in the publish set --------------------------------
/** @returns {Promise<{state: "ok", versions: Set<string>} | {state: "gone"} | {state: "inconclusive", reason: string}>} */
async function fetchVersions(pkgName) {
  let res;
  try {
    res = await fetch(`${REGISTRY}/${pkgName}`, {
      headers: { Accept: "application/vnd.npm.install-v1+json" },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    return { state: "inconclusive", reason: `${err.name}: ${err.message}` };
  }
  if (res.status === 404) {
    return { state: "gone" };
  }
  if (res.status !== 200) {
    return { state: "inconclusive", reason: `HTTP ${res.status}` };
  }
  let body;
  try {
    body = await res.json();
  } catch (err) {
    return { state: "inconclusive", reason: `response was not valid JSON: ${err.message}` };
  }
  return { state: "ok", versions: new Set(Object.keys(body.versions ?? {})) };
}

const packageResults = new Map();
for (const pkgName of publishSet) {
  packageResults.set(pkgName, await fetchVersions(pkgName));
}

// --- 4. cross the tags with the publish set against what the registry actually has --------
const missing = []; // { tag, pkgName, version }
const gone = []; // pkgName, present in the publish set, absent from the registry entirely
const untagged = []; // { pkgName, version } — on the registry, no tag accounts for it
const inconclusive = []; // { pkgName, reason }

const taggedVersions = new Set(tags.map((t) => t.slice(1)));

for (const pkgName of publishSet) {
  const result = packageResults.get(pkgName);
  if (result.state === "gone") {
    gone.push(pkgName);
    continue;
  }
  if (result.state === "inconclusive") {
    inconclusive.push({ pkgName, reason: result.reason });
    continue;
  }
  // TAG -> REGISTRY: a tagged release that never shipped.
  for (const tag of tags) {
    const version = tag.slice(1);
    if (!result.versions.has(version)) {
      missing.push({ tag, pkgName, version });
    }
  }
  // REGISTRY -> TAG: a shipped version nothing in this repository accounts for.
  for (const version of result.versions) {
    if (!taggedVersions.has(version) && !UNTAGGED_BY_RECORD.has(version)) {
      untagged.push({ pkgName, version });
    }
  }
}

const status =
  missing.length > 0 || gone.length > 0 || untagged.length > 0
    ? "failed"
    : inconclusive.length > 0
      ? "inconclusive"
      : "ok";

// --- 5. report ------------------------------------------------------------------------------
if (jsonMode) {
  process.stdout.write(
    JSON.stringify(
      {
        status,
        publishSet,
        tags,
        skippedTags,
        missing,
        gone,
        untagged,
        untaggedByRecord: Object.fromEntries(UNTAGGED_BY_RECORD),
        inconclusive,
      },
      null,
      2,
    ) + "\n",
  );
} else {
  if (skippedTags.length > 0) {
    process.stdout.write(
      `(ignoring ${skippedTags.length} tag(s) that aren't of the form vX.Y.Z: ${skippedTags.join(", ")})\n`,
    );
  }

  if (gone.length > 0) {
    process.stderr.write(
      `\n  check-release-published: ${gone.length} package(s) in the publish set do not exist ` +
        `on the registry AT ALL:\n\n`,
    );
    for (const pkgName of gone) process.stderr.write(`    ${pkgName}\n`);
    process.stderr.write(
      `\n    This is stranger than a missing version — either the first publish of that package\n` +
        `    never happened, or the publish set has drifted from what release.yml actually\n` +
        `    publishes. Check scripts/check-release-versions.mjs --publish-list against\n` +
        `    docs/releasing.md § What is published.\n`,
    );
  }

  if (missing.length > 0) {
    process.stderr.write(
      `\n  check-release-published: ${missing.length} tagged release(s) never reached npm:\n\n`,
    );
    for (const { tag, pkgName, version } of missing) {
      process.stderr.write(`    ${tag} -> ${pkgName}@${version}\n`);
    }
    process.stderr.write(
      `\n    This is the silent failure documented in release.yml's header note 5 and\n` +
        `    docs/releasing.md § HUMAN CHECKLIST step 17: a tag created with the default\n` +
        `    GITHUB_TOKEN does not trigger release.yml. Every other artifact of a release (the\n` +
        `    tag, the GitHub Release, the CHANGELOG.md entry) exists regardless of whether this\n` +
        `    happened; only the registry is missing the version. Fix it with:\n\n` +
        `        gh workflow run release.yml --ref <tag> -f dry_run=false\n\n` +
        `    See issue #207.\n`,
    );
  }

  if (untagged.length > 0) {
    process.stderr.write(
      `\n  check-release-published: ${untagged.length} published version(s) that NO TAG ` +
        `accounts for:\n\n`,
    );
    for (const { pkgName, version } of untagged) {
      process.stderr.write(`    ${pkgName}@${version}  (no v${version} tag)\n`);
    }
    process.stderr.write(
      `\n    Treat this as a possible compromise until it is explained. A version on the\n` +
        `    registry that no tag in this repository produced is what a publish from a leaked\n` +
        `    or stolen npm token looks like — and it is also what an honest manual publish\n` +
        `    looks like. The registry alone cannot tell you which, so reconcile it:\n\n` +
        `      1. 'npm view <pkg>@<version>' — check the publish time and, if present, gitHead.\n` +
        `      2. Check whether the tarball's contents match any commit in this repository.\n` +
        `      3. If it was authorised, tag it. If you cannot explain it, ROTATE THE TOKENS\n` +
        `         and treat the version as untrusted.\n\n` +
        `    Only then record it in UNTAGGED_BY_RECORD at the top of this file, WITH how you\n` +
        `    know. That list is an attested record, not a mute button.\n`,
    );
  }

  if (inconclusive.length > 0) {
    process.stderr.write(
      `\n  check-release-published: ${inconclusive.length} registry ` +
        `${inconclusive.length === 1 ? "query was" : "queries were"} inconclusive:\n\n`,
    );
    for (const { pkgName, reason } of inconclusive) {
      process.stderr.write(`    ${pkgName}: ${reason}\n`);
    }
    process.stderr.write(
      `\n    This is NOT evidence that a release is missing — it means the registry could not be\n` +
        `    queried at all. Re-run once the network is reliable; do not read this as either a\n` +
        `    pass or a genuine gap.\n`,
    );
  }

  if (status === "ok") {
    const recorded =
      UNTAGGED_BY_RECORD.size > 0
        ? `; ${UNTAGGED_BY_RECORD.size} untagged version(s) accounted for by record ` +
          `(${[...UNTAGGED_BY_RECORD.keys()].join(", ")})`
        : "";
    process.stdout.write(
      `check-release-published: all ${tags.length} tag(s) x ${publishSet.length} package(s) ` +
        `are on the registry, and every published version is accounted for ` +
        `(${publishSet.join(", ")})${recorded}\n`,
    );
  }
}

process.exit(status === "ok" ? 0 : status === "failed" ? 1 : 2);
