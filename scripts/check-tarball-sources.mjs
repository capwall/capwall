/**
 * Post-pack guard: every source map in a tarball must point at a file that is in the same
 * tarball.
 *
 * WHY. `tsconfig.base.json` sets `sourceMap` and `declarationMap`, so every build emits
 * `.js.map` and `.d.ts.map` next to its output. Those maps name their input as
 * `../src/<file>.ts`. Before issue #126 the packages shipped `"files": ["dist"]`, so all 66
 * maps in `@capwall/core` resolved to nothing: 22% of the tarball was bytes that delivered
 * no function, and a `.d.ts.map` that promises the editor a file which is not there is worse
 * than shipping no map at all — with no map, "go to definition" falls back to the `.d.ts`,
 * which is real. The fix was `"files": ["dist", "src"]`; this script is what keeps it fixed.
 *
 * WHY A SCRIPT AND NOT A REVIEW HABIT. npm's unpublish window is 72 hours and narrow inside
 * it. A packaging regression is the one class of mistake in this repo that cannot be taken
 * back, and it is invisible in every other gate: the build passes, the tests pass, the types
 * check, and the tarball is quietly broken. The only thing that catches it is opening the
 * tarball, so the release workflow opens the tarball.
 *
 * It also asserts the inverse of what `assert-pnpm-pack.mjs` covers: that guard stops a bad
 * tarball from being *built*; this one inspects one that already was.
 *
 * Usage:  node scripts/check-tarball-sources.mjs <tarball.tgz> [...]
 *
 * No dependencies — shells out to the system `tar`, which the release runner and the
 * `ci-local` images both have.
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";

const tarballs = process.argv.slice(2);
if (tarballs.length === 0) {
  process.stderr.write("usage: node scripts/check-tarball-sources.mjs <tarball.tgz> [...]\n");
  process.exit(2);
}

/** Every file under `dir`, as absolute paths. */
function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

const errors = [];

for (const tarball of tarballs) {
  if (!existsSync(tarball)) {
    errors.push(`${tarball}: no such file`);
    continue;
  }

  const scratch = mkdtempSync(join(tmpdir(), "capwall-pack-check-"));
  try {
    const tar = spawnSync("tar", ["xzf", resolve(tarball), "-C", scratch], { encoding: "utf8" });
    if (tar.status !== 0) {
      errors.push(`${tarball}: tar exited ${tar.status}: ${(tar.stderr ?? "").trim()}`);
      continue;
    }
    // npm tarballs put everything under a single `package/` prefix.
    const root = join(scratch, "package");
    if (!existsSync(root)) {
      errors.push(`${tarball}: no package/ directory inside the tarball`);
      continue;
    }

    const files = walk(root);
    const maps = files.filter((f) => f.endsWith(".map"));
    let dangling = 0;
    let refs = 0;

    for (const map of maps) {
      let parsed;
      try {
        parsed = JSON.parse(readFileSync(map, "utf8"));
      } catch {
        errors.push(`${tarball}: ${relative(root, map)} is not valid JSON`);
        continue;
      }
      // A map whose sources are inlined carries its own content and needs no companion file.
      // TypeScript only does this for `.js.map` (`inlineSources`), never for `.d.ts.map` —
      // verified against tsc 5.9 — which is why shipping `src/` is the only fix that covers
      // "go to definition" as well as stack traces.
      const inlined = Array.isArray(parsed.sourcesContent) && parsed.sourcesContent.every((c) => typeof c === "string");
      if (inlined) continue;
      for (const source of parsed.sources ?? []) {
        refs++;
        const target = resolve(dirname(map), parsed.sourceRoot ?? "", source);
        if (!existsSync(target)) {
          dangling++;
          if (dangling <= 3) {
            errors.push(
              `${tarball}: ${relative(root, map)} points at ${source}, which is not in the tarball`,
            );
          }
        }
        // A map that escapes the package root would resolve on the packer's machine and
        // nowhere else — the same failure wearing a disguise.
        if (relative(root, target).startsWith(`..${sep}`)) {
          errors.push(`${tarball}: ${relative(root, map)} points outside the package: ${source}`);
        }
      }
    }

    if (dangling > 3) {
      errors.push(`${tarball}: ...and ${dangling - 3} more dangling source references`);
    }
    process.stdout.write(
      `${tarball}: ${maps.length} maps, ${refs} source references, ${dangling} dangling\n`,
    );
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

if (errors.length > 0) {
  process.stderr.write("\n  tarball source-map check failed:\n");
  for (const e of errors) process.stderr.write(`    ${e}\n`);
  process.stderr.write(
    "\n  A published map that names a file the tarball does not contain is dead weight and\n" +
      "  breaks 'go to definition'. See issue #126 and docs/releasing.md.\n\n",
  );
  process.exit(1);
}

process.stdout.write("tarball source-map check: every map resolves inside its own tarball\n");
