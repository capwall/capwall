/**
 * Reading capwall's own source as text, for the structural guards.
 *
 * NOT a test file (no `.test.ts` suffix, so vitest's default `include` never collects it).
 *
 * Three of the repo's guards are source scans — `process-patch-sites.test.ts` (#107),
 * `trust-root-exemptions.test.ts` and `capwall-env-table.test.ts` (both #139) — and every one of
 * them has the same first problem: **this codebase talks about the thing it forbids.**
 * `global-egress.ts` discusses `globalThis.fetch = evil` three times in its header;
 * `attribution/index.ts` mentions `APP_ROOT` in a dozen doc comments explaining why the trust
 * root's exemptions are dangerous. A scan that matched those would either fire on prose (and be
 * disabled) or be written loosely enough not to fire on anything.
 *
 * So the scans all start here, by blanking what is not code. Extracted from #107's file, which
 * is where the technique was written and where its meta-tests still live.
 */
import { readdirSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Blank out comments and (optionally) string/template bodies, PRESERVING OFFSETS so line
 * numbers still compute.
 *
 * `strings: false` keeps string bodies intact, for a scan whose subject IS a string literal —
 * `process.env["CAPWALL_MODE"]` is a read of a named variable, not prose about one. Comments are
 * blanked either way: a doc comment naming an env var is documentation, which is the thing being
 * checked rather than a use.
 */
export function blankNonCode(src: string, { strings = true }: { strings?: boolean } = {}): string {
  const out = src.split("");
  const blank = (from: number, to: number): void => {
    for (let i = from; i < to && i < out.length; i++) if (out[i] !== "\n") out[i] = " ";
  };
  let i = 0;
  // Depth of `${` interpolations we are inside, so a template can contain code containing a
  // template. `0` means "not in a template".
  const templateStack: number[] = [];
  while (i < src.length) {
    const two = src.slice(i, i + 2);
    if (two === "//") {
      const end = src.indexOf("\n", i);
      const stop = end === -1 ? src.length : end;
      blank(i, stop);
      i = stop;
      continue;
    }
    if (two === "/*") {
      const end = src.indexOf("*/", i + 2);
      const stop = end === -1 ? src.length : end + 2;
      blank(i, stop);
      i = stop;
      continue;
    }
    const ch = src[i];
    if (!strings) {
      i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < src.length && src[j] !== ch) j += src[j] === "\\" ? 2 : 1;
      blank(i + 1, j);
      i = j + 1;
      continue;
    }
    if (ch === "`") {
      let j = i + 1;
      while (j < src.length) {
        if (src[j] === "\\") {
          j += 2;
          continue;
        }
        if (src[j] === "`") break;
        if (src[j] === "$" && src[j + 1] === "{") break;
        j++;
      }
      blank(i + 1, j);
      if (src[j] === "$") {
        templateStack.push(1);
        i = j + 2;
        continue;
      }
      i = j + 1;
      continue;
    }
    if (templateStack.length > 0 && ch === "}") {
      // Close the interpolation and resume the template literal.
      templateStack.pop();
      let j = i + 1;
      while (j < src.length) {
        if (src[j] === "\\") {
          j += 2;
          continue;
        }
        if (src[j] === "`") break;
        if (src[j] === "$" && src[j + 1] === "{") break;
        j++;
      }
      blank(i + 1, j);
      if (src[j] === "$") {
        templateStack.push(1);
        i = j + 2;
        continue;
      }
      i = j + 1;
      continue;
    }
    i++;
  }
  return out.join("");
}

/** `.cts`/`.mts` too — `src/real-builtins.cts` (#78) is source like any other and must not
 *  escape a scan on a filename technicality. */
export function tsFilesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...tsFilesUnder(full));
    else if (/\.[cm]?ts$/.test(entry.name)) out.push(full);
  }
  return out.sort();
}

/** `packages/core/test/helpers` → the monorepo root. */
export const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "..",
);

/**
 * Every TypeScript source file in every workspace package, as `{ rel, file }` where `rel` is
 * relative to `packages/` (`core/src/shims/env.ts`) — short enough to read in a failure message
 * and unambiguous across packages.
 *
 * ALL packages, not just core: `@capwall/cli` reads `CAPWALL_MODE` too, and a scan that looked
 * only at core would have called that read undocumented or missed it entirely.
 */
export function workspaceSources(): { rel: string; file: string }[] {
  const packages = path.join(REPO_ROOT, "packages");
  const out: { rel: string; file: string }[] = [];
  for (const pkg of readdirSync(packages, { withFileTypes: true })) {
    if (!pkg.isDirectory()) continue;
    const src = path.join(packages, pkg.name, "src");
    let files: string[];
    try {
      files = tsFilesUnder(src);
    } catch {
      continue; // a package with no src/ (nothing to scan)
    }
    for (const file of files) out.push({ rel: path.relative(packages, file), file });
  }
  return out.sort((a, b) => a.rel.localeCompare(b.rel));
}
