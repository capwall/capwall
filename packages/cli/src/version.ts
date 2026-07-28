/**
 * `capwall --version` (issue #124).
 *
 * WHY A SECURITY TOOL NEEDS THIS MORE THAN MOST. The first question on any bug report, any
 * CVE triage and any "did the fix ship?" conversation is *which version are you running*, and
 * until now there was no way to answer it — `capwall --version` exited 2 with "unknown
 * command". It also makes a `capwall diff` line in a CI log unattributable to a build.
 *
 * WHY IT PRINTS TWO VERSIONS. The CLI does not enforce anything. It injects
 * `@capwall/core/preload` into a **different process** through `NODE_OPTIONS`, so "which core
 * actually mediated that run" is a genuinely separate question from "which CLI did I invoke" —
 * a globally-installed `capwall` in front of a project-local `@capwall/core`, or a stale
 * `dist/` in a clone, makes them differ. The core reported here is resolved through the SAME
 * `require.resolve("@capwall/core/preload")` the runner uses (`run.ts`), so it is the one that
 * would actually be injected, not merely one that happens to be installed.
 *
 * `scripts/check-release-versions.mjs` keeps the four packages in version lockstep, so the two
 * lines agreeing is the normal case and them disagreeing is the thing worth seeing.
 *
 * NOTHING IS HARDCODED. Every package is at `0.0.0` today and the release process bumps four
 * manifests at once; a literal here would be wrong the moment that happens. Both numbers are
 * read from a `package.json` on disk at call time.
 */
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

/** Read the `version` field of a package.json, or undefined if it cannot be read. */
function versionOf(manifestPath: string): string | undefined {
  try {
    const parsed: unknown = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (typeof parsed === "object" && parsed !== null) {
      const version = (parsed as { version?: unknown }).version;
      if (typeof version === "string") return version;
    }
  } catch {
    // Missing, unreadable or malformed — reported as "unknown" rather than thrown. `--version`
    // must never be the command that fails.
  }
  return undefined;
}

/**
 * Walk up from `start` looking for a `package.json` naming `expectedName`.
 *
 * Not `require.resolve("<pkg>/package.json")`: both manifests declare an `exports` map with no
 * `./package.json` entry, so that throws ERR_PACKAGE_PATH_NOT_EXPORTED. Not a fixed `../` hop
 * either — that silently reads the wrong file if a package's entry point ever moves out of
 * `dist/`. The name check makes a wrong answer impossible rather than unlikely.
 */
function manifestFor(start: string, expectedName: string): string | undefined {
  let dir = start;
  for (let i = 0; i < 8; i++) {
    const candidate = path.join(dir, "package.json");
    try {
      const parsed: unknown = JSON.parse(readFileSync(candidate, "utf8"));
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        (parsed as { name?: unknown }).name === expectedName
      ) {
        return candidate;
      }
    } catch {
      // Not here (or not readable) — keep climbing.
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return undefined;
}

/** This CLI's own version, read from `@capwall/cli`'s manifest. */
function cliVersion(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const manifest = manifestFor(here, "@capwall/cli");
  return (manifest && versionOf(manifest)) ?? "unknown";
}

/**
 * The version of the `@capwall/core` this CLI would inject — resolved exactly as `run.ts`
 * resolves it, so the answer describes the enforcement that would actually happen.
 */
function coreVersion(): string {
  try {
    const preload = createRequire(import.meta.url).resolve("@capwall/core/preload");
    const manifest = manifestFor(path.dirname(preload), "@capwall/core");
    return (manifest && versionOf(manifest)) ?? "unknown";
  } catch {
    return "unresolved";
  }
}

/** The full `--version` output, newline-terminated. */
export function versionReport(): string {
  return `capwall ${cliVersion()}\n@capwall/core ${coreVersion()} (injected into the target process)\n`;
}
