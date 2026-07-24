/**
 * Minimal path-glob matcher for fs policy grants. Zero-dependency on purpose (every dep is
 * attack surface — AGENTS.md § 5). Supported syntax:
 *   - `*`  within a segment: any characters except `/`
 *   - `?`  within a segment: any single character except `/`
 *   - `**` as a whole segment: any number of segments (including zero)
 *   - a bare `*` or `**` pattern: matches every path
 *
 * `dir/**` also matches `dir` itself, so granting `./logs/**` covers the common
 * `mkdirSync("./logs")` that precedes writing into it.
 *
 * Both pattern and candidate are expected as absolute paths with `/` separators — either
 * POSIX-style (leading `/`, e.g. `/app/logs/**`) or Windows-style drive paths (a drive
 * letter as the first segment, e.g. `C:/app/logs/**`). The policy loader (`load.ts`
 * `normalizeGlob`) and the fs shim (`shims/fs.ts` `coercePath`) both produce this shape via
 * `path.resolve(p).split(path.sep).join("/")`, run through the OS-native `path` module — on
 * POSIX that yields `/a/b`, on Windows it yields `C:/a/b` (no leading slash: Windows absolute
 * paths don't have one). `compile()` anchors on whichever shape the pattern has, so a
 * POSIX-authored policy matches POSIX candidates and a Windows-authored policy matches
 * Windows candidates; the two shapes never cross-match (a `/…` pattern never matches a
 * `C:/…` candidate or vice versa — they're different filesystems).
 *
 * Windows drive letters are matched case-insensitively (`c:` grants match `C:` candidates and
 * vice versa) since Windows itself is case-insensitive about the drive letter. The REST of a
 * Windows path stays case-sensitive here, same as POSIX segments — capwall's matching is
 * lexical everywhere else, and silently widening a grant to match case-varying paths would be
 * a bigger blast-radius mistake than a spurious deny; authors needing that can widen with
 * `*`/`**`. UNC paths (`\\server\share\...`) are NOT specially handled — they fall through to
 * the plain-segment path below.
 *
 * Comparison is purely lexical — symlinks/fds are out of scope (docs/threat-model.md).
 */

/** A single Windows drive-letter segment, e.g. `C:` or `c:` (exactly one letter + colon). */
const DRIVE_SEGMENT = /^[A-Za-z]:$/;

const regexCache = new Map<string, RegExp>();

function segmentToRegex(segment: string): string {
  let out = "";
  for (const ch of segment) {
    if (ch === "*") out += "[^/]*";
    else if (ch === "?") out += "[^/]";
    else out += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return out;
}

function compile(pattern: string): RegExp {
  const cached = regexCache.get(pattern);
  if (cached) return cached;

  // Collapse consecutive `**` segments so an author-written `dir/**/**` compiles to ONE
  // `(?:/[^/]+)*` group rather than two adjacent ones — adjacent unbounded groups are a
  // catastrophic-backtracking (ReDoS) shape, and the candidate path is attacker-adjacent
  // (a dependency's fs argument) on the hot guard path. `**/**` and `**` are equivalent.
  const raw = pattern.split("/").filter((s) => s.length > 0);
  const segments: string[] = [];
  for (const seg of raw) {
    if (seg === "**" && segments[segments.length - 1] === "**") continue;
    segments.push(seg);
  }
  let out = "^";
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i]!;
    if (seg === "**") {
      // `(/…)*` — zero or more whole segments; also allows matching the base dir itself.
      out += "(?:/[^/]+)*";
    } else if (i === 0 && DRIVE_SEGMENT.test(seg)) {
      // Windows drive-letter anchor (e.g. pattern segment "C:" from "C:/proj/**"). Unlike a
      // POSIX absolute segment, this is NOT preceded by "/" — Windows absolute paths (as
      // produced by coercePath/normalizeGlob) start directly with the drive letter. The
      // letter itself is matched case-insensitively; see the file-level doc comment.
      const letter = seg[0]!;
      out += `[${letter.toUpperCase()}${letter.toLowerCase()}]:`;
    } else {
      out += "/" + segmentToRegex(seg);
    }
  }
  out += "$";
  const re = new RegExp(out);
  regexCache.set(pattern, re);
  return re;
}

/** Does `candidatePath` (absolute, `/`-separated) match `pattern` (absolute glob)? */
export function matchesGlob(pattern: string, candidatePath: string): boolean {
  if (pattern === "*" || pattern === "**") return true;
  return compile(pattern).test(candidatePath);
}
