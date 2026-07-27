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

/*
 * ───────────────────────────────────────────────────────────────────────────────────────────
 * NODE-GLOB REACH ANALYSIS (issue #106)
 * ───────────────────────────────────────────────────────────────────────────────────────────
 *
 * Everything above is capwall's OWN glob dialect — the one a policy author writes. What follows
 * answers a different question about a DIFFERENT dialect: given a pattern handed to Node's
 * `fs.glob` (Node ≥22, minimatch-flavoured and considerably richer than the above), how far from
 * the directory it starts in can the resulting walk get?
 *
 * It lives here rather than in `shims/fs.ts` because it is glob-syntax knowledge, and next to the
 * matcher so the two dialects' differences are visible in one file instead of being rediscovered.
 * It is deliberately PURE SYNTAX: no path resolution, no `node:path`, no filesystem. The shim
 * resolves what this returns against the call's pinned `cwd`, because separator normalization and
 * `path.resolve` already live there.
 */

/**
 * Characters that make a pattern SEGMENT magic — i.e. it can expand to something other than the
 * literal text it contains, so the literal prefix stops before it.
 *
 * `{`/`}` are magic too but are handled separately ({@link bracesAreSegmentLocal}), because a
 * brace group is the one construct that can span segment boundaries. `!`, `+` and `@` are NOT
 * here: they are extglob openers only in front of a `(`, which is already in the set, and
 * treating a bare `@` as magic would truncate the prefix of every ordinary
 * `node_modules/@scope/pkg/**` for nothing.
 */
const NODE_GLOB_MAGIC = /[*?[\]()]/;

/**
 * True when every brace group in `s` is confined to a single path segment — no `/` and no `..`
 * inside any group — and every group is balanced.
 *
 * WHY THIS IS THE LOAD-BEARING CHECK. Brace expansion happens before matching, so
 * `{/etc,/tmp}/*.conf` reaches `/etc` no matter what `cwd` is, and `{.,..}/*.conf` reaches the
 * parent — both verified against real `fs.globSync` on Node 22. A "literal prefix" derived by
 * stopping at the first magic character says `cwd` for both, which would be a gate on the wrong
 * directory: fail-OPEN, and the reason the prefix-only rule sketched in #106 is not what shipped.
 * A group with neither `/` nor `..` in it can only ever name alternatives WITHIN one segment, so
 * it cannot move the walk's root.
 */
/** Brace-group content that could move the walk's root: a separator, or a parent reference. */
const ESCAPING_BRACE_CONTENT = /\/|\.\./;

function bracesAreSegmentLocal(s: string): boolean {
  let depth = 0;
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (c === "}") {
      depth--;
      if (depth < 0) return false; // unbalanced — not analyzable, so not bounded
      if (depth === 0 && ESCAPING_BRACE_CONTENT.test(s.slice(start + 1, i))) return false;
    }
  }
  return depth === 0;
}

/**
 * The literal leading path prefix of a Node glob `pattern` — the deepest directory the pattern
 * cannot escape — or `null` when its reach **cannot be bounded**.
 *
 * The return value is a `/`-separated, un-resolved path fragment for the caller to resolve
 * against the call's `cwd`: `""` means "the cwd itself", `"/"`/`"C:/"` mean the filesystem root,
 * and anything else is a relative or absolute fragment (which MAY contain `..` — a leading `..`
 * is exact, not an escape, because `path.resolve` accounts for it precisely).
 *
 * `null` is the fail-closed answer, and the caller must translate it into the filesystem ROOT,
 * not into "no restriction". Three constructs produce it, each verified to be a real escape (or
 * an un-analyzable one) against `fs.globSync` on Node 22:
 *
 *  - a `..` SEGMENT after the first magic segment. `**` matches ZERO segments as well as many,
 *    so a pattern of `**` then `..` then `*.conf` is also just `../*.conf`, which walks the
 *    parent of `cwd`.
 *  - a brace group that spans a `/` or contains `..` — see {@link bracesAreSegmentLocal}.
 *  - a backslash anywhere. On POSIX that is minimatch's ESCAPE character, so the segmentation
 *    above is no longer reliable; capwall does not model it and refuses to guess. (The fs shim
 *    normalizes `\` to `/` before calling this on win32, where it is a separator instead, so
 *    that case never reaches here.)
 *
 * NOT modelled, deliberately, because none of them moves the walk's ROOT: `*`/`?`/character
 * classes/extglobs (all confined to one segment), `**` (descends only), and a leading `!`
 * (selects a different set under the same root).
 */
export function nodeGlobPrefix(pattern: string): string | null {
  if (pattern.includes("\\")) return null;
  const segments = pattern.split("/");
  let firstMagic = segments.length;
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i]!;
    if (NODE_GLOB_MAGIC.test(seg) || seg.includes("{") || seg.includes("}")) {
      firstMagic = i;
      break;
    }
  }
  const rest = segments.slice(firstMagic);
  if (rest.includes("..")) return null;
  if (!bracesAreSegmentLocal(rest.join("/"))) return null;

  const prefix = segments.slice(0, firstMagic).join("/");
  // An absolute pattern whose FIRST segment is magic (`/*.conf`, `/**`) splits to `["", "*…"]`,
  // so the joined prefix is the empty string — which would otherwise read as "the cwd" and gate
  // the wrong directory entirely. Its root is `/`.
  if (prefix === "" && pattern.startsWith("/")) return "/";
  // A bare Windows drive segment is not a directory to `path.resolve`: `resolve("D:/x", "C:")`
  // yields the process's CURRENT directory on drive C, not `C:/`. Make it a root explicitly.
  if (DRIVE_SEGMENT.test(prefix)) return prefix + "/";
  return prefix;
}
