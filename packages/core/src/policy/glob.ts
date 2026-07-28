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

import * as path from "node:path";

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
 * The ANALYSIS is pure syntax — no filesystem, and it runs identically on a Node with no
 * `fs.glob` at all; only the last step, {@link nodeGlobBase}, resolves the result against the
 * call's pinned `cwd`. That step moved here in #120, from the shim, because the property test
 * that compares capwall's answer against real `fs.globSync` has to exercise the whole
 * pattern → directory derivation, not just its first half.
 */

/**
 * Characters that make a pattern SEGMENT magic — i.e. it can expand to something other than the
 * literal text it contains, so the literal prefix stops before it.
 *
 * `{`/`}` are NOT here because braces never reach this test: {@link expandBraces} removes them
 * first (see the issue-#120 note below). `!`, `+` and `@` are not here either: they are extglob
 * openers only in front of a `(`, which is already in the set, and treating a bare `@` as magic
 * would truncate the prefix of every ordinary `node_modules/@scope/pkg/**` for nothing.
 */
const NODE_GLOB_MAGIC = /[*?[\]()]/;

/**
 * A `*` or `?` anywhere in a segment. See {@link segmentIsDownwardOnly} for why this single
 * character class is the load-bearing distinction and not a stylistic one.
 */
const WILDCARD = /[*?]/;

/**
 * A segment built ONLY out of dots and glob punctuation, with no ordinary character anywhere.
 *
 * This is the shape that can REDUCE to a literal `.` / `..` path component — `..`, `[.][.]`,
 * `[.-.][.-.]`, `.[.]`, `@(..)`, `[..]`. A segment containing any character outside this set
 * (a letter, a digit, `_`, `/`-free punctuation like `#`) carries that character into whatever
 * it reduces to, so it can never reduce to a run of dots. See {@link segmentIsDownwardOnly}.
 *
 * `|` is included because it is extglob's alternation separator, i.e. syntax rather than an
 * ordinary character: `@(.|.)` must be treated the same way as `@(..)`, while `@(a|b)` — which
 * carries the ordinary `a`/`b` — must not.
 */
const ONLY_DOTS_AND_GLOB_PUNCTUATION = /^[.[\]()!+@|,^-]*$/;

/**
 * Hard cap on the number of alternatives {@link expandBraces} will produce. A brace bomb
 * (`{a,b}` twenty times over) is 2²⁰ strings; refusing past the cap costs a fail-CLOSED `null`
 * for a pattern nobody writes, which is the correct side to be wrong on. Chosen well above any
 * realistic hand-written pattern (`{js,ts,jsx,tsx}` twice over is 16).
 */
const MAX_BRACE_EXPANSIONS = 256;

/**
 * Expand every brace group in `pattern` into the full set of alternatives, or `null` when the
 * expansion cannot be performed EXACTLY.
 *
 * ─────────────────────────────────────────────────────────────────────────────────────────────
 * WHY THIS EXISTS AT ALL (issue #120) — and why it replaces a check rather than joining it.
 * ─────────────────────────────────────────────────────────────────────────────────────────────
 * Until #120 the reach analysis below asked two STRING questions of the raw pattern text: does a
 * post-prefix segment equal `".."`, and does any brace group contain a `/` or a `..`. Both are
 * string tests standing in for a MATCHING question, and minimatch's grammar is wider than either:
 * `..{,}`, `.{.,.}`, `{a,[.][.]}` and `[.][.]{,}` all reach the parent of `cwd` — verified
 * against real `fs.globSync` — while spelling the `..` in a way neither test could see. That is
 * the same failure shape as #84's `getEvalOrigin` regex and #95's port heuristic: a parser
 * deciding a security boundary while modelling a narrower grammar than its consumer accepts.
 *
 * So capwall no longer tries to SEE a `..` through the braces. It performs the expansion the
 * matcher itself performs, and then analyzes each concrete alternative — the same question, asked
 * of text that no longer has a brace in it. `{/etc,/tmp}/*.conf` becomes two ordinary patterns
 * rooted at `/etc` and `/tmp`; `..{,}/**` becomes `../**`, whose leading `..` the caller resolves
 * exactly. `bracesAreSegmentLocal` is gone with the class of bug it was written for.
 *
 * WHAT IS REFUSED RATHER THAN GUESSED AT, each one fail-closed (`null`):
 *  - an unbalanced brace, or a `}` with no `{` before it — not analyzable;
 *  - a group with no TOP-LEVEL COMMA. Both spellings that produces are constructs capwall does
 *    not model: a bash/minimatch RANGE (`{1..3}`, `{a..z}`), which expands to a sequence this
 *    function would otherwise mistake for the literal `1..3`; and a single-alternative group
 *    (`{a}`), which minimatch does NOT expand at all — it stays the literal `{a}`. Modelling
 *    either would be re-introducing a second grammar to be wrong about;
 *  - more than {@link MAX_BRACE_EXPANSIONS} alternatives.
 *
 * The cap is enforced INSIDE the recursion, so a brace bomb costs O(cap × groups) work rather
 * than being expanded and then rejected.
 */
function expandBraces(pattern: string): string[] | null {
  const open = pattern.indexOf("{");
  if (open === -1) {
    // No group left. A `}` still present is an unbalanced close — not analyzable.
    return pattern.includes("}") ? null : [pattern];
  }
  // A `}` BEFORE the first `{` is unbalanced too, and would otherwise survive into the output.
  if (pattern.slice(0, open).includes("}")) return null;

  let depth = 0;
  let close = -1;
  const commas: number[] = [];
  for (let i = open; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) {
        close = i;
        break;
      }
    } else if (c === "," && depth === 1) commas.push(i);
  }
  if (close === -1) return null; // unbalanced open
  if (commas.length === 0) return null; // a range, or a non-expanding `{a}` — see the doc above

  const head = pattern.slice(0, open);
  const tail = pattern.slice(close + 1);
  const alternatives: string[] = [];
  let start = open + 1;
  for (const comma of commas) {
    alternatives.push(pattern.slice(start, comma));
    start = comma + 1;
  }
  alternatives.push(pattern.slice(start, close));

  const out: string[] = [];
  for (const alternative of alternatives) {
    // `head` has no `{` left, so each recursion consumes one group and the recursion terminates.
    const expanded = expandBraces(head + alternative + tail);
    if (expanded === null) return null;
    if (out.length + expanded.length > MAX_BRACE_EXPANSIONS) return null;
    out.push(...expanded);
  }
  return out;
}

/**
 * Can this brace-free segment, appearing AT OR AFTER the first magic segment, only ever take the
 * walk DOWNWARD?
 *
 * ─────────────────────────────────────────────────────────────────────────────────────────────
 * THE MECHANISM THIS IS BUILT ON, measured rather than assumed (issue #120).
 * ─────────────────────────────────────────────────────────────────────────────────────────────
 * A glob walk moves upward in exactly one way: a segment that the implementation resolves to a
 * literal `..` PATH COMPONENT, which it then joins onto the walk's root. A segment that survives
 * as a MATCHER cannot, because matching is done against directory entries and `readdir` never
 * yields `.` or `..`.
 *
 * That is the difference between the two halves of #120's table, and it is observable:
 * a first segment of `[.][.]` or `[.-.][.-.]` reaches the parent (each single-character class
 * collapses to the literal `.`, so the segment collapses to `..`), while `[.]`+`*`, `..`+`*`,
 * `?.`, `*.`, `@(..)` and `[..]` do NOT — they stay matchers and find nothing. Every one of those
 * was run against real `fs.globSync` on Node 22; the property test in `test/fs-glob.test.ts`
 * re-runs that comparison over generated patterns so the next construct minimatch grows fails the
 * suite instead of the gate.
 *
 * So the test is: does this segment PROVABLY survive as a matcher, or PROVABLY reduce to
 * something that is not a parent reference? Concretely, in order:
 *
 *  1. It contains a `*` or `?`. Nothing in the grammar removes those, so the segment is a
 *     matcher — downward-only. This is what keeps every ordinary pattern working: `**`, `*`,
 *     `*.conf`, `.*`, `*.*`, `[.]*`, `?ab`.
 *  2. It is exactly `.`. A same-directory reference moves nothing.
 *  3. It is built ONLY from dots and glob punctuation ({@link ONLY_DOTS_AND_GLOB_PUNCTUATION}).
 *     capwall cannot prove where that reduces to, so it is UNBOUNDED. This is deliberately
 *     blunter than the truth — `@(..)`, `[..]` and `[.][.][.]` are all harmless in practice —
 *     because the alternative is modelling character-class and extglob reduction, which is the
 *     grammar-modelling this issue exists to stop doing. Conservative by construction: anything
 *     not proven bounded is unbounded.
 *  4. Anything else carries an ordinary character (a letter, a digit, `_`, `#`, …) through
 *     whatever reduction the implementation performs, so it can never become a run of dots.
 *     Bounded: `lib`, `[ab]`, `@(a|b)`, `node_modules`.
 *
 * COST, stated rather than implied. Rule 3 refuses a handful of legitimate spellings — a segment
 * of pure punctuation such as `dir/[.]/x` or `dir/@(..)/x` is treated as unbounded and therefore
 * gated on the filesystem root, which no reasonable policy grants. Adding a `*` or any ordinary
 * character to the segment, or globbing from a directory the package is granted, both work. That
 * is the price of not having a fourth instance of #84/#95/#120.
 */
function segmentIsDownwardOnly(segment: string): boolean {
  if (WILDCARD.test(segment)) return true;
  if (segment === ".") return true;
  return !ONLY_DOTS_AND_GLOB_PUNCTUATION.test(segment);
}

/**
 * The literal leading path prefix of ONE brace-free glob alternative — the deepest directory that
 * alternative's walk cannot escape — or `null` when its reach cannot be bounded.
 *
 * The return value is a `/`-separated, un-resolved path fragment for the caller to resolve
 * against the call's `cwd`: `""` means "the cwd itself", `"/"`/`"C:/"` mean the filesystem root,
 * and anything else is a relative or absolute fragment (which MAY contain `..` — a leading `..`
 * is exact, not an escape, because `path.resolve` accounts for it precisely).
 */
function prefixOfAlternative(alternative: string): string | null {
  const segments = alternative.split("/");
  let firstMagic = segments.length;
  for (let i = 0; i < segments.length; i++) {
    if (NODE_GLOB_MAGIC.test(segments[i]!)) {
      firstMagic = i;
      break;
    }
  }
  // Everything from the first magic segment on has to be provably downward-only. `**` matches
  // ZERO segments as well as many, so a `**` segment followed by `..` followed by `*.conf` is
  // also just `../*.conf` — which is why the scan starts AT `firstMagic` rather than after it,
  // and why a literal `..` there is an escape even though a leading one (in the prefix) is exact.
  for (let i = firstMagic; i < segments.length; i++) {
    if (!segmentIsDownwardOnly(segments[i]!)) return null;
  }

  const prefix = segments.slice(0, firstMagic).join("/");
  // An absolute pattern whose FIRST segment is magic (`/*.conf`, `/**`) splits to `["", "*…"]`,
  // so the joined prefix is the empty string — which would otherwise read as "the cwd" and gate
  // the wrong directory entirely. Its root is `/`.
  if (prefix === "" && alternative.startsWith("/")) return "/";
  // A bare Windows drive segment is not a directory to `path.resolve`: `resolve("D:/x", "C:")`
  // yields the process's CURRENT directory on drive C, not `C:/`. Make it a root explicitly.
  if (DRIVE_SEGMENT.test(prefix)) return prefix + "/";
  return prefix;
}

/**
 * Every literal leading path prefix a Node glob `pattern` can walk from — one per brace
 * alternative, deduplicated — or `null` when its reach **cannot be bounded**.
 *
 * `null` is the fail-closed answer, and the caller must translate it into the filesystem ROOT,
 * not into "no restriction". It is produced by:
 *
 *  - a segment at or after the first magic segment that is not provably downward-only — see
 *    {@link segmentIsDownwardOnly}, which covers a literal `..` and every spelling that may
 *    reduce to one;
 *  - a brace construct capwall refuses to expand — see {@link expandBraces};
 *  - a backslash anywhere. On POSIX that is minimatch's ESCAPE character, so the segmentation
 *    above is no longer reliable; capwall does not model it and refuses to guess. (The fs shim
 *    normalizes `\` to `/` before calling this on win32, where it is a separator instead, so
 *    that case never reaches here.)
 *
 * MORE THAN ONE PREFIX IS THE NORMAL CASE for a braced pattern, and it is the reason this
 * returns a list rather than the single string it did before #120: `data/{a,b}/*` walks from
 * `data/a` AND from `data/b`, and `{.,..}/*.conf` walks from `cwd` AND from its parent. The
 * caller resolves each against `cwd` and gates their common ancestor — see {@link nodeGlobBase} —
 * which is both correct and strictly tighter than the pre-#120 answer, where any brace group
 * spanning a `/` collapsed to "unbounded ⇒ filesystem root".
 */
export function nodeGlobPrefixes(pattern: string): string[] | null {
  if (pattern.includes("\\")) return null;
  const alternatives = expandBraces(pattern);
  if (alternatives === null) return null;
  const prefixes = new Set<string>();
  for (const alternative of alternatives) {
    const prefix = prefixOfAlternative(alternative);
    if (prefix === null) return null; // ONE unbounded alternative makes the whole call unbounded
    prefixes.add(prefix);
  }
  return [...prefixes];
}

/**
 * The deepest directory that contains both `/`-separated absolute paths, or `fallbackRoot` when
 * they share nothing (different Windows drives, or a POSIX path compared against a drive path).
 */
function commonAncestor(a: string, b: string, fallbackRoot: string): string {
  if (a === b) return a;
  const as = a.split("/");
  const bs = b.split("/");
  const shared: string[] = [];
  for (let i = 0; i < Math.min(as.length, bs.length); i++) {
    if (as[i] !== bs[i]) break;
    shared.push(as[i]!);
  }
  // A POSIX absolute path splits to `["", "a", …]`, so one shared (empty) element means "only
  // the root is common"; a Windows one splits to `["C:", "a", …]`, where one shared element is
  // the bare drive — neither is a directory `path.resolve` would accept, so both become a root.
  if (shared.length === 0) return fallbackRoot;
  if (shared.length === 1) {
    const only = shared[0]!;
    if (only === "") return "/";
    if (DRIVE_SEGMENT.test(only)) return only + "/";
  }
  return shared.join("/");
}

/**
 * The directory a Node glob `pattern`'s walk is rooted at, resolved against `cwdDir` — the single
 * path the `fs.read` decision is taken on (issue #106, hardened by #120).
 *
 * `cwdDir` is an absolute NATIVE path; the result is absolute and `/`-separated, the shape
 * `matchesGlob` matches against. When the pattern's reach cannot be bounded, or when its
 * alternatives walk from unrelated places, the answer is the filesystem ROOT — the fail-closed
 * outcome, because no reasonable policy grants `/` and one that does has already said yes to
 * everything else.
 *
 * This resolution step lives here, next to the syntax analysis it consumes, rather than in the fs
 * shim: `test/fs-glob.test.ts`'s property test compares THIS function's answer against where real
 * `fs.globSync` actually walked, and a second copy of the ancestor arithmetic in the shim would
 * be a copy the property test does not cover.
 */
export function nodeGlobBase(pattern: string, cwdDir: string): string {
  const toPolicyPath = (nativePath: string): string => nativePath.split(path.sep).join("/");
  const root = toPolicyPath(path.parse(cwdDir).root);
  const prefixes = nodeGlobPrefixes(pattern);
  if (prefixes === null) return root;
  let base: string | null = null;
  for (const prefix of prefixes) {
    const resolved = toPolicyPath(path.resolve(cwdDir, prefix));
    base = base === null ? resolved : commonAncestor(base, resolved, root);
  }
  return base ?? root;
}
