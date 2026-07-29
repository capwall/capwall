/**
 * Package-key grammar for `packages` — validation AND matching, in one module (issues #92, #83).
 *
 * WHY IT LIVES HERE, next to `host.ts`, rather than in core. Same reason and the same shape:
 * #83 was not "the matcher is missing a feature", it was "the documented grammar and the
 * implemented grammar disagreed and nothing noticed", and a policy author got silent denials
 * instead of an error. A wildcard that quietly matches nothing is the defect. So the ACCEPTANCE
 * rule (used by the Zod schema, making a bad key a load-time error) and the MATCHING rule (used
 * by `@capwall/core`'s `policyFor`) live in one file. Zero dependencies, pure string work.
 *
 * #118 added the third member of that family, {@link unmatchedPackageKeys}: a key can be
 * well-formed, load without a murmur, and still match no principal that ever runs (`"inner"`
 * when the principal is `outer>inner`; `"loadsh"`; a dependency removed three refactors ago).
 * Load-time validation cannot see that — whether a key matches is a runtime fact — so the CLI
 * asks this module after a run, when the set of principals is known. Same standard as the
 * wildcard rule, applied to the keys the grammar cannot judge.
 *
 * ## What a `packages` key names
 *
 * A principal, as attribution reports it (issue #92): the INSTALL CHAIN from the project root,
 * every `node_modules/<name>` segment joined by {@link CHAIN_SEP}.
 *
 *   node_modules/lodash/index.js                     ->  "lodash"
 *   node_modules/webpack/node_modules/lodash/i.js    ->  "webpack>lodash"
 *   node_modules/a/node_modules/b/node_modules/c/…   ->  "a>b>c"
 *
 * plus the two sentinels `<app>` and `<unknown>`. `>` is the separator because npm forbids it in
 * a package name, so a chain can never collide with a real name.
 *
 * ## The grammar
 *
 * A key is one of:
 *
 *  1. An EXACT principal — no `*` anywhere. Every key that was legal before #92 still is, and
 *     still matches exactly what it matched.
 *  2. `"*>name"` — `name` installed under EXACTLY ONE other package: matches `a>name`, and NOT
 *     `a>b>name`, and NOT the top-level `name`.
 *  3. `"**>name"` — `name` installed under ONE OR MORE other packages: matches `a>name` and
 *     `a>b>name`, and still NOT the top-level `name`.
 *
 * ### This is deliberately the SAME grammar as `net.hosts`, sigil for sigil
 *
 * `*` and `**` already mean something in this file — `host.ts` gives `"*.internal"` (exactly one
 * leading label) and `"**.internal"` (one or more). Two wildcard grammars in one policy document
 * that spelled the same sigil differently would be a trap, so the rules are matched to the
 * letter, only with `>` in place of `.`:
 *
 * | | `net.hosts` | `packages` |
 * |---|---|---|
 * | one leading component | `*.internal` | `*>lodash` |
 * | one or more leading components | `**.internal` | `**>lodash` |
 * | wildcard is confined to the FIRST component | yes | yes |
 * | matches the bare right-hand side (`internal` / `lodash`) | no | no |
 *
 * The "does not match the apex" rule carries over for the same reason it holds for hosts: the
 * top-level install of `lodash` is usually a different thing from the copy some dependency
 * dragged in, and a grant that silently included both would be exactly the surprise #92 is about.
 * Grant `"lodash"` explicitly if you mean it — "everywhere" is two keys.
 *
 * ### What is deliberately NOT borrowed from the host grammar
 *
 * `host.ts` allows a `*` INSIDE a label (`api-*.internal`). A package key does not: a wildcard
 * must be a WHOLE link. Partial matching on package names has no use case that a scope does not
 * cover better, and it has an obvious hazard — `"lod*"` would silently cover a typosquat named
 * `lodasch`. There is likewise no `"evil>*"` subtree form: "everything this package vendors" is
 * the attacker's grant, not an author's. Both are rejected at load time with a message, not left
 * to match nothing.
 *
 * `"*"` on its own is rejected too, and this is the one most likely to be typed: the key that
 * applies to every package is the top-level `default` block, and saying so in an error is better
 * than a key that looks like it works.
 */

/**
 * Separator between the links of an install chain (issue #92).
 *
 * `lodash` is the top-level install; `evil>lodash` is the copy installed *under* `evil`, whether
 * npm put it there to resolve a version conflict or `evil` shipped it in its own tarball. capwall
 * cannot tell those apart from disk, so it declines to conflate either with the top-level install.
 */
export const CHAIN_SEP = ">";

/** `*` — one leading link. `**` — one or more. Both only as the whole first link. */
const ONE_LINK = "*";
const ANY_LINKS = "**";

/**
 * Split a principal into its chain links, or `null` if it is not a chain that may be widened.
 *
 * Returns `null` for a top-level name (nothing to widen), for either sentinel — `<app>` and
 * `<unknown>` contain a `>` and would otherwise be read as a chain with an empty second link,
 * so a key of `"*>"` would have granted the TRUST ROOT — and for anything malformed. The
 * empty-link check is what actually excludes the sentinels; the `<` test is belt-and-braces so a
 * future sentinel cannot reintroduce the hole by being differently shaped.
 */
function splitChain(pkg: string): string[] | null {
  if (pkg.startsWith("<") || !pkg.includes(CHAIN_SEP)) return null;
  const links = pkg.split(CHAIN_SEP);
  if (links.length < 2) return null;
  if (links.some((l) => l === "" || l.includes(ONE_LINK))) return null;
  return links;
}

/**
 * The wildcard keys that could grant `pkg`, MOST SPECIFIC FIRST.
 *
 * Empty for a top-level name or a sentinel: those match by exact key only, which is what keeps a
 * vendored `evil>lodash` from reaching `lodash`'s entry (#92). `policyFor` tries the exact key
 * first, then these in order, then `default` — so a narrow `"*>lodash"` beats a broad
 * `"**>lodash"`, the same way an explicit entry beats `default`.
 *
 * @param pkg a principal as attribution reports it.
 * @returns the candidate wildcard keys, most specific first; empty for a top-level name or a
 *     sentinel. These are keys to LOOK UP, not keys that exist — the caller checks the policy.
 */
export function widenedPackageKeys(pkg: string): string[] {
  const links = splitChain(pkg);
  if (links === null) return [];
  const leaf = links[links.length - 1]!;
  // Exactly one leading link -> both wildcards apply; deeper -> only the "one or more" form.
  return links.length === 2
    ? [`${ONE_LINK}${CHAIN_SEP}${leaf}`, `${ANY_LINKS}${CHAIN_SEP}${leaf}`]
    : [`${ANY_LINKS}${CHAIN_SEP}${leaf}`];
}

/**
 * Does `key` grant `pkg`? The same rule `policyFor` (core's `policy/evaluate.ts`) applies, asked
 * from the other side — exact principal, or one of the wildcard keys that widen to it.
 *
 * It lives here, next to `widenedPackageKeys`, so the two can only ever disagree by someone
 * editing this file: a "did this key match anything?" report that used a *different* notion of
 * matching from the enforcer would be worse than no report, because it would name keys that
 * work and clear keys that do not.
 *
 * @param key a `packages` key, exact or wildcard.
 * @param pkg a principal.
 * @returns whether the key would be consulted for that principal. It does not say the key WINS:
 *     a more specific key may be checked first (see {@link widenedPackageKeys} for the order).
 */
export function packageKeyMatches(key: string, pkg: string): boolean {
  return key === pkg || widenedPackageKeys(pkg).includes(key);
}

/** A `packages` key that granted nothing, with the principals it was probably meant to name. */
export interface UnmatchedPackageKey {
  /** The key exactly as it appears in the policy document. */
  key: string;
  /** Observed principals with the same LEAF as `key` — the near-misses, most likely first. */
  suggestions: string[];
}

/** The last link of a key or principal (`outer>inner` -> `inner`), wildcards stripped. */
function leafOf(key: string): string {
  const links = key.split(CHAIN_SEP);
  return links[links.length - 1] ?? key;
}

/**
 * Which of `keys` matched NONE of `principals` (issue #118).
 *
 * `validatePackageKey` rejects a key that cannot match anything *by grammar*; this answers the
 * other half — a perfectly well-formed key that, in a run that just happened, matched nothing
 * that ran. The two are complementary and neither subsumes the other: `"loadsh"` is a valid key
 * and a dead one, and no amount of load-time validation can know that without watching a
 * process.
 *
 * IT IS A REPORT, NOT A VERDICT, and the caller must keep it that way. A key matching nothing
 * fails CLOSED — the grant simply does not apply — so this is a usability and trust defect
 * rather than a hole: the harm is that `capabilities.json` says something the reader believes
 * and the runtime does not honor. It is also *legitimately* possible for a key to match nothing
 * in one run (an optional dependency, a code path this run did not take), which is exactly why
 * this cannot be a load-time error and why the CLI reports it as a warning.
 *
 * The suggestion is the leaf trick from #118: the mistake a real author makes is writing the
 * bare name they read in `package.json` when the principal is an install chain, so an unmatched
 * `"inner"` next to an observed `outer>inner` is almost always that. Suggestions are drawn only
 * from principals actually seen, so they can never point at a key that would also be dead.
 *
 * @param keys the policy's `packages` keys.
 * @param principals every principal observed in one run — from a trace, not from the policy.
 * @returns one entry per dead key, in the order `keys` yielded them. Empty when every key
 *     matched something, and empty for an empty `keys`. Both arguments are iterated once.
 */
export function unmatchedPackageKeys(
  keys: Iterable<string>,
  principals: Iterable<string>,
): UnmatchedPackageKey[] {
  const seen = [...principals];
  const unmatched: UnmatchedPackageKey[] = [];
  for (const key of keys) {
    if (seen.some((pkg) => packageKeyMatches(key, pkg))) continue;
    const leaf = leafOf(key);
    const suggestions = seen
      .filter((pkg) => pkg !== key && leafOf(pkg) === leaf)
      .sort((a, b) => a.length - b.length || a.localeCompare(b));
    unmatched.push({ key, suggestions });
  }
  return unmatched;
}

/**
 * Validate one `packages` key. Returns `null` when valid, else a message explaining what to write
 * instead — surfaced by the schema as a load-time error.
 *
 * Keys WITHOUT a `*` are accepted unconditionally: they are exact principal names, they were
 * accepted before this grammar existed, and a policy that loaded yesterday must load today. Only
 * a key that reaches for a wildcard can fail, and it fails loudly rather than silently.
 *
 * @param key one `packages` key.
 * @returns `null` when the key is well-formed, otherwise the message to show the author. This
 *     judges GRAMMAR only; a well-formed key that names nothing real is
 *     {@link unmatchedPackageKeys}' question, and cannot be answered until something has run.
 */
export function validatePackageKey(key: string): string | null {
  if (!key.includes(ONE_LINK)) return null; // exact principal — no new rejections, ever

  if (key === ONE_LINK || key === ANY_LINKS) {
    return `package key '${key}': there is no "every package" key — put shared grants in the top-level "default" block instead`;
  }
  const links = key.split(CHAIN_SEP);
  const leaf = links[links.length - 1]!;

  // Order matters: report what the author was REACHING FOR, not the first rule that trips. A
  // key like "evil>*" fails the head test too, but "the head is not a wildcard" would be an
  // unhelpful description of an attempt to grant a subtree.
  if (leaf.includes(ONE_LINK) && links.length > 1) {
    return `package key '${key}': the granted package must be named exactly — there is no "everything this package vendors" form, which would be the attacker's grant rather than an author's`;
  }
  if (links.length < 2) {
    const bare = key.replace(/\*/g, "");
    return `package key '${key}': a wildcard must be the whole first link of a chain — write "${ONE_LINK}${CHAIN_SEP}${bare}" (nested one level) or "${ANY_LINKS}${CHAIN_SEP}${bare}" (any depth); a '*' inside a name is not supported`;
  }
  if (links.length > 2) {
    return `package key '${key}': a wildcard is only allowed as the FIRST link, and a wildcard key has exactly two — write "${ANY_LINKS}${CHAIN_SEP}${leaf}" to grant that package at any depth`;
  }
  if (leaf === "") {
    return `package key '${key}': nothing to grant after '${CHAIN_SEP}' — write e.g. "${links[0]!}${CHAIN_SEP}lodash"`;
  }
  const head = links[0]!;
  if (head !== ONE_LINK && head !== ANY_LINKS) {
    return `package key '${key}': '${head}' is not a wildcard link — use '${ONE_LINK}' for a package nested one level or '${ANY_LINKS}' for any depth (a '*' inside a name is not supported; grant the name exactly)`;
  }
  return null;
}
