/**
 * Host-pattern grammar for `net.hosts` — validation AND matching, in one module (issue #83).
 *
 * WHY IT LIVES IN policy-schema RATHER THAN core. #83 was not "the matcher is missing a
 * feature", it was "the documented grammar and the implemented grammar disagreed and nothing
 * noticed": the docs and the schema docblock advertised `"*.internal"`, the evaluator did exact
 * string equality, and a policy author got silent denials instead of an error. Keeping the
 * grammar's ACCEPTANCE rule (used by the Zod schema, so a bad pattern is a load-time error) and
 * its MATCHING rule (used by `@capwall/core`'s evaluator) in the same file is what stops the two
 * drifting apart again. Zero dependencies, no Node builtins — a pure string grammar.
 *
 * ## The grammar
 *
 * A `hosts` entry is one of:
 *
 *  1. The single literal `"*"` — ANY host, including IP literals and the legacy `<ipc>`
 *     pseudo-host. Unchanged from before #83.
 *  2. A pattern with no `*` — an EXACT hostname. Unchanged from before #83 except that the
 *     comparison is now ASCII-case-insensitive (see below); no pattern that used to be accepted
 *     is now rejected, and no exact pattern matches a host it did not match before.
 *  3. A WILDCARD pattern — dot-separated labels where
 *       - `*` inside a label matches any run of characters that contains no `.`. A label that is
 *         exactly `*` matches ONE WHOLE label and requires it to be non-empty, so `*.internal`
 *         matches `api.internal` but not `.internal`. `*` never crosses a dot, exactly as the
 *         `fs` matcher's `*` never crosses a `/`.
 *       - `**` as a WHOLE FIRST label matches ONE OR MORE leading labels, so `**.internal`
 *         matches `api.internal` and `a.b.internal`.
 *
 * ### The predictions this is chosen to make true
 *
 *  - `*.internal` matches `api.internal`. It does NOT match `internal` (there is no label to
 *    fill), and it does NOT match `a.b.internal` (one `*`, one label). This is the
 *    wildcard-certificate rule from RFC 6125 § 6.4.3 — the wildcard-host rule practically every
 *    author has already met, in TLS certificates and in DNS.
 *  - `evil-internal` is not matched by `*.internal`: the dot is part of the pattern, so a
 *    wildcard can never eat the separator and turn a suffix into a substring.
 *  - Want any depth? Say so: `**.internal`. It still does not match the apex `internal` —
 *    the apex is usually a different service, and a grant that silently included it would be
 *    the kind of surprise this issue is about. Grant `internal` explicitly if you mean it.
 *    (This is a deliberate divergence from the `fs` matcher, where `dir/**` DOES match `dir`
 *    itself so that `mkdirSync("./logs")` works under `./logs/**`. Paths and hostnames read in
 *    opposite directions and the ergonomics do not transfer.)
 *  - `api-*.internal` works: `*` is allowed mid-label. `api-*` alone is a legal single-label
 *    pattern too (intranet short names), and matches only single-label hosts.
 *  - A leading dot, a trailing dot, or an empty label in a wildcard pattern is a load-time
 *    ERROR, not a pattern that quietly matches nothing. Silent non-matching is the defect.
 *
 * ### IP literals
 *
 * A wildcard pattern NEVER matches a host that could be read as an IP address. `*.1.1` matching
 * `1.1.1.1`, or `**.0.1` matching `127.0.0.1`, would be an alarming way to lose a grant's
 * meaning — an IP address is not a DNS name and its dots are not delegation boundaries. Two
 * defenses, both fail-closed:
 *   - {@link isIpLiteral} is deliberately GENEROUS about what counts as an IP (any host
 *     containing `:`, which covers unbracketed IPv6 as stored since #46; anything built only
 *     from digits and dots, which covers `1.1.1.1`, the zero-padded `010.1.1.1` and the
 *     integer form `3232235777`). Being generous here can only ever make a wildcard match
 *     FEWER hosts.
 *   - {@link validateHostPattern} REJECTS a wildcard pattern that looks like it was meant to
 *     match an IP (an all-numeric rightmost label, or any `:`), so the author is told rather
 *     than left with an entry that can never fire. IP addresses must be listed exactly.
 *
 * ### Case and Unicode
 *
 * Matching lowercases A–Z on both sides — and ONLY A–Z. Hostnames are case-insensitive
 * (RFC 4343), so `API.example.com` and `api.example.com` are the same host and matching them
 * interchangeably grants no endpoint that was not already granted. `String#toLowerCase()` is
 * NOT used, because full Unicode case folding maps distinct characters onto ASCII ones —
 * U+212A KELVIN SIGN lowercases to `k`, U+0130 to `i` + a combining mark — which would let a
 * non-ASCII host match an ASCII grant. ASCII-only folding cannot do that.
 *
 * No IDNA/punycode conversion is performed, in either direction. Node's URL-based egress
 * (`fetch`, `http.request(url)`, `http2.connect`) hands capwall the ALREADY-punycoded
 * `hostname`, so that is what a policy must list — `xn--mnchen-3ya.de`, which is also what
 * `capwall observe` records. A raw `net.connect({ host: "münchen.de" })` is not converted by
 * Node either, and capwall matches it literally. Doing the conversion here would mean shipping
 * (or approximating) IDNA mapping tables in the hot path to paper over a difference Node itself
 * makes; matching what Node dials is the honest rule. A non-ASCII pattern is accepted and
 * matched literally, byte for byte.
 */

/** The one literal that grants every host, including IP literals. Predates #83. */
export const ANY_HOST = "*";

/**
 * Could `host` be read as an IP address? Deliberately over-inclusive: a false positive only
 * narrows a wildcard grant (fail closed), a false negative would let `*.1.1` match `1.1.1.1`.
 *
 * `:` covers IPv6 in the UNBRACKETED spelling capwall guards and records (#46) and the
 * bracketed one an author might mistakenly write. Digits-and-dots covers dotted-quad IPv4 and
 * its zero-padded / integer variants. Neither shape is ever a legitimate DNS name: the
 * rightmost label of a domain name may not be all-numeric, precisely so names and addresses
 * stay distinguishable.
 *
 * @param host a destination hostname as capwall guards it — for IPv6, unbracketed.
 * @returns whether it could be read as an address. A `true` here only ever makes a wildcard
 *     grant match fewer hosts.
 */
export function isIpLiteral(host: string): boolean {
  if (host.includes(":")) return true;
  return /^[0-9.]+$/.test(host);
}

/** Lowercase A–Z and nothing else — see the module header on why not `toLowerCase()`. */
function asciiLower(value: string): string {
  return value.replace(/[A-Z]+/g, (run) => run.toLowerCase());
}

/** A label made only of `*` characters (`*`, `**`, `***`, …). */
const ALL_STARS = /^\*+$/;

/**
 * Validate one `hosts` entry. Returns `null` when valid, else a message explaining what to
 * write instead — surfaced by the schema as a load-time error, because #83 is fundamentally
 * about a pattern that failed silently.
 *
 * Patterns WITHOUT a `*` are accepted unconditionally. That is deliberate: they are exact
 * hostnames, they were accepted before #83, and a policy that loaded yesterday must load today.
 *
 * @param pattern one `net.hosts` entry.
 * @returns `null` when the pattern is acceptable, otherwise the message to show the author.
 *     Never throws — the schema turns a message into a load-time issue.
 */
export function validateHostPattern(pattern: string): string | null {
  if (pattern === ANY_HOST) return null;
  if (!pattern.includes("*")) return null; // exact host — no new rejections, ever

  if (pattern.includes(":")) {
    return `host pattern '${pattern}': wildcards cannot be used in an IP literal — list the address exactly (IPv6 unbracketed, e.g. "::1")`;
  }
  const labels = pattern.split(".");
  if (labels.some((l) => l.length === 0)) {
    return `host pattern '${pattern}': empty label (a leading dot, a trailing dot, or '..') — write e.g. "*.internal"`;
  }
  for (let i = 0; i < labels.length; i++) {
    const label = labels[i]!;
    if (label.includes("**")) {
      if (!ALL_STARS.test(label) || label.length !== 2) {
        return `host pattern '${pattern}': '**' must be a whole label on its own (write "**.internal", not "${label}")`;
      }
      if (i !== 0) {
        return `host pattern '${pattern}': '**' is only allowed as the FIRST label (it matches one or more leading labels)`;
      }
    } else if (ALL_STARS.test(label) && label.length > 1) {
      return `host pattern '${pattern}': '${label}' is not a wildcard — use '*' for one label or '**' for one or more`;
    }
  }
  if (labels.length === 1 && ALL_STARS.test(labels[0]!)) {
    return `host pattern '${pattern}': use the single literal "*" to grant any host`;
  }
  const last = labels[labels.length - 1]!;
  if (/^[0-9]+$/.test(last)) {
    return `host pattern '${pattern}': a wildcard host pattern never matches an IP address (its dots are not name boundaries) — list the address exactly`;
  }
  return null;
}

const regexCache = new Map<string, RegExp>();

/** Escape everything a regex would otherwise read as syntax. `*` is handled by the caller. */
function escapeLiteral(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function labelToRegex(label: string): string {
  // A label that is EXACTLY `*` stands for one whole, non-empty label; a `*` inside a longer
  // label is an ordinary zero-or-more run (the surrounding literal text already forces the
  // label to be non-empty).
  if (label === ANY_HOST) return "[^.]+";
  return label
    .split("*")
    .map(escapeLiteral)
    .join("[^.]*");
}

/** Compile an already-lowercased wildcard pattern. Cached: the evaluator is on the hot path. */
function compile(pattern: string): RegExp {
  const cached = regexCache.get(pattern);
  if (cached) return cached;
  const labels = pattern.split(".");
  let out = "^";
  let start = 0;
  if (labels[0] === "**") {
    // One or more leading labels, each non-empty and each followed by its dot. The `\.` inside
    // the group means every repetition must consume a separator, so the number of repetitions
    // is bounded by the number of dots in the candidate — this is not the unbounded-adjacent-
    // groups shape that makes a glob ReDoS-able, and `**` is grammatically confined to the
    // first label so two such groups can never end up next to each other.
    out += "(?:[^.]+\\.)+";
    start = 1;
  }
  out += labels
    .slice(start)
    .map(labelToRegex)
    .join("\\.");
  out += "$";
  const re = new RegExp(out);
  regexCache.set(pattern, re);
  return re;
}

/**
 * Does `host` match `pattern`? `host` is the destination exactly as capwall guards it — for
 * IPv6, unbracketed (#46).
 *
 * Order matters: `"*"` first (it must keep granting IP literals, as it always has), then the
 * exact comparison (no wildcard, so no IP special case is needed and none is applied), then the
 * IP guard, then the compiled glob.
 *
 * @param pattern one `net.hosts` entry, assumed to have passed {@link validateHostPattern}. An
 *     invalid pattern does not throw here; it simply matches nothing useful, which is the
 *     silent failure the schema exists to prevent.
 * @param host the destination being decided.
 * @returns whether the entry grants that host. ASCII-case-insensitive on both sides.
 */
export function matchesHostPattern(pattern: string, host: string): boolean {
  if (pattern === ANY_HOST) return true;
  const p = asciiLower(pattern);
  const h = asciiLower(host);
  if (!pattern.includes("*")) return p === h;
  if (isIpLiteral(h)) return false; // a wildcard never matches an address — see the header
  return compile(p).test(h);
}
