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
 * Both pattern and candidate are expected as absolute paths with `/` separators (the policy
 * loader normalizes globs against the project root; shims resolve call paths). Comparison is
 * purely lexical — symlinks/fds are out of scope (docs/threat-model.md).
 */

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

  const segments = pattern.split("/").filter((s) => s.length > 0);
  let out = "^";
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i]!;
    if (seg === "**") {
      // `(/…)*` — zero or more whole segments; also allows matching the base dir itself.
      out += "(?:/[^/]+)*";
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
