/**
 * `packages` key grammar (issue #92) — the widening table, and the load-time rejection of a
 * malformed key.
 *
 * Deliberately the sibling of `policy-hosts.test.ts`, because the grammar is deliberately the
 * sibling of the host grammar. #92 introduced install-chain principals (`webpack>lodash`), and a
 * chain needs a way to say "this package, wherever it is nested" — which means a second wildcard
 * grammar in a policy file that already had one. Two grammars spelling `*` differently would be a
 * trap, so the rules are matched sigil for sigil against `net.hosts`:
 *
 *   *.internal   one leading LABEL     |   *>lodash    one leading LINK
 *   **.internal  one or more labels    |   **>lodash   one or more links
 *   neither matches the bare `internal` / the top-level `lodash`
 *
 * And #83's lesson applies here too: a wildcard that silently matches nothing is the defect, so a
 * key that cannot work is refused at load time rather than left to quietly grant nobody.
 */
import { describe, expect, it } from "vitest";
import { parsePolicy, validatePackageKey, widenedPackageKeys } from "@capwall/policy-schema";

/** Would a policy whose only entry is `key` grant `pkg`? Exercises the real lookup. */
function covers(key: string, pkg: string): boolean {
  return widenedPackageKeys(pkg).includes(key) || key === pkg;
}

describe("package keys — the widening table", () => {
  // [key, principal, expected]
  const table: Array<[string, string, boolean]> = [
    // Exact keys: unchanged, and the only thing that reaches a top-level install.
    ["lodash", "lodash", true],
    ["lodash", "evil>lodash", false],
    ["webpack>lodash", "webpack>lodash", true],
    ["webpack>lodash", "lodash", false],

    // `*>name` — EXACTLY ONE leading link, like `*.internal` is exactly one leading label.
    ["*>lodash", "evil>lodash", true],
    ["*>lodash", "a>b>lodash", false],
    ["*>lodash", "lodash", false],

    // `**>name` — ONE OR MORE, like `**.internal`. Still never the top-level install.
    ["**>lodash", "evil>lodash", true],
    ["**>lodash", "a>b>lodash", true],
    ["**>lodash", "a>b>c>lodash", true],
    ["**>lodash", "lodash", false],

    // Only the LAST link is wildcarded: there is no subtree grant.
    ["**>lodash", "lodash>evil", false],
    ["*>lodash", "lodash>evil", false],

    // Scoped names are ordinary links.
    ["**>@scope/pkg", "a>@scope/pkg", true],
    ["*>@scope/pkg", "@scope/host>@scope/pkg", true],
  ];

  for (const [key, pkg, expected] of table) {
    it(`'${key}' ${expected ? "covers" : "does not cover"} '${pkg}'`, () => {
      expect(covers(key, pkg)).toBe(expected);
    });
  }

  it("offers the narrower key first when both could apply", () => {
    // `policyFor` walks this list in order, so a `*>lodash` entry beats a `**>lodash` one for a
    // principal both could match — the same "more specific wins" an exact entry has over
    // `default`.
    expect(widenedPackageKeys("a>lodash")).toEqual(["*>lodash", "**>lodash"]);
    expect(widenedPackageKeys("a>b>lodash")).toEqual(["**>lodash"]);
  });

  it("offers nothing for a top-level name — the whole point of #92", () => {
    expect(widenedPackageKeys("lodash")).toEqual([]);
  });

  it("offers nothing for either sentinel, which both CONTAIN a '>'", () => {
    // A naive "split on the last '>'" widening reads `<app>` as a chain with an empty leaf, so a
    // key of `"*>"` would have granted the TRUST ROOT. Pinned because it is not obvious from the
    // sentinel spellings that they interact with this grammar at all.
    expect(widenedPackageKeys("<app>")).toEqual([]);
    expect(widenedPackageKeys("<unknown>")).toEqual([]);
  });
});

describe("package keys — a malformed key is a load-time error, not a silent non-match", () => {
  const bad: Array<[string, RegExp]> = [
    ["*", /no "every package" key/],
    ["**", /no "every package" key/],
    ["*>", /nothing to grant after/],
    ["**>", /nothing to grant after/],
    ["evil>*", /must be named exactly/],
    ["evil>**", /must be named exactly/],
    ["*>*", /must be named exactly/],
    ["lod*", /whole first link/],
    ["*lodash", /whole first link/],
    ["a>*>b", /only allowed as the FIRST link/],
    ["*>a>b", /only allowed as the FIRST link/],
    ["***>lodash", /is not a wildcard link/],
    ["a*>lodash", /is not a wildcard link/],
  ];

  for (const [key, message] of bad) {
    it(`rejects '${key}'`, () => {
      expect(validatePackageKey(key)).toMatch(message);
      expect(() => parsePolicy({ version: 1, packages: { [key]: { vm: true } } })).toThrow();
    });
  }

  const good = [
    "lodash",
    "@scope/pkg",
    "webpack>lodash",
    "a>b>c",
    "*>lodash",
    "**>lodash",
    "**>@scope/pkg",
    "<app>",
    "<unknown>",
  ];
  for (const key of good) {
    it(`accepts '${key}'`, () => {
      expect(validatePackageKey(key)).toBeNull();
      expect(() => parsePolicy({ version: 1, packages: { [key]: { vm: true } } })).not.toThrow();
    });
  }

  it("accepts any wildcard-free key, however odd — exact names gain no new rejections", () => {
    // The compatibility guarantee, same as the host grammar's: a policy that loaded yesterday
    // loads today. Only a key that reaches for a `*` can fail.
    for (const key of ["a>", ">b", "..", "node_modules", "a b"]) {
      expect(validatePackageKey(key)).toBeNull();
    }
  });
});
