/**
 * `net.hosts` matching (issue #83) — the matching table, the surprising cases the grammar was
 * chosen to make predictable, and the load-time rejection of malformed patterns.
 *
 * The defect #83 records is not "a feature is missing", it is "the docs promised `*.internal`
 * and the evaluator did exact equality, and nothing complained". So these tests pin BOTH halves
 * of the fix: what a pattern matches, and that a pattern which cannot work is an error rather
 * than an entry that silently matches nothing.
 *
 * The last block is the compatibility guarantee: every exact-host policy behaves exactly as it
 * did before.
 */
import { describe, expect, it } from "vitest";
import { matchesHostPattern, parsePolicy, validateHostPattern } from "@capwall/policy-schema";
import { isGranted } from "../src/policy/evaluate.js";
import type { PackagePolicy } from "@capwall/policy-schema";

function netGrant(hosts: string[], ports: Array<number | "*"> = [443]): PackagePolicy {
  return { net: { hosts, ports } };
}

function allows(hosts: string[], host: string, port = 443): boolean {
  return isGranted(netGrant(hosts), { kind: "net", host, port });
}

describe("host patterns — the matching table", () => {
  // [pattern, host, expected]
  const table: Array<[string, string, boolean]> = [
    // The single literal "*" — unchanged since before #83: any host at all.
    ["*", "api.internal", true],
    ["*", "1.1.1.1", true],
    ["*", "::1", true],

    // Exact hostnames — unchanged, except that the comparison is case-insensitive.
    ["api.internal", "api.internal", true],
    ["api.internal", "db.internal", false],
    ["api.internal", "x.api.internal", false],
    ["API.Internal", "api.internal", true],
    ["api.internal", "API.INTERNAL", true],

    // `*` = exactly one label, and it never crosses a dot (RFC 6125's wildcard-cert rule).
    ["*.internal", "api.internal", true],
    ["*.internal", "db.internal", true],
    ["*.internal", "internal", false], // no label to fill — the apex is not granted
    ["*.internal", "a.b.internal", false], // one star, one label
    ["*.internal", "evil-internal", false], // the dot is part of the pattern
    ["*.internal", ".internal", false], // an empty label is not a label
    ["*.internal", "api.internal.", false], // trailing root dot is a different string
    ["*.INTERNAL", "API.internal", true],

    // `*` mid-label, and a single-label pattern.
    ["api-*.internal", "api-1.internal", true],
    ["api-*.internal", "api-.internal", true], // zero characters, but the label is non-empty
    ["api-*.internal", "apx-1.internal", false],
    ["api-*.internal", "api-1.2.internal", false],
    ["api-*", "api-1", true],
    ["api-*", "api-1.internal", false],
    ["*.*", "a.b", true],
    ["*.*", "a.b.c", false],

    // `**` = one or more leading labels. Still not the apex — say `internal` if you mean it.
    ["**.internal", "api.internal", true],
    ["**.internal", "a.b.internal", true],
    ["**.internal", "a.b.c.d.internal", true],
    ["**.internal", "internal", false],
    ["**.internal", "evil-internal", false],
    ["**.example.com", "a.b.example.com", true],
    ["**.example.com", "example.com", false],

    // IP literals are never reached by a wildcard — see policy-schema/src/host.ts.
    ["*.1.1", "1.1.1.1", false],
    ["**.1", "127.0.0.1", false],
    ["*.internal", "10.0.0.5", false],
    ["**.internal", "3232235777", false],
    ["*.internal", "::1", false],
    ["*.internal", "fe80::1", false],
    ["::1", "::1", true], // exact IPv6, unbracketed as capwall stores it (#46)
    ["::1", "::2", false],
    ["1.1.1.1", "1.1.1.1", true],

    // Case folding is ASCII-only on purpose: `toLowerCase()` would fold U+212A KELVIN SIGN
    // onto `k` and let a non-ASCII host satisfy an ASCII grant.
    ["k.internal", "K.internal", false],
    ["K.internal", "k.internal", false],
    // No IDNA conversion in either direction — a policy lists what Node dials.
    ["*.münchen.de", "api.münchen.de", true],
    ["*.münchen.de", "api.xn--mnchen-3ya.de", false],
    ["*.xn--mnchen-3ya.de", "api.xn--mnchen-3ya.de", true],

    // The pseudo-host a pre-#72 policy uses for IPC is an ordinary string to this matcher.
    ["*", "<ipc>", true],
    ["*.internal", "<ipc>", false],
  ];

  for (const [pattern, host, expected] of table) {
    it(`'${pattern}' ${expected ? "matches" : "does not match"} '${host}'`, () => {
      expect(matchesHostPattern(pattern, host)).toBe(expected);
    });
  }
});

describe("host patterns — malformed patterns are a load-time error, not a silent non-match", () => {
  const bad: Array<[string, RegExp]> = [
    ["*.internal.", /empty label/],
    [".*.internal", /empty label/],
    ["*..internal", /empty label/],
    ["a.**.b", /only allowed as the FIRST label/],
    ["**.a.**", /only allowed as the FIRST label/],
    ["**foo.internal", /whole label/],
    ["foo**.internal", /whole label/],
    ["***.internal", /whole label/],
    ["**", /use the single literal/],
    ["2001:db8:*", /IP literal/],
    ["*::1", /IP literal/],
    ["*.1.1", /never matches an IP address/],
    ["**.0.1", /never matches an IP address/],
  ];

  for (const [pattern, message] of bad) {
    it(`rejects '${pattern}'`, () => {
      expect(validateHostPattern(pattern)).toMatch(message);
      expect(() =>
        parsePolicy({ version: 1, packages: { dep: { net: { hosts: [pattern], ports: [443] } } } }),
      ).toThrow();
    });
  }

  const good = ["*", "api.internal", "*.internal", "**.internal", "api-*.internal", "api-*", "*.*", "::1"];
  for (const pattern of good) {
    it(`accepts '${pattern}'`, () => {
      expect(validateHostPattern(pattern)).toBeNull();
      expect(() =>
        parsePolicy({ version: 1, packages: { dep: { net: { hosts: [pattern], ports: [443] } } } }),
      ).not.toThrow();
    });
  }

  it("accepts a pattern with a leading dot when it has no wildcard — it is an exact host, and exact hosts gain no new rejections", () => {
    expect(validateHostPattern(".internal")).toBeNull();
    expect(matchesHostPattern(".internal", ".internal")).toBe(true);
  });
});

describe("host patterns through the evaluator", () => {
  it("grants a wildcard host only on a granted port", () => {
    expect(allows(["*.internal"], "api.internal", 443)).toBe(true);
    expect(allows(["*.internal"], "api.internal", 8443)).toBe(false);
  });

  it("a wildcard entry alongside exact entries is additive", () => {
    const hosts = ["registry.example.com", "*.internal"];
    expect(allows(hosts, "registry.example.com")).toBe(true);
    expect(allows(hosts, "db.internal")).toBe(true);
    expect(allows(hosts, "evil.com")).toBe(false);
  });

  it("an empty hosts list still denies everything", () => {
    expect(allows([], "api.internal")).toBe(false);
  });
});

describe("BACKWARD COMPATIBILITY: exact-host policies are unchanged by #83", () => {
  // Every host spelling capwall can produce, against an exact grant for the same host and
  // against an exact grant for a different one. If any of these moved, an existing deployed
  // policy changed meaning.
  const exactHosts = ["api.example.com", "localhost", "127.0.0.1", "::1", "example.com", "<ipc>"];

  for (const host of exactHosts) {
    it(`'${host}' is granted by its own exact entry and by nothing else`, () => {
      expect(allows([host], host)).toBe(true);
      for (const other of exactHosts) {
        if (other === host) continue;
        expect(allows([other], host)).toBe(false);
      }
    });
  }

  it("`hosts: [\"*\"]` still grants every host, IP literals included", () => {
    for (const host of [...exactHosts, "anything.at.all"]) {
      expect(allows(["*"], host)).toBe(true);
    }
  });

  it("an exact entry never gains wildcard behavior", () => {
    expect(allows(["internal"], "api.internal")).toBe(false);
    expect(allows(["example.com"], "evil.example.com")).toBe(false);
    expect(allows(["api.example.com"], "api.example.com.evil.test")).toBe(false);
  });

  it("a wildcard entry is a strict WIDENING of its pre-#83 reading — nothing it used to match stopped matching", () => {
    // Before #83 `"*.internal"` matched a host *literally named* `*.internal` and nothing else.
    // It still does (`*` is a character `[^.]+` accepts), so no policy lost a match; it now
    // also matches the hosts the author meant. Every behavior change in #83 is in this
    // direction, which is why the existing suite is unmoved.
    expect(allows(["*.internal"], "*.internal")).toBe(true);
    expect(allows(["*.internal"], "api.internal")).toBe(true);
  });
});
