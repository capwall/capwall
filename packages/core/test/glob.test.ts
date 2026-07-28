/** Glob matching + policy-loader glob normalization for fs grants. */
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { matchesGlob, nodeGlobBase, nodeGlobPrefixes } from "../src/policy/glob.js";
import { evaluate } from "../src/policy/evaluate.js";
import { loadPolicyFromObject } from "../src/policy/load.js";

describe("matchesGlob", () => {
  it("bare * matches everything", () => {
    expect(matchesGlob("*", "/etc/passwd")).toBe(true);
  });

  it("** crosses segments and includes the base dir itself", () => {
    expect(matchesGlob("/app/logs/**", "/app/logs/a/b.log")).toBe(true);
    expect(matchesGlob("/app/logs/**", "/app/logs")).toBe(true);
    expect(matchesGlob("/app/logs/**", "/app/other")).toBe(false);
  });

  it("* within a segment does not cross /", () => {
    expect(matchesGlob("/app/*.txt", "/app/a.txt")).toBe(true);
    expect(matchesGlob("/app/*.txt", "/app/sub/a.txt")).toBe(false);
  });

  it("exact paths match only themselves (and escapes regex chars)", () => {
    expect(matchesGlob("/app/a.txt", "/app/a.txt")).toBe(true);
    expect(matchesGlob("/app/a.txt", "/app/axtxt")).toBe(false);
  });

  it("collapses adjacent ** segments (ReDoS hardening) without changing semantics", () => {
    // `dir/**/**` must behave exactly like `dir/**` and not build adjacent unbounded groups.
    expect(matchesGlob("/app/**/**", "/app/a/b.log")).toBe(true);
    expect(matchesGlob("/app/**/**", "/app")).toBe(true);
    expect(matchesGlob("/app/**/**", "/other")).toBe(false);
    // A pathological pattern against a long non-matching path must return promptly, not hang.
    const long = "/app/" + "a/".repeat(40) + "nope.txt";
    expect(matchesGlob("/app/**/**/**/**/x", long)).toBe(false);
  });
});

// Windows-style drive paths (issue #18). These are pure string tests — no real Windows FS or
// `path` module involved, so they run identically on Linux CI. `coercePath` (shims/fs.ts) and
// `normalizeGlob` (load.ts) both produce this exact shape on a real Windows process:
// `path.resolve(p).split(path.sep).join("/")` → "C:/proj/logs/app.log" (no leading slash).
describe("matchesGlob — Windows drive paths (#18)", () => {
  it("a drive-letter glob matches a drive-letter candidate", () => {
    expect(matchesGlob("C:/proj/logs/**", "C:/proj/logs/app.log")).toBe(true);
    expect(matchesGlob("C:/proj/logs/**", "C:/proj/logs")).toBe(true); // dir itself, like POSIX
    expect(matchesGlob("C:/proj/logs/**", "C:/proj/other/app.log")).toBe(false);
  });

  it("* and ? within a segment behave the same as on POSIX", () => {
    expect(matchesGlob("C:/proj/*.txt", "C:/proj/a.txt")).toBe(true);
    expect(matchesGlob("C:/proj/*.txt", "C:/proj/sub/a.txt")).toBe(false);
    expect(matchesGlob("C:/proj/a?.log", "C:/proj/a1.log")).toBe(true);
  });

  it("exact drive-letter paths match only themselves", () => {
    expect(matchesGlob("C:/proj/a.txt", "C:/proj/a.txt")).toBe(true);
    expect(matchesGlob("C:/proj/a.txt", "C:/proj/axtxt")).toBe(false);
  });

  it("drive letter is matched case-insensitively (grant vs. candidate, either direction)", () => {
    expect(matchesGlob("c:/proj/logs/**", "C:/proj/logs/app.log")).toBe(true);
    expect(matchesGlob("C:/proj/logs/**", "c:/proj/logs/app.log")).toBe(true);
    expect(matchesGlob("c:/proj/logs/**", "c:/proj/logs/app.log")).toBe(true);
  });

  it("the rest of a Windows path stays case-sensitive, same as POSIX segments", () => {
    expect(matchesGlob("C:/proj/Logs/**", "C:/proj/logs/app.log")).toBe(false);
  });

  it("a different drive letter does not match", () => {
    expect(matchesGlob("C:/proj/logs/**", "D:/proj/logs/app.log")).toBe(false);
  });

  it("POSIX and Windows shapes never cross-match", () => {
    expect(matchesGlob("/proj/logs/**", "C:/proj/logs/app.log")).toBe(false);
    expect(matchesGlob("C:/proj/logs/**", "/proj/logs/app.log")).toBe(false);
  });

  it("existing POSIX cases are unaffected by drive-letter support", () => {
    // Same assertions as the POSIX describe block above, re-run after the Windows-path
    // change, to pin that ordinary absolute POSIX paths are byte-for-byte unchanged.
    expect(matchesGlob("/app/logs/**", "/app/logs/a/b.log")).toBe(true);
    expect(matchesGlob("/app/logs/**", "/app/logs")).toBe(true);
    expect(matchesGlob("/app/logs/**", "/app/other")).toBe(false);
    expect(matchesGlob("/app/*.txt", "/app/a.txt")).toBe(true);
    expect(matchesGlob("/app/*.txt", "/app/sub/a.txt")).toBe(false);
  });
});

describe("policy glob normalization against projectRoot — Windows absolute glob (#18)", () => {
  // The test suite runs on Linux, where the host `path` module (POSIX) does NOT consider
  // "C:/…" or "C:\…" absolute (`path.isAbsolute("C:/x")` is false on POSIX) — so without
  // load.ts's explicit Windows-drive check, a Windows-authored absolute glob would be wrongly
  // resolved AS IF relative, against `projectRoot`, producing garbage like
  // "/proj/C:/proj/logs/**". These tests pin that `normalizeGlob` recognizes drive-absolute
  // globs regardless of host OS and reshapes them to the same "C:/…" form `coercePath`
  // (shims/fs.ts) produces for a real Windows call-time path — including reshaping a
  // backslash-written glob (as an author would literally type on Windows).
  it("a forward-slash 'C:/…' absolute glob is left as-is (not resolved against projectRoot)", () => {
    const policy = loadPolicyFromObject(
      { version: 1, packages: { pino: { fs: { read: [], write: ["C:/proj/logs/**"] } } } },
      { projectRoot: "/proj" }, // must be ignored: the glob is already absolute
    );
    const d = evaluate(policy, "enforce", "pino", {
      kind: "fs",
      access: "write",
      path: "C:/proj/logs/app.log",
    });
    expect(d.allowed).toBe(true);
  });

  it("a backslash-written 'C:\\…' absolute glob is reshaped to forward slashes", () => {
    const policy = loadPolicyFromObject(
      {
        version: 1,
        packages: { pino: { fs: { read: [], write: ["C:\\proj\\logs\\**"] } } },
      },
      { projectRoot: "/proj" },
    );
    const d = evaluate(policy, "enforce", "pino", {
      kind: "fs",
      access: "write",
      path: "C:/proj/logs/app.log",
    });
    expect(d.allowed).toBe(true);
  });

  it("does NOT match under a different drive letter", () => {
    const policy = loadPolicyFromObject(
      { version: 1, packages: { pino: { fs: { read: [], write: ["C:/proj/logs/**"] } } } },
      { projectRoot: "/proj" },
    );
    const d = evaluate(policy, "enforce", "pino", {
      kind: "fs",
      access: "write",
      path: "D:/proj/logs/app.log",
    });
    expect(d.allowed).toBe(false);
  });
});

describe("policy glob normalization against projectRoot", () => {
  const policy = loadPolicyFromObject(
    {
      version: 1,
      packages: { pino: { fs: { read: [], write: ["./logs/**"] } } },
    },
    { projectRoot: "/proj" },
  );

  it("grants relative globs resolved to the project root", () => {
    const d = evaluate(policy, "enforce", "pino", {
      kind: "fs",
      access: "write",
      path: "/proj/logs/app.log",
    });
    expect(d.allowed).toBe(true);
  });

  it("denies the same relative path under a different root", () => {
    const d = evaluate(policy, "enforce", "pino", {
      kind: "fs",
      access: "write",
      path: "/elsewhere/logs/app.log",
    });
    expect(d.allowed).toBe(false);
  });

  it("read grant does not imply write", () => {
    const d = evaluate(policy, "enforce", "pino", {
      kind: "fs",
      access: "read",
      path: "/proj/logs/app.log",
    });
    expect(d.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------
// nodeGlobPrefixes / nodeGlobBase (#106, hardened by #120) — reach analysis for NODE's glob
// dialect, not capwall's.
//
// The analysis is pure syntax (no filesystem), so this runs identically on Node 20 (where
// `fs.glob` does not exist) and on Node 22. The corresponding "…and Node really does escape
// like that" evidence — including the generated-pattern property test — lives in
// fs-glob.test.ts, which can only run where the API exists.
// ---------------------------------------------------------------------------------------

/** `nodeGlobBase` against a POSIX-style cwd, so the expectations read as absolute paths. */
const baseFrom = (pattern: string, cwd = "/proj/app"): string => nodeGlobBase(pattern, cwd);
/** True on POSIX, where the absolute-path expectations below are meaningful. */
const POSIX = path.sep === "/";

describe("nodeGlobPrefixes — bounded patterns", () => {
  it("returns the literal leading segments before the first magic segment", () => {
    expect(nodeGlobPrefixes("data/*.txt")).toEqual(["data"]);
    expect(nodeGlobPrefixes("data/sub/**")).toEqual(["data/sub"]);
    expect(nodeGlobPrefixes("/etc/*.conf")).toEqual(["/etc"]);
    expect(nodeGlobPrefixes("/etc/default/x.conf")).toEqual(["/etc/default/x.conf"]);
  });

  it('an empty prefix means "the cwd itself", which is not the same as the root', () => {
    expect(nodeGlobPrefixes("**")).toEqual([""]);
    expect(nodeGlobPrefixes("*.txt")).toEqual([""]);
    expect(nodeGlobPrefixes("")).toEqual([""]);
  });

  it("an ABSOLUTE pattern whose first segment is magic is rooted at /, never at the cwd", () => {
    // The regression this guards: `["", "**"].slice(0, 1).join("/")` is the empty string, which
    // would read as "the cwd" and gate a directory the walk never starts in — fail-open.
    expect(nodeGlobPrefixes("/**")).toEqual(["/"]);
    expect(nodeGlobPrefixes("/*.conf")).toEqual(["/"]);
  });

  it("keeps a leading .. in the prefix, where path.resolve accounts for it exactly", () => {
    expect(nodeGlobPrefixes("../data/*.txt")).toEqual(["../data"]);
    expect(nodeGlobPrefixes("data/../secrets/*")).toEqual(["data/../secrets"]);
  });

  it("segment-local magic does not move the root", () => {
    expect(nodeGlobPrefixes("data/[ab]/*")).toEqual(["data"]);
    expect(nodeGlobPrefixes("data/@(a|b)/*")).toEqual(["data"]);
    expect(nodeGlobPrefixes("data/?ab/*")).toEqual(["data"]);
  });

  it("does not treat a bare @ / + / ! as magic — @scope prefixes stay in the prefix", () => {
    expect(nodeGlobPrefixes("node_modules/@scope/pkg/**")).toEqual([
      "node_modules/@scope/pkg",
    ]);
    expect(nodeGlobPrefixes("a+b/!c/**")).toEqual(["a+b/!c"]);
  });

  it("a bare Windows drive prefix is turned into a root", () => {
    // `path.win32.resolve("D:/x", "C:")` is the CURRENT directory on drive C, not `C:/`.
    expect(nodeGlobPrefixes("C:/**")).toEqual(["C:/"]);
    expect(nodeGlobPrefixes("C:/proj/*.ts")).toEqual(["C:/proj"]);
  });

  // #120: braces are EXPANDED rather than pattern-matched for a `/` or a `..`, so a braced
  // pattern legitimately has one prefix per alternative and the caller gates their common
  // ancestor. Before #120 the first of these collapsed to a single prefix and the rest were
  // "unbounded ⇒ filesystem root"; both answers are now exact.
  it("a brace group yields one prefix per alternative", () => {
    expect(nodeGlobPrefixes("data/{a,b}/*.txt")).toEqual(["data/a", "data/b"]);
    expect(nodeGlobPrefixes("{/etc,/tmp}/*.conf")).toEqual(["/etc", "/tmp"]);
    expect(nodeGlobPrefixes("{.,..}/*.conf")).toEqual([".", ".."]);
    expect(nodeGlobPrefixes("data/{../..,b}/*")).toEqual(["data/../..", "data/b"]);
  });

  it("identical alternatives collapse to one prefix", () => {
    // `..{,}` is #120's PoC spelling: two alternatives, both `..`.
    expect(nodeGlobPrefixes("..{,}/**")).toEqual([".."]);
  });
});

describe("nodeGlobBase — the single directory the fs.read decision is taken on", () => {
  it.runIf(POSIX)("resolves a bounded prefix against the cwd", () => {
    expect(baseFrom("data/*.txt")).toBe("/proj/app/data");
    expect(baseFrom("**")).toBe("/proj/app");
    expect(baseFrom("/etc/*.conf")).toBe("/etc");
    expect(baseFrom("../data/*.txt")).toBe("/proj/data");
  });

  it.runIf(POSIX)("gates the COMMON ANCESTOR when a brace pattern walks from several roots", () => {
    expect(baseFrom("data/{a,b}/*.txt")).toBe("/proj/app/data");
    expect(baseFrom("{.,..}/*.conf")).toBe("/proj");
    // Unrelated absolute alternatives share only the filesystem root — the fail-closed answer.
    expect(baseFrom("{/etc,/tmp}/*.conf")).toBe("/");
  });

  it.runIf(POSIX)("an unbounded pattern is the filesystem root", () => {
    expect(baseFrom("**/../*.conf")).toBe("/");
    expect(baseFrom("data/{a,b/*")).toBe("/");
  });
});

describe("nodeGlobPrefixes — UNBOUNDED patterns (null ⇒ the shim gates the filesystem root)", () => {
  it("a .. segment after the first magic segment escapes upward", () => {
    // `**` matches zero segments too, so the first of these is just `../*.conf` — verified
    // against real fs.globSync on Node 22 in fs-glob.test.ts.
    expect(nodeGlobPrefixes("**/../*.conf")).toBeNull();
    expect(nodeGlobPrefixes("*/../../etc/*")).toBeNull();
  });

  it("a brace construct capwall does not model is refused, not guessed at", () => {
    // A RANGE. Expanding it as the single literal `1..3` would have been wrong in the fail-open
    // direction, so a group with no top-level comma is refused outright.
    expect(nodeGlobPrefixes("{1..3}/*")).toBeNull();
    expect(nodeGlobPrefixes("{a..z}/*")).toBeNull();
    // A single-alternative group, which minimatch does NOT expand — `{a}` stays literal.
    expect(nodeGlobPrefixes("{a}/*")).toBeNull();
  });

  it("a brace bomb is refused rather than expanded", () => {
    expect(nodeGlobPrefixes("{a,b}".repeat(20) + "/*")).toBeNull();
  });

  it("an unbalanced brace is not analyzable, so it is not bounded", () => {
    expect(nodeGlobPrefixes("data/{a,b/*")).toBeNull();
    expect(nodeGlobPrefixes("data/a,b}/*")).toBeNull();
    expect(nodeGlobPrefixes("data/}{a,b}/*")).toBeNull();
  });

  it("a backslash (minimatch's POSIX escape) is refused rather than guessed at", () => {
    expect(nodeGlobPrefixes("data/\\*.txt")).toBeNull();
  });

  // ─────────────────────────────────────────────────────────────────────────────────────────
  // #120 — a `..` SPELLED as a glob expansion. Every one of these walked past the pre-#120
  // prefix resolver, which asked whether a segment was literally the string `..`. The rule is
  // now "prove the segment is downward-only or treat it as unbounded", so the list below is
  // evidence, not the mechanism: `test/fs-glob.test.ts`'s property test is what checks capwall
  // against real `fs.globSync` over patterns nobody wrote down.
  // ─────────────────────────────────────────────────────────────────────────────────────────
  it("a segment that can REDUCE to `..` is unbounded, however it is spelled", () => {
    for (const token of [
      "[.][.]",
      "[.].",
      ".[.]",
      "[.-.][.-.]",
      "{a,[.][.]}",
      "[.][.]{,}",
      "[.]",
      "@(..)",
      "[..]",
    ]) {
      expect(nodeGlobPrefixes(`${token}/**`), token).toBeNull();
    }
  });

  it.runIf(POSIX)("...while the HONEST spelling stays exact, and is denied on the real parent", () => {
    // A leading literal `..` is not an escape from capwall's point of view: it is in the prefix,
    // `path.resolve` accounts for it precisely, and the decision lands on the directory the walk
    // genuinely starts in. #120's whole point is that the eight spellings above reached that same
    // directory while capwall decided about the cwd.
    expect(nodeGlobPrefixes("../**")).toEqual([".."]);
    expect(baseFrom("../**")).toBe("/proj");
    expect(baseFrom("..{,}/**")).toBe("/proj");
    expect(baseFrom(".{.,.}/**")).toBe("/proj");
  });

  it("...and chaining the spelling does not help", () => {
    const chained = ["[.][.]", "[.][.]", "[.][.]", "[.][.]", "**"].join("/");
    expect(nodeGlobPrefixes(chained)).toBeNull();
  });

  it("a segment that survives as a MATCHER still bounds the walk (no over-denial)", () => {
    // `*`/`?` are never removed by the grammar, so these stay matchers over directory entries —
    // and `readdir` never yields `.` or `..`. Verified against real fs.globSync in fs-glob.test.ts.
    expect(nodeGlobPrefixes("data/.*")).toEqual(["data"]);
    expect(nodeGlobPrefixes("data/*.*")).toEqual(["data"]);
    expect(nodeGlobPrefixes("data/[.]*")).toEqual(["data"]);
    expect(nodeGlobPrefixes("data/..*")).toEqual(["data"]);
    expect(nodeGlobPrefixes("data/?.")).toEqual(["data"]);
  });
});
