/** Glob matching + policy-loader glob normalization for fs grants. */
import { describe, expect, it } from "vitest";
import { matchesGlob, nodeGlobPrefix } from "../src/policy/glob.js";
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
// nodeGlobPrefix (#106) — reach analysis for NODE's glob dialect, not capwall's.
//
// Pure syntax: no filesystem and no `node:path`, so this runs identically on Node 20 (where
// `fs.glob` does not exist) and on Node 22. The corresponding "…and Node really does escape
// like that" evidence lives in fs-glob.test.ts, which can only run where the API exists.
// ---------------------------------------------------------------------------------------
describe("nodeGlobPrefix — bounded patterns", () => {
  it("returns the literal leading segments before the first magic segment", () => {
    expect(nodeGlobPrefix("data/*.txt")).toBe("data");
    expect(nodeGlobPrefix("data/sub/**")).toBe("data/sub");
    expect(nodeGlobPrefix("/etc/*.conf")).toBe("/etc");
    expect(nodeGlobPrefix("/etc/default/x.conf")).toBe("/etc/default/x.conf");
  });

  it('an empty prefix means "the cwd itself", which is not the same as the root', () => {
    expect(nodeGlobPrefix("**")).toBe("");
    expect(nodeGlobPrefix("*.txt")).toBe("");
    expect(nodeGlobPrefix("")).toBe("");
  });

  it("an ABSOLUTE pattern whose first segment is magic is rooted at /, never at the cwd", () => {
    // The regression this guards: `["", "**"].slice(0, 1).join("/")` is the empty string, which
    // would read as "the cwd" and gate a directory the walk never starts in — fail-open.
    expect(nodeGlobPrefix("/**")).toBe("/");
    expect(nodeGlobPrefix("/*.conf")).toBe("/");
  });

  it("keeps a leading .. in the prefix, where path.resolve accounts for it exactly", () => {
    expect(nodeGlobPrefix("../data/*.txt")).toBe("../data");
    expect(nodeGlobPrefix("data/../secrets/*")).toBe("data/../secrets");
  });

  it("segment-local magic does not move the root", () => {
    expect(nodeGlobPrefix("data/{a,b}/*.txt")).toBe("data");
    expect(nodeGlobPrefix("data/[ab]/*")).toBe("data");
    expect(nodeGlobPrefix("data/@(a|b)/*")).toBe("data");
    expect(nodeGlobPrefix("data/?ab/*")).toBe("data");
  });

  it("does not treat a bare @ / + / ! as magic — @scope prefixes stay in the prefix", () => {
    expect(nodeGlobPrefix("node_modules/@scope/pkg/**")).toBe("node_modules/@scope/pkg");
    expect(nodeGlobPrefix("a+b/!c/**")).toBe("a+b/!c");
  });

  it("a bare Windows drive prefix is turned into a root", () => {
    // `path.win32.resolve("D:/x", "C:")` is the CURRENT directory on drive C, not `C:/`.
    expect(nodeGlobPrefix("C:/**")).toBe("C:/");
    expect(nodeGlobPrefix("C:/proj/*.ts")).toBe("C:/proj");
  });
});

describe("nodeGlobPrefix — UNBOUNDED patterns (null ⇒ the shim gates the filesystem root)", () => {
  it("a .. segment after the first magic segment escapes upward", () => {
    // `**` matches zero segments too, so the first of these is just `../*.conf` — verified
    // against real fs.globSync on Node 22 in fs-glob.test.ts.
    expect(nodeGlobPrefix("**/../*.conf")).toBeNull();
    expect(nodeGlobPrefix("*/../../etc/*")).toBeNull();
  });

  it("a brace group that spans a / or contains .. escapes", () => {
    expect(nodeGlobPrefix("{/etc,/tmp}/*.conf")).toBeNull();
    expect(nodeGlobPrefix("{.,..}/*.conf")).toBeNull();
    expect(nodeGlobPrefix("data/{../..,b}/*")).toBeNull();
    expect(nodeGlobPrefix("{1..3}/*")).toBeNull();
  });

  it("an unbalanced brace is not analyzable, so it is not bounded", () => {
    expect(nodeGlobPrefix("data/{a,b/*")).toBeNull();
    expect(nodeGlobPrefix("data/a,b}/*")).toBeNull();
  });

  it("a backslash (minimatch's POSIX escape) is refused rather than guessed at", () => {
    expect(nodeGlobPrefix("data/\\*.txt")).toBeNull();
  });
});
