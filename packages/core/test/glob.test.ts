/** Glob matching + policy-loader glob normalization for fs grants. */
import { describe, expect, it } from "vitest";
import { matchesGlob } from "../src/policy/glob.js";
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
