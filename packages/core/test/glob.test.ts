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
