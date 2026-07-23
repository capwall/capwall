/**
 * Smoke tests for the real, implemented parts of @capwall/core: the policy evaluator's
 * deny-by-default semantics and the observe-mode pass-through. These MUST stay passing —
 * extend them as the engine grows; do not delete (see AGENTS.md § 7).
 */
import { describe, expect, it } from "vitest";
import { evaluate, isGranted } from "../src/policy/evaluate.js";
import { loadPolicyFromObject } from "../src/policy/load.js";
import type { Policy } from "@capwall/policy-schema";

const policy: Policy = loadPolicyFromObject({
  version: 1,
  mode: "enforce",
  default: { fs: { read: [], write: [] } },
  packages: {
    logger: { fs: { read: [], write: ["*"] } },
  },
});

describe("enforce mode — deny-by-default", () => {
  it("denies a package that is NOT in the policy", () => {
    const d = evaluate(policy, "enforce", "totally-unknown-pkg", {
      kind: "fs",
      access: "read",
      path: "/etc/passwd",
    });
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/deny-by-default/);
  });

  it("denies env read for a package with no env grant", () => {
    const d = evaluate(policy, "enforce", "logger", {
      kind: "env",
      key: "AWS_SECRET_ACCESS_KEY",
    });
    expect(d.allowed).toBe(false);
  });

  it("allows a granted capability", () => {
    const d = evaluate(policy, "enforce", "logger", {
      kind: "fs",
      access: "write",
      path: "/var/log/app.log",
    });
    expect(d.allowed).toBe(true);
  });
});

describe("observe mode — never blocks, records", () => {
  it("allows everything but reports what it observed", () => {
    const d = evaluate(policy, "observe", "totally-unknown-pkg", {
      kind: "net",
      host: "evil.example.com",
      port: 443,
    });
    expect(d.allowed).toBe(true);
    expect(d.observed).toEqual({ kind: "net", host: "evil.example.com", port: 443 });
  });
});

describe("isGranted — pure gate checks", () => {
  it("treats child_process/vm/worker as boolean gates (default false)", () => {
    expect(isGranted({}, { kind: "child_process" })).toBe(false);
    expect(isGranted({ child_process: true }, { kind: "child_process" })).toBe(true);
    expect(isGranted({ vm: true }, { kind: "vm" })).toBe(true);
  });

  it("honors the env wildcard", () => {
    expect(isGranted({ env: ["*"] }, { kind: "env", key: "ANYTHING" })).toBe(true);
    expect(isGranted({ env: ["NODE_ENV"] }, { kind: "env", key: "SECRET" })).toBe(false);
  });
});
