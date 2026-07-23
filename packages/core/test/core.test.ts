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

  it("honors a net port wildcard (dynamic/ephemeral ports, #27)", () => {
    const grant = { net: { hosts: ["127.0.0.1"], ports: ["*" as const] } };
    expect(isGranted(grant, { kind: "net", host: "127.0.0.1", port: 49152 })).toBe(true);
    expect(isGranted(grant, { kind: "net", host: "127.0.0.1", port: 65000 })).toBe(true);
    // Host still gated: wildcard port doesn't widen the host allowlist.
    expect(isGranted(grant, { kind: "net", host: "evil.com", port: 49152 })).toBe(false);
    // A concrete port list still denies an unlisted port.
    expect(
      isGranted({ net: { hosts: ["*"], ports: [443] } }, { kind: "net", host: "x", port: 8080 }),
    ).toBe(false);
  });

  it("all grant kinds ignore a polluted Object.prototype (own-property only)", () => {
    // Regression: an empty grant {} must not inherit ANY grant from a polluted prototype —
    // boolean gates, fs globs, net rules, and the env allowlist.
    const proto = Object.prototype as unknown as Record<string, unknown>;
    proto["child_process"] = true;
    proto["vm"] = true;
    proto["worker_threads"] = true;
    proto["fs"] = { read: ["**"], write: ["**"] };
    proto["net"] = { hosts: ["*"], ports: [443] };
    proto["env"] = ["*"];
    try {
      expect(isGranted({}, { kind: "child_process" })).toBe(false);
      expect(isGranted({}, { kind: "vm" })).toBe(false);
      expect(isGranted({}, { kind: "worker_threads" })).toBe(false);
      expect(isGranted({}, { kind: "fs", access: "read", path: "/etc/passwd" })).toBe(false);
      expect(isGranted({}, { kind: "net", host: "evil.com", port: 443 })).toBe(false);
      expect(isGranted({}, { kind: "env", key: "SECRET" })).toBe(false);
    } finally {
      for (const k of ["child_process", "vm", "worker_threads", "fs", "net", "env"]) {
        delete proto[k];
      }
    }
  });
});
