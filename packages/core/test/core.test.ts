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

describe("install-chain principals and the `*>` / `**>` widenings (#92)", () => {
  const chainPolicy: Policy = loadPolicyFromObject({
    version: 1,
    mode: "enforce",
    default: {},
    packages: {
      lodash: { env: ["TOP"] },
      "webpack>lodash": { env: ["NESTED"] },
      // Two different packages, so each wildcard's reach is measured on its own. (Both keys for
      // ONE package is legal and is tested separately, under precedence.)
      "*>chalk": { env: ["ONE_DEEP"] },
      "**>kleur": { env: ["ANY_DEPTH"] },
    },
  });
  const envReq = (key: string) => ({ kind: "env", key }) as const;

  it("keeps a bare key and a chain key as separate principals", () => {
    // The #92 fix, at the policy layer: `evil>lodash` gets nothing from `lodash`'s entry.
    expect(evaluate(chainPolicy, "enforce", "lodash", envReq("TOP")).allowed).toBe(true);
    expect(evaluate(chainPolicy, "enforce", "evil>lodash", envReq("TOP")).allowed).toBe(false);
    expect(evaluate(chainPolicy, "enforce", "webpack>lodash", envReq("NESTED")).allowed).toBe(true);
    // …and the chain key does not leak back onto the top-level install either.
    expect(evaluate(chainPolicy, "enforce", "lodash", envReq("NESTED")).allowed).toBe(false);
  });

  it("matches `*>name` against ONE leading link and `**>name` against one or more", () => {
    // Deliberately the same one-vs-many rule `net.hosts` uses (`*.internal` / `**.internal`),
    // over `>` instead of `.`. Two wildcard grammars in one policy file that spelled the same
    // sigil differently would be a trap, so they are matched sigil for sigil.
    expect(evaluate(chainPolicy, "enforce", "a>chalk", envReq("ONE_DEEP")).allowed).toBe(true);
    expect(evaluate(chainPolicy, "enforce", "a>b>chalk", envReq("ONE_DEEP")).allowed).toBe(false);
    expect(evaluate(chainPolicy, "enforce", "a>kleur", envReq("ANY_DEPTH")).allowed).toBe(true);
    expect(evaluate(chainPolicy, "enforce", "a>b>kleur", envReq("ANY_DEPTH")).allowed).toBe(true);
    // Only the FINAL link is wildcarded — there is no "everything this package vendors" key.
    expect(evaluate(chainPolicy, "enforce", "kleur>evil", envReq("ANY_DEPTH")).allowed).toBe(false);
  });

  it("does NOT let either wildcard reach the top-level install", () => {
    // Documented: "everywhere" is two keys. The wildcards read as "nested under something",
    // matching `**.internal` not matching the apex `internal`.
    expect(evaluate(chainPolicy, "enforce", "chalk", envReq("ONE_DEEP")).allowed).toBe(false);
    expect(evaluate(chainPolicy, "enforce", "kleur", envReq("ANY_DEPTH")).allowed).toBe(false);
  });

  it("never lets a wildcard reach a sentinel", () => {
    // `<app>` and `<unknown>` CONTAIN a `>`. A naive "split on the last `>`" widening reads
    // `<app>` as a chain with an empty leaf, so a key of `"*>"` would have granted the TRUST
    // ROOT. Sentinels match by exact key only.
    const sentinelWild: Policy = loadPolicyFromObject({
      version: 1,
      mode: "enforce",
      default: {},
      packages: { "*>app": { env: ["X"] }, "**>unknown": { env: ["X"] } },
    });
    expect(evaluate(sentinelWild, "enforce", "<app>", envReq("X")).allowed).toBe(false);
    expect(evaluate(sentinelWild, "enforce", "<unknown>", envReq("X")).allowed).toBe(false);
  });

  it("prefers the narrower wildcard when both could apply", () => {
    const both: Policy = loadPolicyFromObject({
      version: 1,
      mode: "enforce",
      default: {},
      packages: { "**>chalk": { env: ["WIDE"] }, "*>chalk": { env: ["NARROW"] } },
    });
    // `a>chalk` is covered by both; the one-level key wins, as an explicit entry beats `default`.
    expect(evaluate(both, "enforce", "a>chalk", envReq("NARROW")).allowed).toBe(true);
    expect(evaluate(both, "enforce", "a>chalk", envReq("WIDE")).allowed).toBe(false);
    // `a>b>chalk` is out of `*>`'s reach, so it falls through to `**>`.
    expect(evaluate(both, "enforce", "a>b>chalk", envReq("WIDE")).allowed).toBe(true);
  });

  it("prefers an exact chain entry over the wildcard", () => {
    const both: Policy = loadPolicyFromObject({
      version: 1,
      mode: "enforce",
      default: {},
      packages: { "*>chalk": { env: ["WIDE"] }, "a>chalk": { env: ["NARROW"] } },
    });
    expect(evaluate(both, "enforce", "a>chalk", envReq("NARROW")).allowed).toBe(true);
    // The exact entry REPLACES the wildcard rather than merging with it, so a narrower entry
    // is genuinely narrower — the same way an explicit entry replaces `default`.
    expect(evaluate(both, "enforce", "a>chalk", envReq("WIDE")).allowed).toBe(false);
  });
});

describe("the `compile` capability (#93)", () => {
  it("is deny-by-default and ignores the filename", () => {
    expect(isGranted({}, { kind: "compile", filename: "/x/index.js" })).toBe(false);
    expect(isGranted({ compile: true }, { kind: "compile", filename: "/x/index.js" })).toBe(true);
    // Boolean gate: any filename, same answer. A filename allowlist would be a per-run
    // artifact and would not narrow the capability anyway — a package that may compile one
    // foreign filename may compile any.
    expect(isGranted({ compile: true }, { kind: "compile", filename: "<any>" })).toBe(true);
  });

  it("is not implied by any other grant, including vm", () => {
    // `vm` carries comparable power by a different route, but the two are separate grants and
    // neither is a superset of the other in the policy.
    expect(isGranted({ vm: true }, { kind: "compile", filename: "/x.js" })).toBe(false);
    expect(isGranted({ compile: true }, { kind: "vm" })).toBe(false);
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
