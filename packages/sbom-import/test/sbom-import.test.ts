/**
 * Tests for @capwall/sbom-import: CycloneDX → starter capwall policy.
 *
 * See src/index.ts for the `capwall:*` CBOM property convention these fixtures exercise.
 */
import { describe, expect, it } from "vitest";
import { parsePolicy } from "@capwall/policy-schema";
import { parseCycloneDx, sbomToPolicy } from "../src/index.js";

/**
 * A minimal CycloneDX SBOM with three components:
 *  - "express": annotated with capwall:* CBOM properties (fs, net, env) — should seed grants.
 *  - "left-pad": no properties at all — should get an empty grant `{}`.
 *  - "pino": annotated with only a boolean gate + duplicate/repeated fs:read properties,
 *    to exercise accumulation across repeated property names.
 */
const fixtureSbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  components: [
    {
      type: "library",
      name: "express",
      version: "4.19.2",
      purl: "pkg:npm/express@4.19.2",
      "bom-ref": "pkg:npm/express@4.19.2",
      properties: [
        { name: "capwall:fs:read", value: "./views/**,./public/**" },
        { name: "capwall:net:hosts", value: "*" },
        { name: "capwall:net:ports", value: "3000,8080" },
        { name: "capwall:env", value: "NODE_ENV,PORT" },
        { name: "some:other:vendor:property", value: "ignored" },
      ],
    },
    {
      type: "library",
      name: "left-pad",
      version: "1.3.0",
      purl: "pkg:npm/left-pad@1.3.0",
    },
    {
      type: "library",
      name: "pino",
      version: "9.0.0",
      properties: [
        { name: "capwall:fs:write", value: "./logs/**" },
        { name: "capwall:fs:read", value: "./config/pino.json" },
        { name: "capwall:child_process", value: "false" },
      ],
    },
  ],
};

describe("parseCycloneDx", () => {
  it("parses well-formed components with no warnings", () => {
    const warnings: string[] = [];
    const components = parseCycloneDx(fixtureSbom, warnings);
    expect(components.map((c) => c.name).sort()).toEqual(["express", "left-pad", "pino"]);
    // The fixture's express grants a wildcard host → one advisory; no parse-error warnings.
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toContain("WILDCARD net");
  });

  it("derives the expected grant from capwall:* properties", () => {
    const components = parseCycloneDx(fixtureSbom);
    const express = components.find((c) => c.name === "express");
    expect(express?.grant).toEqual({
      fs: { read: ["./views/**", "./public/**"], write: [] },
      net: { hosts: ["*"], ports: [3000, 8080] },
      env: ["NODE_ENV", "PORT"],
    });
  });

  it("accumulates repeated capwall:* property names", () => {
    const components = parseCycloneDx(fixtureSbom);
    const pino = components.find((c) => c.name === "pino");
    expect(pino?.grant).toEqual({
      fs: { read: ["./config/pino.json"], write: ["./logs/**"] },
      child_process: false,
    });
  });

  it("gives an unannotated component an empty grant", () => {
    const components = parseCycloneDx(fixtureSbom);
    const leftPad = components.find((c) => c.name === "left-pad");
    expect(leftPad?.grant).toEqual({});
    expect(leftPad?.purl).toBe("pkg:npm/left-pad@1.3.0");
  });

  it("does not throw on a malformed top-level document", () => {
    const warnings: string[] = [];
    expect(() => parseCycloneDx(null, warnings)).not.toThrow();
    expect(() => parseCycloneDx("not an object", warnings)).not.toThrow();
    expect(() => parseCycloneDx({ components: "not-an-array" }, warnings)).not.toThrow();
    expect(warnings.length).toBeGreaterThan(0);
  });

  it("skips a malformed individual component with a warning instead of throwing", () => {
    const warnings: string[] = [];
    const bom = {
      components: [
        { name: "good-component" },
        { name: 12345 }, // invalid name type
        "not-an-object",
        { properties: "not-an-array", name: "weird-props" },
      ],
    };
    const components = parseCycloneDx(bom, warnings);
    expect(components.map((c) => c.name)).toEqual(["good-component", "weird-props"]);
    expect(warnings.some((w) => w.includes("skipped"))).toBe(true);
    expect(warnings.some((w) => w.includes("properties"))).toBe(true);
  });

  it("ignores malformed capability values without throwing", () => {
    const warnings: string[] = [];
    const bom = {
      components: [
        {
          name: "flaky",
          properties: [
            { name: "capwall:net:ports", value: "not-a-number,443" },
            { name: "capwall:vm", value: "maybe" },
          ],
        },
      ],
    };
    const components = parseCycloneDx(bom, warnings);
    expect(components).toHaveLength(1);
    expect(components[0]?.grant.net).toEqual({ hosts: [], ports: [443] });
    expect(components[0]?.grant.vm).toBeUndefined();
    expect(warnings.some((w) => w.includes("capwall:net:ports"))).toBe(true);
    expect(warnings.some((w) => w.includes("capwall:vm"))).toBe(true);
  });
});

describe("sbomToPolicy", () => {
  it("emits a schema-valid policy with sorted package entries", () => {
    const policy = sbomToPolicy(fixtureSbom);
    expect(() => parsePolicy(policy)).not.toThrow();
    expect(Object.keys(policy.packages)).toEqual(["express", "left-pad", "pino"]);
    expect(policy.version).toBe(1);
    expect(policy.mode).toBe("observe");
  });

  it("seeds grants from annotated components and leaves unannotated ones empty", () => {
    const policy = sbomToPolicy(fixtureSbom);
    expect(policy.packages["left-pad"]).toEqual({});
    expect(policy.packages["express"]?.net?.hosts).toEqual(["*"]);
    expect(policy.packages["pino"]?.child_process).toBe(false);
  });

  it("respects an explicit mode option", () => {
    const policy = sbomToPolicy(fixtureSbom, { mode: "enforce" });
    expect(policy.mode).toBe("enforce");
  });

  it("collects warnings instead of throwing on malformed input", () => {
    const warnings: string[] = [];
    const policy = sbomToPolicy({ components: [{ name: "ok" }, { notAName: true }] }, {
      warnings,
    });
    expect(policy.packages["ok"]).toEqual({});
    expect(Object.keys(policy.packages)).toEqual(["ok"]);
    expect(warnings.length).toBeGreaterThan(0);
  });

  it("does not throw for a completely garbage top-level input", () => {
    const warnings: string[] = [];
    const policy = sbomToPolicy("garbage", { warnings });
    expect(policy.packages).toEqual({});
    expect(() => parsePolicy(policy)).not.toThrow();
    expect(warnings.length).toBeGreaterThan(0);
  });

  it("handles reserved-name components safely (no pollution; __proto__ skipped w/ warning)", () => {
    const before = ({} as Record<string, unknown>).polluted;
    const warnings: string[] = [];
    const policy = sbomToPolicy(
      {
        components: [
          { name: "__proto__" },
          { name: "constructor" },
          { name: "prototype" },
          { name: "normal" },
        ],
      },
      { warnings },
    );
    // No global prototype pollution.
    expect(({} as Record<string, unknown>).polluted).toBe(before);
    // __proto__ can't be a policy key → skipped with a warning (not silently lost).
    expect(warnings.some((w) => w.includes("__proto__"))).toBe(true);
    // constructor/prototype/normal are ordinary keys and survive.
    expect(Object.keys(policy.packages).sort()).toEqual(["constructor", "normal", "prototype"]);
    expect(() => parsePolicy(policy)).not.toThrow();
  });

  it("rejects out-of-range and non-integer ports (no silent truncation)", () => {
    const warnings: string[] = [];
    const policy = sbomToPolicy(
      {
        components: [
          {
            name: "netdep",
            properties: [
              { name: "capwall:net:hosts", value: "api.example.com" },
              { name: "capwall:net:ports", value: "443,80.5,0x50,99999,-1,abc" },
            ],
          },
        ],
      },
      { warnings },
    );
    // Only the valid 443 survives; the rest are warned and dropped.
    expect(policy.packages["netdep"]?.net?.ports).toEqual([443]);
    expect(warnings.filter((w) => w.includes("net:ports")).length).toBe(5);
    expect(() => parsePolicy(policy)).not.toThrow();
  });

  it("warns when a wildcard host/env grant is seeded from the SBOM", () => {
    const warnings: string[] = [];
    sbomToPolicy(
      {
        components: [
          {
            name: "greedy",
            properties: [
              { name: "capwall:net:hosts", value: "*" },
              { name: "capwall:env", value: "*" },
            ],
          },
        ],
      },
      { warnings },
    );
    expect(warnings.some((w) => w.includes("WILDCARD net"))).toBe(true);
    expect(warnings.some((w) => w.includes("WILDCARD env"))).toBe(true);
  });
});
