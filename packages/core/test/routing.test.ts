/**
 * End-to-end loader-routing tests for the M4 shims: requiring `net`/`child_process`/`vm`
 * from within an install() window returns capwall's shim, and a deny-by-default enforce
 * policy blocks a dependency's use of each. This complements the per-shim unit tests (which
 * exercise the shim factories directly) by proving the require registry actually routes.
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { install, loadPolicyFromObject, type Policy } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");

interface FixtureDep {
  connect(host: string, port: number): { destroy(): void };
  spawn(): unknown;
  runVm(code: string): unknown;
}

function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

function withCapwall<T>(policy: Policy, mode: "observe" | "enforce", fn: (dep: FixtureDep) => T): T {
  const handle = install(policy, mode, { projectRoot: here, onDecision: () => {} });
  try {
    return fn(loadFixtureFresh());
  } finally {
    handle.uninstall();
  }
}

const denyAll = (): Policy => loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: here });

describe("loader routing — M4 shims deny-by-default in enforce", () => {
  it("net.connect is routed + denied for an ungranted dependency", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.connect("evil.example.com", 443)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("child_process.spawnSync is routed + denied", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.spawn()).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("vm.runInNewContext is routed + denied", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.runVm("1 + 1")).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });
});

describe("loader routing — granted capabilities pass through", () => {
  it("allows net/child_process/vm when granted", () => {
    const policy = loadPolicyFromObject(
      {
        version: 1,
        mode: "enforce",
        packages: {
          "fixture-dep": {
            net: { hosts: ["127.0.0.1"], ports: [1] },
            child_process: true,
            vm: true,
          },
        },
      },
      { projectRoot: here },
    );
    withCapwall(policy, "enforce", (dep) => {
      // net: guard passes; the socket then fails to connect (port 1) — not a CapabilityError.
      expect(() => dep.connect("127.0.0.1", 1).destroy()).not.toThrow();
      expect(() => dep.spawn()).not.toThrow();
      expect(dep.runVm("1 + 1")).toBe(2);
    });
  });
});

describe("loader routing — observe never blocks", () => {
  it("allows all three under a deny-all policy in observe mode", () => {
    withCapwall(denyAll(), "observe", (dep) => {
      expect(() => dep.connect("evil.example.com", 443).destroy()).not.toThrow();
      expect(() => dep.spawn()).not.toThrow();
      expect(dep.runVm("2 + 3")).toBe(5);
    });
  });
});
