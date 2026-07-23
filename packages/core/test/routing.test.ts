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
  connectViaSocketClass(host: string, port: number): { destroy(): void };
  connectViaTls(host: string, port: number): { destroy(): void };
  spawnViaChildProcessClass(): unknown;
  sendViaDgram(host: string, port: number): { close(): void };
  connectViaSocketConstructorEscape(host: string, port: number): void;
  connectViaSocketPrototype(host: string, port: number): void;
  spawnViaChildProcessConstructorEscape(): unknown;
  connectViaHttpAgent(host: string, port: number): void;
  sendViaDgramSocketClass(host: string, port: number): void;
  tlsConnectPositional(port: number, host: string): void;
  sendUdpUnbound(host: string, port: number, cb: (err: unknown) => void): void;
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

  // Regression: capability-bearing CLASSES / alternate egress modules must not bypass the
  // guard (the fs.ReadStream-class defect, found again across net/cp/tls/dgram by review).
  it("new net.Socket().connect() is denied (not just net.connect)", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.connectViaSocketClass("evil.example.com", 443)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("tls.connect() is denied (egress not bypassable via tls)", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.connectViaTls("evil.example.com", 443)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("new child_process.ChildProcess().spawn() is denied", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.spawnViaChildProcessClass()).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("dgram UDP send is denied", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.sendViaDgram("evil.example.com", 53)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  // Round-2 regressions: class-escape / alias vectors must NOT bypass the guard.
  it("denies net.Socket via .constructor escape and prototype-method borrowing", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.connectViaSocketConstructorEscape("evil.example.com", 443)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
      expect(() => dep.connectViaSocketPrototype("evil.example.com", 443)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("denies ChildProcess spawn via .constructor escape", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.spawnViaChildProcessConstructorEscape()).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("denies http.Agent.createConnection egress", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.connectViaHttpAgent("evil.example.com", 80)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("denies direct new dgram.Socket().send()", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.sendViaDgramSocketClass("evil.example.com", 53)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("denies tls.connect positional (port, host) — no false-allow via localhost default", () => {
    // Grant only localhost:443; a positional connect to a different host must still deny.
    const policy = loadPolicyFromObject(
      {
        version: 1,
        mode: "enforce",
        packages: { "fixture-dep": { net: { hosts: ["localhost"], ports: [443] } } },
      },
      { projectRoot: here },
    );
    withCapwall(policy, "enforce", (dep) => {
      expect(() => dep.tlsConnectPositional(443, "192.0.2.1")).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("an allowed unbound UDP send does not crash on Node's auto-bind replay (DoS regression)", async () => {
    const policy = loadPolicyFromObject(
      {
        version: 1,
        mode: "enforce",
        packages: { "fixture-dep": { net: { hosts: ["127.0.0.1"], ports: [12345] } } },
      },
      { projectRoot: here },
    );
    await new Promise<void>((resolve, reject) => {
      withCapwall(policy, "enforce", (dep) => {
        dep.sendUdpUnbound("127.0.0.1", 12345, (err) => {
          // Delivered via callback (real send) — NOT an uncaught CapabilityError crash.
          if (err && (err as { name?: string }).name === "CapabilityError") reject(err as Error);
          else resolve();
        });
      });
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
