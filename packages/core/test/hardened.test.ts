/**
 * Opt-in hardened mode (issue #17) — `install(policy, mode, { hardened: true })` /
 * `CAPWALL_HARDENED=1`.
 *
 * capwall's shims are ordinary mutable objects by default, so a dependency can reassign
 * `fs.readFileSync` (or `net.Socket.prototype.connect`) and silently disable enforcement for
 * the whole process. Hardened mode freezes the surfaces capwall created; the price is
 * `graceful-fs` (and every other legitimate `fs` patcher), which is why it is opt-in.
 *
 * The load-bearing assertion in every hardened case below is NOT "the write threw" — a frozen
 * write throws only under `"use strict"` and silently no-ops otherwise. It is that the
 * ORIGINAL guarded method is still in place and still DENYING afterwards. Both are asserted.
 *
 * The hardened-OFF cases are equally deliberate: they prove the default is untouched (the
 * patch lands and defeats the guard), which is exactly the graceful-fs compatibility capwall
 * trades enforcement strength for by default.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import {
  install,
  loadPolicyFromObject,
  type Decision,
  type Policy,
} from "../src/index.js";
import { createFsShim } from "../src/shims/fs.js";
import { createChildProcessShim } from "../src/shims/child_process.js";
import { createHttpShim, createNetShim } from "../src/shims/net.js";
import { createVmShim } from "../src/shims/vm.js";
import { createWorkerThreadsShim } from "../src/shims/worker_threads.js";
import type { ShimContext } from "../src/shims/runtime.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");

/** The REAL builtins, captured OUTSIDE any patched window — hardened mode must never
 * freeze these (freezing a builtin is a process-global side effect that outlives uninstall). */
const REAL_FS = requireCjs("node:fs") as typeof import("node:fs");
const REAL_NET = requireCjs("node:net") as typeof import("node:net");

type AnyFn = (...args: unknown[]) => unknown;

interface FixtureDep {
  readData(): string;
  readDataAsync(): Promise<string>;
  patchShimMethod(replacement: AnyFn): unknown;
  patchShimMethodStrict(replacement: AnyFn): unknown;
  deleteShimMethod(): string;
  redefineShimMethod(replacement: AnyFn): string;
  patchPromisesMethod(replacement: AnyFn): unknown;
  patchSocketPrototypeConnect(replacement: AnyFn): unknown;
  patchSocketPrototypeConnectStrict(replacement: AnyFn): unknown;
  inspectFrozen(): { fs: boolean; fsPromises: boolean; socketPrototype: boolean };
  connectViaSocketPrototype(host: string, port: number): void;
}

/** Require the fixture fresh (cache cleared) so its top-level require("fs") re-runs. */
function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

const emptyEnforcePolicy = (): Policy =>
  loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: here });

type Recorded = { pkg: string; decision: Decision };

/** Run `fn` inside a tight install window (hardened on or off), collecting every decision. */
function withCapwall<T>(
  hardened: boolean,
  fn: (dep: FixtureDep) => T,
  policy: Policy = emptyEnforcePolicy(),
): { result: T; decisions: Recorded[] } {
  const decisions: Recorded[] = [];
  const handle = install(policy, "enforce", {
    projectRoot: here,
    hardened,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
  });
  try {
    return { result: fn(loadFixtureFresh()), decisions };
  } finally {
    handle.uninstall();
  }
}

const replacement: AnyFn = () => "PATCHED";

/** Build a shim directly, bypassing the loader — used to inspect frozen-ness per surface. */
function ctxFor(hardened: boolean): ShimContext {
  return {
    policy: emptyEnforcePolicy(),
    mode: "enforce",
    onDecision: () => {},
    projectRoot: here,
    hardened,
  };
}

describe("hardened mode OFF (the default) — shims stay patchable (graceful-fs compatibility)", () => {
  it("nothing capwall hands out is frozen", () => {
    const { result } = withCapwall(false, (dep) => dep.inspectFrozen());
    expect(result).toEqual({ fs: false, fsPromises: false, socketPrototype: false });
  });

  it("a dependency CAN replace a shim method, and the replacement takes effect", () => {
    // This is the un-patch the threat model documents, reproduced deliberately: with hardened
    // off the write lands and enforcement is gone. That is the graceful-fs trade-off.
    const { result } = withCapwall(false, (dep) => {
      expect(dep.patchShimMethod(replacement)).toBe(replacement);
      return dep.readData(); // would throw CapabilityError if the guard were still in place
    });
    expect(result).toBe("PATCHED");
  });

  it("a dependency CAN replace a guarded prototype method", () => {
    withCapwall(false, (dep) => {
      expect(dep.patchSocketPrototypeConnect(replacement)).toBe(replacement);
      // The guard is gone: an ungranted connect no longer throws.
      expect(() => dep.connectViaSocketPrototype("evil.example", 443)).not.toThrow();
    });
  });

  it("fs.promises is patchable too", () => {
    const { result } = withCapwall(false, (dep) => {
      expect(dep.patchPromisesMethod(replacement)).toBe(replacement);
      // The replacement is called in place of the guarded wrapper — no rejection, no guard.
      return dep.readDataAsync() as unknown as string;
    });
    expect(result).toBe("PATCHED");
  });

  it("directly-built shims are unfrozen", () => {
    const shim = createFsShim(ctxFor(false));
    expect(Object.isFrozen(shim)).toBe(false);
    expect(Object.isFrozen(shim.promises)).toBe(false);
    expect(Object.isFrozen(shim.readFileSync)).toBe(false);
  });
});

describe("hardened mode ON — namespace-property patching cannot remove a guard", () => {
  it("a sloppy-mode reassignment silently no-ops AND the original guard still denies", () => {
    const { result, decisions } = withCapwall(true, (dep) => {
      // Sloppy mode: the write is a no-op, not a throw. Observable behavior asserted as-is.
      expect(() => dep.patchShimMethod(replacement)).not.toThrow();
      expect(dep.patchShimMethod(replacement)).not.toBe(replacement);
      // THE assertion that matters: the guarded wrapper is still there, still enforcing.
      expect(() => dep.readData()).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
      return dep.inspectFrozen();
    });
    expect(result.fs).toBe(true);
    expect(decisions.some((d) => d.pkg === "fixture-dep" && !d.decision.allowed)).toBe(true);
  });

  it("the same reassignment under 'use strict' throws a TypeError, and the guard survives", () => {
    withCapwall(true, (dep) => {
      expect(() => dep.patchShimMethodStrict(replacement)).toThrowError(TypeError);
      expect(() => dep.readData()).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("`delete fs.readFileSync` no-ops — the method is still a function", () => {
    const { result } = withCapwall(true, (dep) => dep.deleteShimMethod());
    expect(result).toBe("function");
  });

  it("Object.defineProperty over a guarded method throws TypeError", () => {
    const { result } = withCapwall(true, (dep) => dep.redefineShimMethod(replacement));
    expect(result).toBe("TypeError");
  });

  it("fs.promises is frozen too, and still rejects after a patch attempt", async () => {
    const { result } = withCapwall(true, (dep) => {
      expect(dep.patchPromisesMethod(replacement)).not.toBe(replacement);
      expect(dep.inspectFrozen().fsPromises).toBe(true);
      return dep.readDataAsync();
    });
    await expect(result).rejects.toMatchObject({ name: "CapabilityError" });
  });
});

describe("hardened mode ON — prototype-method patching cannot remove a guard", () => {
  it("a sloppy-mode `net.Socket.prototype.connect = evil` no-ops AND the guard still denies", () => {
    withCapwall(true, (dep) => {
      expect(dep.inspectFrozen().socketPrototype).toBe(true);
      expect(dep.patchSocketPrototypeConnect(replacement)).not.toBe(replacement);
      // The guarded prototype method is still in place: an ungranted connect still throws.
      expect(() => dep.connectViaSocketPrototype("evil.example", 443)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("the same write under 'use strict' throws a TypeError, and the guard survives", () => {
    withCapwall(true, (dep) => {
      expect(() => dep.patchSocketPrototypeConnectStrict(replacement)).toThrowError(TypeError);
      expect(() => dep.connectViaSocketPrototype("evil.example", 443)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });
});

describe("hardened mode ON — which surfaces are (and are not) frozen", () => {
  it("freezes every shim namespace capwall hands out", () => {
    const ctx = ctxFor(true);
    const fs = createFsShim(ctx);
    expect(Object.isFrozen(fs)).toBe(true);
    expect(Object.isFrozen(fs.promises)).toBe(true);
    expect(Object.isFrozen(fs.readFileSync)).toBe(true); // the guarded wrapper itself
    expect(Object.isFrozen(createNetShim(ctx))).toBe(true);
    expect(Object.isFrozen(createHttpShim(ctx))).toBe(true);
    expect(Object.isFrozen(createChildProcessShim(ctx))).toBe(true);
    expect(Object.isFrozen(createWorkerThreadsShim(ctx))).toBe(true);
    expect(Object.isFrozen(createVmShim(ctx))).toBe(true);
  });

  it("freezes the guarded subclasses AND their prototypes", () => {
    const ctx = ctxFor(true);
    const net = createNetShim(ctx);
    const cp = createChildProcessShim(ctx);
    expect(Object.isFrozen(net.Socket)).toBe(true);
    expect(Object.isFrozen(net.Socket.prototype)).toBe(true);
    expect(Object.isFrozen(cp.ChildProcess)).toBe(true);
    expect(Object.isFrozen(cp.ChildProcess.prototype)).toBe(true);
    // instanceof must still work through the frozen Symbol.hasInstance override.
    expect(new REAL_NET.Socket() instanceof net.Socket).toBe(true);
  });

  it("does NOT freeze the real builtins — freezing those would be a process-global side effect", () => {
    const ctx = ctxFor(true);
    createFsShim(ctx);
    createNetShim(ctx);
    createVmShim(ctx);
    createWorkerThreadsShim(ctx);
    expect(Object.isFrozen(REAL_FS)).toBe(false);
    expect(Object.isFrozen(REAL_FS.readFileSync)).toBe(false);
    expect(Object.isFrozen(REAL_NET)).toBe(false);
    expect(Object.isFrozen(REAL_NET.Socket)).toBe(false);
    expect(Object.isFrozen(REAL_NET.Socket.prototype)).toBe(false);
  });

  it("does NOT freeze the construct-trap Proxy class wrappers (freezing a Proxy freezes its real target)", () => {
    // Documented, deliberate gap: fs.ReadStream/WriteStream, vm.Script and
    // worker_threads.Worker are Proxies over the real class, so Object.freeze would forward
    // to — and permanently freeze — the builtin. The namespace freeze still prevents
    // replacing the slot; the real class stays reachable via `.prototype.constructor`.
    const ctx = ctxFor(true);
    const fs = createFsShim(ctx);
    expect(Object.isFrozen(fs.ReadStream)).toBe(false);
    expect(Object.isFrozen(REAL_FS.ReadStream)).toBe(false); // the real class is untouched
    expect(Object.isFrozen(createVmShim(ctx).Script)).toBe(false);
    expect(Object.isFrozen(createWorkerThreadsShim(ctx).Worker)).toBe(false);
  });
});

describe("hardened mode is orthogonal to policy decisions", () => {
  it("a granted read still succeeds with hardened on (freezing changes no decision)", () => {
    const granted = loadPolicyFromObject(
      {
        version: 1,
        mode: "enforce",
        packages: { "fixture-dep": { fs: { read: ["./fixtures/**"], write: [] } } },
      },
      { projectRoot: here },
    );
    const { result } = withCapwall(true, (dep) => dep.readData(), granted);
    expect(result).toBe("fixture data\n");
  });
});

/* ------------------------------------------------------------------------------------- */
/* CAPWALL_HARDENED=1 — the preload env override (runs against the built dist/preload.js). */

const PRELOAD = requireCjs.resolve("../dist/preload.js");

function frozenInSubprocess(env: Record<string, string>): Promise<{ fs: boolean; promises: boolean }> {
  const code =
    "console.log(JSON.stringify({" +
    "fs: Object.isFrozen(require('fs'))," +
    "promises: Object.isFrozen(require('fs/promises'))" +
    "}))";
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      ["-e", code],
      {
        cwd: here,
        env: {
          ...process.env,
          NODE_OPTIONS: `--import ${pathToFileURL(PRELOAD).href}`,
          CAPWALL_PROJECT_ROOT: here,
          ...env,
        },
      },
      (err, stdout) => {
        if (err) return reject(err);
        resolve(JSON.parse(stdout.trim()) as { fs: boolean; promises: boolean });
      },
    );
  });
}

describe("CAPWALL_HARDENED env override (preload)", () => {
  it("CAPWALL_HARDENED=1 freezes the shims the preload installs", async () => {
    expect(existsSync(PRELOAD), `built preload not found at ${PRELOAD} — run 'pnpm build'`).toBe(true);
    await expect(frozenInSubprocess({ CAPWALL_MODE: "observe", CAPWALL_HARDENED: "1" })).resolves.toEqual({
      fs: true,
      promises: true,
    });
  });

  it("is off by default, and off for any value other than '1'", async () => {
    await expect(frozenInSubprocess({ CAPWALL_MODE: "observe" })).resolves.toEqual({
      fs: false,
      promises: false,
    });
    await expect(frozenInSubprocess({ CAPWALL_MODE: "observe", CAPWALL_HARDENED: "0" })).resolves.toEqual({
      fs: false,
      promises: false,
    });
  });
});
