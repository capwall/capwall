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
 *
 * COVERAGE NOTE (#64/#70 interaction). `fs.ReadStream`/`WriteStream`, `vm.Script`/
 * `SourceTextModule`/`SyntheticModule` and `worker_threads.Worker` used to be construct-trap
 * Proxies, which hardened mode could NOT freeze: `Object.freeze` on a Proxy forwards
 * `[[PreventExtensions]]` to its target, so freezing one would have frozen the real builtin
 * class process-wide. #70 converted all three to guarded subclasses — objects capwall owns —
 * so they are now frozen like every other guarded class, and this file asserts that.
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
import { createHttpShim, createNetShim, createTlsShim, createDgramShim } from "../src/shims/net.js";
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
const REAL_VM = requireCjs("node:vm") as typeof import("node:vm");
const REAL_WT = requireCjs("node:worker_threads") as typeof import("node:worker_threads");

type AnyFn = (...args: unknown[]) => unknown;

interface FrozenReport {
  fs: boolean;
  fsPromises: boolean;
  fsReadFileSync: boolean;
  socketPrototype: boolean;
  readStream: boolean;
  readStreamPrototype: boolean;
  vmScript: boolean;
  vmScriptPrototype: boolean;
  worker: boolean;
  workerPrototype: boolean;
  readAliasIdentity: boolean;
}

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
  patchStreamClass(replacement: AnyFn): unknown;
  patchVmScriptClass(replacement: AnyFn): unknown;
  patchWorkerClassStrict(replacement: AnyFn): unknown;
  inspectFrozen(): FrozenReport;
  connectViaSocketPrototype(host: string, port: number): void;
  readViaReadStreamConstructorEscape(target: string): void;
  runVmViaScriptConstructorEscape(code: string): unknown;
  spawnWorkerViaConstructorEscape(): { terminate(): Promise<number> };
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
    expect(result).toMatchObject({
      fs: false,
      fsPromises: false,
      fsReadFileSync: false,
      socketPrototype: false,
      readStream: false,
      readStreamPrototype: false,
      vmScript: false,
      vmScriptPrototype: false,
      worker: false,
      workerPrototype: false,
    });
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

  it("a dependency CAN replace a guarded class on the namespace", () => {
    withCapwall(false, (dep) => {
      expect(dep.patchStreamClass(replacement)).toBe(replacement);
      expect(dep.patchVmScriptClass(replacement)).toBe(replacement);
      expect(() => dep.patchWorkerClassStrict(replacement)).not.toThrow();
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
    expect(Object.isFrozen(shim.ReadStream)).toBe(false);
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

describe("hardened mode ON — the classes #70 converted from Proxies are now frozen too", () => {
  // Before #64/#70 these three were construct-trap Proxies, which hardened mode had to skip:
  // Object.freeze on a Proxy forwards to its target, so freezing one would have frozen the
  // REAL builtin class process-wide. As guarded subclasses they are capwall's own objects.
  it("freezes fs.ReadStream, vm.Script and worker_threads.Worker (and their prototypes)", () => {
    const { result } = withCapwall(true, (dep) => dep.inspectFrozen());
    expect(result).toMatchObject({
      readStream: true,
      readStreamPrototype: true,
      vmScript: true,
      vmScriptPrototype: true,
      worker: true,
      workerPrototype: true,
      readAliasIdentity: true, // #70's FileReadStream === ReadStream survives the freeze
    });
  });

  it("replacing one of those classes on the namespace fails, and the constructor guard holds", () => {
    withCapwall(true, (dep) => {
      expect(dep.patchStreamClass(replacement)).not.toBe(replacement);
      expect(dep.patchVmScriptClass(replacement)).not.toBe(replacement);
      expect(() => dep.patchWorkerClassStrict(replacement)).toThrowError(TypeError);
      // …and the #64 `.prototype.constructor` escape is still denied under hardened mode.
      expect(() => dep.readViaReadStreamConstructorEscape(path.join(FIXTURE, "data.txt"))).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
      expect(() => dep.runVmViaScriptConstructorEscape("1+1")).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
      expect(() => dep.spawnWorkerViaConstructorEscape()).toThrowError(
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
    expect(Object.isFrozen(createTlsShim(ctx))).toBe(true);
    expect(Object.isFrozen(createDgramShim(ctx))).toBe(true);
    expect(Object.isFrozen(createChildProcessShim(ctx))).toBe(true);
    expect(Object.isFrozen(createWorkerThreadsShim(ctx))).toBe(true);
    expect(Object.isFrozen(createVmShim(ctx))).toBe(true);
  });

  it("freezes every guarded class AND its prototype, in every shim", () => {
    const ctx = ctxFor(true);
    const fs = createFsShim(ctx);
    const net = createNetShim(ctx);
    const tls = createTlsShim(ctx);
    const http = createHttpShim(ctx);
    const dgram = createDgramShim(ctx);
    const cp = createChildProcessShim(ctx);
    const guarded: Array<[string, unknown]> = [
      ["fs.ReadStream", fs.ReadStream],
      ["fs.WriteStream", fs.WriteStream],
      ["net.Socket", net.Socket],
      ["tls.TLSSocket", tls.TLSSocket],
      ["http.ClientRequest", http.ClientRequest],
      ["http.Agent", http.Agent],
      ["dgram.Socket", dgram.Socket],
      ["child_process.ChildProcess", cp.ChildProcess],
      ["vm.Script", createVmShim(ctx).Script],
      ["worker_threads.Worker", createWorkerThreadsShim(ctx).Worker],
    ];
    for (const [name, Cls] of guarded) {
      expect(Object.isFrozen(Cls), `${name} should be frozen`).toBe(true);
      expect(
        Object.isFrozen((Cls as { prototype: object }).prototype),
        `${name}.prototype should be frozen`,
      ).toBe(true);
    }
  });

  it("does NOT freeze the real builtins — freezing those would be a process-global side effect", () => {
    const ctx = ctxFor(true);
    createFsShim(ctx);
    createNetShim(ctx);
    createVmShim(ctx);
    createWorkerThreadsShim(ctx);
    expect(Object.isFrozen(REAL_FS)).toBe(false);
    expect(Object.isFrozen(REAL_FS.readFileSync)).toBe(false);
    expect(Object.isFrozen(REAL_FS.ReadStream)).toBe(false);
    expect(Object.isFrozen(REAL_FS.ReadStream.prototype)).toBe(false);
    expect(Object.isFrozen(REAL_NET)).toBe(false);
    expect(Object.isFrozen(REAL_NET.Socket.prototype)).toBe(false);
    expect(Object.isFrozen(REAL_VM.Script.prototype)).toBe(false);
    expect(Object.isFrozen(REAL_WT.Worker.prototype)).toBe(false);
  });

  it("does NOT freeze process.env (documented gap — the guard is a Proxy over the live object)", () => {
    const handle = install(emptyEnforcePolicy(), "enforce", { projectRoot: here, hardened: true });
    try {
      expect(Object.isFrozen(process.env)).toBe(false);
      process.env["CAPWALL_HARDENED_TEST"] = "1"; // must still be assignable
      expect(process.env["CAPWALL_HARDENED_TEST"]).toBe("1");
      delete process.env["CAPWALL_HARDENED_TEST"];
    } finally {
      handle.uninstall();
    }
  });

  it("a frozen guarded class can still be extended by a dependency (compatibility)", () => {
    const fs = createFsShim(ctxFor(true));
    expect(() => {
      class Mine extends (fs.ReadStream as unknown as new (...a: never[]) => object) {}
      return Mine;
    }).not.toThrow();
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

interface SubprocessReport {
  fs: boolean;
  promises: boolean;
  readStream: boolean;
}

function frozenInSubprocess(env: Record<string, string>): Promise<SubprocessReport> {
  const code =
    "console.log(JSON.stringify({" +
    "fs: Object.isFrozen(require('fs'))," +
    "promises: Object.isFrozen(require('fs/promises'))," +
    "readStream: Object.isFrozen(require('fs').ReadStream)" +
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
        resolve(JSON.parse(stdout.trim()) as SubprocessReport);
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
      readStream: true,
    });
  });

  it("is off by default, and off for any value other than '1'", async () => {
    await expect(frozenInSubprocess({ CAPWALL_MODE: "observe" })).resolves.toEqual({
      fs: false,
      promises: false,
      readStream: false,
    });
    await expect(frozenInSubprocess({ CAPWALL_MODE: "observe", CAPWALL_HARDENED: "0" })).resolves.toEqual({
      fs: false,
      promises: false,
      readStream: false,
    });
  });
});
