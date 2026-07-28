/**
 * WEB STORAGE — `localStorage` as an `fs` read/write on its backing file (issue #156).
 *
 * Node 26 ships Web Storage. `sessionStorage` is in-memory; `localStorage` is **file-backed**,
 * and with `--localstorage-file=<path>` Node performs that file's I/O internally, BELOW the `fs`
 * shim. Before `shims/web-storage.ts` a dependency read and wrote that file with no `fs` grant
 * and no recorded decision — nothing denied in `enforce`, nothing in the `observe` trace, nothing
 * for `capwall diff`. Same shape as the module-system read channel #123 closed, on a different
 * internal.
 *
 * ── THE VERSION-CONDITIONAL DISCIPLINE (AGENTS.md § 7, and #156 asked for it by name) ────────
 * The flag exists only on Node ≥26, and the vitest worker itself is never started with it, so the
 * guarded cases have to run in children and cannot run at all on 22 or 24. Two rules follow and
 * both are obeyed here:
 *
 *   - the version-gated cases use `it.skipIf(...)`, which the reporter SHOWS, never a bare
 *     `if (…) return;` that reports green with zero assertions;
 *   - the ABSENT case is asserted rather than assumed. The first `describe` runs on **every**
 *     supported Node and pins the no-op claim in both halves: `localStorageAvailable()` is false,
 *     and capwall registers no `localStorage` patch site. A guard that started patching
 *     unconditionally — or that probed by READING the global, which prints an ExperimentalWarning
 *     on Node 26 into the same stderr capwall's DENY lines use — fails there.
 */
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { install, loadPolicyFromObject } from "../src/index.js";
import { processPatchSites } from "../src/lifecycle/process-patch.js";
import {
  localStorageAvailable,
  resolveLocalStorageFile,
} from "../src/shims/web-storage.js";
import {
  assertPreloadBuilt,
  PRELOAD_IMPORT_FLAG,
  runNode,
  type NodeRunResult,
} from "./helpers/subprocess.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(here, "fixtures", "web-storage-app.cjs");
const APP_DIR = path.dirname(APP);

/** `--localstorage-file` landed in Node 26; below that the flag is rejected outright. */
const HAS_WEB_STORAGE = Number(process.versions.node.split(".")[0]) >= 26;

let tmpDir: string;
/** The operator's chosen backing file. A dependency has no say in this path — that is the point. */
let backingFile: string;
let denyPolicy: string;
let grantPolicy: string;

beforeAll(async () => {
  assertPreloadBuilt();
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-web-storage-"));
  backingFile = path.join(tmpDir, "storage.db");
  denyPolicy = path.join(tmpDir, "deny.json");
  grantPolicy = path.join(tmpDir, "grant.json");
  await writeFile(denyPolicy, JSON.stringify({ version: 1, mode: "enforce", default: {}, packages: {} }));
  await writeFile(
    grantPolicy,
    JSON.stringify({
      version: 1,
      mode: "enforce",
      packages: { "storage-dep": { fs: { read: [backingFile], write: [backingFile] } } },
    }),
  );
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

/** One child, started with the flag, under the built preload. */
function runApp(env: Record<string, string | undefined>): Promise<NodeRunResult> {
  return runNode([`--localstorage-file=${backingFile}`, PRELOAD_IMPORT_FLAG, APP], {
    cwd: APP_DIR,
    env: { CAPWALL_PROJECT_ROOT: APP_DIR, ...env },
  });
}

describe("#156 — the guard is a clean no-op without --localstorage-file", () => {
  it("does not consider localStorage available in this process, on any supported Node", () => {
    // True on 22 and 24 (no such global) AND on 26 without the flag (present-but-unavailable).
    expect(localStorageAvailable()).toBe(false);
    // The detector must not READ the global: on Node 26 that prints an ExperimentalWarning on
    // stderr, in every mediated process. `Object.keys` answers the same question silently, and
    // asserting the property is non-enumerable is what pins that it can.
    if ("localStorage" in globalThis) {
      const desc = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
      expect(desc?.enumerable, "Node marks it enumerable exactly when the flag exposes it").toBe(
        false,
      );
    } else {
      expect(Number(process.versions.node.split(".")[0])).toBeLessThan(26);
    }
  });

  it("registers no localStorage patch site, so install() cannot touch the global", () => {
    const handle = install(
      loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: here }),
      "enforce",
      { projectRoot: here, env: false, globalEgress: false },
    );
    try {
      const names = [...processPatchSites()].map((s) => s.name);
      expect(names).not.toContain("globalThis.localStorage");
      // …and the registered set is non-empty, so this is not passing because the registry is.
      expect(names).toContain("process.dlopen");
    } finally {
      handle.uninstall();
    }
  });

  it("resolves no backing file when the flag is absent from both channels", () => {
    expect(process.execArgv.join(" ")).not.toContain("--localstorage-file");
    expect(resolveLocalStorageFile()).toBeUndefined();
  });
});

describe.skipIf(!HAS_WEB_STORAGE)("#156 — localStorage under --localstorage-file (Node ≥26)", () => {
  it("denies both directions for an ungranted dependency, and nothing reaches the file", async () => {
    const r = await runApp({ CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy });
    // Every member, both accesses, charged to the DEPENDENCY rather than to the app.
    expect(r.stdout).toContain("setItem:BLOCKED:storage-dep");
    expect(r.stdout).toContain("getItem:BLOCKED:storage-dep");
    expect(r.stdout).toContain("length:BLOCKED:storage-dep");
    expect(r.stdout).toContain("key:BLOCKED:storage-dep");
    expect(r.stdout).toContain("removeItem:BLOCKED:storage-dep");
    expect(r.stdout).toContain("clear:BLOCKED:storage-dep");
    // The decision names the OPERATOR's file and the right access, as an ordinary `fs` grant.
    expect(r.stderr).toContain(`DENY 'storage-dep' fs:write ${backingFile}`);
    expect(r.stderr).toContain(`DENY 'storage-dep' fs:read ${backingFile}`);
    // Denied BEFORE the effect: the write never happened, so the value is not on disk.
    const onDisk = await readFile(backingFile, "utf8").catch(() => "");
    expect(onDisk).not.toContain("inert-fixture-value");
    // sessionStorage is in-memory — no file, so no `fs` question. It must still work.
    expect(r.stdout).toContain('session:OK:"v"');
    // capwall's view is still a Storage to ordinary code.
    expect(r.stdout).toContain('shape:{"instanceOfStorage":true,"protoIsStoragePrototype":true}');
  });

  it("allows both directions when the dependency is granted that path", async () => {
    const r = await runApp({ CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: grantPolicy });
    expect(r.stdout).toContain('setItem:OK:"written"');
    expect(r.stdout).toContain('getItem:OK:"inert-fixture-value"');
    expect(r.stdout).toContain("length:OK:1");
    expect(r.stdout).toContain('key:OK:"token"');
    expect(r.stdout).toContain('removeItem:OK:"removed"');
    expect(r.stdout).toContain('clear:OK:"cleared"');
    expect(r.stderr).not.toMatch(/DENY 'storage-dep'/);
  });

  it("observe blocks nothing and records the reads and writes it saw", async () => {
    const r = await runApp({ CAPWALL_MODE: "observe" });
    expect(r.stdout).toContain('getItem:OK:"inert-fixture-value"');
    expect(r.stderr).toContain(`recorded fs:write ${backingFile} for 'storage-dep'`);
    expect(r.stderr).toContain(`recorded fs:read ${backingFile} for 'storage-dep'`);
    // The recorded target is the file, never sessionStorage or a synthesized pseudo-path.
    expect(r.stderr).not.toContain("<localstorage>");
    expect(r.code).toBe(0);
  });
});
