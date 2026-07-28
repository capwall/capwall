/**
 * Enforcement-mode resolution (issue #55). Two layers:
 *
 *  1. `resolveMode()` in isolation — the precedence table itself.
 *  2. The preload end-to-end, spawning `node --import <preload> app.mjs` against the same ESM
 *     fixture `esm.test.ts` uses. These are the tests that would have caught the original bug:
 *     a policy declaring `"mode": "enforce"` used to be silently inert.
 *
 * Requires `pnpm build` first — the end-to-end cases run the built `dist/preload.js`.
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { resolveMode } from "../src/policy/mode.js";
import {
  assertPreloadBuilt,
  PRELOAD_IMPORT_FLAG,
  runNode,
  type NodeRunResult,
} from "./helpers/subprocess.js";

describe("resolveMode — precedence", () => {
  it("CAPWALL_MODE wins over the policy's declared mode", () => {
    expect(resolveMode("observe", "enforce")).toEqual({ mode: "observe", source: "env" });
    expect(resolveMode("enforce", "observe")).toEqual({ mode: "enforce", source: "env" });
  });

  it("falls back to the policy's declared mode when CAPWALL_MODE is unset or empty", () => {
    expect(resolveMode(undefined, "enforce")).toEqual({ mode: "enforce", source: "policy" });
    expect(resolveMode(undefined, "observe")).toEqual({ mode: "observe", source: "policy" });
    // An exported-but-empty var is "unset" as far as a shell user is concerned.
    expect(resolveMode("", "enforce")).toEqual({ mode: "enforce", source: "policy" });
  });

  it("stays inert when neither channel declares a mode", () => {
    expect(resolveMode(undefined, undefined)).toBeUndefined();
    expect(resolveMode("", undefined)).toBeUndefined();
  });

  it("stays inert on an unrecognized CAPWALL_MODE rather than falling through", () => {
    // A typo must not silently resolve to the policy's mode — the caller asked for something
    // specific, and both "silently enforce" and "silently don't" are worse than nothing.
    expect(resolveMode("enfroce", "enforce")).toBeUndefined();
    expect(resolveMode("ENFORCE", "enforce")).toBeUndefined();
    expect(resolveMode("1", undefined)).toBeUndefined();
  });
});

const here = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(here, "fixtures", "esm", "app.mjs");
const APP_DIR = path.dirname(APP);
/** Spawn the fixture app under the built preload with exactly `env` (CAPWALL_* only). */
function runApp(env: Record<string, string>): Promise<NodeRunResult> {
  return runNode([APP], {
    cwd: APP_DIR,
    env: {
      NODE_OPTIONS: PRELOAD_IMPORT_FLAG,
      CAPWALL_PROJECT_ROOT: APP_DIR,
      // The vitest runner's own environment must not leak a mode into these cases.
      CAPWALL_MODE: undefined,
      CAPWALL_POLICY_FILE: undefined,
      ...env,
    },
  });
}

let tmpDir: string;
/** Grants nothing, declares `"mode": "enforce"` — so honoring the field means a DENY. */
let declaresEnforce: string;
/** Grants nothing, declares `"mode": "observe"` — honoring it means log-but-allow. */
let declaresObserve: string;
/** Grants nothing and declares NO mode — honoring the schema means staying inert. */
let declaresNothing: string;

beforeAll(async () => {
  assertPreloadBuilt();
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-mode-"));
  declaresEnforce = path.join(tmpDir, "declares-enforce.json");
  declaresObserve = path.join(tmpDir, "declares-observe.json");
  declaresNothing = path.join(tmpDir, "declares-nothing.json");
  await writeFile(
    declaresEnforce,
    JSON.stringify({ version: 1, mode: "enforce", default: {}, packages: {} }),
  );
  await writeFile(
    declaresObserve,
    JSON.stringify({ version: 1, mode: "observe", default: {}, packages: {} }),
  );
  await writeFile(declaresNothing, JSON.stringify({ version: 1, default: {}, packages: {} }));
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

describe("preload — the policy file's `mode` is honored (#55)", () => {
  it("enforces with no CAPWALL_MODE when the policy declares enforce", async () => {
    const r = await runApp({ CAPWALL_POLICY_FILE: declaresEnforce });
    expect(r.stdout).toContain("BLOCKED:esm-fixture-dep");
    expect(r.stderr).toMatch(/DENY 'esm-fixture-dep' fs:read/);
    expect(r.code).toBe(1);
  });

  it("observes (never blocks) with no CAPWALL_MODE when the policy declares observe", async () => {
    const r = await runApp({ CAPWALL_POLICY_FILE: declaresObserve });
    expect(r.stdout).toContain("READ_OK:esm fixture data");
    expect(r.stderr).toMatch(/observe: recorded fs:read .* for 'esm-fixture-dep'/);
    expect(r.code).toBe(0);
  });

  it("stays inert when the policy declares no mode and CAPWALL_MODE is unset", async () => {
    const r = await runApp({ CAPWALL_POLICY_FILE: declaresNothing });
    expect(r.stdout).toContain("READ_OK:esm fixture data");
    expect(r.stderr).not.toContain("[capwall]");
    expect(r.code).toBe(0);
  });

  it("stays inert with neither a policy file nor CAPWALL_MODE", async () => {
    const r = await runApp({});
    expect(r.stdout).toContain("READ_OK:esm fixture data");
    expect(r.stderr).not.toContain("[capwall]");
    expect(r.code).toBe(0);
  });
});

describe("preload — CAPWALL_MODE overrides the policy file's `mode` (#55)", () => {
  it("CAPWALL_MODE=observe downgrades a policy that declares enforce", async () => {
    const r = await runApp({ CAPWALL_POLICY_FILE: declaresEnforce, CAPWALL_MODE: "observe" });
    expect(r.stdout).toContain("READ_OK:esm fixture data");
    expect(r.code).toBe(0);
  });

  it("CAPWALL_MODE=enforce upgrades a policy that declares observe", async () => {
    const r = await runApp({ CAPWALL_POLICY_FILE: declaresObserve, CAPWALL_MODE: "enforce" });
    expect(r.stdout).toContain("BLOCKED:esm-fixture-dep");
    expect(r.code).toBe(1);
  });

  it("an unrecognized CAPWALL_MODE is inert, not a fall-through to the declared enforce", async () => {
    const r = await runApp({ CAPWALL_POLICY_FILE: declaresEnforce, CAPWALL_MODE: "enfroce" });
    expect(r.stdout).toContain("READ_OK:esm fixture data");
    expect(r.stderr).not.toContain("[capwall]");
    expect(r.code).toBe(0);
  });
});
