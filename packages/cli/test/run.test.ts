/**
 * `capwall run` — the modeless entry point that makes `capabilities.json`'s `mode` field real
 * (issue #55). Runs the BUILT cli + core (dist/), same as cli.test.ts; `pnpm build` first.
 *
 * The interesting assertion is the pair: the SAME command and the SAME fixture app produce a
 * deny or an allow depending only on the one word in the committed policy file.
 */
import { existsSync } from "node:fs";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Policy } from "@capwall/policy-schema";
import { runNode, type NodeRunResult } from "../../core/test/helpers/subprocess.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(here, "..", "dist", "index.js");
const FIXTURE_APP = path.join(here, "fixtures", "app");

/** Run the built CLI; resolves (never rejects) with exit code + output. */
function runCli(
  args: string[],
  cwd: string,
  env: Record<string, string | undefined> = {},
): Promise<NodeRunResult> {
  // CAPWALL_MODE outranks the policy file, so the runner's own environment must not leak one
  // in; individual cases set it deliberately.
  return runNode([CLI, ...args], { cwd, env: { CAPWALL_MODE: undefined, ...env } });
}

let appDir: string;
const policyPath = (): string => path.join(appDir, "capabilities.json");

/** Rewrite the fixture's committed policy with the given `mode` (or none at all). */
async function setDeclaredMode(mode: "observe" | "enforce" | undefined): Promise<void> {
  const policy = JSON.parse(await readFile(policyPath(), "utf8")) as Policy;
  if (mode === undefined) delete policy.mode;
  else policy.mode = mode;
  await writeFile(policyPath(), JSON.stringify(policy, null, 2));
}

beforeAll(async () => {
  expect(
    existsSync(CLI),
    `built CLI not found at ${CLI} — run 'pnpm build' before 'pnpm test'`,
  ).toBe(true);
  appDir = path.join(await mkdtemp(path.join(os.tmpdir(), "capwall-run-test-")), "app");
  await cp(FIXTURE_APP, appDir, { recursive: true });
  // Generate the starter policy the same way a user would, so `run` is tested against a real
  // observe-produced document rather than a hand-written one.
  const seed = await runCli(["observe", "--", "node", "main.js"], appDir);
  expect(seed.code).toBe(0);
});

afterAll(async () => {
  await rm(path.dirname(appDir), { recursive: true, force: true });
});

describe("capwall run — mode comes from the policy document", () => {
  it('denies an un-granted read when the policy declares "mode": "enforce"', async () => {
    await setDeclaredMode("enforce");
    const r = await runCli(["run", "--", "node", "extra.js"], appDir);
    expect(r.stderr).toContain('mode "enforce"');
    expect(r.stderr).toMatch(/DENY 'trace-dep' fs:read .*other\.txt/);
    expect(r.stdout).not.toContain("unexpected data");
    expect(r.code).not.toBe(0);
  });

  it('allows the same read when the policy declares "mode": "observe"', async () => {
    await setDeclaredMode("observe");
    const r = await runCli(["run", "--", "node", "extra.js"], appDir);
    expect(r.stderr).toContain('mode "observe"');
    expect(r.stderr).not.toMatch(/DENY/);
    expect(r.stdout).toContain("extra: unexpected data");
    expect(r.code).toBe(0);
  });

  it("runs the granted path clean under a declared enforce", async () => {
    await setDeclaredMode("enforce");
    const r = await runCli(["run", "--", "node", "main.js"], appDir);
    expect(r.stderr).not.toMatch(/DENY/);
    expect(r.stdout).toContain("main: expected data");
    expect(r.code).toBe(0);
  });

  it("refuses, with a fix-it message, when the policy declares no mode", async () => {
    await setDeclaredMode(undefined);
    const r = await runCli(["run", "--", "node", "main.js"], appDir);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('declares no "mode"');
    expect(r.stderr).toContain("capwall enforce -- node main.js");
    expect(r.stdout).not.toContain("main: expected data"); // never launched the target
  });

  it("refuses when the policy file is missing", async () => {
    const r = await runCli(["run", "-p", "nope.json", "--", "node", "main.js"], appDir);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("policy file not found: nope.json");
  });
});

describe("capwall run — CAPWALL_MODE still outranks the file", () => {
  it("CAPWALL_MODE=observe downgrades a policy that declares enforce", async () => {
    await setDeclaredMode("enforce");
    const r = await runCli(["run", "--", "node", "extra.js"], appDir, {
      CAPWALL_MODE: "observe",
    });
    expect(r.stderr).toContain("CAPWALL_MODE=observe overrides");
    expect(r.stdout).toContain("extra: unexpected data");
    expect(r.code).toBe(0);
  });

  it("refuses rather than silently running unmediated on a bad CAPWALL_MODE", async () => {
    // The preload treats an unrecognized CAPWALL_MODE as "stay inert"; `run` must not let that
    // turn into a target process that quietly gets no mediation at all.
    await setDeclaredMode("enforce");
    const r = await runCli(["run", "--", "node", "extra.js"], appDir, {
      CAPWALL_MODE: "enfroce",
    });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("would take precedence and leave capwall inert");
    expect(r.stdout).not.toContain("unexpected data");
  });
});
