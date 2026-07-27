/**
 * End-to-end round-trip for `net.hosts` globs, against the BUILT cli + core (dist/) — run
 * `pnpm build` first, as CI does.
 *
 *  - #83 `net.hosts` globs: observe records the concrete host, an author tightens it to
 *    `"*.internal"`, and enforce/diff/explain all agree — the exact workflow the issue says
 *    silently failed before. Plus: a malformed pattern is a load-time error.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import type { Policy } from "@capwall/policy-schema";

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(here, "..", "dist", "index.js");
const FIXTURE_APP = path.join(here, "fixtures", "app");

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function runCli(args: string[], cwd: string): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, [CLI, ...args], { cwd }, (err, stdout, stderr) => {
      if (err && typeof err.code !== "number") return reject(err);
      resolve({ code: err ? (err.code as number) : 0, stdout, stderr });
    });
  });
}

let appDir: string;

beforeAll(() => {
  expect(existsSync(CLI), `built CLI not found at ${CLI} — run 'pnpm build' first`).toBe(true);
});

afterEach(async () => {
  if (appDir) await rm(path.dirname(appDir), { recursive: true, force: true });
});

async function freshAppDir(): Promise<string> {
  const dir = path.join(await mkdtemp(path.join(os.tmpdir(), "capwall-gran-test-")), "app");
  await cp(FIXTURE_APP, dir, { recursive: true });
  return dir;
}

async function writePolicy(dir: string, packages: Record<string, unknown>): Promise<void> {
  await writeFile(
    path.join(dir, "capabilities.json"),
    JSON.stringify({ version: 1, mode: "enforce", default: {}, packages }, null, 2),
  );
}

/**
 * Node's own ESM loader reads this from a stack with no caller frame, so every run produces one
 * `<unknown>` env read (#60). Granting it explicitly keeps these tests about the capability
 * under test rather than about that documented escape hatch.
 */
const LOADER_ENV = { "<unknown>": { env: ["WATCH_REPORT_DEPENDENCIES"] } };

describe("net host globs round-trip (#83)", () => {
  it("observe records the concrete host, and enforce accepts an author-tightened `*.internal`", async () => {
    appDir = await freshAppDir();
    const observed = await runCli(["observe", "--", "node", "netglob.js"], appDir);
    expect(observed.code).toBe(0);
    const policy = JSON.parse(
      await readFile(path.join(appDir, "capabilities.json"), "utf8"),
    ) as Policy;
    expect(policy.packages["trace-dep"]?.net?.hosts).toEqual(["api.internal"]);

    // The hand-tightening step from the issue: swap the concrete host for the wildcard the
    // docs advertised. Before #83 this silently denied every internal host.
    await writePolicy(appDir, {
      "trace-dep": { net: { hosts: ["*.internal"], ports: [9999] } },
      ...LOADER_ENV,
    });
    const r = await runCli(["enforce", "--", "node", "netglob.js"], appDir);
    expect(r.stdout).toContain("net: allowed-through");
    expect(r.stderr).not.toMatch(/DENY/);
  });

  it("`**.internal` also grants it; a non-matching wildcard still denies", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, {
      "trace-dep": { net: { hosts: ["**.internal"], ports: [9999] } },
      ...LOADER_ENV,
    });
    expect((await runCli(["enforce", "--", "node", "netglob.js"], appDir)).stdout).toContain(
      "net: allowed-through",
    );

    await writePolicy(appDir, {
      "trace-dep": { net: { hosts: ["*.example"], ports: [9999] } },
      ...LOADER_ENV,
    });
    const denied = await runCli(["enforce", "--", "node", "netglob.js"], appDir);
    expect(denied.stdout).toContain("net: CapabilityError");
    expect(denied.stderr).toMatch(/DENY 'trace-dep' net api\.internal:9999/);
  });

  it("diff agrees with enforce about a wildcard grant", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, {
      "trace-dep": { net: { hosts: ["*.internal"], ports: [9999] } },
      ...LOADER_ENV,
    });
    expect((await runCli(["diff", "--", "node", "netglob.js"], appDir)).code).toBe(0);

    await writePolicy(appDir, {
      "trace-dep": { net: { hosts: ["*.example"], ports: [9999] } },
      ...LOADER_ENV,
    });
    const drifted = await runCli(["diff", "--", "node", "netglob.js"], appDir);
    expect(drifted.code).toBe(1);
    expect(drifted.stderr).toMatch(/net api\.internal:9999 \(not granted\)/);
  });

  it("explain agrees with enforce", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, { "trace-dep": { net: { hosts: ["*.internal"], ports: [443] } } });
    expect((await runCli(["explain", "trace-dep", "net", "api.internal:443"], appDir)).code).toBe(0);
    expect((await runCli(["explain", "trace-dep", "net", "internal:443"], appDir)).code).toBe(1);
    expect((await runCli(["explain", "trace-dep", "net", "a.b.internal:443"], appDir)).code).toBe(1);
  });

  it("a MALFORMED pattern fails the policy load loudly instead of matching nothing", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, { "trace-dep": { net: { hosts: ["a.**.b"], ports: [443] } } });
    const r = await runCli(["explain", "trace-dep", "net", "a.x.b:443"], appDir);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/FIRST label/);
  });
});
