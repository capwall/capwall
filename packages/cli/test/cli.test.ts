/**
 * CLI integration tests: the full trace→policy→enforce round-trip for fs, against the
 * BUILT cli + core (dist/). Run `pnpm build` first — CI does (build, then test).
 *
 * - observe on a fixture app records trace-dep's fs read and emits capabilities.json
 * - enforce under that generated policy runs clean (the round-trip)
 * - enforce denies (deny-by-default) an fs read the policy never saw
 * - observe never blocks, even for the un-granted read
 * - the express-app example boots under both observe and enforce (AGENTS.md § 7)
 */
import { execFile, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { cp, mkdtemp, readFile, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Policy } from "@capwall/policy-schema";

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(here, "..", "dist", "index.js");
const FIXTURE_APP = path.join(here, "fixtures", "app");
const EXPRESS_APP = path.resolve(here, "..", "..", "..", "examples", "express-app");

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Run the built CLI; resolves (never rejects) with exit code + output. */
function runCli(args: string[], cwd: string): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, [CLI, ...args], { cwd }, (err, stdout, stderr) => {
      if (err && typeof err.code !== "number") return reject(err);
      resolve({ code: err ? (err.code as number) : 0, stdout, stderr });
    });
  });
}

let appDir: string;

beforeAll(async () => {
  expect(
    existsSync(CLI),
    `built CLI not found at ${CLI} — run 'pnpm build' before 'pnpm test'`,
  ).toBe(true);
  // Copy the fixture app out of the repo so the generated capabilities.json is throwaway.
  appDir = path.join(await mkdtemp(path.join(os.tmpdir(), "capwall-cli-test-")), "app");
  await cp(FIXTURE_APP, appDir, { recursive: true });
});

afterAll(async () => {
  await rm(path.dirname(appDir), { recursive: true, force: true });
});

describe("trace → policy → enforce round-trip (fs)", () => {
  it("observe runs the app, blocks nothing, and emits a starter policy", async () => {
    const r = await runCli(["observe", "--", "node", "main.js"], appDir);
    expect(r.stderr).toContain("observe: recorded fs:read");
    expect(r.stdout).toContain("main: expected data"); // nothing was blocked
    expect(r.code).toBe(0);

    const policy = JSON.parse(
      await readFile(path.join(appDir, "capabilities.json"), "utf8"),
    ) as Policy;
    expect(policy.packages["trace-dep"]?.fs?.read).toContain(
      "./node_modules/trace-dep/data.txt",
    );
  });

  it("enforce under the generated policy runs clean", async () => {
    const r = await runCli(["enforce", "--", "node", "main.js"], appDir);
    expect(r.stderr).not.toMatch(/DENY/);
    expect(r.stdout).toContain("main: expected data");
    expect(r.code).toBe(0);
  });

  it("enforce denies-by-default an fs read the policy never saw", async () => {
    const r = await runCli(["enforce", "--", "node", "extra.js"], appDir);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/DENY 'trace-dep' fs:read .*other\.txt/);
    expect(r.stderr).toContain("CapabilityError");
    expect(r.stdout).not.toContain("unexpected data"); // denied BEFORE any effect
  });

  it("observe never blocks, even for the un-granted read", async () => {
    const r = await runCli(["observe", "--", "node", "extra.js"], appDir);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("extra: unexpected data");
  });

  it("explain answers with the same evaluator enforce uses", async () => {
    const allowed = await runCli(
      ["explain", "trace-dep", "fs:read", "./node_modules/trace-dep/data.txt"],
      appDir,
    );
    expect(allowed.code).toBe(0);
    expect(allowed.stdout).toMatch(/^ALLOW/);

    const denied = await runCli(["explain", "trace-dep", "fs:write", "./anything"], appDir);
    expect(denied.code).toBe(1);
    expect(denied.stdout).toMatch(/^DENY/);
  });
});

describe("trace → policy → enforce round-trip (native addon, S2/#49)", () => {
  /**
   * The whole loop for the `native` capability, end to end through the real CLI. The fixture
   * `.node` is a placeholder, which is fine and in fact useful: the gate decides before
   * `process.dlopen` opens the file, so `native: CapabilityError` vs. `native: Error` in the
   * app's own output is an unambiguous denied-vs-allowed signal that needs no compiler.
   */
  let generated: string;

  it("observe records the addon load and emits `native: true` for the owning package", async () => {
    generated = path.join(await mkdtemp(path.join(os.tmpdir(), "capwall-native-")), "policy.json");
    const r = await runCli(["observe", "-o", generated, "--", "node", "native.js"], appDir);
    expect(r.code).toBe(0);
    expect(r.stderr).toMatch(/observe: recorded native .*trace-dep\.node/);
    // Never blocked in observe: the load reached the real loader and failed on the file.
    expect(r.stdout).toContain("native: Error");

    const policy = JSON.parse(await readFile(generated, "utf8")) as Policy;
    // The grant is the BOOLEAN question, not the observed path — an addon path is a
    // platform/arch/ABI build artifact and would not reproduce on another machine (#27/#57).
    expect(policy.packages["trace-dep"]?.native).toBe(true);
    expect(JSON.stringify(policy)).not.toContain(".node");
  });

  it("enforce denies-by-default a package that was never granted `native`", async () => {
    const r = await runCli(["enforce", "--", "node", "native.js"], appDir);
    expect(r.stderr).toMatch(/DENY 'trace-dep' native .*trace-dep\.node/);
    expect(r.stdout).toContain("native: CapabilityError");
  });

  it("enforce under the generated policy lets the load through", async () => {
    const r = await runCli(["enforce", "--policy", generated, "--", "node", "native.js"], appDir);
    expect(r.stderr).not.toMatch(/DENY/);
    expect(r.stdout).toContain("native: Error"); // gate passed; the placeholder file failed
  });

  it("diff reports an ungranted addon load as drift", async () => {
    const r = await runCli(["diff", "--json", "--", "node", "native.js"], appDir);
    expect(r.code).toBe(1);
    const drift = JSON.parse(r.stdout.trim().split("\n").at(-1)!) as Array<{
      pkg: string;
      kind: string;
      detail: string;
    }>;
    expect(drift).toContainEqual(
      expect.objectContaining({ pkg: "trace-dep", kind: "native" }),
    );
    expect(drift.find((d) => d.kind === "native")!.detail).toMatch(/^native .*trace-dep\.node$/);
  });

  it("explain answers for `native`, with and without a path target", async () => {
    const denied = await runCli(["explain", "trace-dep", "native"], appDir);
    expect(denied.code).toBe(1);
    expect(denied.stdout).toMatch(/^DENY.*native <any addon>/);

    const allowed = await runCli(
      ["explain", "--policy", generated, "trace-dep", "native", "./build/Release/trace-dep.node"],
      appDir,
    );
    expect(allowed.code).toBe(0);
    expect(allowed.stdout).toMatch(/^ALLOW/);
  });
});

describe("express-app example (AGENTS.md § 7)", () => {
  const PORT = 3000 + (process.pid % 20000);
  const BASE = `http://localhost:${PORT}`;

  /** Start the CLI wrapping the server, wait for it to serve, run `probe`, SIGINT, await exit. */
  async function withServer(
    mode: "observe" | "enforce",
    extraArgs: string[],
    probe: () => Promise<void>,
  ): Promise<{ code: number | null; stderr: string }> {
    const child = spawn(process.execPath, [CLI, mode, ...extraArgs, "--", "node", "src/server.js"], {
      cwd: EXPRESS_APP,
      env: { ...process.env, PORT: String(PORT) },
    });
    let stderr = "";
    child.stderr.on("data", (c: Buffer) => (stderr += c.toString()));
    const exited = new Promise<number | null>((resolve) =>
      child.on("close", (code) => resolve(code)),
    );
    try {
      let up = false;
      for (let i = 0; i < 50 && !up; i++) {
        up = await fetch(`${BASE}/`).then((r) => r.ok).catch(() => false);
        if (!up) await new Promise((r) => setTimeout(r, 200));
      }
      expect(up, `server did not come up on ${BASE}; stderr:\n${stderr}`).toBe(true);
      await probe();
    } finally {
      child.kill("SIGINT");
    }
    return { code: await exited, stderr };
  }

  it("runs under observe and generates a policy for what it did", async () => {
    const tmp = await mkdtemp(path.join(os.tmpdir(), "capwall-express-"));
    const policyFile = path.join(tmp, "capabilities.json");
    try {
      const { code, stderr } = await withServer("observe", ["-o", policyFile], async () => {
        const res = await fetch(`${BASE}/log`);
        expect(await res.text()).toBe("logged\n");
      });
      expect(code).toBe(0);
      expect(stderr).toContain("observe: recorded fs:write");

      const policy = JSON.parse(await readFile(policyFile, "utf8")) as Policy;
      expect(policy.packages["<app>"]?.fs?.write).toContain("./logs/requests.log");

      // ...and enforce under that generated policy runs clean.
      const enforced = await withServer("enforce", ["--policy", policyFile], async () => {
        const res = await fetch(`${BASE}/log`);
        expect(await res.text()).toBe("logged\n");
      });
      expect(enforced.code).toBe(0);
      expect(enforced.stderr).not.toMatch(/DENY/);
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  }, 60_000);
});
