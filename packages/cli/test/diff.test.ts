/**
 * `capwall diff` (roadmap S3): observe a run, then diff what it did against the committed
 * policy — against the BUILT cli + core (dist/). Run `pnpm build` first — CI does (build,
 * then test). Reuses the `fixtures/app` + vendored `trace-dep` pattern from cli.test.ts:
 * `main.js` makes exactly one capability call (trace-dep reading its own data.txt).
 *
 * - a policy that already grants what the run does → diff exits 0, reports no drift
 * - a policy missing that grant → diff exits 1 and names the drifted capability
 * - --json emits the same finding as a machine-readable array
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { cp, mkdtemp, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(here, "..", "dist", "index.js");
const FIXTURE_APP = path.join(here, "fixtures", "app");

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

beforeAll(() => {
  expect(
    existsSync(CLI),
    `built CLI not found at ${CLI} — run 'pnpm build' before 'pnpm test'`,
  ).toBe(true);
});

afterEach(async () => {
  if (appDir) await rm(path.dirname(appDir), { recursive: true, force: true });
});

/** Fresh copy of the fixture app (so each test's capabilities.json is throwaway). */
async function freshAppDir(): Promise<string> {
  const dir = path.join(await mkdtemp(path.join(os.tmpdir(), "capwall-diff-test-")), "app");
  await cp(FIXTURE_APP, dir, { recursive: true });
  return dir;
}

describe("capwall diff", () => {
  it("exits 0 with no drift when the policy already grants what the run does", async () => {
    appDir = await freshAppDir();
    await writeFile(
      path.join(appDir, "capabilities.json"),
      JSON.stringify(
        {
          version: 1,
          mode: "enforce",
          default: {},
          packages: {
            "trace-dep": {
              fs: { read: ["./node_modules/trace-dep/data.txt"], write: [] },
            },
            // This used to need `"<unknown>": { env: ["WATCH_REPORT_DEPENDENCIES"] }` as well:
            // Node's own ESM loader reads that variable from a stack with no caller frame, and
            // the read was recorded, so it was drift until granted. Since #119 a read Node
            // itself initiated is not recorded — the one grant every project needed for a
            // reason that was never the project's is gone.
          },
        },
        null,
        2,
      ),
    );

    const r = await runCli(["diff", "--", "node", "main.js"], appDir);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("main: expected data"); // the target actually ran
    expect(r.stderr).toContain("no drift");
    expect(r.stderr).not.toContain("DRIFT");
  });

  it("exits 1 and names the drifted capability when the policy lacks the grant", async () => {
    appDir = await freshAppDir();
    await writeFile(
      path.join(appDir, "capabilities.json"),
      JSON.stringify(
        {
          version: 1,
          mode: "enforce",
          default: {},
          packages: {
            // Grants trace-dep a DIFFERENT fs read — main.js's data.txt read is not covered.
            "trace-dep": {
              fs: { read: ["./node_modules/trace-dep/other.txt"], write: [] },
            },
          },
        },
        null,
        2,
      ),
    );

    const r = await runCli(["diff", "--", "node", "main.js"], appDir);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("DRIFT");
    expect(r.stderr).toMatch(/trace-dep\s+fs:read .*data\.txt \(not granted\)/);
  });

  it("--json emits the drift as a machine-readable array", async () => {
    appDir = await freshAppDir();
    await writeFile(
      path.join(appDir, "capabilities.json"),
      JSON.stringify(
        {
          version: 1,
          mode: "enforce",
          default: {},
          // Empty: the only drift left is trace-dep's. (Pre-#119 this needed an `<unknown>`
          // env grant to keep Node's own loader read out of the array — see above.)
          packages: {},
        },
        null,
        2,
      ),
    );

    const r = await runCli(["diff", "--json", "--", "node", "main.js"], appDir);
    expect(r.code).toBe(1);
    // The target's own (inherited) stdout precedes our report; --json is always the last line.
    const lines = r.stdout.trim().split("\n");
    const drift = JSON.parse(lines[lines.length - 1] ?? "") as Array<{
      pkg: string;
      kind: string;
      detail: string;
    }>;
    expect(drift).toHaveLength(1);
    expect(drift[0]).toMatchObject({ pkg: "trace-dep", kind: "fs" });
    expect(drift[0]?.detail).toMatch(/fs:read .*data\.txt/);
  });

  it("exits 2 when the policy file is missing", async () => {
    appDir = await freshAppDir();
    const r = await runCli(["diff", "--", "node", "main.js"], appDir);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("policy file not found");
  });
});
