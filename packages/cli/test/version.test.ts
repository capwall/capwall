/**
 * `capwall --version`, the help banner's doc links, and readable policy-validation errors
 * (issue #124). Runs the BUILT CLI (`dist/`), like the other CLI suites.
 *
 * These are small surfaces, but they are the first three an evaluator touches and each one had
 * a concrete failure: `--version` exited 2 with "unknown command", the banner pointed at
 * repo-relative paths that mean nothing from `node_modules/@capwall/cli`, and the best error
 * text in the project arrived as an escaped-JSON Zod issue array.
 */
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(here, "..", "dist", "index.js");
const PKG_ROOT = path.resolve(here, "..");

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

describe("#124 — capwall --version", () => {
  // The whole point is that it is NOT hardcoded: every package is 0.0.0 today and the release
  // bumps four manifests at once, so the test reads the manifest the same way the CLI must.
  const declared = (JSON.parse(
    readFileSync(path.join(PKG_ROOT, "package.json"), "utf8"),
  ) as { version: string }).version;

  for (const flag of ["--version", "-V", "-v", "version"]) {
    it(`'${flag}' prints the CLI version from package.json and exits 0`, async () => {
      const r = await runCli([flag], PKG_ROOT);
      expect(r.code).toBe(0);
      expect(r.stdout).toContain(`capwall ${declared}`);
    });
  }

  it("also reports the @capwall/core it would inject, because that is a different process", async () => {
    const r = await runCli(["--version"], PKG_ROOT);
    // Resolved through the same require.resolve("@capwall/core/preload") run.ts uses, so it
    // must never come back "unresolved" from inside the workspace.
    expect(r.stdout).toMatch(/@capwall\/core \d+\.\d+\.\d+/);
    expect(r.stdout).not.toContain("unresolved");
    expect(r.stdout).not.toContain("unknown");
  });
});

describe("#124 — the help banner points at URLs, not repo-relative paths", () => {
  it("links docs that resolve from an installed package", async () => {
    const r = await runCli(["--help"], PKG_ROOT);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("https://github.com/williamzujkowski/capwall/blob/main/docs/policy-format.md");
    // roadmap.md is the internal build-order tracker — the wrong thing to send a user to.
    expect(r.stdout).not.toContain("docs/roadmap.md");
  });
});

describe("#124 — a policy validation failure is readable", () => {
  let dir: string;

  beforeAll(async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), "capwall-version-test-"));
    await writeFile(
      path.join(dir, "capabilities.json"),
      JSON.stringify({
        version: 1,
        mode: "enforce",
        default: {},
        packages: { "sneak*": { env: ["A"] } },
      }),
    );
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("surfaces the message as `path: message`, not as a raw Zod issue array", async () => {
    const r = await runCli(["run", "--", "node", "-e", ""], dir);
    expect(r.code).not.toBe(0);
    // The good part of the message survives...
    expect(r.stderr).toContain('a wildcard must be the whole first link of a chain');
    // ...prefixed by where it applies, and NOT wrapped in JSON.
    expect(r.stderr).toContain('packages["sneak*"]:');
    expect(r.stderr).not.toContain('"code": "custom"');
  });
});
