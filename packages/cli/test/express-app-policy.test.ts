/**
 * Regression gate for `examples/express-app`'s COMMITTED `capabilities.json` (issue #57).
 *
 * AGENTS.md § 2 and § 7 claim the flagship example runs clean under its own policy. It
 * silently stopped being true when the M4 `env` shim landed: the committed policy predated
 * it, so enforce emitted ~89 soft-deny lines and `capwall diff` reported ~89 drift entries.
 * Nothing failed loudly, because env denials are soft (they return `undefined`), so the
 * README walkthrough still "worked" while the console filled with denials. This test makes
 * that failure loud.
 *
 * Two assertions, both against the checked-in policy file (never a freshly generated one):
 *   - `capwall enforce` runs the example with ZERO `DENY` lines and exits 0.
 *   - `capwall diff` (roadmap S3) reports no observed-vs-declared drift and exits 0.
 *
 * Both run under a SCRUBBED, deliberately hostile environment rather than the ambient one.
 * That is the whole point: `debug` calls `Object.keys(process.env)` at load, so every key
 * present on the host is attributed to it. A policy that only passes in one developer's
 * shell is not reproducible, and this test would not catch that if it inherited that shell.
 * The junk keys below stand in for "whatever the next machine happens to have set".
 */
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { parsePolicy } from "@capwall/policy-schema";

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(here, "..", "dist", "index.js");
const EXPRESS_APP = path.resolve(here, "..", "..", "..", "examples", "express-app");
const POLICY = path.join(EXPRESS_APP, "capabilities.json");

// Distinct from cli.test.ts's express-app port (3000 + pid % 20000) by a fixed offset, so the
// two files can run concurrently under vitest's default parallel file scheduling.
const PORT = 20000 + (process.pid % 20000);
const BASE = `http://localhost:${PORT}`;

/**
 * A minimal environment plus host-specific noise the policy must tolerate. Deliberately
 * omits everything else the ambient shell has — including `DEBUG`, which would make `debug`
 * write back to `process.env` (a separate shim limitation, not a policy question).
 */
function scrubbedEnv(): NodeJS.ProcessEnv {
  const keep = ["PATH", "HOME", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE"];
  const env: NodeJS.ProcessEnv = {};
  for (const key of keep) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  return {
    ...env,
    PORT: String(PORT),
    // Host-specific noise: on a real machine these would be SSH_AUTH_SOCK, PYENV_ROOT, CI
    // runner vars, etc. `debug` enumerates them all, so a key-by-key policy would drift here.
    CAPWALL_TEST_HOST_JUNK: "1",
    ZZ_SOME_OTHER_HOST_VAR: "2",
    // Not real credentials — a placeholder proving the "*" grant's cost is visible in tests.
    AWS_SECRET_ACCESS_KEY: "not-a-real-secret",
  };
}

interface ServerRun {
  code: number | null;
  stderr: string;
  stdout: string;
}

/** Start `capwall <mode>` wrapping the example server, exercise both routes, then SIGINT. */
async function runExampleUnder(mode: "enforce" | "diff"): Promise<ServerRun> {
  const child = spawn(process.execPath, [CLI, mode, "--", "node", "src/server.js"], {
    cwd: EXPRESS_APP,
    env: scrubbedEnv(),
  });
  let stderr = "";
  let stdout = "";
  child.stderr.on("data", (c: Buffer) => (stderr += c.toString()));
  child.stdout.on("data", (c: Buffer) => (stdout += c.toString()));
  const exited = new Promise<number | null>((resolve) => child.on("close", resolve));
  try {
    let up = false;
    for (let i = 0; i < 60 && !up; i++) {
      up = await fetch(`${BASE}/`)
        .then((r) => r.ok)
        .catch(() => false);
      if (!up) await new Promise((r) => setTimeout(r, 200));
    }
    expect(up, `server did not come up on ${BASE}; stderr:\n${stderr}`).toBe(true);
    // Exercise the fs:write route too, so the granted write is actually taken.
    expect(await fetch(`${BASE}/log`).then((r) => r.text())).toBe("logged\n");
  } finally {
    child.kill("SIGINT");
  }
  return { code: await exited, stderr, stdout };
}

beforeAll(() => {
  expect(
    existsSync(CLI),
    `built CLI not found at ${CLI} — run 'pnpm build' before 'pnpm test'`,
  ).toBe(true);
});

describe("examples/express-app committed policy (#57)", () => {
  it("is a valid policy that grants every package the example actually uses", () => {
    const policy = parsePolicy(JSON.parse(readFileSync(POLICY, "utf8")));
    expect(policy.packages["<app>"]?.fs?.write).toContain("./logs/requests.log");
    // The env grants are the part that rots: they only appeared once the M4 env shim landed.
    expect(policy.packages["express"]?.env).toContain("NODE_ENV");
    expect(policy.packages["depd"]?.env).toContain("NO_DEPRECATION");
    expect(policy.packages["mime"]?.env).toContain("DEBUG_MIME");
    // `debug` enumerates the whole environment (Object.keys(process.env)) but only READS
    // `DEBUG_*`. That enumeration used to be recorded as a value read of every key, which
    // forced a bare `["*"]` grant here; since #67 it is not, so the grant is back to concrete
    // keys. Asserted exactly — a regression in the enumeration fix would show up as this list
    // re-acquiring host-specific keys, and asserting the exact set is what catches that.
    expect(policy.packages["debug"]?.env).toEqual([
      "DEBUG",
      "DEBUG_COLORS",
      "DEBUG_DEPTH",
      "DEBUG_FD",
      "DEBUG_SHOWHIDDEN",
    ]);
    // No package in the committed policy holds a wildcard env grant (#67 removed the last one).
    for (const [name, grant] of Object.entries(policy.packages)) {
      expect(grant.env ?? [], `'${name}' should not need a wildcard env grant`).not.toContain("*");
    }
  });

  it("runs under `capwall enforce` with zero denials, in a scrubbed environment", async () => {
    const { code, stderr } = await runExampleUnder("enforce");
    expect(stderr, `expected no denials under the committed policy:\n${stderr}`).not.toMatch(
      /DENY/,
    );
    expect(stderr).not.toMatch(/CapabilityError/);
    expect(code).toBe(0);
  }, 60_000);

  it("reports no drift under `capwall diff`, in a scrubbed environment", async () => {
    const { code, stderr } = await runExampleUnder("diff");
    expect(stderr, `expected no observed-vs-declared drift:\n${stderr}`).not.toMatch(/DRIFT/);
    expect(stderr).toContain("no drift");
    expect(code).toBe(0);
  }, 60_000);
});
