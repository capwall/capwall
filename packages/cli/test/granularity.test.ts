/**
 * End-to-end round-trips for the two policy-granularity features, against the BUILT cli + core
 * (dist/) — run `pnpm build` first, as CI does.
 *
 *  - #72 `ipc.paths`: observe → policy → enforce → diff for a unix-domain socket, including
 *    that a grant for one socket is not a grant for another, and that the pre-#72
 *    `net: { hosts: ["<ipc>"] }` shape still works.
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

// Every policy below used to carry `"<unknown>": { env: ["WATCH_REPORT_DEPENDENCIES"] }`, because
// Node's own ESM loader reads that variable from a stack with no caller frame and the read was
// recorded as real drift. Since #119 a read Node itself initiated is not recorded at all, so the
// fixtures grant only the capability each test is about.

// The socket lives inside the project root, so this is the path an app under test uses and
// `observe` stores as the portable `./api.sock`.
const SOCK = "./api.sock";

describe.skipIf(process.platform === "win32")("ipc.paths round-trip (#72)", () => {
  it("observe records the CONCRETE socket path, project-relative so the policy is portable", async () => {
    appDir = await freshAppDir();
    const r = await runCli(["observe", "--", "node", "ipc.js"], appDir);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("ipc: connected"); // observe never blocks
    expect(r.stderr).toMatch(/observe: recorded ipc .*api\.sock/);

    const policy = JSON.parse(
      await readFile(path.join(appDir, "capabilities.json"), "utf8"),
    ) as Policy;
    expect(policy.packages["trace-dep"]?.ipc?.paths).toEqual([SOCK]);
    // The old shape is NOT emitted any more: no `<ipc>` pseudo-host, no port 0.
    expect(policy.packages["trace-dep"]?.net?.hosts ?? []).not.toContain("<ipc>");
  });

  it("enforce under the generated policy runs clean", async () => {
    appDir = await freshAppDir();
    await runCli(["observe", "--", "node", "ipc.js"], appDir);
    const r = await runCli(["enforce", "--", "node", "ipc.js"], appDir);
    expect(r.stderr).not.toMatch(/DENY/);
    expect(r.stdout).toContain("ipc: connected");
    expect(r.code).toBe(0);
  });

  it("a grant for ONE socket is not a grant for another — the whole point of #72", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, {
      "trace-dep": { ipc: { paths: ["./other.sock"] } },
    });
    const r = await runCli(["enforce", "--", "node", "ipc.js"], appDir);
    expect(r.stdout).toContain("ipc: CapabilityError");
    expect(r.stderr).toMatch(/DENY 'trace-dep' ipc .*api\.sock/);
  });

  it("a glob over a socket directory grants it", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, { "trace-dep": { ipc: { paths: ["./*.sock"] } } });
    const r = await runCli(["enforce", "--", "node", "ipc.js"], appDir);
    expect(r.stdout).toContain("ipc: connected");
    expect(r.code).toBe(0);
  });

  it("the pre-#72 `net: { hosts: [\"<ipc>\"], ports: [0] }` grant still works (all IPC)", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, {
      "trace-dep": { net: { hosts: ["<ipc>"], ports: [0] } },
    });
    const r = await runCli(["enforce", "--", "node", "ipc.js"], appDir);
    expect(r.stdout).toContain("ipc: connected");
    expect(r.code).toBe(0);
  });

  it("diff reports an ungranted socket as drift, naming the path", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, {
      "trace-dep": { ipc: { paths: ["./other.sock"] } },
    });
    const r = await runCli(["diff", "--json", "--", "node", "ipc.js"], appDir);
    expect(r.code).toBe(1);
    const lines = r.stdout.trim().split("\n");
    const drift = JSON.parse(lines[lines.length - 1] ?? "") as Array<{
      pkg: string;
      kind: string;
      detail: string;
    }>;
    expect(drift).toHaveLength(1);
    expect(drift[0]).toMatchObject({ pkg: "trace-dep", kind: "ipc" });
    expect(drift[0]?.detail).toMatch(/^ipc .*api\.sock$/);
  });

  it("diff reports no drift once the socket is granted", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, { "trace-dep": { ipc: { paths: [SOCK] } } });
    const r = await runCli(["diff", "--", "node", "ipc.js"], appDir);
    expect(r.code).toBe(0);
    expect(r.stderr).toContain("no drift");
  });

  it("explain answers with the same evaluator enforce uses", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, { "trace-dep": { ipc: { paths: ["./run/*.sock"] } } });
    const allowed = await runCli(["explain", "trace-dep", "ipc", "./run/api.sock"], appDir);
    expect(allowed.code).toBe(0);
    expect(allowed.stdout).toMatch(/^ALLOW/);

    const denied = await runCli(["explain", "trace-dep", "ipc", "/var/run/docker.sock"], appDir);
    expect(denied.code).toBe(1);
    expect(denied.stdout).toMatch(/^DENY: .*ipc \/var\/run\/docker\.sock/);
  });
});

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
    });
    const r = await runCli(["enforce", "--", "node", "netglob.js"], appDir);
    expect(r.stdout).toContain("net: allowed-through");
    expect(r.stderr).not.toMatch(/DENY/);
  });

  it("`**.internal` also grants it; a non-matching wildcard still denies", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, {
      "trace-dep": { net: { hosts: ["**.internal"], ports: [9999] } },
    });
    expect((await runCli(["enforce", "--", "node", "netglob.js"], appDir)).stdout).toContain(
      "net: allowed-through",
    );

    await writePolicy(appDir, {
      "trace-dep": { net: { hosts: ["*.example"], ports: [9999] } },
    });
    const denied = await runCli(["enforce", "--", "node", "netglob.js"], appDir);
    expect(denied.stdout).toContain("net: CapabilityError");
    expect(denied.stderr).toMatch(/DENY 'trace-dep' net api\.internal:9999/);
  });

  it("diff agrees with enforce about a wildcard grant", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, {
      "trace-dep": { net: { hosts: ["*.internal"], ports: [9999] } },
    });
    expect((await runCli(["diff", "--", "node", "netglob.js"], appDir)).code).toBe(0);

    await writePolicy(appDir, {
      "trace-dep": { net: { hosts: ["*.example"], ports: [9999] } },
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
