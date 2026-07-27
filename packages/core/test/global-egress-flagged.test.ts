/**
 * FLAG-ONLY global egress classes (#80): `WebSocket` and `EventSource`.
 *
 * Node's global egress surface is not the same on the two versions in the CI matrix:
 *
 *   | global      | Node 20                      | Node 22 / 24                 |
 *   |-------------|------------------------------|------------------------------|
 *   | fetch       | on                           | on                           |
 *   | WebSocket   | --experimental-websocket     | on                           |
 *   | EventSource | --experimental-eventsource   | --experimental-eventsource   |
 *
 * So an in-process assertion would skip `WebSocket` entirely on Node 20 and `EventSource`
 * everywhere, i.e. the half of the matrix that is most likely to regress would prove nothing.
 * This file spawns a child process with both flags set, under the built preload, so both classes
 * exist and are exercised identically on every supported Node.
 *
 * Requires `pnpm build` first — it runs against `dist/preload.js` (CI does build → test).
 *
 * Hermetic: the target is an ephemeral loopback port that was bound and immediately closed, so
 * an ALLOWED construction fails at the transport rather than reaching any real network. The
 * distinction the assertions rely on is `BLOCKED` (a `CapabilityError` from capwall's guard,
 * raised before any socket opens) vs `ALLOWED` (anything else).
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(here, "fixtures", "global-egress-app.cjs");
const APP_DIR = path.dirname(APP);
const PRELOAD = createRequire(import.meta.url).resolve("../dist/preload.js");

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function runApp(env: Record<string, string>): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      [
        "--experimental-websocket",
        "--experimental-eventsource",
        "--import",
        pathToFileURL(PRELOAD).href,
        APP,
        `127.0.0.1:${wsPort}`,
        `127.0.0.1:${esPort}`,
      ],
      { cwd: APP_DIR, env: { ...process.env, CAPWALL_PROJECT_ROOT: APP_DIR, ...env } },
      (err, stdout, stderr) => {
        if (err && typeof err.code !== "number") return reject(err);
        resolve({ code: err ? (err.code as number) : 0, stdout, stderr });
      },
    );
  });
}

/** Bind an ephemeral port, then close it immediately — connecting to it afterwards reliably
 * yields ECONNREFUSED without ever leaving the loopback interface. */
function closedLocalPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = addr && typeof addr === "object" ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

let tmpDir: string;
let denyPolicy: string;
let grantPolicy: string;
/** Distinct ports per class, so the preload's per-process decision dedup cannot collapse the
 * WebSocket and EventSource trace lines into one and hide a missing guard. */
let wsPort: number;
let esPort: number;

beforeAll(async () => {
  expect(existsSync(PRELOAD), `built preload not found at ${PRELOAD} — run 'pnpm build' first`).toBe(true);
  wsPort = await closedLocalPort();
  esPort = await closedLocalPort();
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-globals-"));
  denyPolicy = path.join(tmpDir, "deny.json");
  grantPolicy = path.join(tmpDir, "grant.json");
  await writeFile(denyPolicy, JSON.stringify({ version: 1, mode: "enforce", default: {}, packages: {} }));
  await writeFile(
    grantPolicy,
    JSON.stringify({
      version: 1,
      mode: "enforce",
      packages: { "fixture-dep": { net: { hosts: ["127.0.0.1"], ports: [wsPort, esPort] } } },
    }),
  );
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

describe("#80 — WebSocket and EventSource under their experimental flags", () => {
  it("denies both for an ungranted dependency in enforce (deny-by-default)", async () => {
    const r = await runApp({ CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy });
    expect(r.stdout).toContain("WS:BLOCKED");
    expect(r.stdout).toContain("ES:BLOCKED");
    expect(r.stderr).toContain(`DENY 'fixture-dep' net 127.0.0.1:${wsPort}`);
    expect(r.stderr).toContain(`DENY 'fixture-dep' net 127.0.0.1:${esPort}`);
  });

  it("allows both when the dependency is granted that host:port", async () => {
    const r = await runApp({ CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: grantPolicy });
    expect(r.stdout).toContain("WS:ALLOWED");
    expect(r.stdout).toContain("ES:ALLOWED");
    // No `net` denial. (An unrelated `<unknown>` env denial is expected on every CLI run —
    // Node's own ESM loader reads WATCH_REPORT_DEPENDENCIES from a stack with no caller frame,
    // see docs/threat-model.md § attribution outcomes.)
    expect(r.stderr).not.toMatch(/DENY '[^']*' net /);
  });

  it("observe records both and blocks neither", async () => {
    const r = await runApp({ CAPWALL_MODE: "observe" });
    expect(r.stdout).toContain("WS:ALLOWED");
    expect(r.stdout).toContain("ES:ALLOWED");
    expect(r.stderr).toContain(`recorded net 127.0.0.1:${wsPort} for 'fixture-dep'`);
    expect(r.stderr).toContain(`recorded net 127.0.0.1:${esPort} for 'fixture-dep'`);
  });

  it("CAPWALL_GLOBAL_EGRESS=0 turns the guard off entirely", async () => {
    const r = await runApp({
      CAPWALL_MODE: "enforce",
      CAPWALL_POLICY_FILE: denyPolicy,
      CAPWALL_GLOBAL_EGRESS: "0",
    });
    expect(r.stdout).toContain("WS:ALLOWED");
    expect(r.stdout).toContain("ES:ALLOWED");
    expect(r.stderr).not.toMatch(/DENY '[^']*' net /);
  });
});
