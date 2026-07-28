/**
 * FLAG-ONLY global egress classes (#80): `WebSocket` and `EventSource`.
 *
 * Node's global egress surface is not uniform across the CI matrix:
 *
 *   | global      | Node 22 / 24 / 26            |
 *   |-------------|------------------------------|
 *   | fetch       | on                           |
 *   | WebSocket   | on (unflagged since 22.4)    |
 *   | EventSource | --experimental-eventsource   |
 *
 * Dropping Node 20 removed the `WebSocket` asymmetry — it is now on by default everywhere, so
 * the in-process suites cover it. `EventSource` is the one that did NOT get better: it is still
 * flag-only on 22, 24 AND 26, so an in-process assertion would prove nothing about it on any
 * supported runtime. This file remains the only place it is exercised — it spawns a child with
 * both flags set, under the built preload, so both classes exist and are covered identically on
 * every supported Node. Do not delete it because `WebSocket` no longer needs it.
 *
 * Requires `pnpm build` first — it runs against `dist/preload.js` (CI does build → test).
 *
 * Hermetic: the target is an ephemeral loopback port that was bound and immediately closed, so
 * an ALLOWED construction fails at the transport rather than reaching any real network. The
 * distinction the assertions rely on is `BLOCKED` (a `CapabilityError` from capwall's guard,
 * raised before any socket opens) vs `ALLOWED` (anything else).
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  assertPreloadBuilt,
  PRELOAD_IMPORT_FLAG,
  runNode,
  type NodeRunResult,
} from "./helpers/subprocess.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(here, "fixtures", "global-egress-app.cjs");
const APP_DIR = path.dirname(APP);

/**
 * Every case here is one run of the same app under a different environment, so the (env → run)
 * mapping is total: `runNode` runs each distinct environment once and shares it (#145). The
 * hardened-vs-plain comparison at the bottom re-states four environments the four cases above it
 * already ran, and now costs nothing extra rather than four more ~0.5 s processes.
 */
function runApp(env: Record<string, string>): Promise<NodeRunResult> {
  return runNode(
    [
      "--experimental-websocket",
      "--experimental-eventsource",
      PRELOAD_IMPORT_FLAG,
      APP,
      `127.0.0.1:${wsPort}`,
      `127.0.0.1:${esPort}`,
    ],
    // Sound to share: both policy files are written once in `beforeAll` and never rewritten,
    // so the environment is the only input that varies.
    { share: true, cwd: APP_DIR, env: { CAPWALL_PROJECT_ROOT: APP_DIR, ...env } },
  );
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
  assertPreloadBuilt();
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
    // No `net` denial. (There used to be an unrelated `<unknown>` env denial on every run, from
    // Node's own ESM loader reading WATCH_REPORT_DEPENDENCIES on a stack with no caller frame;
    // since #119 a read Node initiated is not recorded. See docs/threat-model.md § residuals.)
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

/**
 * HARDENED × the flag-only globals — the cell `hardened-allowed.test.ts` cannot reach (#112).
 *
 * `hardened-allowed.test.ts` is the "#90 blind spot 2" matrix: for every guarded surface, a
 * GRANTED call still works and an UNGRANTED one is still denied, with `hardened: true`. Its
 * `EventSource` row is gated on `hasGlobal("EventSource")` and therefore skips on Node 22, 24
 * AND 26 — vitest is never handed `--experimental-eventsource` — so that row proves nothing on
 * any supported runtime, and this file's four original cases never set `CAPWALL_HARDENED`.
 * The `WebSocket` row had the same hole on the Node 20 leg; that half closed when 20 was
 * dropped, and the `EventSource` half did not.
 *
 * The gap matters because hardening genuinely touches this guard: `hardenClass` freezes the
 * guarded subclass and its prototype, and `pinGlobalEgress` re-pins the installed global with
 * `writable: false` (`shims/global-egress.ts`). #86 was precisely a hardened pin colliding with
 * a guard's own `defineProperty` and breaking ALLOWED operations — so "granted still works
 * under hardening" is the assertion that has to exist somewhere, and this is the only place it
 * can run for these two classes.
 *
 * The subprocess already has both flags, so both classes exist on every supported Node.
 */
describe("#80 × #17 — WebSocket and EventSource under hardened mode (#112)", () => {
  it("still denies an ungranted dependency with CAPWALL_HARDENED=1", async () => {
    const r = await runApp({
      CAPWALL_MODE: "enforce",
      CAPWALL_POLICY_FILE: denyPolicy,
      CAPWALL_HARDENED: "1",
    });
    expect(r.stdout).toContain("WS:BLOCKED");
    expect(r.stdout).toContain("ES:BLOCKED");
    expect(r.stderr).toContain(`DENY 'fixture-dep' net 127.0.0.1:${wsPort}`);
    expect(r.stderr).toContain(`DENY 'fixture-dep' net 127.0.0.1:${esPort}`);
  });

  it("still lets a GRANTED dependency through with CAPWALL_HARDENED=1 (the #86 shape)", async () => {
    const r = await runApp({
      CAPWALL_MODE: "enforce",
      CAPWALL_POLICY_FILE: grantPolicy,
      CAPWALL_HARDENED: "1",
    });
    // The load-bearing half: a frozen guarded class / pinned global must not turn an ALLOWED
    // construction into a TypeError. `label()` in the fixture app reports anything that is not
    // a CapabilityError as ALLOWED, so the FATAL check below is what catches a throw from
    // Node's own machinery rather than from the guard.
    expect(r.stdout).not.toContain("FATAL:");
    expect(r.stdout).toContain("WS:ALLOWED");
    expect(r.stdout).toContain("ES:ALLOWED");
    expect(r.stderr).not.toMatch(/DENY '[^']*' net /);
    expect(r.code).toBe(0);
  });

  it("hardening does not change WHICH calls are refused (deny/grant, on vs off)", async () => {
    // Stated as one comparison so any difference is attributable to hardening and not to the
    // policy — the same shape `hardened-allowed.test.ts` uses for the in-process surfaces.
    const outcomes: Record<string, string> = {};
    for (const hardened of [false, true]) {
      for (const [label, policyFile] of [
        ["granted", grantPolicy],
        ["denied", denyPolicy],
      ] as const) {
        const env: Record<string, string> = {
          CAPWALL_MODE: "enforce",
          CAPWALL_POLICY_FILE: policyFile,
        };
        if (hardened) env["CAPWALL_HARDENED"] = "1";
        const r = await runApp(env);
        const ws = /WS:(BLOCKED|ALLOWED)/.exec(r.stdout)?.[1] ?? `missing(${r.stdout.trim()})`;
        const es = /ES:(BLOCKED|ALLOWED)/.exec(r.stdout)?.[1] ?? `missing(${r.stdout.trim()})`;
        outcomes[`${label}/${hardened ? "hardened" : "plain"}`] = `WS=${ws} ES=${es}`;
      }
    }
    expect(outcomes).toEqual({
      "granted/plain": "WS=ALLOWED ES=ALLOWED",
      "granted/hardened": "WS=ALLOWED ES=ALLOWED",
      "denied/plain": "WS=BLOCKED ES=BLOCKED",
      "denied/hardened": "WS=BLOCKED ES=BLOCKED",
    });
  });
});
