/**
 * Regression tests for issue #60 — attribution used to fail OPEN onto the `<app>` sentinel.
 *
 * The walk discarded every frame with no filesystem path and then `return APP_ROOT`, so
 * "capwall could not work out whose code this is" and "this is the application" were the same
 * value — and `<app>` is exempt from gating in the `process.env` shim and the `dgram` guard.
 * A dependency could reach that state with ordinary ESM: run its payload from a `data:` URL
 * module (no path on any frame) and detach one tick through a timer (V8's async stack traces
 * keep the dependency on the stack if it `await`s straight through, so the detachment is
 * essential to reproduce). It then read any `process.env` key and sent UDP, with no log line
 * at all. `eval`, `new Function`, and handing a native function to `setTimeout` reached the
 * same state without `data:` URLs.
 *
 * These run the built `dist/preload.js` in a subprocess (`pnpm build` first — CI does build →
 * test), because the vectors depend on real ESM loading and real timer detachment.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const APP_DIR = path.join(here, "fixtures", "launder");
const APP = path.join(APP_DIR, "app.mjs");
const PRELOAD = createRequire(import.meta.url).resolve("../dist/preload.js");
const SECRET_VALUE = "fixture-placeholder-not-a-real-secret";

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Run one fixture vector under the built preload with `policyFile` in enforce mode. */
function runVector(vector: string, policyFile: string): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      [`--import=${pathToFileURL(PRELOAD).href}`, APP, vector],
      {
        cwd: APP_DIR,
        env: {
          ...process.env,
          CAPWALL_MODE: "enforce",
          CAPWALL_POLICY_FILE: policyFile,
          CAPWALL_PROJECT_ROOT: APP_DIR,
          LAUNDER_FIXTURE_SECRET: SECRET_VALUE,
        },
      },
      (err, stdout, stderr) => {
        if (err && typeof err.code !== "number") return reject(err);
        resolve({ code: err ? (err.code as number) : 0, stdout, stderr });
      },
    );
  });
}

let tmpDir: string;
/** Grants nothing at all — every principal is deny-by-default. */
let denyAll: string;
/** Grants the APP broad env + net, the normal shape of a real policy (the app is trusted). */
let grantApp: string;

beforeAll(async () => {
  expect(
    existsSync(PRELOAD),
    `built preload not found at ${PRELOAD} — run 'pnpm build' before 'pnpm test'`,
  ).toBe(true);
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-launder-"));
  denyAll = path.join(tmpDir, "deny.json");
  grantApp = path.join(tmpDir, "grant-app.json");
  await writeFile(
    denyAll,
    JSON.stringify({ version: 1, mode: "enforce", default: {}, packages: {} }),
  );
  await writeFile(
    grantApp,
    JSON.stringify({
      version: 1,
      mode: "enforce",
      default: {},
      packages: {
        "<app>": { env: ["*"], net: { hosts: ["127.0.0.1"], ports: [9] } },
      },
    }),
  );
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

/**
 * Every vector a dependency can use to run its capability calls from frames with no
 * filesystem path. All of them used to be charged to `<app>`; none may be now.
 *
 * `expectedPkg` is what the denial must NAME: the vectors where V8 still tells us where the
 * code was compiled (`eval`, `new Function`) or still has the dependency's own frame on the
 * stack (the non-detached `data:` import) are charged to the dependency BY NAME; the rest are
 * `<unknown>`, which is a principal like any other — evaluated, recorded, deny-by-default.
 */
const VECTORS: Array<{ vector: string; expectedPkg: string }> = [
  { vector: "data-detached", expectedPkg: "<unknown>" },
  { vector: "data-direct", expectedPkg: "launder-dep" },
  { vector: "eval-detached", expectedPkg: "launder-dep" },
  { vector: "function-detached", expectedPkg: "launder-dep" },
  { vector: "native-detached", expectedPkg: "<unknown>" },
];

describe("#60 — a dependency cannot launder capability calls onto the <app> sentinel", () => {
  for (const { vector, expectedPkg } of VECTORS) {
    it(`gates the env read for the '${vector}' vector and names '${expectedPkg}'`, async () => {
      const r = await runVector(vector, denyAll);
      // Soft deny: the value is hidden, the dependency is not crashed.
      expect(r.stdout).toContain("env=undefined");
      expect(r.stdout).not.toContain(SECRET_VALUE);
      // "with no log line at all" was half the finding — the denial must be recorded.
      expect(r.stderr).toContain(`DENY '${expectedPkg}' env:LAUNDER_FIXTURE_SECRET`);
    });

    it(`denies the UDP send for the '${vector}' vector`, async () => {
      const r = await runVector(vector, denyAll);
      expect(r.stderr).toContain(`DENY '${expectedPkg}' net 127.0.0.1:9`);
      // The datagram must not go out. A denial inside a detached tick surfaces as an
      // uncaught CapabilityError (nonzero exit), never as `udp=SENT`.
      expect(r.stdout).not.toContain("udp=SENT");
    });
  }

  it("still denies the same operations even when the policy grants the app broadly", async () => {
    // The realistic deployment: `<app>` holds broad grants because it is the trust root. This
    // is the case the fail-open was worth the most in — the laundered call inherited them.
    const r = await runVector("data-detached", grantApp);
    expect(r.stdout).toContain("env=undefined");
    expect(r.stdout).not.toContain(SECRET_VALUE);
    expect(r.stdout).not.toContain("udp=SENT");
    expect(r.stderr).toContain("DENY '<unknown>' env:LAUNDER_FIXTURE_SECRET");
  });

  it("gates a laundered module.register(), closing the #74 ESM-perimeter gate too", async () => {
    // `shims/module.ts` allows `<app>` for the same reason env and dgram do, and its own
    // header documented that it therefore inherited this bug. Fixing attribution fixes it:
    // the registration attributes to `<unknown>`, which is not the trust root. Worth its own
    // case because a registered loader hook runs AHEAD of capwall's and can un-mediate imports
    // for every package — the widest consequence of the three gates.
    const r = await runVector("register-detached", denyAll);
    expect(r.stdout).toContain("register=BLOCKED:<unknown>");
    expect(r.stdout).not.toContain("register=REGISTERED");
    expect(r.stderr).toContain("DENY '<unknown>' module.register()");
  });

  it("charges the dependency by name when it calls directly (unchanged behavior)", async () => {
    const r = await runVector("dep-direct", denyAll);
    expect(r.stdout).toContain("env=undefined");
    expect(r.stderr).toContain("DENY 'launder-dep' env:LAUNDER_FIXTURE_SECRET");
    expect(r.stderr).toContain("DENY 'launder-dep' net 127.0.0.1:9");
  });
});

describe("#60 — ordinary application code is unaffected", () => {
  for (const vector of ["app-direct", "app-detached"]) {
    it(`'${vector}' still attributes to <app> and passes through ungated`, async () => {
      // `<app>` is exempt from the env and dgram gates by design (the app is the trust root),
      // so under a policy that grants NOTHING the app still reads its own environment and
      // sends its own datagram. That exemption is exactly what must not leak to `<unknown>`.
      const r = await runVector(vector, denyAll);
      expect(r.stdout).toContain(`env=${SECRET_VALUE}`);
      expect(r.stdout).toContain("udp=SENT");
      expect(r.stdout).toContain("done");
      expect(r.stderr).not.toContain("DENY '<unknown>' env:LAUNDER_FIXTURE_SECRET");
      expect(r.stderr).not.toContain("DENY '<app>'");
      expect(r.code).toBe(0);
    });
  }
});
