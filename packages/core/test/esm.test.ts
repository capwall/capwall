/**
 * ESM loader-hook end-to-end tests (roadmap M5). Spawns `node --import <preload> app.mjs` on
 * a vendored ESM app whose dependency (`esm-fixture-dep`) does a STATIC `import` of `node:fs`.
 * A subprocess per case gives a clean module graph (ESM synthetic modules are cached per
 * process, so in-process policy switching wouldn't isolate). Requires `pnpm build` first —
 * it runs against the built `dist/preload.js` (CI does build → test).
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
const APP = path.join(here, "fixtures", "esm", "app.mjs");
const APP_DIR = path.dirname(APP);
/** #59 regression entry: a dep that reaches builtins via its own subpath-imports map. */
const LAUNDER_APP = path.join(APP_DIR, "launder-app.mjs");
const PRELOAD = createRequire(import.meta.url).resolve("../dist/preload.js");

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function runApp(env: Record<string, string>, entry: string = APP): Promise<RunResult> {
  const nodeOptions = `--import ${pathToFileURL(PRELOAD).href}`;
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      [entry],
      {
        cwd: APP_DIR,
        env: { ...process.env, NODE_OPTIONS: nodeOptions, CAPWALL_PROJECT_ROOT: APP_DIR, ...env },
      },
      (err, stdout, stderr) => {
        if (err && typeof err.code !== "number") return reject(err);
        resolve({ code: err ? (err.code as number) : 0, stdout, stderr });
      },
    );
  });
}

let tmpDir: string;
let denyPolicy: string;
let grantPolicy: string;

beforeAll(async () => {
  expect(existsSync(PRELOAD), `built preload not found at ${PRELOAD} — run 'pnpm build' first`).toBe(true);
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-esm-"));
  denyPolicy = path.join(tmpDir, "deny.json");
  grantPolicy = path.join(tmpDir, "grant.json");
  await writeFile(denyPolicy, JSON.stringify({ version: 1, mode: "enforce", default: {}, packages: {} }));
  await writeFile(
    grantPolicy,
    JSON.stringify({
      version: 1,
      mode: "enforce",
      packages: { "esm-fixture-dep": { fs: { read: ["./node_modules/esm-fixture-dep/**"], write: [] } } },
    }),
  );
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

describe("M5 ESM loader hook — static import of node:fs is mediated", () => {
  it("denies an ungranted ESM dependency's fs read in enforce (deny-by-default)", async () => {
    const r = await runApp({ CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy });
    expect(r.stdout).toContain("BLOCKED:esm-fixture-dep");
    expect(r.stderr).toMatch(/DENY 'esm-fixture-dep' fs:read/);
    expect(r.code).toBe(1);
  });

  it("allows the ESM dependency's fs read when granted", async () => {
    const r = await runApp({ CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: grantPolicy });
    expect(r.stdout).toContain("READ_OK:esm fixture data");
    expect(r.code).toBe(0);
  });

  it("observe mode never blocks the ESM dependency, but records the attributed read", async () => {
    const trace = path.join(tmpDir, "trace.jsonl");
    const r = await runApp({ CAPWALL_MODE: "observe", CAPWALL_TRACE_FILE: trace });
    expect(r.stdout).toContain("READ_OK:esm fixture data");
    expect(r.code).toBe(0);
    expect(r.stderr).toMatch(/observe: recorded fs:read .* for 'esm-fixture-dep'/);
  });

  it("CAPWALL_ESM=0 disables ESM mediation (the import reaches the real builtin)", async () => {
    // With ESM off, the dep's node:fs import is NOT shimmed, so a deny-all policy does not
    // block it — the read succeeds. (Proves the toggle works; CJS remains mediated regardless.)
    const r = await runApp({ CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy, CAPWALL_ESM: "0" });
    expect(r.stdout).toContain("READ_OK:esm fixture data");
    expect(r.code).toBe(0);
  });
});

describe("#59 — a specifier that RESOLVES to a mediated builtin is mediated, however spelled", () => {
  // esm-launder-dep never writes `fs` or `child_process` as a specifier: it maps private
  // `#…` specifiers onto the bare builtin names in its OWN package.json `imports` field
  // (plain, documented Node metadata — bare targets work, `"node:fs"` targets are rejected by
  // Node). Against the pre-fix hook, which classified on the specifier STRING, every route
  // below reached the raw builtin and produced no capwall log line at all.
  const ROUTES = ["bare-fs", "cond-fs", "pat-fs"] as const;

  it("denies every subpath-imports route to fs under a deny-all policy", async () => {
    const r = await runApp(
      { CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy },
      LAUNDER_APP,
    );
    for (const route of ROUTES) {
      expect(r.stdout, `route ${route} reached the raw builtin`).toContain(
        `LAUNDER:${route}:BLOCKED:esm-launder-dep`,
      );
    }
    expect(r.stdout).not.toMatch(/LAUNDER:[a-z-]+:RAW/);
  });

  it("denies the subpath-imports route to child_process too", async () => {
    const r = await runApp(
      { CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy },
      LAUNDER_APP,
    );
    expect(r.stdout).toContain("LAUNDER:bare-cp:BLOCKED:esm-launder-dep");
  });

  it("records the laundered read in observe mode, attributed to the laundering package", async () => {
    // The pre-fix bypass was SILENT — invisible to `observe` and therefore to `capwall diff`.
    // Attribution must survive the indirection, so the trace names esm-launder-dep.
    const r = await runApp({ CAPWALL_MODE: "observe" }, LAUNDER_APP);
    expect(r.stdout).toContain("LAUNDER:bare-fs:RAW:esm launder data");
    expect(r.stderr).toMatch(/observe: recorded fs:read .* for 'esm-launder-dep'/);
    expect(r.stderr).toMatch(/observe: recorded child_process for 'esm-launder-dep'/);
  });
});
