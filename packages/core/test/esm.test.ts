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
/** #61 regression entry: a dep that tries to register a loader hook ahead of capwall's. */
const HOOKJACK_APP = path.join(APP_DIR, "hookjack-app.mjs");
/** #62 regression entry: an embedder swapping policy at runtime (installs capwall itself). */
const POLICY_SWAP_APP = path.join(APP_DIR, "policy-swap-app.mjs");
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

describe("#61 — a dependency cannot register a loader hook ahead of capwall's", () => {
  it("refuses module.registerHooks()/register() from a dependency in enforce", async () => {
    const r = await runApp(
      { CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy },
      HOOKJACK_APP,
    );
    // `registerHooks` is Node >=22.15; on an older runtime the API is simply absent, which is
    // not a bypass. `register` (Node >=20.6) is always present, so it always asserts.
    expect(r.stdout).toMatch(/HOOKJACK:registerHooks:(BLOCKED:esm-hookjack-dep|UNSUPPORTED)/);
    expect(r.stdout).toContain("HOOKJACK:register:BLOCKED:esm-hookjack-dep");
    expect(r.stderr).toMatch(/DENY 'esm-hookjack-dep' module\.register/);
  });

  it("keeps an innocent third package's node:fs import mediated", async () => {
    // The point of the finding: hook-jacking de-mediates EVERY package, not just the
    // attacker. esm-victim-dep is an ordinary package doing `import * as fs from "node:fs"`,
    // imported only after the jacking attempt. Pre-fix it read its file through the raw
    // builtin under a deny-all policy, with no capwall log line at all.
    const r = await runApp(
      { CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy },
      HOOKJACK_APP,
    );
    expect(r.stdout).toContain("HOOKJACK:victim:BLOCKED:esm-victim-dep");
    expect(r.stdout).not.toContain("HOOKJACK:victim:RAW");
  });

  it("warns loudly instead of blocking in observe mode (observe never denies)", async () => {
    const r = await runApp({ CAPWALL_MODE: "observe" }, HOOKJACK_APP);
    expect(r.stdout).toContain("HOOKJACK:register:REGISTERED");
    expect(r.stderr).toMatch(/WARN 'esm-hookjack-dep' called module\.register/);
    expect(r.code).toBe(0);
  });

  it("CAPWALL_ALLOW_LOADER_HOOKS=1 permits it, still warning", async () => {
    const r = await runApp(
      {
        CAPWALL_MODE: "enforce",
        CAPWALL_POLICY_FILE: denyPolicy,
        CAPWALL_ALLOW_LOADER_HOOKS: "1",
      },
      HOOKJACK_APP,
    );
    expect(r.stdout).toContain("HOOKJACK:register:REGISTERED");
    expect(r.stderr).toMatch(/WARN 'esm-hookjack-dep' called module\.register.*CAPWALL_ALLOW_LOADER_HOOKS=1/);
  });
});

describe("#62 — a runtime policy swap reaches already-imported ESM specifiers", () => {
  // The subprocess is load-bearing, not incidental: synthetic ESM modules are cached per
  // process and never re-evaluated, so an in-process test would be asserting against whatever
  // policy the FIRST install in the worker happened to leave behind — which is the bug.
  let out: RunResult;

  beforeAll(async () => {
    out = await new Promise<RunResult>((resolve, reject) => {
      execFile(
        process.execPath,
        [POLICY_SWAP_APP],
        { cwd: APP_DIR, env: { ...process.env, CAPWALL_MODE: "", CAPWALL_POLICY_FILE: "" } },
        (err, stdout, stderr) => {
          if (err && typeof err.code !== "number") return reject(err);
          resolve({ code: err ? (err.code as number) : 0, stdout, stderr });
        },
      );
    });
  });

  it("applies a TIGHTER policy installed after the specifier was already imported", () => {
    // The finding: uninstall() + install(tighter) was a silent no-op on the ESM path, because
    // getEsmShim() ran once per synthetic module and its result was captured in const bindings.
    expect(out.stdout).toContain("SWAP:loose:OK:esm fixture data");
    expect(out.stdout).toContain("SWAP:strict:CapabilityError:esm-fixture-dep");
  });

  it("fails closed after uninstall() with no reinstall", () => {
    // docs/threat-model.md claimed this already held; it held only for NEVER-imported
    // specifiers. Both cases are now covered, by different mechanisms.
    expect(out.stdout).toContain("SWAP:uninstalled:CapabilityError:esm-fixture-dep");
    expect(out.stdout).toContain("SWAP:never-imported:FAILS_CLOSED");
  });

  it("is a live policy, not a one-way ratchet — loosening applies too", () => {
    expect(out.stdout).toContain("SWAP:reloose:OK:esm fixture data");
    expect(out.code).toBe(0);
  });
});
