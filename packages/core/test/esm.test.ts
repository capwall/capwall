/**
 * ESM loader-hook end-to-end tests (roadmap M5). Spawns `node --import <preload> app.mjs` on
 * a vendored ESM app whose dependency (`esm-fixture-dep`) does a STATIC `import` of `node:fs`.
 * A subprocess per case gives a clean module graph (ESM synthetic modules are cached per
 * process, so in-process policy switching wouldn't isolate). Requires `pnpm build` first —
 * it runs against the built `dist/preload.js` (CI does build → test).
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import * as nodeModule from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MEDIATED_MODULES } from "../src/loader/require.js";
import {
  assertPreloadBuilt,
  PRELOAD_IMPORT_FLAG,
  runNode,
  type NodeRunResult,
} from "./helpers/subprocess.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(here, "fixtures", "esm", "app.mjs");
const APP_DIR = path.dirname(APP);
/** #59 regression entry: a dep that reaches builtins via its own subpath-imports map. */
const LAUNDER_APP = path.join(APP_DIR, "launder-app.mjs");
/** #61 regression entry: a dep that tries to register a loader hook ahead of capwall's. */
const HOOKJACK_APP = path.join(APP_DIR, "hookjack-app.mjs");
/** #62 regression entry: an embedder swapping policy at runtime (installs capwall itself). */
const POLICY_SWAP_APP = path.join(APP_DIR, "policy-swap-app.mjs");
/** #78 regression entry: a loader hook ahead of capwall's, caught by the load()-level backstop. */
const BACKSTOP_APP = path.join(APP_DIR, "backstop-app.mjs");

/**
 * `module.registerHooks()` is Node ≥22.15 — absent on the Node 20 leg of the CI matrix.
 *
 * Evaluated ONCE here, at module scope, so the two tests that depend on it can `skipIf` (which
 * the reporter shows) instead of accepting an `UNSUPPORTED` alternative in an assertion or
 * returning silently mid-body (which it does not). #112 found both shapes here: an
 * `expect(...).toMatch(/…|UNSUPPORTED/)` that the Node-20 leg satisfied without ever testing
 * the gate, and a `if (…UNSUPPORTED) return;` that made a whole test a no-op there.
 */
// Read off the namespace rather than imported by name: `@types/node` is pinned at v20 here, so
// `registerHooks` is not in the declarations even on a runtime that has it.
const HAS_REGISTER_HOOKS =
  typeof (nodeModule as { registerHooks?: unknown }).registerHooks === "function";

/** Identical (entry, env) pairs run once and are shared — see test/helpers/subprocess.ts (#145). */
function runApp(env: Record<string, string>, entry: string = APP): Promise<NodeRunResult> {
  return runNode([entry], {
    // Sound to share: the vendored ESM fixture is committed and both policy files are written
    // once in `beforeAll`; nothing here rewrites an input between two identical calls.
    share: true,
    cwd: APP_DIR,
    env: { NODE_OPTIONS: PRELOAD_IMPORT_FLAG, CAPWALL_PROJECT_ROOT: APP_DIR, ...env },
  });
}

let tmpDir: string;
let denyPolicy: string;
let grantPolicy: string;

beforeAll(async () => {
  assertPreloadBuilt();
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
  //
  // `self-fs` (a module reached through the package's own `exports` map by package name, which
  // re-exports `#bare-fs`), `data-fs` (a `data:` URL module re-exporting the builtin — no
  // filesystem parent, and the route #60 showed defeats attribution if it is not handled) and
  // `meta-fs` (`import.meta.resolve` to a `node:` URL, then importing that string) are the same
  // finding reached three other ways.
  const ROUTES = ["bare-fs", "cond-fs", "pat-fs", "self-fs", "data-fs", "meta-fs"] as const;

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

  it("denies the subpath-imports routes to child_process and fs/promises too", async () => {
    // `fs/promises` is a separate registry key with its own shim surface and its own denial
    // channel (a rejected promise, not a synchronous throw), so it is its own route rather than
    // a spelling of `fs`.
    const r = await runApp(
      { CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy },
      LAUNDER_APP,
    );
    expect(r.stdout).toContain("LAUNDER:bare-cp:BLOCKED:esm-launder-dep");
    expect(r.stdout).toContain("LAUNDER:bare-fsp:BLOCKED:esm-launder-dep");
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
    //
    // The expected string is DERIVED from the runtime rather than offered as an alternation:
    // `/…(BLOCKED:esm-hookjack-dep|UNSUPPORTED)/` let the Node-20 leg pass on the un-guarded
    // outcome, so the `registerHooks` gate had no coverage there and would not have had any if
    // it were deleted on 22 either — the alternation accepted both (#112).
    expect(r.stdout).toContain(
      HAS_REGISTER_HOOKS
        ? "HOOKJACK:registerHooks:BLOCKED:esm-hookjack-dep"
        : "HOOKJACK:registerHooks:UNSUPPORTED",
    );
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

describe("#78 — the load()-level re-mediation backstop actually fires", () => {
  /**
   * Every builtin capwall mediates. The point of the suite is that the backstop covers the WHOLE
   * set: it is only reachable for a specifier whose `node:` URL is absent from the ESM module
   * cache, and capwall's own bootstrap is the only thing that could have put one there.
   */
  const MEDIATED = [
    "fs",
    "fs/promises",
    "net",
    "http",
    "https",
    "tls",
    "http2",
    "dgram",
    "child_process",
    "worker_threads",
    "vm",
    "module",
  ] as const;

  let out: NodeRunResult;

  beforeAll(async () => {
    out = await runApp(
      { CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy },
      BACKSTOP_APP,
    );
  });

  it("covers the whole mediated set — the list above is not allowed to drift", () => {
    // A capability added to MEDIATED_MODULES but not here would leave the new specifier's backstop
    // unexercised, and the suite would still be green. `esm-backstop-dep` carries the same list;
    // it is a fixture, so it cannot import from src.
    const distinct = [
      ...new Set(MEDIATED_MODULES.map((m) => m.replace(/^node:/, ""))),
    ].sort();
    expect([...MEDIATED].sort()).toEqual(distinct);
  });

  it("re-mediates every mediated builtin a foreign hook resolved straight to the raw URL", () => {
    // The app registers a loader hook that short-circuits `raw:<builtin>` to `node:<builtin>` with
    // `shortCircuit: true, format: "builtin"` — the strongest form. Node runs the newest hook
    // first, so capwall's `resolve` is never consulted for any of these; only `load` is left.
    //
    // Pre-#78 this returned RAW for every specifier capwall's own shims had ESM-imported (which
    // was all of them): a `node:` URL already in the ESM cache is served from cache and the load
    // chain is never consulted at all. Measured both ways — re-adding a single
    // `import "node:fs"` to `preload.ts` flips the `fs` row below back to RAW.
    for (const spec of MEDIATED) {
      expect(out.stdout, `${spec} reached the raw builtin`).toContain(`BACKSTOP:${spec}:SHIM`);
    }
    // Covers the `enforce-fs:RAW:<contents>` line too, which is what a bypass actually looks like.
    expect(out.stdout).not.toMatch(/BACKSTOP:[a-z_/-]+:RAW\b/);
  });

  it("says so on stderr — once per specifier, because reaching here is never normal", () => {
    // capwall's only in-band signal that something is ahead of it in the hook chain. This is also
    // the version-independent half of the proof: it does not depend on
    // `process.getBuiltinModule`, which the fixture uses to tell shim from raw.
    for (const spec of MEDIATED) {
      expect(out.stderr, `no re-mediation warning for node:${spec}`).toContain(
        `WARN another module-customization hook resolved 'node:${spec}' straight to the raw builtin`,
      );
    }
  });

  it.skipIf(!HAS_REGISTER_HOOKS)("holds against the SYNCHRONOUS registerHooks chain too, which runs ahead of capwall's", async () => {
    // `module.registerHooks()` (Node ≥22.15) is the strictly stronger position: its resolve chain
    // runs entirely ahead of the asynchronous `register` chain capwall lives in. The asynchronous
    // LOAD chain still descends to capwall, which is what makes the backstop reach this case —
    // asserted rather than assumed, since it is the case the backstop most needs to cover.
    // Absent on Node 20, where the API simply does not exist; that is not a bypass.
    const r = await runApp(
      {
        CAPWALL_MODE: "enforce",
        CAPWALL_POLICY_FILE: denyPolicy,
        BACKSTOP_SYNC_HOOK: "1",
      },
      BACKSTOP_APP,
    );
    // The runtime-level skip is `skipIf(!HAS_REGISTER_HOOKS)` above, which the reporter shows.
    // This pins that the CHILD agrees with the parent's view — a silent `return` here used to
    // turn the whole test into a green no-op on Node 20 (#112).
    expect(r.stdout).not.toContain("BACKSTOP:UNSUPPORTED");
    for (const spec of MEDIATED) {
      expect(r.stdout, `${spec} reached the raw builtin via the sync chain`).toContain(
        `BACKSTOP:${spec}:SHIM`,
      );
    }
    expect(r.stdout).toContain("BACKSTOP:enforce-fs:BLOCKED:esm-backstop-dep");
  });

  it("re-mediates into a shim that ENFORCES, not merely one that is not the builtin", () => {
    // Identity is necessary but not sufficient. Under the deny-all policy the re-mediated `fs`
    // must actually deny, attributed to the importing package — and the re-mediated `node:module`
    // must still carry #61's loader-hook gate, which is the one shim that is a Proxy over a class
    // rather than a plain namespace.
    expect(out.stdout).toContain("BACKSTOP:enforce-fs:BLOCKED:esm-backstop-dep");
    expect(out.stdout).toContain("BACKSTOP:enforce-module:BLOCKED:esm-backstop-dep");
    expect(out.stderr).toMatch(/DENY 'esm-backstop-dep' fs:read/);
  });
});

describe("#62 — a runtime policy swap reaches already-imported ESM specifiers", () => {
  // The subprocess is load-bearing, not incidental: synthetic ESM modules are cached per
  // process and never re-evaluated, so an in-process test would be asserting against whatever
  // policy the FIRST install in the worker happened to leave behind — which is the bug.
  let out: NodeRunResult;

  beforeAll(async () => {
    out = await runNode([POLICY_SWAP_APP], {
      cwd: APP_DIR,
      env: { CAPWALL_MODE: "", CAPWALL_POLICY_FILE: "" },
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
