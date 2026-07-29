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
 * `module.registerHooks()` is Node ≥22.15, and the supported floor is now exactly that — so this
 * is TRUE ON EVERY RUNTIME IN THE MATRIX and the two tests it gated run unconditionally. It was
 * a `skipIf` predicate for the Node 20 leg; #112 had previously found two worse shapes here (an
 * `expect(...).toMatch(/…|UNSUPPORTED/)` that Node 20 satisfied without testing the gate, and an
 * `if (…UNSUPPORTED) return;` that made a whole test a no-op there).
 *
 * It is kept as an ASSERTED PRECONDITION rather than deleted outright. The API's presence is a
 * load-bearing premise of the synchronous-chain backstop test below — that test is only
 * meaningful if the sync chain actually exists — so it is asserted once, loudly, instead of
 * being assumed by a test whose failure would read as a backstop regression.
 *
 * Read off the namespace rather than imported by name so this stays a RUNTIME check: the point
 * is what the running Node has, not what the types promise.
 */
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

/**
 * Every route the hookjack fixture walks to `register`/`registerHooks`. The list is the finding
 * in #181: the gate used to be a wrapper on two KEYS of the `node:module` shim, and four of these
 * five reach the same two functions without going through those keys. Asserted as a SWEEP rather
 * than as "and also the `Module` one", because a denylist of key names is exactly what #181 says
 * is not a gate — a future Node alias, or a sixth route, has to fail here.
 */
const HOOKJACK_ROUTES = [
  "named-export",
  "Module-class",
  "require-Module",
  "module-constructor",
  "getBuiltinModule",
] as const;

describe("#61 — a dependency cannot register a loader hook ahead of capwall's", () => {
  it("refuses module.registerHooks()/register() from a dependency in enforce", async () => {
    const r = await runApp(
      { CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy },
      HOOKJACK_APP,
    );
    // BOTH registration APIs are gated, and both assertions are now unconditional. This used to
    // derive the expected string from the runtime, because `registerHooks` (Node ≥22.15) did not
    // exist on the Node 20 leg — one step better than the `/…(BLOCKED:…|UNSUPPORTED)/` alternation
    // #112 deleted, which accepted the UN-guarded outcome on every version, but still a branch
    // that only ever asserted the gate on part of the matrix.
    //
    // With the floor at ≥22.15 there is no arm to choose: `UNSUPPORTED` coming back from the
    // fixture is now a FAILURE, not a runtime fact, which is exactly the state you want the
    // #61 gate's regression test in.
    expect(r.stdout).toContain("HOOKJACK:named-export:registerHooks:BLOCKED:esm-hookjack-dep");
    expect(r.stdout).not.toContain("HOOKJACK:named-export:registerHooks:UNSUPPORTED");
    expect(r.stdout).toContain("HOOKJACK:named-export:register:BLOCKED:esm-hookjack-dep");
    expect(r.stderr).toMatch(/DENY 'esm-hookjack-dep' module\.register/);
  });

  it("#181 — refuses it by EVERY route to the functions, not just the named export", async () => {
    // The gate's whole value was one un-shimmed own key away: `import { Module, registerHooks }
    // from "node:module"` refused the second identifier and handed back the first, in the same
    // statement, and `module.constructor` gave every CJS file the same class with no `require`.
    // Since #181 the gate is on the two function objects, so which route was used is not part of
    // the mechanism — which is what this sweep asserts, one row per route per API.
    const r = await runApp(
      { CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy },
      HOOKJACK_APP,
    );
    for (const route of HOOKJACK_ROUTES) {
      for (const api of ["registerHooks", "register"]) {
        expect(r.stdout, `${route}:${api} reached the registration API ungated`).toContain(
          `HOOKJACK:${route}:${api}:BLOCKED:esm-hookjack-dep`,
        );
      }
    }
    // No route may report UNSUPPORTED / UNREACHABLE: that would be a fixture that failed to
    // acquire the function, which passes the sweep above without testing anything — the exact
    // hollow shape #112 found six of.
    expect(r.stdout).not.toMatch(/HOOKJACK:[^\n]*:(UNSUPPORTED|UNREACHABLE)/);
  });

  it("#181 — and `process.getBuiltinModule` no longer walks past it either", async () => {
    // Called out separately because `docs/threat-model.md` named this one as the residual that
    // "defeats this gate exactly as it defeats every other shim". It does not any more: the gate
    // is a patch on the real function, and `getBuiltinModule` returns the real module. That is
    // the same thing #93's prototype patch bought for `_compile`, one level up.
    const r = await runApp(
      { CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy },
      HOOKJACK_APP,
    );
    expect(r.stdout).toContain("HOOKJACK:getBuiltinModule:registerHooks:BLOCKED:esm-hookjack-dep");
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
    expect(r.stdout).toContain("HOOKJACK:named-export:register:REGISTERED");
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
    expect(r.stdout).toContain("HOOKJACK:named-export:register:REGISTERED");
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

  it("mediates every mediated builtin a foreign hook resolved straight to the raw URL", () => {
    // The app registers a loader hook that short-circuits `raw:<builtin>` to `node:<builtin>` with
    // `shortCircuit: true, format: "builtin"` — the strongest form.
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

  it("beats an ASYNCHRONOUS module.register() hook at RESOLVE now, without needing the backstop", () => {
    // CHANGED BY #152, and it is a strengthening rather than an adaptation. This arm of the
    // fixture registers the hostile short-circuit through `module.register()`. While capwall was
    // ITSELF in that asynchronous chain, "the most recently registered hook runs first" meant the
    // app's hook got ahead of capwall's `resolve` and only the `load` backstop was left — so this
    // test asserted a re-mediation WARNING for all twelve specifiers.
    //
    // capwall now lives in the SYNCHRONOUS `registerHooks` chain, which Node runs entirely ahead
    // of the asynchronous one (measured on 22/24/26). capwall's `resolve` therefore runs FIRST,
    // calls `nextResolve` — which descends into the async chain and comes back with
    // `node:<builtin>` — and classifies on that resolved URL (#59's rule), so the specifier is
    // mediated one layer earlier and the backstop is never reached. The row above still asserts
    // every specifier comes back as the shim; this one asserts capwall did not have to fall back
    // to do it.
    expect(out.stderr).not.toContain("WARN another module-customization hook resolved");
  });

  it("holds against the SYNCHRONOUS registerHooks chain, which does run ahead of capwall's", async () => {
    // The attacker position that is still stronger than capwall's: a `registerHooks` hook
    // registered AFTER capwall's is newer, so Node runs it first, and capwall's `resolve` never
    // sees these specifiers. This is now the ONLY route to the `load`-level backstop, which makes
    // this test the whole of #78's proof rather than half of it.
    //
    // This used to `skipIf(!HAS_REGISTER_HOOKS)` for the Node 20 leg. With the floor at ≥22.15
    // the API is present everywhere, so the strongest laundering case in this file now runs on
    // EVERY leg of the matrix instead of all-but-one. The premise is asserted rather than
    // dropped: if a runtime ever lacks the API, this fails as a missing precondition rather than
    // as a phantom backstop regression.
    expect(
      HAS_REGISTER_HOOKS,
      "module.registerHooks() is required by the supported floor (Node >=22.15) — see engines",
    ).toBe(true);
    const r = await runApp(
      {
        CAPWALL_MODE: "enforce",
        CAPWALL_POLICY_FILE: denyPolicy,
        BACKSTOP_SYNC_HOOK: "1",
      },
      BACKSTOP_APP,
    );
    // The CHILD must agree with the parent's view of the API. A silent `return` here used to
    // turn the whole test into a green no-op on Node 20 (#112); now that the floor guarantees
    // the API, `UNSUPPORTED` coming back from the child would mean the fixture failed to install
    // the sync hook, which is a real failure rather than a runtime that lacks it.
    expect(r.stdout).not.toContain("BACKSTOP:UNSUPPORTED");
    for (const spec of MEDIATED) {
      expect(r.stdout, `${spec} reached the raw builtin via the sync chain`).toContain(
        `BACKSTOP:${spec}:SHIM`,
      );
    }
    expect(r.stdout).toContain("BACKSTOP:enforce-fs:BLOCKED:esm-backstop-dep");
    // …and says so on stderr, once per specifier, because reaching the backstop is never normal.
    // capwall's only in-band signal that something is ahead of it in the hook chain, and the
    // version-independent half of the proof: it does not depend on `process.getBuiltinModule`,
    // which the fixture uses to tell shim from raw. Moved here from the `register()` arm above,
    // which no longer reaches the backstop at all.
    for (const spec of MEDIATED) {
      expect(r.stderr, `no re-mediation warning for node:${spec}`).toContain(
        `WARN another module-customization hook resolved 'node:${spec}' straight to the raw builtin`,
      );
    }
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

  it("fails closed after uninstall() for a specifier that was already imported", () => {
    // A CAPTURE cannot be revoked, so the only honest options for one are the torn-down
    // install's grants or none. It denies.
    expect(out.stdout).toContain("SWAP:uninstalled:CapabilityError:esm-fixture-dep");
  });

  it("un-mediates a NEVER-IMPORTED specifier after the last uninstall(), matching CJS (#152)", () => {
    // CHANGED BY #152, deliberately, and this is the one assertion in this file whose expected
    // value moved. It used to be `SWAP:never-imported:FAILS_CLOSED` — an explicit "capwall is no
    // longer installed" throw from the bridge — because `module.register()` had no working
    // teardown and the hook outlived `uninstall()`. `module.registerHooks()` returns a real
    // `deregister()`, so the hooks are gone and a FRESH import reaches the real builtin exactly
    // as a fresh `require` does. docs/threat-model.md § ESM known limits carried that asymmetry
    // as the one place the install lifecycle differed between the two paths; it no longer does.
    //
    // This is not a weakening. The old behaviour was fail-closed for a *fresh* access in a
    // process where nothing is mediating anything — and worse, an ESM module that throws during
    // evaluation is cached in its errored state, so the specifier stayed poisoned for the rest
    // of the process. The property that actually matters, a stale CAPTURE failing closed, is the
    // assertion above and is unchanged.
    expect(out.stdout).toContain("SWAP:never-imported:UNMEDIATED");
  });

  it("re-mediates that specifier for a LATER install — the gap import does not poison it", () => {
    // The obligation the change above creates: an import taken while capwall was uninstalled puts
    // the raw `node:` URL in the ESM registry, and a registry entry is permanent. It does not
    // de-mediate the next install, because a mediated import resolves to a `capwall-esm:` URL —
    // a different key, which is not in that registry. Asserted rather than reasoned about,
    // because "a cached raw URL is served from cache and the hook chain is never consulted" is
    // exactly the mechanism that made the #78 backstop dead code for four months.
    expect(out.stdout).toContain("SWAP:after-gap-reinstall:MEDIATED");
  });

  it("is a live policy, not a one-way ratchet — loosening applies too", () => {
    expect(out.stdout).toContain("SWAP:reloose:OK:esm fixture data");
    expect(out.code).toBe(0);
  });

  /*
   * #182 rides on the same fixture, because it is the same cycle seen from the other side. The
   * assertions above say what the gap import does NOT cost (mediation); these say what it does.
   */
  it("#182 — WARNS once when an install follows a deregistration, instead of retiring the backstop silently", () => {
    // The finding was the silence, not the window: `uninstall()` → `import("node:fs")` →
    // `install()` left the raw `node:` URL in the ESM registry, so the load-level backstop was
    // dead for that specifier for the rest of the process, with no WARN, no decision and nothing
    // in `observe`. capwall is not in the hook chain during the gap and cannot enumerate what was
    // imported, so the warning names the CONSEQUENCE — which is still the difference between a
    // control that is off and a control that is off and says so (`CAPWALL_ENV=0`'s rule).
    expect(out.stderr).toMatch(/WARN capwall was uninstalled and re-installed/);
    // Once, not once per install: the fixture installs three times in total.
    expect(out.stderr.match(/WARN capwall was uninstalled and re-installed/g)?.length).toBe(1);
  });

  it("#182 — and the backstop really is inert for the gap-imported specifier, and only for it", () => {
    // The consequence, demonstrated rather than asserted from the code. Both imports go through a
    // hook the APPLICATION registered — which is allowed, it is the trust root — that
    // short-circuits `resolve` straight to the raw `node:` URL, so capwall is reached at `load`
    // and only the backstop can save either one. `node:net` was imported during the gap and its
    // raw URL is cached, so the load chain is never consulted for it; `node:dgram` never was, so
    // the same hook, the same install and the same policy re-mediate it.
    expect(out.stdout).toContain("SWAP:backstop:node:net:RAW");
    expect(out.stdout).toContain("SWAP:backstop:node:dgram:REMEDIATED");
    // …and the one that survived says so on stderr, which is how an operator would see it.
    expect(out.stderr).toContain(
      "WARN another module-customization hook resolved 'node:dgram' straight to the raw builtin",
    );
  });
});
