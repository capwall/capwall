/**
 * THE COMPOSITION MATRIX — issue #90.
 *
 * Five confirmed defects (#84 CRITICAL, #89 HIGH, #86, #87, #88) were all present on `main` with
 * `pnpm test` fully green, and they clustered in three blind spots. This file closes the first
 * one: **cross-subsystem composition**. Every other test in this directory exercises ONE shim at
 * a time, so "subsystem A's global switch meets subsystem B's assumption" was structurally
 * invisible — which is precisely the shape of #89 (`child_process`'s process-wide env-gate
 * suspension walked through by a getter on `options.cwd`) and #86 (hardened mode's
 * non-configurable `send` versus the dgram replay fix's `defineProperty`).
 *
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * THE SHARED MUTABLE STATE, ENUMERATED. This list is the deliverable; the tests below are
 * written against it rather than against imagination. Anything process-wide, or scoped to the
 * dynamic extent of a call rather than to one object, is here.
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 *
 *  S1  `liveCtx` — the ONE long-lived context box every mediated surface reads at CALL time
 *      (`policy`, `mode`, `onDecision`, `projectRoot`, `maxFrames`, `hardened`).
 *      loader/live-context.ts. Read by: every `guard()`, the env guard, the global-egress
 *      guard, the native gate, the `_compile` gate, the CJS registry and the ESM bridge.
 *  S2  the install STACK (`installs[]` + the `installed` flag) that re-points S1.
 *      loader/live-context.ts. Drives `getEsmShim`'s fail-closed error and every teardown.
 *  S3  the shim REGISTRIES, memoized by `path:hardenedness` and built exactly once each.
 *      loader/live-context.ts. A rebuild would strand every existing capture.
 *  S4  the `Module._load` patch CHAIN (`installChain`). loader/require.ts.
 *  S5  the `process.dlopen` patch CHAIN (`installChain`). loader/native.ts.
 *  S6  the `Module.prototype._compile` patch — exactly ONE per process, REFERENCE-COUNTED
 *      (`compileGateInstalls`). shims/module.ts. Stacking it would make the inner patch see the
 *      outer patch's frame instead of Node's loader and gate EVERY `require` in the process.
 *  S7  `hookRegistered` — `module.register()` is one-shot per process. loader/esm-hook.ts.
 *  S8  `authorizedEnvKeys` — the key-scoped env authorization, live only for the dynamic extent
 *      of a real spawn. shims/runtime.ts. This is what #98 replaced `suspendEnvGate` with.
 *  S9  `unproxiedEnv` — the un-gated `process.env` reference the child_process shim builds a
 *      child's environment block from. shims/runtime.ts.
 *  S10 `dgramAuthorization` — the single-use, single-socket, single-destination replay
 *      authorization, live only for the dynamic extent of an already-guarded `send`. shims/net.ts.
 *  S11 `process.env` itself — replaced process-wide by the env guard's Proxy. shims/env.ts.
 *  S12 `globalThis.fetch` / `WebSocket` / `EventSource` — replaced process-wide.
 *      shims/global-egress.ts.
 *  S13 `guardedWebSocketCache` — one guarded `WebSocket` subclass shared between the global and
 *      the `http.WebSocket` re-export. shims/global-egress.ts + shims/net.ts.
 *  S14 the per-view `shadow` map and `wrappers` WeakMap inside `guardedInstanceMethods` — the
 *      `http(s).globalAgent` view over a process-global connection pool. shims/runtime.ts.
 *  S15 the path→package resolution cache used by attribution. attribution/index.ts.
 *
 * ORDERING ASSUMPTIONS between them, which is the other half of "composition":
 *
 *  O1  `patchRequire` pushes onto S2 BEFORE patching S4, so a require landing between the two
 *      can never be evaluated against the previous install's policy.
 *  O2  the four non-require-routed guards (env, global egress, native, `_compile`) are handed
 *      S1, never a per-install context — that divergence WAS #87.
 *  O3  the child_process shim PINS the caller's options before opening S8, never after.
 *  O4  the dgram shim evaluates the policy before arming S10, and mints a fresh token per read.
 *  O5  S6 must not stack (see above), while S4/S5 must (they relink around an out-of-order
 *      removal).
 *  O6  `hardened` is consumed at shim BUILD time, so S3 is keyed by it; S11/S12 are built once
 *      and pinned in place instead.
 *  O7  S12 is always installed `configurable: true`, even hardened, so teardown can restore it.
 *
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * WHAT THIS FILE ASSERTS. Two shapes, applied to the pairs above:
 *
 *   (a) A privileged window one package opens must not open ANYTHING — on any subsystem, for
 *       any package. S8 and S10 are the only two dynamically-scoped authorizations capwall has,
 *       and both are reachable from caller-controlled code (a getter on a spawn option; an
 *       accessor on an element of a `send` buffer list). Each is crossed with every other
 *       capability and with a second, entirely ungranted principal.
 *   (b) A guard that authorizes one call must not authorize a second call, a different target,
 *       or a different object — across subsystem boundaries, not just within one.
 *
 * Deliberately NOT re-covered here (already pinned elsewhere, and duplicating them would just
 * make the suite slower): the #89 spawn-getter × env matrix itself (child_process-env.test.ts),
 * the dgram replay-token theft cases (dgram.test.ts), the `_load` chain's out-of-order relink
 * (loader-uninstall.test.ts), and the `_compile` refcount (compile-gate-lifecycle.test.ts).
 */
import * as nodeHttp from "node:http";
import { createRequire } from "node:module";
import * as net from "node:net";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  install,
  loadPolicyFromObject,
  type Decision,
  type InstallHandle,
  type Policy,
} from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");
const DATA = "fixture data\n";

/** Deliberately NOT a `CAPWALL_*` name — those are exempt from env gating (see shims/env.ts). */
const SECRET_KEY = "COMPOSITION_TEST_SECRET";
const SECRET_VALUE = "s3cr3t";

/** One named capability attempt, run inside a privileged window and outside it. */
interface OpOutcome {
  ok: boolean;
  value?: unknown;
  error?: string;
}
interface WindowResult {
  inside: OpOutcome;
  outside: OpOutcome;
}

interface FixtureDep {
  duringSpawnWindow(op: string, args?: unknown[]): WindowResult;
  duringAuthorizedDgramSend(
    allowed: { host: string; port: number },
    op: string,
    args: unknown[],
    cb: (r: WindowResult) => void,
  ): void;
  runOp(op: string, args?: unknown[]): OpOutcome;
  tryOp(family: "captured" | "fresh", name: string, args?: unknown[]): OpOutcome;
}

function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

/** Bind an ephemeral port and close it: connecting afterwards yields ECONNREFUSED without ever
 * leaving loopback, so an ALLOWED decision is observed before any real traffic. Same trick
 * net.test.ts uses. */
async function closedLocalPort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => resolve(addr && typeof addr === "object" ? addr.port : 0));
    });
  });
}

type Recorded = { pkg: string; decision: Decision };
const decisions: Recorded[] = [];
const open: InstallHandle[] = [];

function capwall(policy: Policy): FixtureDep {
  decisions.length = 0;
  open.push(
    install(policy, "enforce", {
      projectRoot: here,
      onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
    }),
  );
  return loadFixtureFresh();
}

afterEach(() => {
  while (open.length > 0) open.pop()?.uninstall();
});

beforeAll(() => {
  process.env[SECRET_KEY] = SECRET_VALUE; // on the REAL env, before any proxy exists
});

/** fixture-dep may spawn, read its own files, and dial ONE loopback port. fixture-envpeek holds
 * nothing at all — it is the second principal that makes "does A's window open something for B?"
 * answerable. */
const policyGranting = (allowedPort: number): Policy =>
  loadPolicyFromObject(
    {
      version: 1,
      mode: "enforce",
      packages: {
        "fixture-dep": {
          child_process: true,
          fs: { read: ["./fixtures/**"] },
          net: { hosts: ["127.0.0.1"], ports: [allowedPort] },
          env: [SECRET_KEY],
        },
      },
    },
    { projectRoot: here },
  );

let ALLOWED_PORT = 0;
beforeAll(async () => {
  ALLOWED_PORT = await closedLocalPort();
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * S8 (the spawn env authorization) × every other subsystem.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("S8 × everything — a spawn's env authorization authorizes nothing else (#89, #90)", () => {
  /**
   * The generalized form of #89. That issue was found because a getter on `options.cwd` read the
   * whole environment; the fix scoped the authorization to a fixed list of key NAMES. But the
   * window is still a window, and the question "what ELSE can code running inside it do?" has
   * never been asked of any subsystem other than `env`.
   *
   * The assertion is the strongest available and needs no per-op expectation table: whatever the
   * op does OUTSIDE the window, it must do INSIDE it. A window that changes any answer is a
   * window that confers authority.
   */
  const OPS: Array<[string, unknown[]]> = [
    ["self:env", [SECRET_KEY]],
    ["self:envHarvest", []],
    ["self:fs", []],
    ["self:dgram", ["10.0.0.1", 9999]],
    ["self:vm", []],
    ["other:env", [SECRET_KEY]],
    ["other:envHarvest", []],
    ["other:fs", []],
    ["other:dgram", ["10.0.0.1", 9999]],
    ["other:vm", []],
  ];

  for (const [op, args] of OPS) {
    it(`answers '${op}' identically inside and outside a real spawn`, () => {
      const dep = capwall(policyGranting(ALLOWED_PORT));
      const { inside, outside } = dep.duringSpawnWindow(op, args);
      expect(inside).toEqual(outside);
    });
  }

  it("does not let the SPAWNING package dial a denied host from inside its own spawn", () => {
    // The spawning package holds `child_process` and one loopback port. Being inside the spawn
    // must not widen that to a different destination — different subsystem, different target.
    const dep = capwall(policyGranting(ALLOWED_PORT));
    const { inside } = dep.duringSpawnWindow("self:net", ["10.0.0.1", 9999]);
    expect(inside).toEqual({ ok: false, error: "CapabilityError" });
  });

  it("does not let a SECOND package spawn just because the first one is spawning", () => {
    // `child_process` is a boolean gate, so this is the cleanest "one package's privileged
    // operation must not open a window for a different package" case there is.
    const dep = capwall(policyGranting(ALLOWED_PORT));
    const { inside, outside } = dep.duringSpawnWindow("other:spawn", []);
    expect(inside).toEqual({ ok: false, error: "CapabilityError" });
    expect(inside).toEqual(outside);
  });

  it("still records the ungranted second package's attempt made from inside the window", () => {
    // #89's other half: the window was not merely permissive, it was SILENT. A denial that
    // happens inside a spawn must reach `onDecision` exactly like one that happens outside.
    const dep = capwall(policyGranting(ALLOWED_PORT));
    dep.duringSpawnWindow("other:env", [SECRET_KEY]);
    expect(
      decisions.some((d) => d.pkg === "fixture-envpeek" && !d.decision.allowed),
    ).toBe(true);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * S10 (the dgram replay authorization) × every other subsystem.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("S10 × everything — an authorized dgram send authorizes nothing else (#86, #90)", () => {
  /**
   * `dgramAuthorization` is a module-scoped `let` that says "capwall has already allowed THIS
   * send". dgram.test.ts asks whether the replay TOKEN can be stolen and misused within dgram.
   * Nothing asks what the window does to the OTHER subsystems, and the window is reachable:
   * Node's `fixBufferList` reads `list[i]` off a buffer LIST argument, so an accessor there runs
   * with the authorization armed.
   */
  const OPS: Array<[string, unknown[]]> = [
    ["self:env", [SECRET_KEY]],
    ["self:fs", []],
    ["self:spawn", []],
    ["self:vm", []],
    ["other:env", [SECRET_KEY]],
    ["other:fs", []],
    ["other:spawn", []],
    ["other:dgram", ["10.0.0.1", 9999]],
  ];

  for (const [op, args] of OPS) {
    it(`answers '${op}' identically inside and outside an authorized send`, async () => {
      const dep = capwall(policyGranting(ALLOWED_PORT));
      const result = await new Promise<WindowResult>((resolve) => {
        dep.duringAuthorizedDgramSend({ host: "127.0.0.1", port: ALLOWED_PORT }, op, args, resolve);
      });
      expect(result.inside).toEqual(result.outside);
    });
  }

  it("does not let the sending package reach a DIFFERENT destination from inside the window", async () => {
    // The authorization carries its own content — one socket, one host:port, one use — so being
    // inside it must not authorize a second, different target even for the same package on the
    // same subsystem. dgram.test.ts proves that for a stolen token; this proves it for an
    // ordinary `send` issued from inside the window, which takes no token at all.
    const dep = capwall(policyGranting(ALLOWED_PORT));
    const result = await new Promise<WindowResult>((resolve) => {
      dep.duringAuthorizedDgramSend(
        { host: "127.0.0.1", port: ALLOWED_PORT },
        "self:dgram",
        ["10.0.0.1", 9999],
        resolve,
      );
    });
    expect(result.inside).toEqual({ ok: false, error: "CapabilityError" });
  });

  it("does not let the sending package re-use it for the SAME destination on a fresh socket", async () => {
    // The same host:port, so the policy allows it on its own merits — the point is that it is
    // allowed by the POLICY and recorded, not waved through by the armed authorization. A
    // recorded decision for the second send is the observable difference.
    const dep = capwall(policyGranting(ALLOWED_PORT));
    const result = await new Promise<WindowResult>((resolve) => {
      dep.duringAuthorizedDgramSend(
        { host: "127.0.0.1", port: ALLOWED_PORT },
        "self:dgram",
        ["127.0.0.1", ALLOWED_PORT],
        resolve,
      );
    });
    expect(result.inside.ok).toBe(true);
    const netDecisions = decisions.filter(
      (d) => d.pkg === "fixture-dep" && d.decision.observed.kind === "net",
    );
    expect(netDecisions.length).toBeGreaterThanOrEqual(2); // the outer send AND the inner one
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * S1 — one live context, one frame budget, one policy, across every attribution site.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("S1 — every attribution site shares one budget and one policy (#15, #58, #90)", () => {
  /**
   * `attributionOptionsFor(ctx)` exists so that `guard()`, the env guard, the dgram gate, the
   * native gate and the `_compile` gate all walk with the SAME budget. A site that quietly kept
   * the default while the rest honored a raised cap would attribute the same call to a different
   * package depending on which capability it touched — a genuinely confusing failure, and one no
   * single-subsystem test can see.
   *
   * A budget of 1 is below every real call's depth, so EVERY site must fall back to `<unknown>`.
   * The assertion is on the agreement, not on the individual answers.
   */
  it("a maxFrames of 1 truncates fs, env and dgram attribution alike — never just one of them", () => {
    decisions.length = 0;
    open.push(
      install(policyGranting(ALLOWED_PORT), "enforce", {
        projectRoot: here,
        attribution: { maxFrames: 1 },
        onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
      }),
    );
    const dep = loadFixtureFresh();
    dep.runOp("self:fs", []);
    dep.runOp("self:env", [SECRET_KEY]);
    dep.runOp("self:dgram", ["127.0.0.1", ALLOWED_PORT]);

    const byKind = (kind: string): string[] =>
      decisions.filter((d) => d.decision.observed.kind === kind).map((d) => d.pkg);
    // Every site agrees, and every site agrees on the SAME principal.
    expect(byKind("fs")).toContain("<unknown>");
    expect(byKind("env")).toContain("<unknown>");
    expect(byKind("net")).toContain("<unknown>");
    expect(decisions.every((d) => d.pkg === "<unknown>")).toBe(true);
  });

  it("and a generous budget attributes all three to the same real package", () => {
    const dep = capwall(policyGranting(ALLOWED_PORT));
    dep.runOp("self:fs", []);
    dep.runOp("self:env", [SECRET_KEY]);
    dep.runOp("self:dgram", ["127.0.0.1", ALLOWED_PORT]);
    expect(decisions.length).toBeGreaterThan(0);
    expect(decisions.every((d) => d.pkg === "fixture-dep")).toBe(true);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * S12 × S13 — the global egress guard and the `net`-family shims share one `net` grant.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("S12 × the net shims — one grant, one authority, however it is spelled (#80, #90)", () => {
  /**
   * `globalThis.fetch` is guarded by shims/global-egress.ts and `http.request` by shims/net.ts —
   * two subsystems, deliberately evaluating the SAME `net` capability, because a dependency
   * dialing a host is the same authority whichever API it reached for. That is a composition
   * property: if the two ever drifted, a policy reviewer would have to know which API a package
   * happens to use. Nothing crossed them before.
   */
  it("a grant for one host:port authorizes fetch AND http.request, and neither for another", async () => {
    const dep = capwall(policyGranting(ALLOWED_PORT)) as FixtureDep & {
      fetchUrl(url: string): Promise<unknown>;
    };
    // Allowed target: both spellings pass the guard (the connection itself is refused by the OS,
    // which is the point of using a just-closed port — no traffic ever leaves loopback).
    await expect(dep.fetchUrl(`http://127.0.0.1:${ALLOWED_PORT}/`)).rejects.not.toMatchObject({
      name: "CapabilityError",
    });
    expect(dep.tryOp("fresh", "http", ["127.0.0.1", ALLOWED_PORT])).toEqual({
      ok: true,
      value: "requested",
    });

    // A different port is a different authority, on both surfaces.
    await expect(dep.fetchUrl(`http://127.0.0.1:${ALLOWED_PORT + 1}/`)).rejects.toMatchObject({
      name: "CapabilityError",
    });
    expect(dep.tryOp("fresh", "http", ["127.0.0.1", ALLOWED_PORT + 1])).toEqual({
      ok: false,
      error: "CapabilityError",
    });
  });

  /*
   * S13, SPLIT SO EACH HALF ASSERTS SOMETHING (#112 item 3).
   *
   * This used to be one test that (a) `return`ed silently after installing capwall when
   * `globalThis.WebSocket` was absent — reporting green with zero assertions on the Node 20 leg
   * of the CI matrix, invisible in the report, against the convention `fs-glob.test.ts:165`
   * argues for in prose — and (b) accepted `TypeError` as proof of guarding. `TypeError` is the
   * UN-guarded outcome: `new undefined(...)` when `http.WebSocket` does not exist. "The property
   * is missing" satisfied "the property is guarded".
   *
   * Availability differs per surface, so the skip conditions do too:
   *   `globalThis.WebSocket` — on from Node 22; `--experimental-websocket` on Node 20.
   *   `http.WebSocket`       — the same class object, re-exported from Node 22 only.
   */
  const HAS_GLOBAL_WEBSOCKET = typeof (globalThis as { WebSocket?: unknown }).WebSocket === "function";
  const HAS_HTTP_WEBSOCKET =
    typeof (nodeHttp as unknown as { WebSocket?: unknown }).WebSocket === "function";
  const DENIED_WS = "ws://10.0.0.1:9999/";

  it.skipIf(!HAS_GLOBAL_WEBSOCKET)("guards the global WebSocket (S12/S13)", async () => {
    const dep = capwall(policyGranting(ALLOWED_PORT)) as FixtureDep & {
      openWebSocket(url: string): Promise<string>;
    };
    await expect(dep.openWebSocket(DENIED_WS)).rejects.toMatchObject({ name: "CapabilityError" });
  });

  it.skipIf(!HAS_HTTP_WEBSOCKET)(
    "guards the SAME class through the http namespace re-export (S13)",
    () => {
      const dep = capwall(policyGranting(ALLOWED_PORT)) as FixtureDep & {
        openWebSocketViaHttpNamespace(url: string): unknown;
      };
      // Strictly `CapabilityError`. Nothing else counts: a `TypeError` here would mean the shim
      // dropped the property, and "unguarded" means it forwarded the real class.
      const viaHttp = ((): string => {
        try {
          dep.openWebSocketViaHttpNamespace(DENIED_WS);
          return "unguarded";
        } catch (err) {
          return (err as { name: string }).name;
        }
      })();
      expect(viaHttp).toBe("CapabilityError");
    },
  );

  it("the http shim neither invents nor drops `WebSocket` relative to the real module", () => {
    // The always-running half, and the honest Node-20 statement: on a runtime where real
    // `node:http` has no `WebSocket`, the dependency must not see one either — that, and not a
    // bare `TypeError`, is why the previous assertion could not fail there.
    const dep = capwall(policyGranting(ALLOWED_PORT)) as FixtureDep & {
      httpNamespaceWebSocketType(): string;
    };
    expect(dep.httpNamespaceWebSocketType()).toBe(HAS_HTTP_WEBSOCKET ? "function" : "undefined");
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * S6 / S5 × S1 — the eagerly-installed gates track the LIVE policy, not the one that built them.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("S5/S6 × S1 — the non-routed gates follow the live context, not their installer (#87, #90)", () => {
  /**
   * The `_compile` gate and the native gate are installed EAGERLY from `install()` and are handed
   * `liveCtx` rather than the per-install context, precisely so a policy swap reaches them (O2).
   * That is the property #87 found broken for `fs` while `process.env` had it — a divergence a
   * single-subsystem test cannot see, because it is a statement about two subsystems agreeing.
   *
   * A `_compile` gate that captured its installer's context would keep enforcing the FIRST
   * policy here, exactly as the CJS `fs` shim used to.
   */
  it("applies a tightened policy to the native gate installed by the FIRST install", () => {
    const loose = loadPolicyFromObject(
      {
        version: 1,
        mode: "enforce",
        packages: { "fixture-dep": { native: true, fs: { read: ["./fixtures/**"] } } },
      },
      { projectRoot: here },
    );
    const tight = loadPolicyFromObject(
      { version: 1, mode: "enforce", packages: {} },
      { projectRoot: here },
    );

    const first = install(loose, "enforce", { projectRoot: here });
    open.push(first);
    const dep = loadFixtureFresh() as FixtureDep & {
      NATIVE_ADDON: string;
      loadNativeViaDlopen(target?: string): unknown;
    };
    // Under the loose policy the gate lets it through — the addon itself is a stub that fails to
    // load, so the observable answer is "not a CapabilityError".
    let looseErr: string | undefined;
    try {
      dep.loadNativeViaDlopen();
    } catch (err) {
      looseErr = (err as { name: string }).name;
    }
    expect(looseErr).not.toBe("CapabilityError");

    first.uninstall();
    open.pop();
    open.push(install(tight, "enforce", { projectRoot: here }));

    // The `process.dlopen` patch is the SAME function object as before; only `liveCtx` moved.
    expect(() => dep.loadNativeViaDlopen()).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * S9 × S11 — the env guard's un-proxied reference and the child_process shim.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("S9 × S11 — a granted spawn inherits the real environment under EVERY install shape (#90)", () => {
  /**
   * FOUND BY THIS FILE. `installEnvGuard` captured whatever `process.env` was at install time and
   * registered it as the UN-PROXIED environment (S9). Under a second, nested install that value
   * was the FIRST install's proxy, so `resolveSpawnEnv` enumerated the read gate instead of the
   * real object: every key soft-denied to `undefined`, Node dropped the undefined values, and a
   * GRANTED `spawn` launched its child with a **completely empty environment**.
   *
   * That is #86's shape exactly — a configuration in which the DENIED path still behaves and the
   * ALLOWED path breaks — and no single-install test could see it. Fixed by making the env guard
   * one refcounted process-wide patch, the same rule the `_compile` gate already followed (S6).
   */
  const grantSpawn = (): Policy =>
    loadPolicyFromObject(
      { version: 1, mode: "enforce", packages: { "fixture-dep": { child_process: true } } },
      { projectRoot: here },
    );

  type SpawnDep = FixtureDep & { spawnSyncEnv(options: object): Record<string, string> };

  it("inherits the environment under a single install", () => {
    const dep = capwall(grantSpawn()) as SpawnDep;
    expect(dep.spawnSyncEnv({})[SECRET_KEY]).toBe(SECRET_VALUE);
  });

  it("inherits it under NESTED installs — the child is not handed an empty environment", () => {
    const dep = capwall(grantSpawn()) as SpawnDep;
    open.push(install(grantSpawn(), "enforce", { projectRoot: here }));
    const childEnv = dep.spawnSyncEnv({});
    expect(childEnv[SECRET_KEY]).toBe(SECRET_VALUE);
    expect(Object.keys(childEnv).length).toBeGreaterThan(5);
  });

  it("inherits it when the env guard is disabled, where process.env IS the real object", () => {
    // The `env: false` arm exercises the `unproxiedProcessEnv()` fallback, which must be exact.
    open.push(install(grantSpawn(), "enforce", { projectRoot: here, env: false }));
    const dep = loadFixtureFresh() as SpawnDep;
    expect(dep.spawnSyncEnv({})[SECRET_KEY]).toBe(SECRET_VALUE);
  });

  it("records no env decision for assembling the child's environment, at any nesting depth", () => {
    // The whole reason S9 exists: enumerating the gate would charge ~80 reads to the spawning
    // package and widen every generated policy with keys no dependency asked for.
    const dep = capwall(grantSpawn()) as SpawnDep;
    open.push(install(grantSpawn(), "enforce", { projectRoot: here }));
    decisions.length = 0;
    dep.spawnSyncEnv({});
    expect(decisions.filter((d) => d.decision.observed.kind === "env")).toEqual([]);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * S11 / S12 × S2 — the process-global replacements and the install stack.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("S11/S12 × S2 — the process-global guards survive an out-of-order teardown (#90)", () => {
  /**
   * ALSO FOUND BY THIS FILE. `InstallHandle.uninstall` promises, in so many words, that it
   * "restores the interception POINTS — `Module._load`, `process.env`, `process.dlopen`, the
   * egress globals — so a fresh `require("node:fs")` or `process.env.X` after the last
   * `uninstall()` is genuinely un-mediated". `Module._load` and `process.dlopen` keep a relink
   * chain to make that true under an out-of-LIFO-order removal (#22). `process.env` and the
   * egress globals kept a bare save/restore, so removing the OUTER install first left capwall's
   * proxy/wrapper on the global **permanently** — reading the deny-all torn-down policy for the
   * rest of the process.
   *
   * `loader-uninstall.test.ts` pins this for `_load` alone. The cross-shim form is the one that
   * catches it, because the bug is that two guards disagreed about the same lifecycle event.
   */
  const anyPolicy = (): Policy =>
    loadPolicyFromObject({ version: 1, mode: "enforce", packages: {} }, { projectRoot: here });

  it("restores process.env AND globalThis.fetch when the OUTER install is removed first", () => {
    const realEnv = process.env;
    const realFetch = (globalThis as { fetch?: unknown }).fetch;

    const outer = install(anyPolicy(), "enforce", { projectRoot: here });
    const inner = install(anyPolicy(), "enforce", { projectRoot: here });
    outer.uninstall(); // not LIFO — the shape #22 fixed for `_load`
    inner.uninstall();

    expect(process.env).toBe(realEnv);
    expect((globalThis as { fetch?: unknown }).fetch).toBe(realFetch);
  });

  it("keeps the globals mediated while ANY install is still active", () => {
    const realEnv = process.env;
    const outer = install(anyPolicy(), "enforce", { projectRoot: here });
    const inner = install(anyPolicy(), "enforce", { projectRoot: here });
    outer.uninstall();
    expect(process.env).not.toBe(realEnv); // inner is still in force
    inner.uninstall();
    expect(process.env).toBe(realEnv);
  });

  it("installs exactly ONE proxy and ONE fetch wrapper however many installs nest", () => {
    // A per-install replace wrapped capwall's OWN wrapper, so one `fetch()` was guarded twice
    // and recorded twice — doubling every global-egress line in an observe trace.
    const outer = install(anyPolicy(), "enforce", { projectRoot: here });
    const afterOuterEnv = process.env;
    const afterOuterFetch = (globalThis as { fetch?: unknown }).fetch;
    const inner = install(anyPolicy(), "enforce", { projectRoot: here });
    expect(process.env).toBe(afterOuterEnv);
    expect((globalThis as { fetch?: unknown }).fetch).toBe(afterOuterFetch);
    inner.uninstall();
    outer.uninstall();
  });

  it("records a nested-install fetch denial exactly ONCE, not once per install", async () => {
    const recorded: Recorded[] = [];
    const outer = install(anyPolicy(), "enforce", {
      projectRoot: here,
      onDecision: (pkg, decision) => recorded.push({ pkg, decision }),
    });
    open.push(outer);
    const dep = loadFixtureFresh() as FixtureDep & { fetchUrl(url: string): Promise<unknown> };
    // The inner install shares the outer's sink only because `liveCtx.onDecision` is re-pointed,
    // so pass the same collector explicitly and count what a single call produces.
    open.push(
      install(anyPolicy(), "enforce", {
        projectRoot: here,
        onDecision: (pkg, decision) => recorded.push({ pkg, decision }),
      }),
    );
    recorded.length = 0;
    await expect(dep.fetchUrl("http://10.0.0.1:9999/")).rejects.toMatchObject({
      name: "CapabilityError",
    });
    expect(recorded.filter((d) => d.decision.observed.kind === "net").length).toBe(1);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * S3 × S1 — the registry split by hardened-ness must not split ENFORCEMENT.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("S3 × S1 — a hardened install changes freezing, never a decision (#17, #90)", () => {
  /**
   * `liveRegistry` memoizes ONE registry per (path, hardened-ness), so a hardened install hands
   * out different shim OBJECTS than an un-hardened one. Both read `liveCtx`, so enforcement must
   * be identical — that is the whole claim in live-context.ts's header, and it is a claim about
   * two subsystems (the registry cache and the policy evaluator) not interacting.
   */
  it("gives the same decision from a plain capture and a hardened fresh require", () => {
    const grant = loadPolicyFromObject(
      {
        version: 1,
        mode: "enforce",
        packages: { "fixture-dep": { fs: { read: ["./fixtures/**"] } } },
      },
      { projectRoot: here },
    );
    const deny = loadPolicyFromObject(
      { version: 1, mode: "enforce", packages: {} },
      { projectRoot: here },
    );

    const plain = install(grant, "enforce", { projectRoot: here });
    open.push(plain);
    const dep = loadFixtureFresh();
    expect(dep.tryOp("captured", "fs")).toEqual({ ok: true, value: DATA });

    // Stack a HARDENED install with a tighter policy. The capture is unfrozen and the fresh
    // require is frozen — different objects — but they must agree about the answer.
    open.push(install(deny, "enforce", { projectRoot: here, hardened: true }));
    expect(dep.tryOp("captured", "fs")).toEqual({ ok: false, error: "CapabilityError" });
    expect(dep.tryOp("fresh", "fs")).toEqual({ ok: false, error: "CapabilityError" });
    expect(Object.isFrozen(requireCjs("fs"))).toBe(true); // the hardened registry is live
  });
});
