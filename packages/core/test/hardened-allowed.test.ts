/**
 * HARDENED × GRANTED × DENIED, for every guarded surface — issue #90, blind spot 2.
 *
 * THE HOLE THIS CLOSES. `hardened.test.ts` is thorough about one direction: under
 * `hardened: true`, a denied thing stays denied and a patch attempt fails. It has exactly one
 * assertion in the other direction ("a granted read still succeeds with hardened on"), for `fs`.
 *
 * #86 lived in the gap. Under `CAPWALL_HARDENED=1` every **granted** `dgram.createSocket().send()`
 * threw `Cannot redefine property: send` — hardened mode's non-configurable pin (#17) colliding
 * with the auto-bind replay fix's `defineProperty` (#60). Enforcement was never weakened; the
 * capability was simply broken for the packages that HELD it. A capability firewall that denies
 * what it granted is as much a failure as one that grants what it denied, and it is the failure
 * mode nobody writes a test for.
 *
 * So this file is one row of the matrix, run to the end: for EVERY guarded capability, with
 * `hardened: true`,
 *
 *   · the GRANTED call still works — no `CapabilityError`, no `TypeError` from a pinned
 *     descriptor, no frozen-object write failure inside Node's own machinery;
 *   · the UNGRANTED call is still denied, so the allowed-path assertion cannot be satisfied by
 *     accidentally disabling enforcement;
 *   · and the same pair holds with `hardened: false`, so any difference is attributable.
 *
 * SHAPE OF THE "ALLOWED" ASSERTION. Egress cases dial a loopback port that was bound and then
 * closed, so the guard's ALLOW is observed before the OS refuses the connection — the hermetic
 * trick net.test.ts uses. Nothing here leaves loopback, and no test asserts that a connection
 * SUCCEEDED, only that capwall did not refuse it.
 *
 * RUNTIME. Entirely in-process: `install(policy, mode, { hardened: true })` is the same switch
 * `CAPWALL_HARDENED=1` sets, and `hardened.test.ts` already covers the env-variable and ESM
 * halves in subprocesses. Adding a subprocess per capability here would multiply the suite's
 * wall-clock cost for no additional coverage of the collision class #86 belongs to.
 */
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
import { packageForPath } from "../src/attribution/index.js";
import {
  REAL_ADDON,
  REAL_ADDON_SKIP_REASON,
  titleWithSkipReason,
} from "./helpers/real-addon.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");
const SECRET_KEY = "HARDENED_ALLOWED_TEST_SECRET";
const SECRET_VALUE = "s3cr3t";

interface OpOutcome {
  ok: boolean;
  value?: unknown;
  error?: string;
}

interface FixtureDep {
  readData(): string;
  readDataAsync(): Promise<string>;
  writeFile(target: string): void;
  readViaStreamClass(): Promise<string>;
  connect(host: string, port: number): unknown;
  connectViaTls(host: string, port: number): unknown;
  connectViaHttpGlobalAgent(host: string, port: number): unknown;
  http2Connect(host: string, port: number): string;
  udpSend(
    flavor: "factory" | "class",
    host: string,
    port: number,
    bindFirst: boolean,
    cb: (err: unknown) => void,
  ): unknown;
  udpConnect(
    flavor: "factory" | "class",
    host: string,
    port: number,
    cb: (err: unknown) => void,
  ): unknown;
  spawn(): { status: number | null };
  runVm(code: string): unknown;
  readEnv(key: string): string | undefined;
  fetchUrl(url: string): Promise<unknown>;
  openWebSocket(url: string): Promise<string>;
  openEventSource(url: string): string;
  loadNativeViaDlopen(target?: string): unknown;
  compileUnder(filename: string, source?: string): unknown;
  tryOp(family: "captured" | "fresh", name: string, args?: unknown[]): OpOutcome;
  NATIVE_ADDON: string;
}

function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

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

const open: InstallHandle[] = [];
const decisions: Array<{ pkg: string; decision: Decision }> = [];
afterEach(() => {
  while (open.length > 0) open.pop()?.uninstall();
});

function capwall(policy: Policy, hardened: boolean): FixtureDep {
  decisions.length = 0;
  open.push(
    install(policy, "enforce", {
      projectRoot: here,
      hardened,
      onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
    }),
  );
  return loadFixtureFresh();
}

let PORT = 0;
beforeAll(async () => {
  PORT = await closedLocalPort();
  process.env[SECRET_KEY] = SECRET_VALUE;
});

/** Everything fixture-dep needs for the ALLOWED arm — every capability kind, at once, so the
 * matrix is one policy and one install per case rather than one per capability. */
const GRANT_ALL = (port: number): Policy =>
  loadPolicyFromObject(
    {
      version: 1,
      mode: "enforce",
      packages: {
        "fixture-dep": {
          fs: { read: ["./fixtures/**", "/tmp/**"], write: ["/tmp/**"] },
          net: { hosts: ["127.0.0.1"], ports: [port] },
          child_process: true,
          worker_threads: true,
          vm: true,
          native: true,
          compile: true,
          env: [SECRET_KEY],
        },
        // The addon file the native gate charges as the OWNER subject lives in this package.
        "fixture-native-loader": { native: true },
        // The native gate charges BOTH the caller and the package that OWNS the `.node` file
        // (loader/native.ts). The borrowed real addon lives in the pnpm store, so its owner is
        // whatever binding package that is — resolved rather than hard-coded, because it is
        // platform-keyed.
        ...(REAL_ADDON === null ? {} : { [packageForPath(REAL_ADDON, here)]: { native: true } }),
      },
    },
    { projectRoot: here },
  );

/** Grants nothing to anyone. */
const GRANT_NONE = (): Policy =>
  loadPolicyFromObject({ version: 1, mode: "enforce", packages: {} }, { projectRoot: here });

const isCapabilityError = (err: unknown): boolean =>
  (err as { name?: string } | null)?.name === "CapabilityError";

/** Run `fn` and report only whether capwall REFUSED it. An ECONNREFUSED, a TLS handshake
 * failure or a missing addon is not a capwall answer and must not be read as one. */
function refused(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch (err) {
    if (isCapabilityError(err)) return true;
    return false;
  }
}

async function refusedAsync(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch (err) {
    return isCapabilityError(err);
  }
}

/**
 * ONE guarded surface: how to exercise it when granted, and when not.
 *
 * `run` must be free of assertions — the driver below runs it under four configurations
 * (granted/denied × hardened on/off) and asserts on the four outcomes together, which is what
 * makes a difference attributable to hardening rather than to the policy.
 */
interface Surface {
  name: string;
  run: (dep: FixtureDep) => boolean | Promise<boolean>;
  /**
   * Skip the whole row when the surface does not exist on this runtime. A row that silently
   * reported "not refused" for both arms because the API is absent would assert nothing while
   * looking green.
   *
   * WHERE THIS STANDS AFTER THE NODE 20 DROP:
   *  - `WebSocket` — **no longer skips**. It is unflagged from Node 22.4, below the ≥22.15 floor,
   *    so this row now runs in-process on every leg of the matrix. That is coverage gained by
   *    moving the floor, not by writing a test.
   *  - `EventSource` — **still skips on 22, 24 AND 26**. It remains behind
   *    `--experimental-eventsource` on every current Node, and vitest is never handed the flag.
   *    This is a real, still-open gap in THIS file, not something the floor fixed.
   *
   * A SKIP IS ONLY ACCEPTABLE WITH COVERAGE ELSEWHERE (#112 item 2). The `EventSource` cell is
   * covered by `global-egress-flagged.test.ts`, which spawns a child WITH the flag and runs the
   * granted/denied × hardened-on/off matrix there — see its `#80 × #17 … under hardened mode`
   * block. The `native` row's skip is covered by `native.test.ts`'s `REAL, loadable addon` suite
   * (same helper, same discovery).
   */
  available?: () => boolean;
  /**
   * What to say when `available()` is false, when "not available on this runtime" is not the
   * whole story. The borrowed-addon row has a real diagnosis to report (#140) — which `.node`
   * files were found and why none of them is loadable here.
   */
  unavailableReason?: () => string;
}

const hasGlobal = (name: string): boolean =>
  typeof (globalThis as Record<string, unknown>)[name] === "function";

const SURFACES: Surface[] = [
  { name: "fs.readFileSync", run: (dep) => refused(() => dep.readData()) },
  {
    name: "fs.promises.readFile",
    run: (dep) => refusedAsync(() => dep.readDataAsync()),
  },
  {
    name: "fs.writeFileSync",
    run: (dep) => refused(() => dep.writeFile(path.join("/tmp", "capwall-hardened-allowed.txt"))),
  },
  { name: "new fs.ReadStream", run: (dep) => refusedAsync(() => dep.readViaStreamClass()) },
  { name: "net.connect", run: (dep) => refused(() => dep.connect("127.0.0.1", PORT)) },
  { name: "tls.connect", run: (dep) => refused(() => dep.connectViaTls("127.0.0.1", PORT)) },
  {
    name: "http.request",
    run: (dep) => dep.tryOp("fresh", "http", ["127.0.0.1", PORT]).error === "CapabilityError",
  },
  {
    name: "http.globalAgent.createConnection",
    run: (dep) => refused(() => dep.connectViaHttpGlobalAgent("127.0.0.1", PORT)),
  },
  { name: "http2.connect", run: (dep) => refused(() => dep.http2Connect("127.0.0.1", PORT)) },
  {
    // THE #86 CELL ITSELF, and the reason this file exists.
    name: "dgram send (unbound, auto-bind replay)",
    run: (dep) =>
      new Promise<boolean>((resolve) => {
        try {
          dep.udpSend("factory", "127.0.0.1", PORT, false, (err) => resolve(isCapabilityError(err)));
        } catch (err) {
          resolve(isCapabilityError(err));
        }
      }),
  },
  {
    name: "dgram send (pre-bound, no replay)",
    run: (dep) =>
      new Promise<boolean>((resolve) => {
        try {
          dep.udpSend("factory", "127.0.0.1", PORT, true, (err) => resolve(isCapabilityError(err)));
        } catch (err) {
          resolve(isCapabilityError(err));
        }
      }),
  },
  {
    name: "dgram connect",
    run: (dep) =>
      new Promise<boolean>((resolve) => {
        try {
          dep.udpConnect("factory", "127.0.0.1", PORT, (err) => resolve(isCapabilityError(err)));
        } catch (err) {
          resolve(isCapabilityError(err));
        }
      }),
  },
  { name: "child_process.spawnSync", run: (dep) => refused(() => dep.spawn()) },
  {
    name: "worker_threads.Worker",
    run: (dep) => dep.tryOp("fresh", "worker_threads").error === "CapabilityError",
  },
  { name: "vm.runInNewContext", run: (dep) => refused(() => dep.runVm("1+1")) },
  {
    // Soft deny: the env guard hides the VALUE rather than throwing, so "refused" is
    // "the value did not come back".
    name: "process.env read",
    run: (dep) => dep.readEnv(SECRET_KEY) === undefined,
  },
  { name: "globalThis.fetch", run: (dep) => refusedAsync(() => dep.fetchUrl(`http://127.0.0.1:${PORT}/`)) },
  {
    name: "globalThis.WebSocket",
    run: (dep) => refusedAsync(() => dep.openWebSocket(`ws://127.0.0.1:${PORT}/`)),
    available: () => hasGlobal("WebSocket"),
  },
  {
    name: "globalThis.EventSource",
    run: (dep) => refused(() => dep.openEventSource(`http://127.0.0.1:${PORT}/`)),
    available: () => hasGlobal("EventSource"),
  },
  {
    // The `native` gate is a `process.dlopen` patch, not a shim — hardened mode does not touch
    // it, which is exactly why it belongs in this row: nothing should CHANGE.
    //
    // POINTED AT A REAL ADDON (#112 item 5). This row used to load fixture-dep's own
    // `build/Release/fixture-addon.node`, which is UTF-8 text, not an addon. `process.dlopen`
    // therefore threw a format error on BOTH arms, and `refused()` reports any non-
    // `CapabilityError` as "not refused" — so the granted arm read identically whether the gate
    // allowed the load or never ran at all. The denied arm discriminated; the granted arm, which
    // is the entire point of this file (#86 broke ALLOWED operations), could not.
    // `helpers/real-addon.ts` borrows a genuinely loadable binding out of the pnpm store; where
    // no such binding exists the row skips loudly rather than reporting a hollow pass.
    name: "native .node load (process.dlopen)",
    run: (dep) => refused(() => dep.loadNativeViaDlopen(REAL_ADDON!)),
    available: () => REAL_ADDON !== null,
    unavailableReason: () => `native .node load: ${REAL_ADDON_SKIP_REASON}`,
  },
  {
    // `Module.prototype._compile` (#93). Also not a shim, also refcounted, also unaffected by
    // hardening — and the gate that #100 found could not stack.
    name: "Module.prototype._compile",
    run: (dep) => refused(() => dep.compileUnder("/definitely/not/fixture-dep/forged.js")),
  },
];

describe("#90 — hardened mode lets GRANTED operations through, on every guarded surface", () => {
  for (const surface of SURFACES) {
    it(`${surface.name}: granted works and ungranted is denied, hardened ON and OFF`, async (ctx) => {
      if (surface.available !== undefined && !surface.available()) {
        ctx.skip(
          surface.unavailableReason?.() ?? `${surface.name} is not available on this runtime`,
        );
      }
      const outcomes: Record<string, boolean> = {};
      for (const hardened of [false, true]) {
        for (const [label, policy] of [
          ["granted", GRANT_ALL(PORT)],
          ["denied", GRANT_NONE()],
        ] as const) {
          const dep = capwall(policy, hardened);
          outcomes[`${label}/${hardened ? "hardened" : "plain"}`] = await surface.run(dep);
          open.pop()?.uninstall();
        }
      }
      // The whole point, stated as one comparison: hardening changes nothing about WHICH calls
      // capwall refuses. #86 would have failed this on `granted/hardened` alone.
      expect(outcomes).toEqual({
        "granted/plain": false,
        "granted/hardened": false,
        "denied/plain": true,
        "denied/hardened": true,
      });
    });
  }
});

describe.skipIf(REAL_ADDON === null)(
  titleWithSkipReason(
    "#90 — a GRANTED native load genuinely initializes, hardened ON and OFF (#112)",
  ),
  () => {
    /**
     * The matrix row above can only say "capwall did not refuse". This says the load actually
     * happened: `process.dlopen` mapped the addon in and its `module.exports` came back
     * populated. That is the discriminating half the stub fixture could never provide — the
     * whole reason `native .node load` was flagged in #112 as a row whose granted arm proved
     * nothing.
     *
     * `helpers/real-addon.ts` documents why loading the same binding repeatedly is safe.
     */
    it("dlopen returns a populated exports object under both hardening settings", () => {
      for (const hardened of [false, true]) {
        const dep = capwall(GRANT_ALL(PORT), hardened);
        const exports = dep.loadNativeViaDlopen(REAL_ADDON!);
        expect({ hardened, type: typeof exports }).toEqual({ hardened, type: "object" });
        expect({ hardened, keys: Object.keys(exports as object).length > 0 }).toEqual({
          hardened,
          keys: true,
        });
        expect(
          decisions.filter((d) => d.decision.observed.kind === "native").length,
        ).toBeGreaterThan(0);
        expect(
          decisions.filter((d) => d.decision.observed.kind === "native" && !d.decision.allowed),
        ).toEqual([]);
        open.pop()?.uninstall();
      }
    });
  },
);

describe("#90 — hardened mode does not change what is RECORDED either", () => {
  /**
   * The audit trail is half of capwall's value (#65's unlogged egress was the worse half of that
   * finding), and hardened mode has no business touching it. A surface that threw a `TypeError`
   * from a pinned descriptor instead of reaching the guard — the #86 failure — would also be
   * MISSING from the trace, so this is the same regression seen from the other side.
   */
  it("records the same allowed decisions for a granted package with hardening on and off", () => {
    const kinds = (hardened: boolean): string[] => {
      const dep = capwall(GRANT_ALL(PORT), hardened);
      dep.readData();
      dep.connect("127.0.0.1", PORT);
      dep.spawn();
      dep.runVm("1+1");
      dep.readEnv(SECRET_KEY);
      const seen = decisions
        .filter((d) => d.pkg === "fixture-dep" && d.decision.allowed)
        .map((d) => d.decision.observed.kind);
      open.pop()?.uninstall();
      return [...new Set(seen)].sort();
    };
    const plain = kinds(false);
    expect(plain).toEqual(["child_process", "env", "fs", "net", "vm"]);
    expect(kinds(true)).toEqual(plain);
  });
});

describe("#90 — the hardened pin does not break ordinary use of a guarded object", () => {
  /**
   * #86's mechanism was a descriptor collision: `send` was pinned non-configurable, and the
   * replay fix needed to redefine it. The fix made `send` an ACCESSOR, so the property is
   * installed once and never touched again. These assertions pin the two properties that fix has
   * to keep simultaneously true, which no single-axis test states together.
   */
  it("a granted dgram send is repeatable — the accessor is not a one-shot", async () => {
    const dep = capwall(GRANT_ALL(PORT), true);
    for (let i = 0; i < 3; i++) {
      const err = await new Promise<unknown>((resolve) => {
        dep.udpSend("factory", "127.0.0.1", PORT, false, resolve);
      });
      expect(isCapabilityError(err)).toBe(false);
    }
    // "No CapabilityError" is also what a DELETED dgram guard looks like. The three sends must
    // additionally have been SEEN and allowed — three trips through the guard, not zero (#112).
    const netDecisions = decisions.filter(
      (d) => d.pkg === "fixture-dep" && d.decision.observed.kind === "net",
    );
    expect(netDecisions).toHaveLength(3);
    expect(netDecisions.every((d) => d.decision.allowed)).toBe(true);
  });

  it("a granted package can still read `socket.send` and get capwall's guarded function", () => {
    const dep = capwall(GRANT_ALL(PORT), true) as FixtureDep & {
      patchUdpSocketSend(flavor: string, replacement: unknown): unknown;
    };
    // Hardened: the write is refused (sloppy mode → silent no-op), and what reads back must
    // still be capwall's guarded function, not `undefined` and not the raw method.
    //
    // The comparison is against the REPLACEMENT ITSELF, not against the string it returns.
    // `expect(after).not.toBe("PATCHED")` compared a function to a string, which is true for
    // every function including the attacker's — so it passed with the hardened pin removed
    // entirely (#112). `dgram.test.ts` has always compared identities; this now matches it.
    const replacement = (): string => "PATCHED";
    const after = dep.patchUdpSocketSend("factory", replacement);
    expect(typeof after).toBe("function");
    expect(after).not.toBe(replacement);
  });

  it("a granted package can still tune http.globalAgent's live pool state under hardening", () => {
    // The one deliberate exception in `guardedInstanceMethods`: pool state stays shared and
    // writable even hardened, because Node's own bookkeeping assigns to it through `this`. A
    // hardened mode that pinned it would break every granted HTTP request in the process — the
    // #86 failure mode again, on a different object.
    const dep = capwall(GRANT_ALL(PORT), true) as FixtureDep & {
      tamperWithGlobalAgent(): { tunePool: { ok: boolean; value?: unknown } };
    };
    expect(dep.tamperWithGlobalAgent().tunePool).toEqual({ ok: true, value: 3 });
  });
});
