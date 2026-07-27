/**
 * Regression suite for the capability-holder escapes: #64 (`.prototype.constructor`), #65
 * (pre-built INSTANCES on a shimmed namespace), and #71 (`Symbol.hasInstance` leaking down the
 * static chain).
 *
 * A construct-trap `Proxy` forwards `get` to its target, so a proxied class's `.prototype` IS
 * the real prototype and its `.constructor` IS the real, unguarded class:
 *
 *     new (fs.ReadStream.prototype.constructor)(deniedPath)   // guard never runs
 *
 * That defeated the three sites still using a Proxy (`fs.ReadStream`/`WriteStream`,
 * `vm.Script`/`SourceTextModule`/`SyntheticModule`, `worker_threads.Worker`) — unguarded file
 * reads/writes, unguarded code evaluation, and unguarded worker spawn, the last being a full
 * capability escape because a worker is a fresh Node context with none of capwall's shims.
 * All three are now guarded SUBCLASSES, the pattern `net`/`child_process` were converted to
 * during the M4 adversarial reviews for exactly this reason.
 *
 * This file covers the WHOLE family of guarded classes, not only the three converted sites,
 * so a future site cannot regress silently:
 *  - a behavioural test per class: the escape is denied end-to-end through the loader;
 *  - a structural test over every guarded class in every shim: the class capwall hands out is
 *    NOT the real class, and its `.prototype.constructor` points back at the guarded class.
 *    A construct-trap Proxy fails the second assertion by construction.
 *  - compatibility tests: the ordinary, non-adversarial shapes still work under a grant.
 *
 * #71 rides on the same structural table: a guarded class overrides `Symbol.hasInstance` so
 * `instanceof` still answers true for instances the real builtin's own factories produce, and
 * that override is INHERITED down the static chain. A dependency writing `class Mine extends
 * net.Socket {}` therefore made `anyRealSocket instanceof Mine` true, where un-shimmed Node says
 * false. The table asserts the corrected semantics over EVERY guarded class at once.
 *
 * #65 extends the same idea from classes to INSTANCES. A shimmed namespace also exposes
 * pre-built objects that carry the capability — `http.globalAgent`/`https.globalAgent` — which
 * the shims copied through verbatim, real `createConnection` and all.
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as realFs from "node:fs";
import * as realNet from "node:net";
import * as realTls from "node:tls";
import * as realHttp from "node:http";
import * as realHttps from "node:https";
import * as realHttp2 from "node:http2";
import * as realDgram from "node:dgram";
import * as realModule from "node:module";
import * as realVm from "node:vm";
import * as realChildProcess from "node:child_process";
import * as realWorkerThreads from "node:worker_threads";
import { describe, expect, it } from "vitest";
import { install, loadPolicyFromObject, type Policy } from "../src/index.js";
import { buildShimRegistry } from "../src/shims/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");
const DATA = path.join(FIXTURE, "data.txt");

/** Only the members this file exercises — the fixture exports far more. */
interface FixtureDep {
  readViaReadStreamConstructorEscape(target: string): void;
  writeViaWriteStreamConstructorEscape(target: string): void;
  runVmViaScriptConstructorEscape(code: string): unknown;
  spawnWorkerViaConstructorEscape(): { terminate(): Promise<number> };
  connectViaSocketPrototypeConstructorEscape(host: string, port: number): void;
  connectViaTlsSocketConstructorEscape(host: string, port: number): void;
  requestViaClientRequestConstructorEscape(host: string, port: number): void;
  connectViaHttpAgentConstructorEscape(host: string, port: number): void;
  sendViaDgramSocketConstructorEscape(host: string, port: number): void;
  spawnViaChildProcessPrototypeConstructorEscape(): unknown;
  connectViaHttpGlobalAgent(host: string, port: number): void;
  connectViaHttpsGlobalAgent(host: string, port: number): void;
  tamperWithGlobalAgent(): Record<string, { ok: boolean; value?: unknown; error?: string }>;
  readViaStreamClass(): Promise<string>;
  writeViaStreamClass(target: string): Promise<boolean>;
  readViaOwnReadStreamSubclass(target: string): Promise<string>;
  streamClassShape(): Record<string, boolean | string>;
}

function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

function withCapwall<T>(policy: Policy, mode: "observe" | "enforce", fn: (dep: FixtureDep) => T): T {
  const handle = install(policy, mode, { projectRoot: here, onDecision: () => {} });
  try {
    return fn(loadFixtureFresh());
  } finally {
    handle.uninstall();
  }
}

const denyAll = (): Policy =>
  loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: here });

const capabilityError = expect.objectContaining({ name: "CapabilityError" });

describe("#64 — .prototype.constructor escapes are denied (deny-all enforce)", () => {
  // The three sites this issue converted. Each was a confirmed, working bypass before the fix.
  it("fs.ReadStream.prototype.constructor cannot read a denied path", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.readViaReadStreamConstructorEscape(DATA)).toThrowError(capabilityError);
    });
  });

  it("fs.WriteStream.prototype.constructor cannot write a denied path", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() =>
        dep.writeViaWriteStreamConstructorEscape(path.join(FIXTURE, "escape-must-not-exist.txt")),
      ).toThrowError(capabilityError);
      // Fail-closed all the way down: nothing was created on disk.
      expect(realFs.existsSync(path.join(FIXTURE, "escape-must-not-exist.txt"))).toBe(false);
    });
  });

  it("vm.Script.prototype.constructor cannot evaluate code", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.runVmViaScriptConstructorEscape("1 + 1")).toThrowError(capabilityError);
    });
  });

  it("worker_threads.Worker.prototype.constructor cannot spawn a worker", () => {
    // The highest-consequence case: a spawned worker is a fresh Node context with no shims, so
    // an unguarded spawn escapes capwall entirely. The guard must fire BEFORE the thread exists.
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.spawnWorkerViaConstructorEscape()).toThrowError(capabilityError);
    });
  });

  // The already-converted sites, pinned here too so the whole family is covered by one suite.
  it("net.Socket.prototype.constructor cannot connect", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() =>
        dep.connectViaSocketPrototypeConstructorEscape("evil.example.com", 443),
      ).toThrowError(capabilityError);
    });
  });

  it("tls.TLSSocket.prototype.constructor cannot connect", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() =>
        dep.connectViaTlsSocketConstructorEscape("evil.example.com", 443),
      ).toThrowError(capabilityError);
    });
  });

  it("http.ClientRequest.prototype.constructor cannot request", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() =>
        dep.requestViaClientRequestConstructorEscape("evil.example.com", 80),
      ).toThrowError(capabilityError);
    });
  });

  it("http.Agent.prototype.constructor cannot create a connection", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() =>
        dep.connectViaHttpAgentConstructorEscape("evil.example.com", 80),
      ).toThrowError(capabilityError);
    });
  });

  it("dgram.Socket.prototype.constructor cannot send", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() =>
        dep.sendViaDgramSocketConstructorEscape("evil.example.com", 53),
      ).toThrowError(capabilityError);
    });
  });

  it("child_process.ChildProcess.prototype.constructor cannot spawn", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.spawnViaChildProcessPrototypeConstructorEscape()).toThrowError(
        capabilityError,
      );
    });
  });
});

/**
 * Every guarded class capwall exposes, by shim specifier. `optional` names are absent on some
 * Node builds (`fs.FileReadStream` aliases; `vm.SourceTextModule`/`SyntheticModule` need
 * `--experimental-vm-modules`) — their absence must not fail the test or the install.
 */
const GUARDED_CLASSES: ReadonlyArray<{
  specifier: string;
  real: Record<string, unknown>;
  names: readonly string[];
}> = [
  {
    specifier: "fs",
    real: realFs as unknown as Record<string, unknown>,
    names: ["ReadStream", "WriteStream", "FileReadStream", "FileWriteStream"],
  },
  { specifier: "net", real: realNet as unknown as Record<string, unknown>, names: ["Socket"] },
  { specifier: "tls", real: realTls as unknown as Record<string, unknown>, names: ["TLSSocket"] },
  {
    specifier: "http",
    real: realHttp as unknown as Record<string, unknown>,
    names: ["ClientRequest", "Agent"],
  },
  {
    specifier: "https",
    real: realHttps as unknown as Record<string, unknown>,
    names: ["ClientRequest", "Agent"],
  },
  { specifier: "dgram", real: realDgram as unknown as Record<string, unknown>, names: ["Socket"] },
  {
    specifier: "vm",
    real: realVm as unknown as Record<string, unknown>,
    names: ["Script", "SourceTextModule", "SyntheticModule"],
  },
  {
    specifier: "child_process",
    real: realChildProcess as unknown as Record<string, unknown>,
    names: ["ChildProcess"],
  },
  {
    specifier: "worker_threads",
    real: realWorkerThreads as unknown as Record<string, unknown>,
    names: ["Worker"],
  },
];

/** Just enough of a constructor type to `extend` and to sit on the right of `instanceof`.
 * Deliberately not `any` — `typescript/no-explicit-any` is an error in this repo. */
type GuardedCtor = new (...args: unknown[]) => object;

describe("#64 — structural invariant over EVERY guarded class", () => {
  it("no guarded class leaks the real class through .prototype.constructor", () => {
    const reg = buildShimRegistry({
      policy: denyAll(),
      mode: "enforce",
      onDecision: () => {},
      projectRoot: here,
    });
    let checked = 0;
    for (const { specifier, real, names } of GUARDED_CLASSES) {
      const shim = reg.get(specifier) as Record<string, unknown> | undefined;
      expect(shim, `${specifier} shim is registered`).toBeDefined();
      for (const name of names) {
        const RealClass = real[name];
        if (typeof RealClass !== "function") continue; // not present on this Node — fine
        const ShimClass = shim![name];
        expect(typeof ShimClass, `${specifier}.${name} is a function`).toBe("function");
        // 1. capwall must hand out its OWN class, never the real one.
        expect(ShimClass, `${specifier}.${name} is not the real class`).not.toBe(RealClass);
        // 2. THE assertion of #64: walking `.prototype.constructor` must land back on the
        //    guarded class. A construct-trap Proxy forwards `.prototype` to its target and so
        //    yields the REAL class here — this is what makes the escape impossible to miss.
        const proto = (ShimClass as { prototype?: unknown }).prototype as
          | Record<string, unknown>
          | undefined;
        expect(proto, `${specifier}.${name}.prototype exists`).toBeDefined();
        expect(
          proto!["constructor"],
          `${specifier}.${name}.prototype.constructor is the guarded class`,
        ).toBe(ShimClass);
        // 3. The guarded class must still be a genuine subclass of the real one, so instances
        //    keep the real prototype chain and `instanceof` stays honest.
        expect(
          Object.getPrototypeOf(proto!),
          `${specifier}.${name} extends the real prototype`,
        ).toBe((RealClass as { prototype: unknown }).prototype);
        expect((ShimClass as { name: string }).name).toBe((RealClass as { name: string }).name);
        checked++;
      }
    }
    // Guard against the table silently going empty (a rename would otherwise pass vacuously).
    expect(checked).toBeGreaterThanOrEqual(11);
  });
});

describe("#71 — Symbol.hasInstance does not leak down the static chain, for EVERY guarded class", () => {
  it("a real instance is NOT instanceof a dependency's own subclass", () => {
    // A guarded class must answer `true` for instances the real builtin's factories produce
    // (`fs.createReadStream()` builds a REAL ReadStream), which is why it overrides
    // `Symbol.hasInstance` at all. But that method is INHERITED down the static chain, so the
    // naive body — "is x an instance of the real class?" — also answered for a dependency's
    // `class Mine extends net.Socket {}`, making `anyRealSocket instanceof Mine` true where
    // un-shimmed Node says false. Silently inverting a package's type dispatch.
    //
    // Instances are built with `Object.create(Cls.prototype)` rather than `new Cls()`: the
    // question is purely about prototype-chain membership, and constructing the real thing for
    // eleven classes would open fds, compile code and spawn an OS thread to prove nothing extra.
    const reg = buildShimRegistry({
      policy: denyAll(),
      mode: "enforce",
      onDecision: () => {},
      projectRoot: here,
    });
    let checked = 0;
    for (const { specifier, real, names } of GUARDED_CLASSES) {
      const shim = reg.get(specifier) as Record<string, unknown> | undefined;
      for (const name of names) {
        const RealClass = real[name];
        if (typeof RealClass !== "function") continue; // not present on this Node — fine
        const ShimClass = shim![name] as GuardedCtor;
        const Sub = class extends ShimClass {}; // what a dependency writes
        const realShaped = Object.create((RealClass as { prototype: object }).prototype) as object;
        const subShaped = Object.create(Sub.prototype) as object;

        // Unchanged: a factory-built real instance still satisfies the guarded class.
        expect(realShaped instanceof ShimClass, `real ${specifier}.${name} instanceof guarded`).toBe(true);
        // THE #71 assertion: it must NOT satisfy the dependency's subclass.
        expect(realShaped instanceof Sub, `real ${specifier}.${name} NOT instanceof user subclass`).toBe(false);
        // ...and the fallback must be real `OrdinaryHasInstance`, not a blanket `false`:
        // the subclass's own instances still match it, and also match the guarded class.
        expect(subShaped instanceof Sub, `${specifier}.${name} subclass instance instanceof subclass`).toBe(true);
        expect(subShaped instanceof ShimClass, `${specifier}.${name} subclass instance instanceof guarded`).toBe(true);
        // An unrelated object matches neither — guards against a hasInstance that says true.
        expect({} instanceof ShimClass, `plain object NOT instanceof ${specifier}.${name}`).toBe(false);
        expect({} instanceof Sub, `plain object NOT instanceof ${specifier}.${name} subclass`).toBe(false);
        checked++;
      }
    }
    expect(checked).toBeGreaterThanOrEqual(11);
  });
});

/**
 * ISSUE #65 — the same escape one shape over: a shimmed namespace exposes pre-built INSTANCES
 * that carry the capability, and the shims' copy loops duplicated them through with their REAL
 * methods intact. `http.globalAgent.createConnection({host, port})` connected under a deny-all
 * enforce policy with no guard and, worse, no log line — invisible to `observe` and `capwall
 * diff` too.
 *
 * The audit behind the fix walked every object-valued export of every shimmed namespace. The
 * table below is that inventory, so a newly-exported instance cannot slip in unexamined.
 */
const INSTANCE_HOLDERS: ReadonlyArray<{ specifier: string; real: Record<string, unknown>; names: readonly string[] }> = [
  { specifier: "http", real: realHttp as unknown as Record<string, unknown>, names: ["globalAgent"] },
  { specifier: "https", real: realHttps as unknown as Record<string, unknown>, names: ["globalAgent"] },
];

describe("#65 — pre-built capability-bearing INSTANCES are guarded, not copied through", () => {
  it("http.globalAgent.createConnection cannot connect (deny-all enforce)", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.connectViaHttpGlobalAgent("evil.example.com", 80)).toThrowError(capabilityError);
    });
  });

  it("https.globalAgent.createConnection cannot connect (deny-all enforce)", () => {
    withCapwall(denyAll(), "enforce", (dep) => {
      expect(() => dep.connectViaHttpsGlobalAgent("evil.example.com", 443)).toThrowError(capabilityError);
    });
  });

  it("the escape is RECORDED, so observe and capwall diff can see it", () => {
    // The half of #65 that made it worse than an ordinary gap: nothing was logged either, so the
    // trace-to-policy workflow could not surface the egress even in observe mode.
    const seen: string[] = [];
    const handle = install(denyAll(), "observe", {
      projectRoot: here,
      onDecision: (pkg, d) => seen.push(`${pkg}:${d.observed?.kind ?? "?"}`),
    });
    try {
      loadFixtureFresh().connectViaHttpGlobalAgent("127.0.0.1", 9);
    } finally {
      handle.uninstall();
    }
    expect(seen).toContain("fixture-dep:net");
  });

  it("the exposed instance is capwall's guarded view, never the real process-global agent", () => {
    const reg = buildShimRegistry({
      policy: denyAll(),
      mode: "enforce",
      onDecision: () => {},
      projectRoot: here,
    });
    let checked = 0;
    for (const { specifier, real, names } of INSTANCE_HOLDERS) {
      const shim = reg.get(specifier) as Record<string, unknown> | undefined;
      expect(shim, `${specifier} shim is registered`).toBeDefined();
      for (const name of names) {
        const realInstance = real[name];
        const shimInstance = shim![name];
        // 1. Not the real object — a verbatim copy is exactly what #65 was.
        expect(shimInstance, `${specifier}.${name} is not the real instance`).not.toBe(realInstance);
        // 2. Stable identity: a fresh wrapper per read would break `===` and WeakMap keying.
        expect(shim![name], `${specifier}.${name} identity is stable`).toBe(shimInstance);
        // 3. Still an Agent as far as any consumer can tell — reads, prototype and `instanceof`
        //    all pass through, which is what keeps the default request path working.
        expect(shimInstance instanceof realHttp.Agent, `${specifier}.${name} instanceof Agent`).toBe(true);
        expect(Object.getPrototypeOf(shimInstance as object)).toBe(
          Object.getPrototypeOf(realInstance as object),
        );
        checked++;
      }
    }
    expect(checked).toBe(2);
  });
});

/**
 * ISSUE #88 — the same guarded view, one operation over: #65 gave it a `get` trap and nothing
 * else, so `set`/`defineProperty`/`deleteProperty`/`preventExtensions` took their DEFAULT
 * behaviour and forwarded to the Proxy's target — the real, process-global `Agent`. A dependency
 * could therefore mutate a process-global through capwall's own guarded view, `uninstall()` could
 * not take it back, and `Object.freeze(http.globalAgent)` broke the HTTP client for the whole
 * process. The guard itself always held (the `get` trap re-wraps whatever the underlying method
 * currently is), so this is a broken design invariant and a capwall-introduced DoS lever rather
 * than an escalation — which is exactly why it belongs next to #64/#65: the same reasoning that
 * moved the guarded CLASSES off Proxies had not been applied at the instance site.
 *
 * The mechanism-level assertions live in `test/net.test.ts`; this is the end-to-end half, run
 * from a real dependency through the loader, plus the part only an install/uninstall cycle can
 * show — that nothing survives teardown.
 */
describe("#88 — a dependency cannot mutate the process-global agent through the guarded view", () => {
  interface Attempt {
    ok: boolean;
    value?: unknown;
    error?: string;
  }

  /** Every own-property fact about the real agent that a forwarded operation would change. */
  const snapshotRealAgent = (): Record<string, unknown> => ({
    ownKeys: Reflect.ownKeys(realHttp.globalAgent).map(String).sort().join(","),
    ownCreateConnection: Object.getOwnPropertyDescriptor(realHttp.globalAgent, "createConnection"),
    createConnection: (realHttp.globalAgent as unknown as Record<string, unknown>)["createConnection"],
    frozen: Object.isFrozen(realHttp.globalAgent),
    extensible: Object.isExtensible(realHttp.globalAgent),
    prototype: Object.getPrototypeOf(realHttp.globalAgent),
  });

  it("the PoC's write/defineProperty/delete/freeze leave the real agent untouched, before AND after uninstall()", () => {
    const before = snapshotRealAgent();
    const originalMaxSockets = (realHttp.globalAgent as unknown as Record<string, unknown>)["maxSockets"];
    let report: Record<string, Attempt>;
    try {
      report = withCapwall(denyAll(), "enforce", (dep) => dep.tamperWithGlobalAgent());

      // The write is accepted into capwall's per-view shadow (ordinary JS semantics for the
      // object the dependency was handed) — and goes no further.
      expect(report["write"]).toMatchObject({ ok: true, value: "function" });
      // Structural operations are refused. In a CJS package's sloppy mode a refused `delete`
      // returns false rather than throwing, while `Object.defineProperty`/`freeze`/
      // `setPrototypeOf` throw whatever the mode.
      expect(report["defineProperty"]).toMatchObject({ ok: false, error: "TypeError" });
      expect(report["freeze"]).toMatchObject({ ok: false, error: "TypeError" });
      expect(report["setProto"]).toMatchObject({ ok: false, error: "TypeError" });
      expect(report["deleteState"]).toMatchObject({ ok: true, value: false });
      // Deleting the guarded key drops only capwall's shadow; the real agent never had an own
      // `createConnection`, so `true` is also what un-shimmed Node reports.
      expect(report["deleteGuarded"]).toMatchObject({ ok: true, value: true });
      // The ONE deliberate exception: live pool state is shared, so tuning still lands.
      expect(report["tunePool"]).toMatchObject({ ok: true, value: 3 });
      expect((realHttp.globalAgent as unknown as Record<string, unknown>)["maxSockets"]).toBe(3);
    } finally {
      (realHttp.globalAgent as unknown as Record<string, unknown>)["maxSockets"] = originalMaxSockets;
    }

    // `withCapwall` has already uninstalled by here — the point of the whole issue. Everything
    // except the deliberate pool write is gone, because it never happened.
    expect(snapshotRealAgent()).toEqual(before);
    expect(Object.isFrozen(realHttp.globalAgent)).toBe(false);
  });

  it("the process's own HTTP client still works afterwards", async () => {
    // The observable consequence of the old behaviour: after a dependency froze the view, every
    // `http.request()` in the process — capwall-mediated or not — threw `Cannot assign to read
    // only property 'totalSocketCount'`. This is the un-shimmed client, after the tampering.
    withCapwall(denyAll(), "enforce", (dep) => dep.tamperWithGlobalAgent());
    const srv = realHttp.createServer((_req, res) => res.end("ok"));
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
    const addr = srv.address();
    const port = addr && typeof addr === "object" ? addr.port : 0;
    try {
      const body = await new Promise<string>((resolve, reject) => {
        const req = realHttp.get(`http://127.0.0.1:${port}/`, (res) => {
          let out = "";
          res.setEncoding("utf8");
          res.on("data", (c: string) => (out += c));
          res.on("end", () => resolve(out));
        });
        req.on("error", reject);
      });
      expect(body).toBe("ok");
    } finally {
      await new Promise<void>((r) => srv.close(() => r()));
    }
  });
});

describe("#64 — ordinary (non-adversarial) shapes still work under a grant", () => {
  const grantFs = (): Policy =>
    loadPolicyFromObject(
      {
        version: 1,
        mode: "enforce",
        packages: { "fixture-dep": { fs: { read: ["./fixtures/**"], write: ["./fixtures/**"] } } },
      },
      { projectRoot: here },
    );

  it("new fs.ReadStream(path) reads and emits data/end", async () => {
    const result = withCapwall(grantFs(), "enforce", (dep) => dep.readViaStreamClass());
    await expect(result).resolves.toBe("fixture data\n");
  });

  it("new fs.WriteStream(path) writes and emits close", async () => {
    const target = path.join(FIXTURE, "written-by-stream-class.txt");
    try {
      const result = withCapwall(grantFs(), "enforce", (dep) => dep.writeViaStreamClass(target));
      await expect(result).resolves.toBe(true);
      expect(realFs.readFileSync(target, "utf8")).toBe("fixture-dep was here\n");
    } finally {
      realFs.rmSync(target, { force: true });
    }
  });

  it("a package may subclass fs.ReadStream further, and the subclass is still guarded", async () => {
    // Real packages do this, so it has to keep working — and the guard has to follow.
    const allowed = withCapwall(grantFs(), "enforce", (dep) =>
      dep.readViaOwnReadStreamSubclass(DATA),
    );
    await expect(allowed).resolves.toBe("fixture data\n");

    const denied = withCapwall(denyAll(), "enforce", (dep) =>
      dep.readViaOwnReadStreamSubclass(DATA),
    );
    await expect(denied).rejects.toMatchObject({ name: "CapabilityError" });
  });

  it("preserves instanceof, .constructor, alias identity, name, and the prototype chain", () => {
    const shape = withCapwall(grantFs(), "enforce", (dep) => dep.streamClassShape());
    expect(shape).toMatchObject({
      // fs.createReadStream builds a REAL ReadStream via Node's own factory; it must still
      // satisfy `instanceof fs.ReadStream` (that is what the Symbol.hasInstance override buys).
      createdInstanceOfGuarded: true,
      directInstanceOfGuarded: true,
      directConstructorIsGuarded: true,
      prototypeConstructorIsGuarded: true,
      // Real fs aliases FileReadStream to ReadStream; the two Proxies the old code built broke
      // that identity, two guarded subclasses would too — one shared subclass preserves it.
      readAliasIdentity: true,
      writeAliasIdentity: true,
      name: "ReadStream",
      protoReachesReadable: true,
      subInstanceOfSub: true,
      // A naive `Symbol.hasInstance` override is inherited down the static chain by a further
      // subclass and would make ANY real stream `instanceof Sub` — it must not.
      createdNotInstanceOfSub: true,
    });
  });
});

/**
 * ISSUE #96 — every guarded wrapper capwall builds restores the REAL function's `name` before
 * handing it out, because a shim that renames the ecosystem's functions is a divergence nobody
 * asked for and hardened mode FREEZES the wrapper, making a wrong name permanent. One site had
 * drifted (`http2.connect`, whose guard is assigned through a computed member, which does not
 * trigger JS name inference, so it reported `""`), and the audit that followed found a second
 * (`dgram.createSocket`) and a third (the `dgram` socket `send`/`connect` guards, which reported
 * `"guarded"` from `const guarded = function …`).
 *
 * It drifted precisely because nothing checked the set AS A WHOLE, so the test is a SWEEP rather
 * than a list of the three: every function-valued export capwall replaces, in every shimmed
 * namespace, compared against the real one. A new wrapper is covered the day it is added.
 */
const SHIM_NAMESPACES: ReadonlyArray<{ specifier: string; real: Record<string, unknown> }> = [
  { specifier: "fs", real: realFs as unknown as Record<string, unknown> },
  { specifier: "fs/promises", real: realFs.promises as unknown as Record<string, unknown> },
  { specifier: "net", real: realNet as unknown as Record<string, unknown> },
  { specifier: "tls", real: realTls as unknown as Record<string, unknown> },
  { specifier: "http", real: realHttp as unknown as Record<string, unknown> },
  { specifier: "https", real: realHttps as unknown as Record<string, unknown> },
  { specifier: "http2", real: realHttp2 as unknown as Record<string, unknown> },
  { specifier: "dgram", real: realDgram as unknown as Record<string, unknown> },
  { specifier: "vm", real: realVm as unknown as Record<string, unknown> },
  { specifier: "child_process", real: realChildProcess as unknown as Record<string, unknown> },
  { specifier: "worker_threads", real: realWorkerThreads as unknown as Record<string, unknown> },
  { specifier: "module", real: realModule as unknown as Record<string, unknown> },
];

describe("#96 — every guarded function reports the REAL function's name", () => {
  it("name parity across every replaced export of every shim namespace", () => {
    const reg = buildShimRegistry({
      policy: denyAll(),
      mode: "enforce",
      onDecision: () => {},
      projectRoot: here,
    });
    let checked = 0;
    for (const { specifier, real } of SHIM_NAMESPACES) {
      const shim = reg.get(specifier) as Record<string, unknown> | undefined;
      expect(shim, `${specifier} shim is registered`).toBeDefined();
      for (const key of Object.keys(shim!)) {
        const shimValue = shim![key];
        const realValue = real[key];
        if (typeof shimValue !== "function" || typeof realValue !== "function") continue;
        if (shimValue === realValue) continue; // copied through untouched — nothing to compare
        expect(
          (shimValue as { name: string }).name,
          `${specifier}.${key} reports the real function's name`,
        ).toBe((realValue as { name: string }).name);
        checked++;
      }
    }
    // A rename or a registry change must not make this pass vacuously. The count is the number
    // of guarded wrappers + guarded classes across every shim — 128 on Node 22, a handful fewer
    // where `fs.glob`/`vm.SourceTextModule` are absent — so the floor is set below the range
    // the supported Node versions produce, not at the exact figure.
    expect(checked).toBeGreaterThanOrEqual(100);
  });

  it("...and for the guarded functions that live on an INSTANCE, which a namespace sweep misses", () => {
    // Both #96 sites the sweep above cannot see: a method installed on an object capwall hands
    // back from a factory (`dgram.createSocket()`) and a method on a guarded instance VIEW
    // (`http.globalAgent`, #65). `dgram`'s real `send`/`connect` report `""` — Node assigns them
    // through a member expression too — so parity here means matching that, not prettifying it.
    const reg = buildShimRegistry({
      policy: denyAll(),
      mode: "enforce",
      onDecision: () => {},
      projectRoot: here,
    });
    const dgramShim = reg.get("dgram") as unknown as typeof realDgram;
    const socket = dgramShim.createSocket("udp4") as unknown as Record<string, unknown>;
    const realSocket = realDgram.createSocket("udp4") as unknown as Record<string, unknown>;
    try {
      for (const key of ["send", "connect"]) {
        expect((socket[key] as { name: string }).name, `dgram socket ${key}`).toBe(
          (realSocket[key] as { name: string }).name,
        );
      }
    } finally {
      // Never bound, so there is no handle to leak; close defensively and ignore the throw a
      // never-bound socket produces on some Node versions.
      for (const s of [socket, realSocket]) {
        try {
          (s["close"] as () => void).call(s);
        } catch {
          /* not running */
        }
      }
    }
    for (const specifier of ["http", "https"]) {
      const shim = reg.get(specifier) as Record<string, unknown>;
      const agent = shim["globalAgent"] as Record<string, unknown>;
      const realAgent = (specifier === "http" ? realHttp : realHttps).globalAgent as unknown as Record<
        string,
        unknown
      >;
      expect((agent["createConnection"] as { name: string }).name, `${specifier}.globalAgent`).toBe(
        (realAgent["createConnection"] as { name: string }).name,
      );
    }
  });
});
