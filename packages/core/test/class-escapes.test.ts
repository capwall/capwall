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
import * as realDgram from "node:dgram";
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
