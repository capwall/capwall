/**
 * ARGUMENT-NORMALIZATION REGRESSIONS — issue #99.
 *
 * capwall re-derives what Node is about to do (which host, which port, which file) in order to
 * check it against a policy, then forwards to the real builtin. **Any divergence between
 * capwall's derivation and Node's real one is a place where the guarded target and the actual
 * target differ** — the same class as the getter-TOCTOU of #26/#56, arrived at by a different
 * route. #95 (a numeric-string `dgram` port that skipped the gate entirely) and #46 (a `tls`
 * overlay object read from an index Node never merges) were both found by accident; #99 was the
 * systematic sweep, comparing each entry point against Node's OWN normalization source rather
 * than against what the signature appears to say.
 *
 * Every case below is a divergence that sweep found. Each is written the way the PoC was: assert
 * the capability capwall RECORDS, and — where a socket or a file is actually reachable — assert
 * that the thing Node really touched is the thing that was guarded. A test that only checks
 * "denied" would have passed against the buggy code for several of these, because the bug was
 * guarding the WRONG target, not failing to guard.
 *
 * Kept in its own file, named for what it covers, so it merges cleanly alongside the
 * composition/lifecycle matrix work.
 */
import { createRequire } from "node:module";
import * as nodeFs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createFsShim } from "../src/shims/fs.js";
import {
  createHttp2Shim,
  createHttpShim,
  createHttpsShim,
  createNetShim,
  createTlsShim,
} from "../src/shims/net.js";
import { install, loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";
import type { ShimContext } from "../src/shims/runtime.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);

type Recorded = { pkg: string; decision: Decision };

function makeCtx(mode: "observe" | "enforce" = "observe"): {
  ctx: ShimContext;
  decisions: Recorded[];
} {
  const decisions: Recorded[] = [];
  // OBSERVE by default: a denial tells us only that something was denied, whereas the whole
  // question here is WHICH target the shim derived. Observe records it and lets the call run.
  const policy: Policy = loadPolicyFromObject({ version: 1, mode }, { projectRoot: here });
  return { decisions, ctx: { policy, mode, onDecision: (pkg, decision) => decisions.push({ pkg, decision }) } };
}

/** The single capability request recorded by a call, as `evaluate` observed it. */
function observedOf(decisions: Recorded[]): Record<string, unknown> {
  expect(decisions.length).toBeGreaterThan(0);
  return decisions[0]!.decision.observed as unknown as Record<string, unknown>;
}

/** Bind an ephemeral port and close it: connecting afterwards is a reliable ECONNREFUSED that
 * never leaves loopback. */
async function closedLocalPort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = addr && typeof addr === "object" ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

/** A loopback TCP server that records how many connections it accepted — the ground truth for
 * "did Node actually dial the host capwall guarded?". Sockets are destroyed on arrival and
 * tracked, so `close()` cannot hang waiting on a client that is still holding one open. */
async function startCounter(): Promise<{ port: number; accepted: () => number; close: () => Promise<void> }> {
  let n = 0;
  const live = new Set<net.Socket>();
  const srv = net.createServer((s) => {
    n += 1;
    live.add(s);
    s.on("close", () => live.delete(s));
    s.on("error", () => {});
    s.destroy();
  });
  await new Promise<void>((resolve, reject) => {
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = srv.address();
  return {
    port: addr && typeof addr === "object" ? addr.port : 0,
    accepted: () => n,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of live) s.destroy();
        srv.close(() => resolve());
      }),
  };
}

/** Let the event loop turn long enough for a connection attempt to reach the server. */
const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 100));

// ═══════════════════════════════════════════════════════════════════════════════════════════
// net — `net._normalizeArgs` (lib/net.js)
// ═══════════════════════════════════════════════════════════════════════════════════════════

describe("#99 net — a string first argument is a PATH only when it is not a number", () => {
  // Node: `isPipeName(s) = typeof s === 'string' && toNumber(s) === false`, where
  // `toNumber(x) = (x = Number(x)) >= 0 ? x : false`. capwall treated EVERY string first
  // argument as an IPC socket path, so a numeric string was recorded as the `ipc` capability
  // while Node opened a TCP connection — a package holding any IPC grant reached arbitrary
  // TCP egress through it.
  it("derives a TCP target from a NUMERIC-STRING port, not an ipc path", async () => {
    const server = await startCounter();
    const { ctx, decisions } = makeCtx();
    const shim = createNetShim(ctx);
    await new Promise<void>((resolve) => {
      const s = shim.connect(String(server.port) as unknown as number, "127.0.0.1", () => {
        s.end();
        resolve();
      });
      s.on("error", () => resolve());
    });
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "127.0.0.1", port: server.port });
    expect(server.accepted()).toBe(1); // Node really did dial it — the guard was not decorative
    await server.close();
  });

  it("still derives an ipc path from a NON-numeric string", () => {
    const { ctx, decisions } = makeCtx();
    const shim = createNetShim(ctx);
    const s = shim.connect("/tmp/capwall-argnorm-no-such.sock");
    s.on("error", () => {});
    s.destroy();
    expect(observedOf(decisions)["kind"]).toBe("ipc");
  });

  it("derives a TCP target from `{ path: '' }` — Node's pipe test is `!!path`, not typeof", async () => {
    // `const { path } = options; const pipe = !!path;` — an empty-string `path` is FALSY, so
    // Node ignores it and dials `host:port`. capwall read `typeof path === "string"` and
    // recorded an `ipc` capability on the empty path instead.
    const server = await startCounter();
    const { ctx, decisions } = makeCtx();
    const shim = createNetShim(ctx);
    await new Promise<void>((resolve) => {
      const s = shim.connect({ path: "", host: "127.0.0.1", port: server.port } as never, () => {
        s.end();
        resolve();
      });
      s.on("error", () => resolve());
    });
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "127.0.0.1", port: server.port });
    expect(server.accepted()).toBe(1);
    await server.close();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// tls — `normalizeConnectArgs` (lib/internal/tls/wrap.js)
// ═══════════════════════════════════════════════════════════════════════════════════════════

describe("#99 tls — the overlay slot is an ObjectAssign MERGE, not a property read", () => {
  // `if (listArgs[1] !== null && typeof listArgs[1] === 'object') ObjectAssign(options, listArgs[1]);
  //  else ObjectAssign(options, listArgs[2]);`
  it("ignores a URL in the overlay slot, which contributes nothing to Node's merge", async () => {
    // A `URL`'s `host`/`port` live on `URL.prototype`, so `ObjectAssign` copies NEITHER. capwall
    // read them through the prototype chain and guarded the URL's host while Node connected to
    // the positional one — #46's shape, one argument shape over.
    const port = await closedLocalPort();
    const { ctx, decisions } = makeCtx();
    const shim = createTlsShim(ctx);
    const s = shim.connect(port, "127.0.0.1", new URL("https://granted.example/") as never);
    s.on("error", () => {});
    s.destroy();
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "127.0.0.1", port });
  });

  it("does not fall through to args[2] when args[1] is an object that merges nothing", async () => {
    // Node consults exactly ONE slot. With an object in slot 1, slot 2 is never read — so an
    // overlay parked there must not move the guarded target.
    const port = await closedLocalPort();
    const { ctx, decisions } = makeCtx();
    const shim = createTlsShim(ctx);
    const s = shim.connect(port, "127.0.0.1", {} as never, { host: "granted.example" } as never);
    s.on("error", () => {});
    s.destroy();
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "127.0.0.1", port });
  });

  it("still honors a real object overlay in slot 1 (the #46 control)", async () => {
    const port = await closedLocalPort();
    const { ctx, decisions } = makeCtx();
    const shim = createTlsShim(ctx);
    const s = shim.connect(443, "granted.example", { host: "127.0.0.1", port } as never);
    s.on("error", () => {});
    s.destroy();
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "127.0.0.1", port });
  });

  it("derives a TCP target from a numeric-string port here too", async () => {
    const port = await closedLocalPort();
    const { ctx, decisions } = makeCtx();
    const shim = createTlsShim(ctx);
    const s = shim.connect(String(port) as never, "127.0.0.1");
    s.on("error", () => {});
    s.destroy();
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "127.0.0.1", port });
  });

  it("does NOT apply the tls overlay merge to `TLSSocket#connect`, which is the net rule", async () => {
    // `normalizeConnectArgs` and its `ObjectAssign` overlay live in `tls.connect` alone.
    // `TLSSocket` defines no `connect`: it inherits `net.Socket.prototype.connect`, which
    // normalizes with `net._normalizeArgs` and merges NOTHING. Sharing the tls resolver between
    // the two made an options object at args[2] displace the positional host — guard
    // `granted.example`, dial `127.0.0.1`, which is #46's false-allow by another route.
    const server = await startCounter();
    const { ctx, decisions } = makeCtx();
    const shim = createTlsShim(ctx);
    // `new tls.TLSSocket()` with no wrapped socket is legal at runtime (the typings insist on
    // one); wrapping an already-constructed socket would skip the connect entirely.
    const sock = new (shim.TLSSocket as unknown as new () => import("node:tls").TLSSocket)();
    (sock.connect as (...a: unknown[]) => unknown)(server.port, "127.0.0.1", {
      host: "granted.example",
    });
    sock.on("error", () => {});
    await settle();
    sock.destroy();
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "127.0.0.1", port: server.port });
    expect(server.accepted()).toBe(1);
    await server.close();
  });

  it("keeps the callback in the slot ObjectAssign also merges", async () => {
    // `tls.connect(port, host, cb)` puts a FUNCTION in the overlay slot; Node merges it
    // harmlessly AND uses it as the callback. Substituting a pinned clone would delete it.
    const port = await closedLocalPort();
    const { ctx } = makeCtx();
    const shim = createTlsShim(ctx);
    const s = (shim.connect as (...a: unknown[]) => import("node:tls").TLSSocket)(port, "127.0.0.1", () => {});
    expect(s.listenerCount("secureConnect")).toBe(1);
    s.on("error", () => {});
    s.destroy();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// http(s) — `ClientRequest` + `urlToHttpOptions` (lib/_http_client.js, lib/internal/url.js)
// ═══════════════════════════════════════════════════════════════════════════════════════════

describe("#99 http — `isURL` is duck-typed, and that decides whether args[1] is an overlay", () => {
  // `isURL(self) = Boolean(self?.href && self.protocol && self.auth === undefined && self.path === undefined)`
  it("treats a duck-typed url-like object as a URL, so args[1] is the OVERLAY", async () => {
    const port = await closedLocalPort();
    const { ctx, decisions } = makeCtx();
    const shim = createHttpShim(ctx);
    const req = shim.request(
      { href: "http://granted.example/", protocol: "http:", hostname: "granted.example", port: 80 } as never,
      { hostname: "127.0.0.1", port } as never,
    );
    req.on("error", () => {});
    req.destroy();
    // Node merges the overlay over the url — so the OVERLAY names the destination, and that is
    // what must be recorded. With `instanceof URL` capwall recorded `granted.example:80`.
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "127.0.0.1", port });
  });

  it("keeps args[1] as the CALLBACK for a plain options bag (the #46 control)", async () => {
    // With an options bag at args[0], Node does `cb = args[1]` — it is NOT an overlay — and then
    // `this.once('response', cb)` throws for a non-function. capwall must derive the same target
    // Node would have, and let that throw happen unchanged rather than merging args[1].
    const port = await closedLocalPort();
    const { ctx, decisions } = makeCtx();
    const shim = createHttpShim(ctx);
    expect(() =>
      shim.request({ hostname: "127.0.0.1", port } as never, { hostname: "granted.example" } as never),
    ).toThrow(/listener/);
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "127.0.0.1", port });
  });

  it("falls through an EMPTY `hostname` to `host`, exactly as Node's `||` chain does", async () => {
    // `validateHost(options.hostname) || validateHost(options.host) || 'localhost'`. capwall
    // tested `typeof hostname === "string"`, so `hostname: ""` survived as the guarded host
    // while Node went on to use `host`.
    const port = await closedLocalPort();
    const { ctx, decisions } = makeCtx();
    const shim = createHttpShim(ctx);
    const req = shim.request({ hostname: "", host: "127.0.0.1", port } as never);
    req.on("error", () => {});
    req.destroy();
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "127.0.0.1", port });
  });

  it("lets a URL's `hostname` beat an overlay's `host`, as Node resolves the MERGED object", async () => {
    // Node merges first and only then applies `hostname || host`, so an overlay that supplies
    // only `host` never displaces the url's `hostname`. Collapsing the two per-layer made
    // capwall guard — and, because it pins what it guards, actually DIAL — the overlay's host.
    const server = await startCounter();
    const { ctx, decisions } = makeCtx();
    const shim = createHttpShim(ctx);
    const req = shim.request(new URL(`http://127.0.0.1:${server.port}/`), { host: "granted.example" } as never);
    req.on("error", () => {});
    req.end();
    await settle();
    req.destroy();
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "127.0.0.1", port: server.port });
    expect(server.accepted()).toBe(1);
    await server.close();
  });

  it("still resolves `defaultPort` ahead of the scheme default (the #46 control)", async () => {
    const { ctx, decisions } = makeCtx();
    const shim = createHttpsShim(ctx);
    const req = shim.request({ hostname: "127.0.0.1", defaultPort: 8123 } as never);
    req.on("error", () => {});
    req.destroy();
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "127.0.0.1", port: 8123 });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// http2 — `connect` (lib/internal/http2/core.js)
// ═══════════════════════════════════════════════════════════════════════════════════════════

describe("#99 http2 — a plain OBJECT is a first-class authority", () => {
  // `assertIsObject(authority, 'authority', ['string', 'Object', 'URL'])`. capwall ran every
  // non-`URL` authority through `new URL(String(authority))`, which for an object parses
  // "[object Object]", throws, and left the guard pointing at the `localhost:443` fallback
  // while Node dialled the object's own hostname and port.
  it("derives the target from an object authority's hostname/port/protocol", async () => {
    const server = await startCounter();
    const { ctx, decisions } = makeCtx();
    const shim = createHttp2Shim(ctx);
    const session = shim.connect({
      protocol: "http:",
      hostname: "127.0.0.1",
      port: server.port,
    } as never);
    session.on("error", () => {});
    await settle();
    session.destroy();
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "127.0.0.1", port: server.port });
    await server.close();
  });

  it("falls back to an object authority's `host` when it has no `hostname`", () => {
    const { ctx, decisions } = makeCtx();
    const shim = createHttp2Shim(ctx);
    const session = shim.connect({ protocol: "http:", host: "granted.example", port: 8080 } as never);
    session.on("error", () => {});
    session.destroy();
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "granted.example", port: 8080 });
  });

  it("keeps the scheme-aware default port for the string form (the control)", () => {
    const { ctx, decisions } = makeCtx();
    const shim = createHttp2Shim(ctx);
    const session = shim.connect("http://granted.example/");
    session.on("error", () => {});
    session.destroy();
    expect(observedOf(decisions)).toEqual({ kind: "net", host: "granted.example", port: 80 });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// fs — `getValidatedPath` → `toPathIfFileURL` → `validatePath` (lib/internal/fs/utils.js)
// ═══════════════════════════════════════════════════════════════════════════════════════════

describe("#99 fs — capwall must accept every path shape Node accepts", () => {
  let dir = "";
  let secret = "";
  let ok = "";

  beforeEach(() => {
    dir = nodeFs.mkdtempSync(path.join(os.tmpdir(), "capwall-argnorm-"));
    secret = path.join(dir, "secret.txt");
    ok = path.join(dir, "ok.txt");
    nodeFs.writeFileSync(secret, "SECRET");
    nodeFs.writeFileSync(ok, "OK");
  });
  afterEach(() => {
    nodeFs.rmSync(dir, { recursive: true, force: true });
  });

  it("gates a DUCK-TYPED file URL — Node's `isURL` is not `instanceof URL`", () => {
    // `toPathIfFileURL` calls the duck-typed `isURL`, so `{href, protocol: "file:", pathname}`
    // is a real path to `fs`. capwall returned `null` for it and skipped the gate ENTIRELY —
    // an un-gated, unlogged read under a deny-all enforce policy, the #95 failure mode.
    const { ctx, decisions } = makeCtx("enforce");
    const shim = createFsShim(ctx);
    const duck = { href: pathToFileURL(secret).href, protocol: "file:", pathname: secret, hostname: "" };
    expect(() => shim.readFileSync(duck as never)).toThrow(/deny-by-default/);
    expect(observedOf(decisions)).toEqual({ kind: "fs", access: "read", path: secret });
  });

  it("gates a plain Uint8Array path — Node's `validatePath` accepts any Uint8Array", () => {
    const { ctx, decisions } = makeCtx("enforce");
    const shim = createFsShim(ctx);
    const u8 = new Uint8Array(Buffer.from(secret));
    expect(() => shim.readFileSync(u8 as never)).toThrow(/deny-by-default/);
    expect(observedOf(decisions)).toEqual({ kind: "fs", access: "read", path: secret });
  });

  it("PINS a URL argument, so a shadowed `pathname` cannot open a different file", () => {
    // capwall converted the URL to compute the guarded path and then forwarded the URL, which
    // real `fs` converts a SECOND time. An own accessor may legally answer differently: guard
    // `/tmp/…/ok.txt`, open `/tmp/…/secret.txt`. The fix forwards the converted STRING.
    const { ctx, decisions } = makeCtx(); // observe: the read must actually happen
    const shim = createFsShim(ctx);
    const u = pathToFileURL(ok);
    let reads = 0;
    Object.defineProperty(u, "pathname", {
      get: () => (reads++ === 0 ? ok : secret),
      configurable: true,
    });
    const content = shim.readFileSync(u, "utf8");
    expect(observedOf(decisions)).toEqual({ kind: "fs", access: "read", path: ok });
    expect(content).toBe("OK"); // the guarded file — not "SECRET"
  });

  it("gates `openAsBlob`, which reads the file's contents", async () => {
    const { ctx, decisions } = makeCtx("enforce");
    const shim = createFsShim(ctx);
    await expect(shim.openAsBlob(secret)).rejects.toThrow(/deny-by-default/);
    expect(observedOf(decisions)).toEqual({ kind: "fs", access: "read", path: secret });
  });

  it("still ignores an fd, which is the documented out-of-scope surface (the control)", () => {
    const { ctx, decisions } = makeCtx("enforce");
    const shim = createFsShim(ctx);
    const fd = nodeFs.openSync(ok, "r");
    try {
      expect(shim.readFileSync(fd, "utf8")).toBe("OK");
    } finally {
      nodeFs.closeSync(fd);
    }
    expect(decisions).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// dgram — `lookup4`/`lookup6` (lib/internal/dgram.js)
// ═══════════════════════════════════════════════════════════════════════════════════════════

describe("#99 dgram — an absent address defaults to an IP, per socket type", () => {
  // `lookup(address || '127.0.0.1', 4, cb)` / `lookup(address || '::1', 6, cb)`. capwall
  // guarded "localhost" for both, so `capwall observe` recorded a host the policy an operator
  // would write (`127.0.0.1`) then denied.
  const decisions: Recorded[] = [];
  let handle: { uninstall(): void } | undefined;

  const hasIpv6Loopback = (): boolean =>
    Object.values(os.networkInterfaces()).some((ifaces) =>
      (ifaces ?? []).some((i) => i.address === "::1" && i.internal),
    );

  beforeEach(() => {
    decisions.length = 0;
    handle = install(
      loadPolicyFromObject({ version: 1, mode: "observe" }, { projectRoot: here }),
      "observe",
      { projectRoot: here, onDecision: (pkg, decision) => decisions.push({ pkg, decision }) },
    );
  });
  afterEach(() => {
    handle?.uninstall();
    delete requireCjs.cache[requireCjs.resolve(path.join(here, "fixtures", "node_modules", "fixture-argnorm"))];
  });

  interface ArgNormFixture {
    udpSendNoAddress(type: string, port: number, cb: (err: unknown) => void): void;
    udpConnectNoAddress(type: string, port: number, cb: (err: unknown) => void): void;
  }

  const load = (): ArgNormFixture =>
    requireCjs(path.join(here, "fixtures", "node_modules", "fixture-argnorm")) as ArgNormFixture;

  it("records 127.0.0.1 for a udp4 send with no address", async () => {
    await new Promise<void>((resolve) => load().udpSendNoAddress("udp4", 9, () => resolve()));
    const first = decisions.find((d) => (d.decision.observed as { kind?: string }).kind === "net");
    expect(first!.pkg).toBe("fixture-argnorm");
    expect(first!.decision.observed).toEqual({ kind: "net", host: "127.0.0.1", port: 9 });
  });

  it("records ::1 for a udp6 send with no address", async () => {
    if (!hasIpv6Loopback()) return; // container without an IPv6 loopback — detected, not assumed
    await new Promise<void>((resolve) => load().udpSendNoAddress("udp6", 9, () => resolve()));
    const first = decisions.find((d) => (d.decision.observed as { kind?: string }).kind === "net");
    expect(first!.decision.observed).toEqual({ kind: "net", host: "::1", port: 9 });
  });

  it("records 127.0.0.1 for a udp4 connect with no address", async () => {
    await new Promise<void>((resolve) => load().udpConnectNoAddress("udp4", 9, () => resolve()));
    const first = decisions.find((d) => (d.decision.observed as { kind?: string }).kind === "net");
    expect(first!.decision.observed).toEqual({ kind: "net", host: "127.0.0.1", port: 9 });
  });
});
