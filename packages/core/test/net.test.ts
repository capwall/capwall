/**
 * Unit tests for the net/http/https capability shim (roadmap M4, issue #5).
 *
 * These build the shim directly via its factory functions with a fake `ShimContext`
 * (no loader registry wiring yet — that lands when `shims/index.ts` is updated to call
 * `registerNetShim`). Kept hermetic: every "allowed" test connects to `127.0.0.1` on a port
 * we just closed, so the guard's decision is observed before the OS-level ECONNREFUSED,
 * without ever reaching a real external network.
 */
import Module, { createRequire } from "node:module";
import * as fs from "node:fs";
import * as net from "node:net";
import * as http from "node:http";
import * as http2 from "node:http2";
import * as os from "node:os";
import * as nodePath from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { createHttp2Shim, createHttpShim, createHttpsShim, createNetShim, createTlsShim } from "../src/shims/net.js";
import { loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";
import type { ShimContext } from "../src/shims/runtime.js";

const requireCjs = createRequire(import.meta.url);

type Recorded = { pkg: string; decision: Decision };

function makeCtx(policy: Policy, mode: "observe" | "enforce"): { ctx: ShimContext; decisions: Recorded[] } {
  const decisions: Recorded[] = [];
  const ctx: ShimContext = {
    policy,
    mode,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
  };
  return { ctx, decisions };
}

const emptyEnforcePolicy = (): Policy => loadPolicyFromObject({ version: 1, mode: "enforce" });

/** A policy granting the calling package (attributes to "<app>" from this test file, which
 * falls back to `default`) egress to 127.0.0.1 on `port`. */
const grantedPolicy = (port: number): Policy =>
  loadPolicyFromObject({
    version: 1,
    mode: "enforce",
    default: { net: { hosts: ["127.0.0.1"], ports: [port] } },
  });

/** Like {@link grantedPolicy} but for an arbitrary loopback host (`::1` for the IPv6 cases). */
const grantedPolicyFor = (host: string, ...ports: number[]): Policy =>
  loadPolicyFromObject({
    version: 1,
    mode: "enforce",
    default: { net: { hosts: [host], ports } },
  });

/** Bind an ephemeral port, then close it immediately — connecting to it afterwards reliably
 * yields ECONNREFUSED without ever leaving the loopback interface. */
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

/** Does this machine actually have an IPv6 loopback? DETECTED, never assumed — CI images and
 * containers routinely run without one, and a test that assumes `::1` binds would be flaky
 * there. The IPv6 assertions that need no socket at all (the guarded host must be the
 * UNBRACKETED `::1`) run unconditionally, so the regression is still covered on such a box; only
 * the end-to-end "the request actually completes" halves are skipped. */
function hasIpv6Loopback(): boolean {
  return Object.values(os.networkInterfaces()).some((ifaces) =>
    (ifaces ?? []).some((i) => i.address === "::1" && i.internal),
  );
}
const IPV6_LOOPBACK = hasIpv6Loopback();

/** Everything a test server actually received — the ground truth for "did the synthesized
 * options object reproduce the call the caller made?" (the class of check whose absence let the
 * IPv6 and h2c regressions ship green). */
interface SeenRequest {
  method: string;
  url: string;
  host: string | undefined;
  authorization: string | undefined;
  body: string;
}

interface EchoServer {
  port: number;
  seen: SeenRequest[];
  close: () => Promise<void>;
}

/** A real loopback HTTP/1.1 server that records each request and echoes its url. */
async function startHttpEcho(bindHost = "127.0.0.1"): Promise<EchoServer> {
  const seen: SeenRequest[] = [];
  const srv = http.createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (c: string) => (body += c));
    req.on("end", () => {
      seen.push({
        method: req.method ?? "",
        url: req.url ?? "",
        host: req.headers.host,
        authorization: req.headers.authorization,
        body,
      });
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(`echo:${req.url ?? ""}`);
    });
  });
  await new Promise<void>((resolve, reject) => {
    srv.once("error", reject);
    srv.listen(0, bindHost, () => resolve());
  });
  const addr = srv.address();
  return {
    port: addr && typeof addr === "object" ? addr.port : 0,
    seen,
    close: () => new Promise<void>((r) => srv.close(() => r())),
  };
}

/** Drive a `ClientRequest` to completion and collect the response. */
async function collectResponse(req: http.ClientRequest): Promise<{ status: number; body: string }> {
  return await new Promise((resolve, reject) => {
    req.once("error", reject);
    req.once("response", (res: http.IncomingMessage) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (c: string) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
  });
}

/** A plaintext HTTP/2 (h2c) server — `createServer`, NOT `createSecureServer`: h2c is the whole
 * point of the `http:` authority scheme, and it needs no certificate. */
async function startH2cEcho(bindHost = "127.0.0.1"): Promise<{ port: number; close: () => Promise<void> }> {
  const srv = http2.createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(`h2c:${req.headers[":path"] ?? ""}`);
  });
  srv.on("sessionError", () => {}); // a non-h2 probe must not crash the test process
  await new Promise<void>((resolve, reject) => {
    srv.once("error", reject);
    srv.listen(0, bindHost, () => resolve());
  });
  const addr = srv.address();
  return {
    port: addr && typeof addr === "object" ? addr.port : 0,
    close: () => new Promise<void>((r) => srv.close(() => r())),
  };
}

/** One h2c GET over an already-open session. */
async function h2cGet(session: http2.ClientHttp2Session, path: string): Promise<string> {
  return await new Promise((resolve, reject) => {
    session.once("error", reject);
    const req = session.request({ ":path": path });
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (c: string) => (body += c));
    req.on("end", () => resolve(body));
    req.on("error", reject);
    req.end();
  });
}

/** Temp dir for unix-domain sockets, torn down once at the end of the file. */
const tmpDirs: string[] = [];
function makeTmpDir(): string {
  const dir = fs.mkdtempSync(nodePath.join(os.tmpdir(), "capwall-net-"));
  tmpDirs.push(dir);
  return dir;
}
afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});

describe("net shim — enforce + deny-by-default", () => {
  it("net.connect({host, port}) throws CapabilityError synchronously, before any socket opens", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const netShim = createNetShim(ctx);
    expect(() => netShim.connect({ host: "evil.com", port: 443 })).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });

  it("net.connect(port, host) positional form is also denied", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const netShim = createNetShim(ctx);
    expect(() => netShim.connect(443, "evil.com")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });

  it("net.createConnection is denied identically to connect (they are aliases)", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const netShim = createNetShim(ctx);
    expect(() => netShim.createConnection({ host: "evil.com", port: 443 })).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });

  it("http.get to a disallowed host throws CapabilityError", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const httpShim = createHttpShim(ctx);
    expect(() => httpShim.get("http://evil.com/")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });

  it("http.request to a disallowed host throws CapabilityError", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const httpShim = createHttpShim(ctx);
    expect(() => httpShim.request({ hostname: "evil.com", port: 80 })).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
  });

  it("https.get to a disallowed host throws CapabilityError, defaulting to port 443", () => {
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const httpsShim = createHttpsShim(ctx);
    expect(() => httpsShim.get("https://evil.com/")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "net", host: "evil.com", port: 443 });
  });

  it("https.request derives the default port 443 when unspecified in options", () => {
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const httpsShim = createHttpsShim(ctx);
    expect(() => httpsShim.request({ hostname: "evil.com" })).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "net", port: 443 });
  });

  it("IPC/unix-socket connect (path form) is approximated as <ipc>:0 and denied by default", () => {
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const netShim = createNetShim(ctx);
    expect(() => netShim.connect("/tmp/does-not-matter.sock")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "net", host: "<ipc>", port: 0 });
  });
});

describe("net shim — enforce + granted", () => {
  it("net.connect proceeds to the real connect when granted (reaches the OS, not blocked by capwall)", async () => {
    const port = await closedLocalPort();
    const { ctx, decisions } = makeCtx(grantedPolicy(port), "enforce");
    const netShim = createNetShim(ctx);
    await new Promise<void>((resolve, reject) => {
      const socket = netShim.connect({ host: "127.0.0.1", port });
      socket.once("error", (err: NodeJS.ErrnoException) => {
        if (err.code === "ECONNREFUSED") resolve();
        else reject(err);
      });
      socket.once("connect", () => {
        socket.destroy();
        resolve();
      });
    });
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(true);
  });

  it("http.get proceeds to the real request when granted (reaches the OS, not blocked by capwall)", async () => {
    const port = await closedLocalPort();
    const { ctx, decisions } = makeCtx(grantedPolicy(port), "enforce");
    const httpShim = createHttpShim(ctx);
    await new Promise<void>((resolve, reject) => {
      const req = httpShim.get({ hostname: "127.0.0.1", port });
      req.once("error", (err: NodeJS.ErrnoException) => {
        if (err.code === "ECONNREFUSED") resolve();
        else reject(err);
      });
      req.once("response", () => resolve());
    });
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(true);
  });
});

describe("net shim — observe mode never blocks", () => {
  it("net.connect never throws in observe mode, and records the observed request", async () => {
    const port = await closedLocalPort();
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "observe");
    const netShim = createNetShim(ctx);
    await new Promise<void>((resolve, reject) => {
      const socket = netShim.connect({ host: "127.0.0.1", port });
      socket.once("error", (err: NodeJS.ErrnoException) => {
        if (err.code === "ECONNREFUSED") resolve();
        else reject(err);
      });
      socket.once("connect", () => {
        socket.destroy();
        resolve();
      });
    });
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(decisions[0]!.decision.observed).toMatchObject({
      kind: "net",
      host: "127.0.0.1",
      port,
    });
  });

  it("http.get never throws in observe mode, and records the observed request", async () => {
    const port = await closedLocalPort();
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "observe");
    const httpShim = createHttpShim(ctx);
    await new Promise<void>((resolve, reject) => {
      const req = httpShim.get({ hostname: "127.0.0.1", port });
      req.once("error", (err: NodeJS.ErrnoException) => {
        if (err.code === "ECONNREFUSED") resolve();
        else reject(err);
      });
      req.once("response", () => resolve());
    });
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(decisions[0]!.decision.observed).toMatchObject({
      kind: "net",
      host: "127.0.0.1",
      port,
    });
  });
});

describe("net shim — shimming net's require does not also gate http", () => {
  // capwall's require interception (loader/require.ts) patches `Module._load`, the CJS
  // loader's internal load function. Node's OWN internal implementation files (e.g.
  // lib/_http_client.js requiring 'net') are loaded through Node's internal NativeModule
  // bootstrap loader, a completely separate path that never calls `Module._load` — so a
  // patch that makes `require("net")` (from user/dependency code) return capwall's net shim
  // has NO effect on what Node's own http implementation does internally. That is the
  // concrete reason http/https need their own wrappers rather than inheriting coverage from
  // the net shim: patching the 'net' specifier's require resolution and patching http's
  // actual outbound connection call are simply different things.
  //
  // This test reproduces that mechanism directly (a scoped, local `Module._load` patch —
  // the same technique loader/require.ts uses) rather than asserting it from documentation.
  it("a Module._load patch that shims 'net' leaves a real http.get() completely unmediated", async () => {
    type ModuleLoad = (request: string, parent: unknown, isMain: boolean) => unknown;
    const moduleInternals = Module as unknown as { _load: ModuleLoad };
    const originalLoad = moduleInternals._load;

    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const netShim = createNetShim(ctx);

    const patchedLoad: ModuleLoad = function (this: unknown, request, parent, isMain) {
      if (request === "net" || request === "node:net") return netShim;
      return originalLoad.call(this, request, parent, isMain);
    };
    moduleInternals._load = patchedLoad;

    try {
      // 'net' is now gated: requiring it and connecting to a disallowed host throws.
      const shimmedNet = requireCjs("net") as typeof net;
      expect(() => shimmedNet.connect({ host: "evil.com", port: 443 })).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
      expect(decisions).toHaveLength(1);

      // A plain, real http.get (Node's own implementation, never touching capwall's net
      // shim object) is entirely unaffected: no CapabilityError, no decision recorded, even
      // though we're still inside the same enforce-mode / deny-by-default policy above.
      // Stay hermetic: target a just-closed local port, never a real remote host.
      const port = await closedLocalPort();
      await new Promise<void>((resolve) => {
        const req = http.get({ hostname: "127.0.0.1", port });
        req.once("error", (err: NodeJS.ErrnoException) => {
          expect(err.name).not.toBe("CapabilityError");
          resolve();
        });
        req.once("response", () => resolve());
      });
      expect(decisions).toHaveLength(1); // unchanged — http.get never reached the net shim
    } finally {
      moduleInternals._load = originalLoad;
    }
  });
});

describe("net shim — getter TOCTOU (issue #26)", () => {
  // A malicious/misbehaving dependency could pass an options object whose `host`/`port` are
  // ACCESSOR (getter) properties that return the GRANTED value the first time (when capwall
  // derives the target to guard) and a DIFFERENT, un-granted value on every subsequent read
  // (when Node itself would normally re-read the options to open the socket). Before the fix,
  // capwall forwarded the SAME options object to the real `net.connect`, so Node's internal
  // re-read observed the second (evil) value — a false-allow egress. The fix pins the
  // derived primitive onto a CLONE forwarded to the real API, so Node never consults the
  // getter again: whatever Node connects to is provably the value capwall guarded.
  //
  // We prove this end-to-end without ever leaving loopback: grant only the port bound by
  // `granted`, and give the options object a `port` getter that returns `granted` once and
  // `evil` (a *closed* port) on every call after. If the connection actually attempted lands
  // on `evil`, we'd observe THAT port's ECONNREFUSED/connect signature instead of `granted`'s
  // listening server accepting the connection — so asserting the granted server's "connection"
  // event fires (and the evil port's listener stays untouched) demonstrates guard target ==
  // connect target, regardless of the getter's second-read value.
  it("net.connect: a port getter returning a different value on re-read cannot desync guard-vs-connect", async () => {
    const grantedPort = await closedLocalPort();
    const evilPort = await closedLocalPort();
    expect(grantedPort).not.toBe(evilPort);

    // A listening server ONLY on the granted port — if capwall pinned correctly, Node connects
    // here and the server sees the connection. If the getter's second read leaked through,
    // Node would instead attempt evilPort, which has nothing listening (ECONNREFUSED) and this
    // server would NEVER see a connection.
    const granted = net.createServer();
    await new Promise<void>((resolve, reject) => {
      granted.on("error", reject);
      granted.listen(grantedPort, "127.0.0.1", () => resolve());
    });
    const accepted = new Promise<void>((resolve) => {
      granted.once("connection", (sock) => {
        sock.destroy();
        resolve();
      });
    });

    let reads = 0;
    const options = {
      host: "127.0.0.1",
      get port() {
        reads++;
        return reads === 1 ? grantedPort : evilPort; // capwall's derive is the ONLY reader
      },
    };

    const { ctx, decisions } = makeCtx(grantedPolicy(grantedPort), "enforce");
    const netShim = createNetShim(ctx);

    const socket = netShim.connect(options);
    const outcome = await new Promise<"connected" | "refused">((resolve, reject) => {
      socket.once("connect", () => resolve("connected"));
      socket.once("error", (err: NodeJS.ErrnoException) => {
        if (err.code === "ECONNREFUSED") resolve("refused");
        else reject(err);
      });
    });
    socket.destroy();
    granted.close();

    // The getter was read exactly once — by capwall's own derivation. Node's real connect
    // never consulted it again (it received the pinned clone), so it could not have read the
    // second (evil) value.
    expect(reads).toBe(1);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port: grantedPort });
    expect(outcome).toBe("connected");
    await accepted; // the granted server actually saw the connection
  });

  it("net.connect: same getter-TOCTOU shape, but the FIRST (guarded) read is the denied value — deny wins, and Node never attempts the socket at all", () => {
    const deniedPort = 1; // never granted below
    const grantedPort = 2;
    let reads = 0;
    const options = {
      host: "127.0.0.1",
      get port() {
        reads++;
        return reads === 1 ? deniedPort : grantedPort;
      },
    };
    const { ctx, decisions } = makeCtx(grantedPolicy(grantedPort), "enforce");
    const netShim = createNetShim(ctx);
    expect(() => netShim.connect(options)).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    // Denied on the FIRST read (the guarded value) — the real connect is never reached, so the
    // getter is read exactly once, never resolving to the "granted" second value.
    expect(reads).toBe(1);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(false);
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port: deniedPort });
  });

  it("tls.connect positional + options-object overlay: a host getter on the overlay is read once and pinned into the merged target", async () => {
    const grantedPort = await closedLocalPort();
    const evilHost = "192.0.2.1"; // TEST-NET-1, never dialed — proves the getter's 2nd read is unused
    let reads = 0;
    const overlay = {
      get host() {
        reads++;
        return reads === 1 ? "127.0.0.1" : evilHost;
      },
    };
    const { ctx, decisions } = makeCtx(grantedPolicy(grantedPort), "enforce");
    const tlsShim = createTlsShim(ctx);
    const socket = tlsShim.connect(grantedPort, "127.0.0.1", overlay);
    await new Promise<void>((resolve, reject) => {
      socket.once("error", (err: NodeJS.ErrnoException) => {
        // Any resolvable error other than the OS actually trying evilHost is fine here — what
        // matters is the getter was consulted exactly once and the guarded decision matches.
        if (err.code === "ECONNREFUSED" || err.code === "ECONNRESET" || err.code === "EPROTO") resolve();
        else reject(err);
      });
      socket.once("secureConnect", () => resolve());
    });
    socket.destroy();
    expect(reads).toBe(1);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port: grantedPort });
  });

  // URL-INSTANCE follow-up (2026-07-23 re-review, PR #46 blocking HIGH): the options-object
  // pinning above does NOT protect a `URL` instance passed as the url argument. Node's
  // `ClientRequest`/`http2` internals re-derive `hostname`/`port` off the SAME url object a
  // second time; if the url instance carries an OWN shadowed `port` (or `host`/`hostname`)
  // accessor — `Object.defineProperty(url, "port", { get(){...} })`, which JS lets any code do
  // to any extensible object, and which Node's own property reads honor exactly like a native
  // one — capwall's derivation-time read and Node's connect-time read can diverge exactly like
  // the plain-options case above. Verified as a live PoC against the pre-fix code (manually,
  // outside this suite): guarding `granted:PORT` while the real TCP connection landed on
  // `evil:PORT`. Proven closed here with TWO independent loopback servers — the getter returns
  // the granted port on read #1 and an unrelated (also-loopback) evil port on every read after
  // — asserting the GRANTED server receives the connection and the EVIL server never does,
  // regardless of the getter's later value, for both `http.get(url)` and `http2.connect(url)`.
  it("http.get(url): a URL instance with an OWN shadowed port getter cannot desync guard-vs-connect", async () => {
    const grantedPort = await closedLocalPort();
    const evilPort = await closedLocalPort();
    expect(grantedPort).not.toBe(evilPort);

    const granted = net.createServer();
    await new Promise<void>((resolve, reject) => {
      granted.on("error", reject);
      granted.listen(grantedPort, "127.0.0.1", () => resolve());
    });
    const acceptedGranted = new Promise<void>((resolve) => {
      granted.once("connection", (sock) => {
        sock.destroy();
        resolve();
      });
    });

    const evil = net.createServer();
    let evilHit = false;
    await new Promise<void>((resolve, reject) => {
      evil.on("error", reject);
      evil.listen(evilPort, "127.0.0.1", () => resolve());
    });
    evil.on("connection", (sock) => {
      evilHit = true;
      sock.destroy();
    });

    const url = new URL(`http://127.0.0.1:${grantedPort}/`);
    let reads = 0;
    Object.defineProperty(url, "port", {
      configurable: true,
      get() {
        reads++;
        return reads === 1 ? String(grantedPort) : String(evilPort); // granted first, evil after
      },
    });

    const { ctx, decisions } = makeCtx(grantedPolicy(grantedPort), "enforce");
    const httpShim = createHttpShim(ctx);

    await new Promise<void>((resolve) => {
      const req = httpShim.get(url);
      // The granted mock server destroys the socket without ever responding — a socket-hang-up
      // style error here is EXPECTED and fine. What this test verifies is which server's
      // "connection" event fired, not whether the HTTP exchange itself completed.
      req.once("response", () => resolve());
      req.once("error", () => resolve());
    });
    await acceptedGranted; // the granted server actually saw the connection
    await new Promise((r) => setTimeout(r, 20)); // settle window for a stray delayed connect
    granted.close();
    evil.close();

    // The getter was read exactly once — by capwall's own derivation. Node's real request
    // never consulted it again (it received the pinned/synthesized options object), so it
    // could not have read the second (evil) value.
    expect(reads).toBe(1);
    expect(evilHit).toBe(false);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port: grantedPort });
  });

  it("http2.connect(url): a URL instance with an OWN shadowed port getter cannot desync guard-vs-connect", async () => {
    const grantedPort = await closedLocalPort();
    const evilPort = await closedLocalPort();
    expect(grantedPort).not.toBe(evilPort);

    const granted = net.createServer();
    await new Promise<void>((resolve, reject) => {
      granted.on("error", reject);
      granted.listen(grantedPort, "127.0.0.1", () => resolve());
    });
    const acceptedGranted = new Promise<void>((resolve) => {
      granted.once("connection", (sock) => {
        sock.destroy();
        resolve();
      });
    });

    const evil = net.createServer();
    let evilHit = false;
    await new Promise<void>((resolve, reject) => {
      evil.on("error", reject);
      evil.listen(evilPort, "127.0.0.1", () => resolve());
    });
    evil.on("connection", (sock) => {
      evilHit = true;
      sock.destroy();
    });

    const url = new URL(`http://127.0.0.1:${grantedPort}/`); // http: → plaintext h2c, no TLS needed
    let reads = 0;
    Object.defineProperty(url, "port", {
      configurable: true,
      get() {
        reads++;
        return reads === 1 ? String(grantedPort) : String(evilPort);
      },
    });

    const { ctx, decisions } = makeCtx(grantedPolicy(grantedPort), "enforce");
    const http2Shim = createHttp2Shim(ctx);

    const session = http2Shim.connect(url);
    session.on("error", () => {}); // the dummy server isn't a real http2 peer — errors expected
    await new Promise<void>((resolve) => {
      session.once("connect", () => resolve());
      session.once("error", () => resolve());
    });
    try {
      session.destroy();
    } catch {
      /* already destroyed */
    }
    await acceptedGranted; // the granted server actually saw the connection
    await new Promise((r) => setTimeout(r, 20)); // settle window for a stray delayed connect
    granted.close();
    evil.close();

    expect(reads).toBe(1);
    expect(evilHit).toBe(false);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port: grantedPort });
  });
});

describe("net shim — https module presence sanity", () => {
  it("createHttpsShim wraps a distinct module object from createHttpShim, real API passed through", () => {
    const { ctx } = makeCtx(emptyEnforcePolicy(), "observe");
    const httpShim = createHttpShim(ctx);
    const httpsShim = createHttpsShim(ctx);
    expect(httpShim as unknown).not.toBe(httpsShim as unknown);
    expect(typeof httpsShim.Agent).toBe("function");
  });
});

describe("net shim — `path`/`socketPath` accessor cannot escape pinning (issue #56)", () => {
  // THE BUG. `deriveNetTarget` read `options.path` once to decide TCP-vs-IPC, but the clone
  // builder skipped only `host`/`hostname`/`port` and copied every OTHER own key BY DESCRIPTOR —
  // so a `path` ACCESSOR survived live into the forwarded clone and Node read it a SECOND time.
  //
  //   { host: "granted.host", port: 443, get path() { return read1 ? undefined : "/var/run/docker.sock" } }
  //
  // Read #1 (capwall's) returned undefined, so capwall guarded — and allowed — the TCP target;
  // read #2 (Node's) returned the socket path, so Node opened a unix-domain socket instead. A
  // dependency granted ONE TCP endpoint reached ARBITRARY unix sockets: the docker socket, an
  // agent socket, a database socket. Verified as a live PoC against the pre-fix build (guarded
  // `127.0.0.1:<granted>`, connected to the unix socket; the getter was read 3 times).
  //
  // Fixed structurally rather than by adding "path" to the skip list: the capability-relevant
  // keys are now one named constant per flavor, and the clone builder FLATTENS every own
  // accessor it copies, so no getter of any kind — known key or not — survives into what Node
  // reads. Both orderings of the getter are asserted below, plus the negative control, so the
  // test proves the IPC gate rather than an incidental failure to connect.

  /** A listening unix-domain socket server — the attacker's target. It must NEVER be reached. */
  async function startIpcServer(): Promise<{ sockPath: string; hit: () => boolean; close: () => Promise<void> }> {
    const sockPath = nodePath.join(makeTmpDir(), "target.sock");
    let hit = false;
    const srv = net.createServer((s) => {
      hit = true;
      s.destroy();
    });
    await new Promise<void>((resolve, reject) => {
      srv.once("error", reject);
      srv.listen(sockPath, () => resolve());
    });
    return { sockPath, hit: () => hit, close: () => new Promise<void>((r) => srv.close(() => r())) };
  }

  it("net.connect: a `path` getter returning the socket path only on the SECOND read never reaches Node", async () => {
    const ipc = await startIpcServer();
    const tcp = await startHttpEcho(); // the ONE endpoint the policy grants
    let reads = 0;
    const options = {
      host: "127.0.0.1",
      port: tcp.port,
      get path(): string | undefined {
        reads++;
        return reads === 1 ? undefined : ipc.sockPath; // benign to capwall, hostile to Node
      },
    };

    const { ctx, decisions } = makeCtx(grantedPolicy(tcp.port), "enforce");
    const netShim = createNetShim(ctx);
    const socket = netShim.connect(options);
    const outcome = await new Promise<string>((resolve, reject) => {
      socket.once("connect", () => resolve("connected"));
      socket.once("error", (err: NodeJS.ErrnoException) => reject(err));
    });
    socket.destroy();
    await new Promise((r) => setTimeout(r, 20)); // settle window for a stray delayed connect
    await ipc.close();
    await tcp.close();

    expect(reads).toBe(1); // capwall's single read is the ONLY one — Node got a data property
    expect(ipc.hit()).toBe(false); // the unix socket was never reached
    expect(outcome).toBe("connected"); // …the granted TCP endpoint was
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port: tcp.port });
  });

  it("net.connect: a `path` getter yielding the socket path on the FIRST read is guarded as <ipc>:0 and DENIED", async () => {
    const ipc = await startIpcServer();
    const grantedPort = await closedLocalPort();
    let reads = 0;
    const options = {
      host: "127.0.0.1",
      port: grantedPort,
      get path(): string | undefined {
        reads++;
        return reads === 1 ? ipc.sockPath : undefined; // hostile first — capwall sees the truth
      },
    };

    const { ctx, decisions } = makeCtx(grantedPolicy(grantedPort), "enforce");
    const netShim = createNetShim(ctx);
    expect(() => netShim.connect(options)).toThrowError(expect.objectContaining({ name: "CapabilityError" }));
    await new Promise((r) => setTimeout(r, 20));
    await ipc.close();

    expect(reads).toBe(1);
    expect(ipc.hit()).toBe(false);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(false);
    // A TCP grant is NOT an IPC grant: the target is the `<ipc>` pseudo-host, not 127.0.0.1.
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "net", host: "<ipc>", port: 0 });
  });

  it("negative control: a plain (non-accessor) `{path}` option is guarded as <ipc>:0 and DENIED under a TCP grant", async () => {
    const ipc = await startIpcServer();
    const grantedPort = await closedLocalPort();
    const { ctx, decisions } = makeCtx(grantedPolicy(grantedPort), "enforce");
    const netShim = createNetShim(ctx);
    // Same policy, same socket, no getter anywhere — proving the DENY above comes from the IPC
    // gate itself and not from some incidental failure of the exotic options object.
    expect(() => netShim.connect({ path: ipc.sockPath })).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    await ipc.close();
    expect(ipc.hit()).toBe(false);
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "net", host: "<ipc>", port: 0 });
  });

  it("http.request({socketPath}) is guarded as <ipc>:0 — a `localhost:80` grant is not a unix-socket grant", async () => {
    const sockPath = nodePath.join(makeTmpDir(), "http.sock");
    let hit = false;
    const srv = http.createServer((_req, res) => {
      hit = true;
      res.end("reached");
    });
    await new Promise<void>((resolve, reject) => {
      srv.once("error", reject);
      srv.listen(sockPath, () => resolve());
    });

    // `socketPath` is http's unix-socket field. Before the fix it was not modelled at all: the
    // call fell through to the `localhost` / default-port target, so ANY package granted
    // `localhost:80` could talk to `/var/run/docker.sock`.
    const { ctx, decisions } = makeCtx(grantedPolicyFor("localhost", 80), "enforce");
    const httpShim = createHttpShim(ctx);
    expect(() => httpShim.request({ socketPath: sockPath, path: "/containers/json" })).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    await new Promise((r) => setTimeout(r, 20));
    await new Promise<void>((r) => srv.close(() => r()));

    expect(hit).toBe(false);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "net", host: "<ipc>", port: 0 });
  });

  it("the object handed to the real API carries NO accessor on ANY key (the fail-closed backstop)", () => {
    // The skip-list approach fails OPEN every time someone adds a capability-relevant field and
    // forgets to list it — how both #26 and #56 happened. The invariant is now stronger than the
    // list: the clone builder flattens EVERY own accessor it copies, so whatever Node reads is a
    // frozen value even on a key capwall does not treat as target-deciding. Asserted directly by
    // capturing the argument the real `Socket.prototype.connect` receives.
    const realConnect = net.Socket.prototype.connect;
    let captured: Record<string, unknown> | undefined;
    Object.defineProperty(net.Socket.prototype, "connect", {
      value: function (this: unknown, ...args: unknown[]) {
        captured = args[0] as Record<string, unknown>;
        return this; // never actually dial
      },
      writable: true,
      configurable: true,
    });
    try {
      // Built while patched, so the guarded subclass captures the probe as the "real" method.
      const { ctx } = makeCtx(grantedPolicy(4242), "enforce");
      const netShim = createNetShim(ctx);
      const socket = new netShim.Socket();
      socket.connect({
        host: "127.0.0.1",
        port: 4242,
        get path(): undefined {
          return undefined;
        },
        get socketPath(): string {
          return "/var/run/docker.sock";
        },
        get lookup(): undefined {
          return undefined;
        },
      } as unknown as net.SocketConnectOpts);
    } finally {
      Object.defineProperty(net.Socket.prototype, "connect", {
        value: realConnect,
        writable: true,
        configurable: true,
      });
    }

    expect(captured).toBeDefined();
    for (const key of Reflect.ownKeys(captured!)) {
      const desc = Object.getOwnPropertyDescriptor(captured!, key)!;
      expect({ key: String(key), get: desc.get, set: desc.set }).toEqual({
        key: String(key),
        get: undefined,
        set: undefined,
      });
    }
    expect(captured!["host"]).toBe("127.0.0.1");
    expect(captured!["port"]).toBe(4242);
    expect(captured!["path"]).toBeUndefined();
  });
});

describe("net shim — IPv6 URLs over http(s) (PR #46 regression)", () => {
  // THE BUG. Once `resolveHttpCall` synthesized its own options instead of forwarding the URL,
  // capwall took over a job Node's internal `urlToHttpOptions` was doing — and did not replicate
  // all of it. Node strips the brackets an IPv6 literal keeps on `URL#hostname`:
  //   new URL("http://[::1]:8080/").hostname                    === "[::1]"
  //   urlToHttpOptions(new URL("http://[::1]:8080/")).hostname  === "::1"
  // capwall passed `hostname` through verbatim, so `net` treated "[::1]" as a DNS NAME and every
  // IPv6 http(s) URL failed ENOTFOUND — in observe mode as well as enforce, and it worked on
  // `main`. The guarded host was `[::1]` too, so a policy written as `::1` never matched either.
  //
  // The bracket-stripping assertions below need no IPv6 stack at all (the guard runs before any
  // socket), so they cover the regression even on a box with no `::1`; only the end-to-end half
  // is conditional.

  it("http.get(url string) with an IPv6 literal guards the UNBRACKETED host", () => {
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const httpShim = createHttpShim(ctx);
    expect(() => httpShim.get("http://[::1]:8080/x")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "net", host: "::1", port: 8080 });
  });

  it("http.get(URL instance) with an IPv6 literal guards the UNBRACKETED host", () => {
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const httpShim = createHttpShim(ctx);
    expect(() => httpShim.get(new URL("http://[2001:db8::1]/"))).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "net", host: "2001:db8::1", port: 80 });
  });

  it.skipIf(!IPV6_LOOPBACK)("http.get over an IPv6 loopback server SUCCEEDS under a granting policy", async () => {
    const server = await startHttpEcho("::1");
    const { ctx, decisions } = makeCtx(grantedPolicyFor("::1", server.port), "enforce");
    const httpShim = createHttpShim(ctx);
    const result = await collectResponse(httpShim.get(`http://[::1]:${server.port}/v6?q=1`));
    await server.close();

    expect(result.status).toBe(200);
    expect(result.body).toBe("echo:/v6?q=1");
    expect(server.seen).toHaveLength(1);
    expect(server.seen[0]!.url).toBe("/v6?q=1");
    // Node builds the Host header from the same hostname it dialed, re-bracketing the literal.
    expect(server.seen[0]!.host).toBe(`[::1]:${server.port}`);
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "::1", port: server.port });
  });

  it.skipIf(!IPV6_LOOPBACK)("observe mode records the unbracketed IPv6 host and still completes the request", async () => {
    const server = await startHttpEcho("::1");
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "observe");
    const httpShim = createHttpShim(ctx);
    const result = await collectResponse(httpShim.get(new URL(`http://[::1]:${server.port}/obs`)));
    await server.close();
    expect(result.body).toBe("echo:/obs");
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "::1", port: server.port });
  });

  it("a bracketed host in a PLAIN options object is left alone (Node dials it literally)", () => {
    // Only a URL's `hostname` carries brackets by construction; `{hostname: "[::1]"}` is dialed
    // verbatim by Node (and fails ENOTFOUND), so capwall must guard it verbatim too — stripping
    // there would guard a host the socket never reaches.
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const httpShim = createHttpShim(ctx);
    expect(() => httpShim.request({ hostname: "[::1]", port: 8080 })).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "[::1]", port: 8080 });
  });
});

describe("net shim — http2 (PR #46 regression: h2c + IPv6 authority)", () => {
  // THE BUG. `createHttp2Shim` rebuilt the authority as a pinned string but defaulted the port
  // to 443 regardless of scheme; Node defaults an `http:` authority to 80. Pre-fix the authority
  // was forwarded unchanged, so `http2.connect("http://internal-svc")` worked — post-fix the
  // rebuilt authority forced `:443` and h2c broke. Second bug in the same rebuild: composing
  // `${protocol}//${host}:${port}` with an unbracketed IPv6 host yields `http://::1:80`, which
  // is not a parseable URL, so Node throws ERR_INVALID_URL on its own re-parse.
  //
  // `net.test.ts` had ZERO http2 coverage, which is why both shipped.

  it("http2.connect('http://…') defaults to port 80 (h2c), not 443", () => {
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const http2Shim = createHttp2Shim(ctx);
    expect(() => http2Shim.connect("http://internal-svc.invalid")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "net", host: "internal-svc.invalid", port: 80 });
  });

  it("http2.connect('https://…') still defaults to port 443", () => {
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const http2Shim = createHttp2Shim(ctx);
    expect(() => http2Shim.connect("https://internal-svc.invalid")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "net", host: "internal-svc.invalid", port: 443 });
  });

  it("http2.connect against a real h2c server (http2.createServer) round-trips a request", async () => {
    const server = await startH2cEcho();
    const { ctx, decisions } = makeCtx(grantedPolicy(server.port), "enforce");
    const http2Shim = createHttp2Shim(ctx);
    const session = http2Shim.connect(`http://127.0.0.1:${server.port}`);
    const body = await h2cGet(session, "/h2c-path");
    session.close();
    await server.close();

    expect(body).toBe("h2c:/h2c-path");
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port: server.port });
  });

  it("http2.connect to an ungranted authority is denied before any socket opens", async () => {
    const server = await startH2cEcho();
    const { ctx } = makeCtx(emptyEnforcePolicy(), "enforce");
    const http2Shim = createHttp2Shim(ctx);
    expect(() => http2Shim.connect(`http://127.0.0.1:${server.port}`)).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    await server.close();
  });

  it("an IPv6 authority is guarded UNBRACKETED", () => {
    const { ctx, decisions } = makeCtx(emptyEnforcePolicy(), "enforce");
    const http2Shim = createHttp2Shim(ctx);
    expect(() => http2Shim.connect("http://[::1]:8080")).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    expect(decisions[0]!.decision.observed).toMatchObject({ kind: "net", host: "::1", port: 8080 });
  });

  it("an IPv6 authority is re-BRACKETED when the pinned authority string is composed", async () => {
    // Runs everywhere: if the composed authority were `http://::1:8080`, Node's own re-parse
    // would fail with ERR_INVALID_URL regardless of whether the machine has an IPv6 stack.
    const port = await closedLocalPort();
    const { ctx } = makeCtx(grantedPolicyFor("::1", port), "enforce");
    const http2Shim = createHttp2Shim(ctx);
    const session = http2Shim.connect(`http://[::1]:${port}`);
    const err = await new Promise<NodeJS.ErrnoException | null>((resolve) => {
      session.once("connect", () => resolve(null));
      session.once("error", (e: NodeJS.ErrnoException) => resolve(e));
    });
    session.destroy();
    expect(err?.code).not.toBe("ERR_INVALID_URL");
  });

  it.skipIf(!IPV6_LOOPBACK)("h2c over an IPv6 loopback server round-trips a request", async () => {
    const server = await startH2cEcho("::1");
    const { ctx, decisions } = makeCtx(grantedPolicyFor("::1", server.port), "enforce");
    const http2Shim = createHttp2Shim(ctx);
    const session = http2Shim.connect(`http://[::1]:${server.port}`);
    const body = await h2cGet(session, "/v6");
    session.close();
    await server.close();
    expect(body).toBe("h2c:/v6");
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "::1", port: server.port });
  });

  it("an options overlay's host/port override the authority, and are guarded as the real target", async () => {
    const server = await startH2cEcho();
    const { ctx, decisions } = makeCtx(grantedPolicy(server.port), "enforce");
    const http2Shim = createHttp2Shim(ctx);
    // Node spreads `options` over `{port, host}` derived from the authority, so the overlay wins.
    const session = http2Shim.connect("http://127.0.0.1:1", { port: server.port });
    const body = await h2cGet(session, "/overlay");
    session.close();
    await server.close();
    expect(body).toBe("h2c:/overlay");
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port: server.port });
  });
});

describe("net shim — ordinary call shapes behave exactly like un-shimmed Node", () => {
  // The reviewers' sharpest criticism of this PR: the suite exercised adversarial getter cases
  // thoroughly but had NO non-adversarial shape tests for the synthesized-options path — which
  // is exactly why the IPv6 break shipped green. These are that missing class of test: common,
  // boring call shapes driven end-to-end against a real loopback server under a granting policy,
  // with the result compared against what un-shimmed Node does with the same call.

  it("http.get(url string): status, body, request line and Host header match un-shimmed Node", async () => {
    const server = await startHttpEcho();
    const url = `http://127.0.0.1:${server.port}/a/b?c=d`;

    const baseline = await collectResponse(http.get(url)); // real Node, same server
    const { ctx, decisions } = makeCtx(grantedPolicy(server.port), "enforce");
    const shimmed = await collectResponse(createHttpShim(ctx).get(url));
    await server.close();

    expect(shimmed).toEqual(baseline);
    expect(shimmed.body).toBe("echo:/a/b?c=d");
    expect(server.seen).toHaveLength(2);
    expect(server.seen[1]).toEqual(server.seen[0]); // byte-identical request, shim vs no shim
    expect(server.seen[0]!.host).toBe(`127.0.0.1:${server.port}`);
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port: server.port });
  });

  it("http.get(URL instance): identical to un-shimmed Node, including the query string", async () => {
    const server = await startHttpEcho();
    const url = new URL(`http://127.0.0.1:${server.port}/u?x=1&y=2`);

    const baseline = await collectResponse(http.get(new URL(url.href)));
    const { ctx } = makeCtx(grantedPolicy(server.port), "enforce");
    const shimmed = await collectResponse(createHttpShim(ctx).get(url));
    await server.close();

    expect(shimmed).toEqual(baseline);
    expect(server.seen[1]).toEqual(server.seen[0]);
    expect(server.seen[0]!.url).toBe("/u?x=1&y=2");
  });

  it("a URL's userinfo still becomes the Authorization header (the `auth` field survives)", async () => {
    const server = await startHttpEcho();
    const url = `http://user:p%40ss@127.0.0.1:${server.port}/secure`;

    const baseline = await collectResponse(http.get(url));
    const { ctx } = makeCtx(grantedPolicy(server.port), "enforce");
    const shimmed = await collectResponse(createHttpShim(ctx).get(url));
    await server.close();

    expect(shimmed).toEqual(baseline);
    expect(server.seen[0]!.authorization).toBe(`Basic ${Buffer.from("user:p@ss").toString("base64")}`);
    expect(server.seen[1]).toEqual(server.seen[0]);
  });

  it("http.request(options) with a method, path and body round-trips unchanged", async () => {
    const server = await startHttpEcho();
    const { ctx, decisions } = makeCtx(grantedPolicy(server.port), "enforce");
    const httpShim = createHttpShim(ctx);
    const req = httpShim.request({
      hostname: "127.0.0.1",
      port: server.port,
      method: "POST",
      path: "/submit?k=v",
      headers: { "content-type": "text/plain" },
    });
    req.end("payload");
    const result = await collectResponse(req);
    await server.close();

    expect(result.status).toBe(200);
    expect(result.body).toBe("echo:/submit?k=v");
    expect(server.seen[0]).toMatchObject({ method: "POST", url: "/submit?k=v", body: "payload" });
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port: server.port });
  });

  it("http.get(url, optionsOverlay, cb): the overlay's headers and path override the url's", async () => {
    const server = await startHttpEcho();
    const { ctx } = makeCtx(grantedPolicy(server.port), "enforce");
    const httpShim = createHttpShim(ctx);
    const result = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = httpShim.get(
        `http://127.0.0.1:${server.port}/from-url`,
        { path: "/from-overlay", headers: { "x-probe": "1" } },
        (res: http.IncomingMessage) => {
          let body = "";
          res.setEncoding("utf8");
          res.on("data", (c: string) => (body += c));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
        },
      );
      req.once("error", reject);
    });
    await server.close();
    expect(result.body).toBe("echo:/from-overlay"); // the overlay won, and the cb still fired
    expect(server.seen[0]!.url).toBe("/from-overlay");
  });

  it("a custom Agent's defaultPort still decides the port — and is what capwall guards", async () => {
    // capwall now always pins an EXPLICIT port onto the forwarded options (an absent port would
    // otherwise be resolved by Node, later, from an `agent.defaultPort` capwall cannot pin — a
    // call guarded as `:80` could connect to `:8123`). To keep that faithful rather than merely
    // safe, capwall resolves Node's own precedence itself: options.port || options.defaultPort
    // || agent.defaultPort || <scheme default>.
    const server = await startHttpEcho();
    const agent = new http.Agent();
    (agent as unknown as { defaultPort: number }).defaultPort = server.port;

    const { ctx, decisions } = makeCtx(grantedPolicy(server.port), "enforce");
    const httpShim = createHttpShim(ctx);
    const result = await collectResponse(httpShim.get({ hostname: "127.0.0.1", agent, path: "/via-agent" }));
    agent.destroy();
    await server.close();

    expect(result.body).toBe("echo:/via-agent");
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port: server.port });
  });

  it("options.defaultPort is honored and guarded (it used to be invisible to the guard)", async () => {
    const server = await startHttpEcho();
    const { ctx, decisions } = makeCtx(grantedPolicy(server.port), "enforce");
    const httpShim = createHttpShim(ctx);
    const result = await collectResponse(
      httpShim.get({ hostname: "127.0.0.1", defaultPort: server.port, path: "/via-default" }),
    );
    await server.close();
    expect(result.body).toBe("echo:/via-default");
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port: server.port });
  });

  it("options.defaultPort cannot redirect a request past the guard when it is not granted", async () => {
    const server = await startHttpEcho();
    const { ctx, decisions } = makeCtx(grantedPolicy(80), "enforce"); // 80 granted, server.port is not
    const httpShim = createHttpShim(ctx);
    expect(() => httpShim.get({ hostname: "127.0.0.1", defaultPort: server.port })).toThrowError(
      expect.objectContaining({ name: "CapabilityError" }),
    );
    await new Promise((r) => setTimeout(r, 20));
    await server.close();
    expect(server.seen).toHaveLength(0); // the server never saw a request — the deny came first
    expect(decisions[0]!.decision.observed).toMatchObject({ port: server.port });
  });

  it("net.connect({host, port}) and net.connect(port, host) both round-trip real bytes", async () => {
    const srv = net.createServer((sock) => {
      sock.on("data", (d: Buffer) => sock.end(`pong:${d.toString("utf8")}`));
      sock.on("error", () => {});
    });
    await new Promise<void>((resolve, reject) => {
      srv.once("error", reject);
      srv.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = srv.address();
    const port = addr && typeof addr === "object" ? addr.port : 0;

    const { ctx, decisions } = makeCtx(grantedPolicy(port), "enforce");
    const netShim = createNetShim(ctx);

    const roundTrip = async (socket: net.Socket, msg: string): Promise<string> =>
      await new Promise<string>((resolve, reject) => {
        let out = "";
        socket.setEncoding("utf8");
        socket.on("data", (c: string) => (out += c));
        socket.on("end", () => resolve(out));
        socket.on("error", reject);
        socket.write(msg);
      });

    expect(await roundTrip(netShim.connect({ host: "127.0.0.1", port }), "opts")).toBe("pong:opts");
    expect(await roundTrip(netShim.connect(port, "127.0.0.1"), "positional")).toBe("pong:positional");
    await new Promise<void>((r) => srv.close(() => r()));

    expect(decisions).toHaveLength(2);
    expect(decisions.every((d) => d.decision.allowed)).toBe(true);
  });

  it("tls.connect (options AND positional forms) reaches exactly the granted endpoint", async () => {
    // No certificate needed: the handshake is expected to fail against a plain TCP listener.
    // What is asserted is WHICH endpoint the socket reached — the shim's job.
    let connections = 0;
    const srv = net.createServer((sock) => {
      connections++;
      sock.destroy();
    });
    await new Promise<void>((resolve, reject) => {
      srv.once("error", reject);
      srv.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = srv.address();
    const port = addr && typeof addr === "object" ? addr.port : 0;

    const { ctx, decisions } = makeCtx(grantedPolicy(port), "enforce");
    const tlsShim = createTlsShim(ctx);
    const settle = async (socket: net.Socket): Promise<void> =>
      await new Promise<void>((resolve) => {
        socket.once("error", () => resolve());
        socket.once("secureConnect", () => resolve());
        socket.once("close", () => resolve());
      });

    await settle(tlsShim.connect({ host: "127.0.0.1", port }));
    await settle(tlsShim.connect(port, "127.0.0.1"));
    await settle(tlsShim.connect(port, "127.0.0.1", { rejectUnauthorized: false }));
    await new Promise((r) => setTimeout(r, 20));
    await new Promise<void>((r) => srv.close(() => r()));

    expect(connections).toBe(3);
    expect(decisions).toHaveLength(3);
    expect(decisions.every((d) => d.decision.allowed)).toBe(true);
    for (const d of decisions) expect(d.decision.observed).toMatchObject({ host: "127.0.0.1", port });
  });

  it("https.request reaches the granted endpoint (TLS over the same loopback listener)", async () => {
    let connections = 0;
    const srv = net.createServer((sock) => {
      connections++;
      sock.destroy();
    });
    await new Promise<void>((resolve, reject) => {
      srv.once("error", reject);
      srv.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = srv.address();
    const port = addr && typeof addr === "object" ? addr.port : 0;

    const { ctx, decisions } = makeCtx(grantedPolicy(port), "enforce");
    const httpsShim = createHttpsShim(ctx);
    const req = httpsShim.request({ hostname: "127.0.0.1", port, path: "/", rejectUnauthorized: false });
    req.end();
    await new Promise<void>((resolve) => {
      req.once("error", () => resolve());
      req.once("response", () => resolve());
    });
    await new Promise((r) => setTimeout(r, 20));
    await new Promise<void>((r) => srv.close(() => r()));

    expect(connections).toBe(1);
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port });
  });

  it("tls.connect(port, host, {}, {host: other}): only the slot Node merges decides the target", async () => {
    // Node's `normalizeConnectArgs` assigns args[1] if it is an object, ELSE args[2] — and
    // nothing else. Treating an object at any other index as an overlay guarded a target Node
    // never dials: this call connects to the POSITIONAL host, so that is what must be guarded.
    const port = await closedLocalPort();
    const { ctx, decisions } = makeCtx(grantedPolicyFor("192.0.2.1", port), "enforce");
    const tlsShim = createTlsShim(ctx);
    expect(() =>
      (tlsShim.connect as unknown as (...a: unknown[]) => unknown)(port, "127.0.0.1", {}, { host: "192.0.2.1" }),
    ).toThrowError(expect.objectContaining({ name: "CapabilityError" }));
    expect(decisions[0]!.decision.observed).toMatchObject({ host: "127.0.0.1", port });
  });
});
