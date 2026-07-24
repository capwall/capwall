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
import * as net from "node:net";
import * as http from "node:http";
import { describe, expect, it } from "vitest";
import { createHttpShim, createHttpsShim, createNetShim, createTlsShim } from "../src/shims/net.js";
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
