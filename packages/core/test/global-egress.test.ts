/**
 * GLOBAL EGRESS GUARD — `globalThis.fetch` / `WebSocket` / `EventSource` (issue #80).
 *
 * The gap these cover, confirmed empirically before the fix: a dependency calling `fetch()`
 * under a **deny-all enforce policy** exfiltrated successfully with **zero decisions recorded**.
 * Not a bypass of a guard — there was no guard, because `fetch` is a global and every other
 * capwall interception point is module loading.
 *
 * Everything here drives the real `install()` (not a shim factory) with the vendored
 * `fixture-dep` under `test/fixtures/node_modules`, so the calls attribute to a *dependency*,
 * which is the whole point: a `fetch` that landed on `<unknown>` would force every real app to
 * grant `<unknown>` just to use `fetch`.
 *
 * Hermetic: a loopback HTTP server on an ephemeral port. Nothing leaves the machine. The
 * WebSocket cases deliberately have no WS server — the assertion is about the GUARD (does it
 * fire before the socket opens?), and a granted socket failing at the transport level is the
 * same trick `net.test.ts` uses with a closed port.
 */
import { createRequire } from "node:module";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { install, loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");

interface FetchResult {
  status: number;
  body: string;
}

interface FixtureDep {
  fetchUrl(url: string, init?: unknown): Promise<FetchResult>;
  fetchViaUrlObject(url: string): Promise<FetchResult>;
  fetchViaHostileUrl(first: string, second: string): Promise<FetchResult>;
  fetchViaShadowedRequest(
    realUrl: string,
    pretendUrl: string,
  ): Promise<FetchResult & { reportedUrl: string }>;
  fetchViaRequest(url: string, init?: unknown): Promise<FetchResult>;
  fetchDataUrl(): Promise<FetchResult>;
  fetchNoAwait(url: string): Promise<FetchResult>;
  fetchThrowingToString(): Promise<unknown>;
  fetchShapes(base: string): Promise<Record<string, unknown>>;
  openWebSocket(url: string): Promise<string>;
  openWebSocketViaConstructorEscape(url: string): unknown;
  openWebSocketViaHttpNamespace(url: string): unknown;
  patchGlobalFetch(replacement: unknown): unknown;
  patchGlobalFetchStrict(replacement: unknown): unknown;
  globalEgressShape(): Record<string, unknown>;
}

type Recorded = { pkg: string; decision: Decision };

function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

interface Window {
  dep: FixtureDep;
  decisions: Recorded[];
}

/** Run `fn` inside an install() window and always tear it down — a leaked global egress guard
 * would poison every later test file in the same worker. */
async function withCapwall<T>(
  policy: Policy,
  mode: "observe" | "enforce",
  fn: (w: Window) => Promise<T> | T,
  options: { hardened?: boolean } = {},
): Promise<T> {
  const decisions: Recorded[] = [];
  const handle = install(policy, mode, {
    projectRoot: here,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
    ...(options.hardened === true ? { hardened: true } : {}),
  });
  try {
    return await fn({ dep: loadFixtureFresh(), decisions });
  } finally {
    handle.uninstall();
  }
}

const denyAll = (): Policy => loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: here });

/** Grant `fixture-dep` egress to loopback on the given ports (and nothing else). */
const grantFixture = (mode: "observe" | "enforce", ...ports: number[]): Policy =>
  loadPolicyFromObject(
    {
      version: 1,
      mode,
      packages: { "fixture-dep": { net: { hosts: ["127.0.0.1"], ports } } },
    },
    { projectRoot: here },
  );

/** The test server. Routes exist to exercise the ordinary shapes a real app relies on. */
function startServer(handler: (url: string, body: string) => {
  status: number;
  headers?: Record<string, string>;
  body?: string;
  chunks?: string[];
}): Promise<{ server: Server; port: number }> {
  const server = createServer((req, res) => {
    const chunksIn: Buffer[] = [];
    req.on("data", (c: Buffer) => chunksIn.push(c));
    req.on("end", () => {
      const out = handler(req.url ?? "/", Buffer.concat(chunksIn).toString("utf8"));
      const headers: Record<string, string> = { "content-type": "text/plain", ...out.headers };
      // Echo request headers back, so a test can prove the caller's headers survived the guard.
      for (const [k, v] of Object.entries(req.headers)) {
        if (k.startsWith("x-capwall-") && typeof v === "string") headers[`x-echo-${k.slice(2)}`] = v;
      }
      res.writeHead(out.status, headers);
      if (out.chunks) {
        for (const c of out.chunks) res.write(c);
        res.end();
      } else {
        res.end(out.body ?? "");
      }
    });
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, port: (server.address() as AddressInfo).port });
    });
  });
}

let main: Server;
let mainPort: number;
let redirectTarget: Server;
let redirectPort: number;
let base: string;

beforeAll(async () => {
  const target = await startServer(() => ({ status: 200, body: "final-hop" }));
  redirectTarget = target.server;
  redirectPort = target.port;
  const m = await startServer((url, body) => {
    if (url === "/missing") return { status: 404, body: "nope" };
    if (url === "/echo") return { status: 200, body };
    if (url === "/chunks") return { status: 200, chunks: ["one-", "two-", "three"] };
    if (url === "/redirect") {
      return { status: 302, headers: { location: `http://127.0.0.1:${redirectPort}/landed` }, body: "" };
    }
    if (url === "/self-redirect") {
      return { status: 302, headers: { location: `http://127.0.0.1:${mainPort}/ok` }, body: "" };
    }
    return { status: 200, body: `ok:${url}` };
  });
  main = m.server;
  mainPort = m.port;
  base = `http://127.0.0.1:${mainPort}`;
});

afterAll(async () => {
  await new Promise((r) => main.close(() => r(null)));
  await new Promise((r) => redirectTarget.close(() => r(null)));
});

/** Assert exactly one decision was recorded, and return it. */
function onlyDecision(decisions: Recorded[]): Recorded {
  expect(decisions).toHaveLength(1);
  return decisions[0]!;
}

describe("#80 — globalThis.fetch is mediated", () => {
  it("denies an ungranted dependency's fetch in enforce, AND records the decision", async () => {
    // This is the regression for the reported bug in both halves: before the fix the fetch
    // SUCCEEDED and `decisions` was empty, so `observe`/`capwall diff` could not see it either.
    await withCapwall(denyAll(), "enforce", async ({ dep, decisions }) => {
      await expect(dep.fetchUrl(`${base}/drop`)).rejects.toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
      const { pkg, decision } = onlyDecision(decisions);
      expect(pkg).toBe("fixture-dep");
      expect(decision.allowed).toBe(false);
      expect(decision.observed).toEqual({ kind: "net", host: "127.0.0.1", port: mainPort });
    });
  });

  it("attributes a dependency's fetch to that dependency — not <app>, not <unknown>", async () => {
    // If an async API detached the caller's frames before the guard ran, this would be
    // `<unknown>` (#60) and every real app would need an `<unknown>` grant to use fetch. The
    // guard runs synchronously, on the caller's stack, before the first await.
    await withCapwall(grantFixture("enforce", mainPort), "enforce", async ({ dep, decisions }) => {
      await dep.fetchUrl(`${base}/ok`);
      expect(onlyDecision(decisions).pkg).toBe("fixture-dep");
    });
  });

  it("allows a granted dependency's fetch and round-trips the response", async () => {
    await withCapwall(grantFixture("enforce", mainPort), "enforce", async ({ dep, decisions }) => {
      await expect(dep.fetchUrl(`${base}/hi`)).resolves.toEqual({ status: 200, body: "ok:/hi" });
      expect(onlyDecision(decisions).decision.allowed).toBe(true);
    });
  });

  it("records but never blocks in observe mode", async () => {
    await withCapwall(loadPolicyFromObject({ version: 1, mode: "observe" }), "observe", async ({ dep, decisions }) => {
      await expect(dep.fetchUrl(`${base}/hi`)).resolves.toEqual({ status: 200, body: "ok:/hi" });
      const { pkg, decision } = onlyDecision(decisions);
      expect(pkg).toBe("fixture-dep");
      expect(decision.allowed).toBe(true);
      expect(decision.observed).toEqual({ kind: "net", host: "127.0.0.1", port: mainPort });
    });
  });

  it("guards a URL instance the same way as a string", async () => {
    await withCapwall(denyAll(), "enforce", async ({ dep, decisions }) => {
      await expect(dep.fetchViaUrlObject(`${base}/drop`)).rejects.toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
      expect(onlyDecision(decisions).decision.observed).toEqual({
        kind: "net",
        host: "127.0.0.1",
        port: mainPort,
      });
    });
  });

  it("defaults the port from the scheme when the URL carries none", async () => {
    await withCapwall(denyAll(), "enforce", async ({ dep, decisions }) => {
      await expect(dep.fetchUrl("https://attacker.example/x")).rejects.toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
      expect(onlyDecision(decisions).decision.observed).toEqual({
        kind: "net",
        host: "attacker.example",
        port: 443,
      });
    });
  });
});

describe("#80 — single-read pinning (the #26/#56 TOCTOU class, fetch flavor)", () => {
  it("a URL whose toString answers differently the 2nd time cannot redirect the request", async () => {
    // Un-pinned, capwall would guard `first` and undici would dial `second` (measured: without
    // pinning, the request lands on the SECOND value). Pinned, the string capwall guarded is the
    // string undici receives, so the request must land on `first`.
    await withCapwall(grantFixture("enforce", mainPort), "enforce", async ({ dep, decisions }) => {
      const res = await dep.fetchViaHostileUrl(`${base}/first`, `${base}/second`);
      expect(res.body).toBe("ok:/first");
      expect(onlyDecision(decisions).decision.allowed).toBe(true);
    });
  });

  it("a Request with a shadowed own `url` accessor is guarded on its REAL destination", async () => {
    // The nastiest shape here: `req.url` reports whatever the attacker's accessor says, while
    // undici dials the immutable internal URL. A guard that trusted `req.url` would have printed
    // an ALLOW line for a request that went somewhere else — worse than no guard at all.
    await withCapwall(denyAll(), "enforce", async ({ dep, decisions }) => {
      await expect(
        dep.fetchViaShadowedRequest(`${base}/real`, "http://granted.example/"),
      ).rejects.toThrowError(expect.objectContaining({ name: "CapabilityError" }));
      // Guarded on the loopback server it would really have reached, NOT on granted.example.
      expect(onlyDecision(decisions).decision.observed).toEqual({
        kind: "net",
        host: "127.0.0.1",
        port: mainPort,
      });
    });
  });

  it("an ordinary Request object still round-trips when granted", async () => {
    await withCapwall(grantFixture("enforce", mainPort), "enforce", async ({ dep }) => {
      await expect(dep.fetchViaRequest(`${base}/echo`, { method: "POST", body: "req-obj" })).resolves.toEqual({
        status: 200,
        body: "req-obj",
      });
    });
  });
});

describe("#80 — a denial arrives through the channel real fetch uses", () => {
  it("rejects the promise instead of throwing synchronously", async () => {
    // Real `fetch` NEVER throws synchronously — even `fetch()` with no arguments returns a
    // rejected promise (verified on Node 20 and 22). A synchronous throw would crash
    // `fetch(url).catch(handle)`, the idiomatic non-async form, with an uncaught exception the
    // caller would never see from real fetch. Same reasoning as the fs stream-denial channel
    // (#40).
    await withCapwall(denyAll(), "enforce", async ({ dep }) => {
      let promise: Promise<unknown> | undefined;
      expect(() => {
        promise = dep.fetchNoAwait(`${base}/drop`);
      }).not.toThrow();
      await expect(promise).rejects.toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("a caller `toString` that throws during pinning also rejects rather than throwing", async () => {
    await withCapwall(denyAll(), "enforce", async ({ dep }) => {
      let promise: Promise<unknown> | undefined;
      expect(() => {
        promise = dep.fetchThrowingToString();
      }).not.toThrow();
      await expect(promise).rejects.toThrowError(/hostile-toString/);
    });
  });
});

describe("#80 — schemes that move no bytes are not gated", () => {
  it("a data: URL fetch is neither denied nor recorded under a deny-all enforce policy", async () => {
    await withCapwall(denyAll(), "enforce", async ({ dep, decisions }) => {
      await expect(dep.fetchDataUrl()).resolves.toEqual({ status: 200, body: "inert" });
      expect(decisions).toHaveLength(0);
    });
  });

  it("an unparseable input produces Node's own error, unchanged, and no decision", async () => {
    await withCapwall(denyAll(), "enforce", async ({ dep, decisions }) => {
      await expect(dep.fetchUrl("not a url")).rejects.toThrowError(/Failed to parse URL/);
      expect(decisions).toHaveLength(0);
    });
  });
});

describe("#80 — ordinary shapes round-trip identically for a granted fetch", () => {
  it("headers, non-2xx, POST bodies, streaming in and out, and AbortSignal all behave", async () => {
    await withCapwall(grantFixture("enforce", mainPort), "enforce", async ({ dep }) => {
      const shapes = await dep.fetchShapes(base);
      expect(shapes["notFoundStatus"]).toBe(404);
      expect(shapes["notFoundOk"]).toBe(false); // fetch does NOT reject on 4xx
      expect(shapes["echoedHeader"]).toBe("1"); // request headers survived the guard
      expect(shapes["postedBody"]).toBe("hello-capwall");
      expect(shapes["streamedBody"]).toBe("streamed-request"); // ReadableStream request body
      expect(shapes["streamedResponse"]).toBe("one-two-three"); // response consumed via reader
      expect(shapes["abortMessage"]).toBe("capwall-abort-marker"); // abort reason, not a capwall error
    });
  });
});

describe("#80 — redirects", () => {
  it("enforce: a granted first hop that 302s to an ungranted host is recorded and rejected", async () => {
    // capwall cannot PREVENT the redirected request (undici follows it internally, with no
    // interception point), but it refuses to be silent: the final origin is evaluated, recorded,
    // and the response withheld. See docs/threat-model.md § global egress residuals.
    await withCapwall(grantFixture("enforce", mainPort), "enforce", async ({ dep, decisions }) => {
      await expect(dep.fetchUrl(`${base}/redirect`)).rejects.toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
      expect(decisions).toHaveLength(2);
      expect(decisions[0]!.decision.observed).toEqual({ kind: "net", host: "127.0.0.1", port: mainPort });
      expect(decisions[0]!.decision.allowed).toBe(true);
      expect(decisions[1]!.decision.observed).toEqual({ kind: "net", host: "127.0.0.1", port: redirectPort });
      expect(decisions[1]!.decision.allowed).toBe(false);
      // Attributed to the dependency, NOT `<unknown>` — the principal is carried over from the
      // synchronous first-hop guard rather than re-derived from a detached `.then` stack.
      expect(decisions[1]!.pkg).toBe("fixture-dep");
    });
  });

  it("enforce: the redirect hop is allowed when the target host:port is granted too", async () => {
    await withCapwall(grantFixture("enforce", mainPort, redirectPort), "enforce", async ({ dep, decisions }) => {
      await expect(dep.fetchUrl(`${base}/redirect`)).resolves.toEqual({ status: 200, body: "final-hop" });
      expect(decisions).toHaveLength(2);
      expect(decisions.every((d) => d.decision.allowed)).toBe(true);
    });
  });

  it("a redirect that stays on the guarded host:port is not re-recorded", async () => {
    await withCapwall(grantFixture("enforce", mainPort), "enforce", async ({ dep, decisions }) => {
      await expect(dep.fetchUrl(`${base}/self-redirect`)).resolves.toEqual({ status: 200, body: "ok:/ok" });
      expect(decisions).toHaveLength(1);
    });
  });

  it("observe: the redirect target is recorded so gen-policy can emit a grant for it", async () => {
    await withCapwall(loadPolicyFromObject({ version: 1, mode: "observe" }), "observe", async ({ dep, decisions }) => {
      await expect(dep.fetchUrl(`${base}/redirect`)).resolves.toEqual({ status: 200, body: "final-hop" });
      expect(decisions.map((d) => d.decision.observed)).toEqual([
        { kind: "net", host: "127.0.0.1", port: mainPort },
        { kind: "net", host: "127.0.0.1", port: redirectPort },
      ]);
    });
  });
});

// `WebSocket` is unflagged only on Node >=22; on Node 20 it needs --experimental-websocket.
// The flagged-runtime coverage for BOTH classes lives in global-egress-flagged.test.ts, which
// spawns a child process with the flags, so Node 20 is covered there rather than skipped.
const hasWebSocket = typeof (globalThis as { WebSocket?: unknown }).WebSocket === "function";

describe.skipIf(!hasWebSocket)("#80 — globalThis.WebSocket is mediated", () => {
  it("denies an ungranted dependency's WebSocket in enforce", async () => {
    await withCapwall(denyAll(), "enforce", async ({ dep, decisions }) => {
      await expect(dep.openWebSocket(`ws://127.0.0.1:${mainPort}/`)).rejects.toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
      const { pkg, decision } = onlyDecision(decisions);
      expect(pkg).toBe("fixture-dep");
      expect(decision.observed).toEqual({ kind: "net", host: "127.0.0.1", port: mainPort });
    });
  });

  it("a granted WebSocket gets past the guard (and then fails at the transport, not at capwall)", async () => {
    // No WS server is running, so the handshake fails — which is exactly what proves the guard
    // ALLOWED it: a denial would have thrown a CapabilityError from the constructor instead.
    await withCapwall(grantFixture("enforce", mainPort), "enforce", async ({ dep, decisions }) => {
      await expect(dep.openWebSocket(`ws://127.0.0.1:${mainPort}/`)).rejects.toThrowError(
        /ws-transport-error/,
      );
      expect(onlyDecision(decisions).decision.allowed).toBe(true);
    });
  });

  it("`WebSocket.prototype.constructor` lands back on the guard (#64 invariant)", async () => {
    await withCapwall(denyAll(), "enforce", async ({ dep }) => {
      expect(() => dep.openWebSocketViaConstructorEscape(`ws://127.0.0.1:${mainPort}/`)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("the `http.WebSocket` re-export is guarded too, not just the global", async () => {
    // Node >=22 puts the same class on the `http` namespace. With the global closed, that copy
    // would otherwise be the remaining one-liner (#80).
    await withCapwall(denyAll(), "enforce", async ({ dep }) => {
      expect(() => dep.openWebSocketViaHttpNamespace(`ws://127.0.0.1:${mainPort}/`)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });
});

describe("#80 — uninstall() leaves no mutated global behind", () => {
  it("restores the exact original function objects and descriptors", async () => {
    const before = new Map<string, PropertyDescriptor | undefined>();
    for (const name of ["fetch", "WebSocket", "EventSource"]) {
      before.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    }
    await withCapwall(denyAll(), "enforce", ({ dep }) => {
      // Sanity: the guard really is installed inside the window.
      expect(globalThis.fetch).not.toBe(before.get("fetch")?.value);
      expect(dep).toBeDefined();
    });
    for (const [name, desc] of before) {
      expect(Object.getOwnPropertyDescriptor(globalThis, name)).toEqual(desc);
    }
  });

  it("a dependency's fetch is un-gated again after uninstall", async () => {
    await withCapwall(denyAll(), "enforce", () => undefined);
    const dep = loadFixtureFresh();
    await expect(dep.fetchUrl(`${base}/after-uninstall`)).resolves.toEqual({
      status: 200,
      body: "ok:/after-uninstall",
    });
  });

  it("does not clobber a replacement someone else installed after capwall", async () => {
    const original = globalThis.fetch;
    const decisions: Recorded[] = [];
    const handle = install(denyAll(), "enforce", { projectRoot: here, onDecision: (p, d) => decisions.push({ pkg: p, decision: d }) });
    const foreign = (() => Promise.resolve()) as unknown as typeof globalThis.fetch;
    globalThis.fetch = foreign;
    handle.uninstall();
    try {
      expect(globalThis.fetch).toBe(foreign); // left alone — capwall's value was already gone
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe("#80 — hardened mode (#17) on the guarded globals", () => {
  it("off by default: a dependency can still replace the global (documented un-patch)", async () => {
    // The write STICKS past uninstall() — capwall restores the original only when its own value
    // is still installed, exactly so a legitimate later replacement is not clobbered. So this
    // test has to put the real `fetch` back itself; that it must is the point of the assertion.
    const original = Object.getOwnPropertyDescriptor(globalThis, "fetch")!;
    try {
      await withCapwall(denyAll(), "enforce", ({ dep }) => {
        const replacement = (): void => {};
        expect(dep.patchGlobalFetch(replacement)).toBe(replacement);
      });
      expect(globalThis.fetch.name).toBe("replacement"); // capwall left the dep's value alone
    } finally {
      Object.defineProperty(globalThis, "fetch", original);
    }
  });

  it("hardened: the write is refused and the guard is still enforcing afterwards", async () => {
    await withCapwall(
      denyAll(),
      "enforce",
      async ({ dep, decisions }) => {
        const replacement = (): void => {};
        // Sloppy-mode CJS (what most published packages are): the write silently no-ops.
        expect(dep.patchGlobalFetch(replacement)).not.toBe(replacement);
        // Strict mode: the same write throws instead.
        expect(() => dep.patchGlobalFetchStrict(replacement)).toThrowError(TypeError);
        // The assertion that actually matters: mediation survived the attempt.
        await expect(dep.fetchUrl(`${base}/still-guarded`)).rejects.toThrowError(
          expect.objectContaining({ name: "CapabilityError" }),
        );
        expect(decisions.some((d) => !d.decision.allowed)).toBe(true);
      },
      { hardened: true },
    );
  });

  it("hardened mode still leaves the global CONFIGURABLE, so uninstall can restore it", async () => {
    // A non-configurable global could never be put back — that is why hardened mode buys
    // `writable: false` here and nothing more. See shims/global-egress.ts § blast radius.
    const original = Object.getOwnPropertyDescriptor(globalThis, "fetch");
    await withCapwall(
      denyAll(),
      "enforce",
      () => {
        expect(Object.getOwnPropertyDescriptor(globalThis, "fetch")?.configurable).toBe(true);
        expect(Object.getOwnPropertyDescriptor(globalThis, "fetch")?.writable).toBe(false);
      },
      { hardened: true },
    );
    expect(Object.getOwnPropertyDescriptor(globalThis, "fetch")).toEqual(original);
  });
});

describe("#80 — the guarded globals keep their observable shape", () => {
  it("name/length/prototype.constructor look like the real ones from inside a dependency", async () => {
    await withCapwall(denyAll(), "enforce", ({ dep }) => {
      const shape = dep.globalEgressShape();
      expect(shape["fetchName"]).toBe("fetch");
      expect(shape["fetchLength"]).toBe(globalThis.fetch.length);
      // Both legs of the CI matrix assert something. On a runtime without `WebSocket` the claim
      // is that capwall did not INVENT one — an `if (hasWebSocket)` with no `else` silently
      // dropped half this test on Node 20 (#112). The guarded-shape claim for `WebSocket` on
      // Node 20 is covered by `global-egress-flagged.test.ts`, which runs under the flag.
      expect({
        name: shape["webSocketName"],
        guarded: shape["webSocketPrototypeConstructorIsGuarded"],
      }).toEqual(
        // `null`, not `undefined`: the fixture reports the absent case explicitly, so a shape
        // object that simply stopped carrying the two keys would not satisfy this either.
        hasWebSocket ? { name: "WebSocket", guarded: true } : { name: null, guarded: null },
      );
    });
  });

  it("the global egress guard can be switched off entirely", async () => {
    const original = globalThis.fetch;
    const handle = install(denyAll(), "enforce", { projectRoot: here, globalEgress: false });
    try {
      expect(globalThis.fetch).toBe(original);
      const dep = loadFixtureFresh();
      await expect(dep.fetchUrl(`${base}/unmediated`)).resolves.toEqual({
        status: 200,
        body: "ok:/unmediated",
      });
    } finally {
      handle.uninstall();
    }
  });
});
