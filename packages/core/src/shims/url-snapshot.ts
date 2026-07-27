/**
 * SINGLE-READ URL PINNING — the shared primitive behind capwall's egress TOCTOU fixes
 * (issues #26, #56, and now the global egress guard, #80).
 *
 * Extracted from `shims/net.ts` verbatim so the `net`/`http(s)`/`tls`/`http2` module shims and
 * the `globalThis.fetch`/`WebSocket`/`EventSource` guard share ONE implementation. Deriving a
 * second one would be the exact mistake #26 and #56 were: two places that each read a
 * caller-controlled URL and disagree about what it said. `shims/global-egress.ts` imports from
 * here rather than from `net.ts` only to keep the import graph acyclic — `net.ts` in turn needs
 * the guarded `WebSocket` class from `global-egress.ts` for the `http.WebSocket` re-export that
 * Node ≥22 puts on the `http` namespace.
 *
 * HOST SPELLING (the reason {@link stripIpv6Brackets} exists at all). An IPv6 literal is
 * guarded — and therefore written in policy — UNBRACKETED (`::1`, not `[::1]`), because that is
 * what Node itself dials: `urlToHttpOptions` and `http2.connect` both strip the brackets a
 * `URL` keeps on `.hostname`. Brackets go back only when composing a URL/authority STRING,
 * where `http://::1:8080` would not parse.
 */

/**
 * A `URL` keeps an IPv6 literal BRACKETED (`new URL("http://[::1]/").hostname === "[::1]"`),
 * but everything that actually dials strips them: Node's `urlToHttpOptions` and
 * `http2.connect` both hand `::1` to `net`/`dns`. capwall guards the UNBRACKETED form so a
 * policy author writes `::1` (the same spelling `net.connect({host})` and the policy's exact
 * host match use) — and so the guarded host is the string Node resolves. Forgetting this made
 * every IPv6 http(s) URL fail with `ENOTFOUND [::1]` once capwall started synthesizing options.
 */
export function stripIpv6Brackets(hostname: string): string {
  return hostname.length > 2 && hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

/** Inverse of {@link stripIpv6Brackets}, for the one place brackets are required: composing a
 * URL/authority STRING. `http://::1:8080` is not a parseable URL; `http://[::1]:8080` is. */
export function bracketIpv6(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

/**
 * Node's OWN test for "is this argument a URL" (`isURL` in `lib/internal/url.js`, byte-identical
 * on Node 20 and 22):
 *
 *     Boolean(self?.href && self.protocol && self.auth === undefined && self.path === undefined)
 *
 * It is **duck-typed, not `instanceof URL`**, and that distinction decides real behavior at two
 * of capwall's entry points, which is why this predicate is shared rather than re-derived (#99):
 *
 *  - `http(s)` `ClientRequest` calls `isURL(input)` to decide whether `args[0]` is a URL to run
 *    through `urlToHttpOptions` — and therefore whether `args[1]` is an options OVERLAY or the
 *    callback. Using `instanceof` instead let `http.request({href, protocol, hostname: granted},
 *    {hostname: evil})` be guarded as `granted` and connected to `evil`.
 *  - `fs`'s `toPathIfFileURL` calls it on every path argument, so a plain object with `href` and
 *    `protocol: "file:"` IS a path to Node. `instanceof` made capwall classify it as "not a path"
 *    and skip the gate entirely.
 *
 * The reads are ordinary property reads, exactly as Node performs them; a caller that installs
 * accessors here has them invoked once by this predicate and once by Node's — which is why every
 * caller of this function goes on to PIN what it derived (a synthesized options object, or the
 * converted path string) rather than forwarding the caller's object for Node to re-read.
 */
export function isNodeUrlLike(v: unknown): boolean {
  if (v === null || (typeof v !== "object" && typeof v !== "function")) return false;
  const o = v as Record<string, unknown>;
  return Boolean(o["href"] && o["protocol"] && o["auth"] === undefined && o["path"] === undefined);
}

/** Coerce an ALREADY-READ raw `port` value to a number; `undefined` when it names no port.
 * Reads nothing — the caller performed the single read. */
export function coercePort(raw: unknown): number | undefined {
  if (typeof raw === "number") return raw;
  if (typeof raw === "string" && raw !== "") {
    const n = Number(raw);
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

/**
 * Fields Node's own `urlToHttpOptions` (and http2's authority parsing) derive from a URL,
 * captured with EACH property read exactly once. A caller-supplied `URL` instance can carry an
 * OWN shadowed accessor for any of these (e.g.
 * `Object.defineProperty(url, "port", { get(){ return firstCall ? granted : evil; } })`) that
 * legally returns a different value on a second read — reading twice (once to guard, once when
 * building what gets forwarded) is exactly the TOCTOU this closes (issue #26, URL-argument
 * follow-up). Every consumer builds its guarded target AND its forwarded args from this ONE
 * snapshot; the URL itself is never consulted again.
 */
export interface UrlSnapshot {
  protocol: string;
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
  href: string;
  username: string;
  password: string;
}

export function snapshotUrl(u: URL): UrlSnapshot {
  return {
    protocol: u.protocol,
    hostname: u.hostname,
    port: u.port, // read once — reused for both the "has a port" check and Number(...) below
    pathname: u.pathname,
    search: u.search,
    hash: u.hash,
    href: u.href,
    username: u.username,
    password: u.password,
  };
}
