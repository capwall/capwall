/**
 * THE LIFECYCLE MATRIX — issue #90, blind spot 3.
 *
 * `install-lifecycle.test.ts` pins #87 for `fs` and `process.env`: capture a reference, swap the
 * policy, assert the capture honors the new one. That is the right test, written for two of the
 * ten mediated surfaces — and #87's report named the divergence explicitly ("`process.env`
 * re-points correctly while `fs` does not"). A divergence between two shims is only visible to a
 * test that asks BOTH the same question at the same moment, which is why this file runs the
 * whole sequence over every shim at once and asserts they agree at every step.
 *
 * THE SEQUENCE, run per shim and then across all of them together:
 *
 *   install(loose) → the dependency CAPTURES its reference at load time
 *                  → uninstall() → install(tighter)
 *                  → the CAPTURED reference must honor the NEW policy
 *                  → …and so must a freshly-required one, so the two can never disagree
 *                  → uninstall() → the capture fails CLOSED, a fresh access is UN-MEDIATED
 *
 * Those last two are #94's deliberate asymmetry and they are pinned here rather than assumed: a
 * capture cannot be revoked (an ESM `const` binding is immutable, a CJS module's private `const
 * fs` is unreachable), so "capwall is off again" is not on the menu for it — the choice is the
 * dead install's grants or none, and refusing is the honest one. A FRESH access after teardown
 * really is un-mediated, because `Module._load` / `process.env` / `process.dlopen` / the egress
 * globals really are restored. Both halves, stated, for every shim.
 *
 * WHAT IS NOT HERE. The ESM half of the same lifecycle is a subprocess concern (synthetic ESM
 * modules are cached per process and never re-evaluated, so an in-process test would assert
 * against whichever policy the first install happened to leave behind — which is the bug). It is
 * covered by `esm.test.ts` § #62 and by the `{cjs, esm} × option` suite in
 * `install-option-parity.test.ts`.
 */
import { createRequire } from "node:module";
import * as net from "node:net";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  install,
  loadPolicyFromObject,
  type InstallHandle,
  type Policy,
} from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");
const SECRET_KEY = "LIFECYCLE_MATRIX_SECRET";
const SECRET_VALUE = "s3cr3t";

interface OpOutcome {
  ok: boolean;
  value?: unknown;
  error?: string;
}
interface FixtureDep {
  tryOp(family: "captured" | "fresh", name: string, args?: unknown[]): OpOutcome;
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

let PORT = 0;
beforeAll(async () => {
  PORT = await closedLocalPort();
  process.env[SECRET_KEY] = SECRET_VALUE; // on the REAL environment, before any proxy exists
});

const open: InstallHandle[] = [];
afterEach(() => {
  while (open.length > 0) open.pop()?.uninstall();
});
function track(handle: InstallHandle): InstallHandle {
  open.push(handle);
  return handle;
}

const OPTS = { projectRoot: here } as const;

const loose = (port: number): Policy =>
  loadPolicyFromObject(
    {
      version: 1,
      mode: "enforce",
      packages: {
        "fixture-dep": {
          fs: { read: ["./fixtures/**"] },
          net: { hosts: ["127.0.0.1"], ports: [port] },
          child_process: true,
          worker_threads: true,
          vm: true,
          env: [SECRET_KEY],
        },
      },
    },
    { projectRoot: here },
  );

const tight = (): Policy =>
  loadPolicyFromObject({ version: 1, mode: "enforce", packages: {} }, { projectRoot: here });

/**
 * Every mediated CJS surface, with the arguments its op needs.
 *
 * `env` is the odd one and deliberately kept in the table: it SOFT-denies (returns `undefined`)
 * where the others throw, so "denied" means something different for it. Normalizing that into a
 * boolean is exactly what lets the cross-shim agreement assertion below be written at all — and
 * the divergence #87 found was between `env` and `fs` specifically.
 */
const SHIMS: Array<{ name: string; args: unknown[]; deniedIsSoft?: boolean }> = [
  { name: "fs", args: [] },
  { name: "net", args: ["127.0.0.1", 0] },
  { name: "http", args: ["127.0.0.1", 0] },
  { name: "dgram", args: ["127.0.0.1", 0] },
  { name: "child_process", args: [] },
  { name: "vm", args: [] },
  { name: "worker_threads", args: [] },
  { name: "env", args: [SECRET_KEY], deniedIsSoft: true },
];

/** Was this op refused? Uniform across hard denials (a thrown CapabilityError) and the env
 * guard's soft denial (the value is withheld). */
function denied(dep: FixtureDep, family: "captured" | "fresh", shim: (typeof SHIMS)[number]): boolean {
  const args = shim.name === "net" || shim.name === "http" || shim.name === "dgram"
    ? [shim.args[0], PORT]
    : shim.args;
  const outcome = dep.tryOp(family, shim.name, args);
  if (shim.deniedIsSoft === true) return outcome.value === undefined;
  return outcome.ok === false && outcome.error === "CapabilityError";
}

describe("#90 — install → capture → uninstall → reinstall tighter, for EVERY shim", () => {
  for (const shim of SHIMS) {
    it(`${shim.name}: the captured reference honors the NEW policy, and agrees with a fresh one`, () => {
      const first = track(install(loose(PORT), "enforce", OPTS));
      const dep = loadFixtureFresh(); // captures every mediated module at load time
      expect([denied(dep, "captured", shim), denied(dep, "fresh", shim)]).toEqual([false, false]);

      first.uninstall();
      open.pop();
      const second = track(install(tight(), "enforce", OPTS));
      // THE #87 ASSERTION, for this shim. A captured shim that closed over its installer's
      // context would still be allowing.
      expect([denied(dep, "captured", shim), denied(dep, "fresh", shim)]).toEqual([true, true]);

      second.uninstall();
      open.pop();
      // Torn down. The capture fails CLOSED; a fresh access is genuinely un-mediated, because
      // the interception points really are restored (#94's deliberate asymmetry).
      expect(denied(dep, "captured", shim)).toBe(true);
      expect(denied(dep, "fresh", shim)).toBe(false);
    });
  }
});

describe("#90 — the shims agree with EACH OTHER at every step of the swap", () => {
  /**
   * This is the assertion #87's report is really about. It observed that `process.env` re-pointed
   * correctly while `fs` did not — one process enforcing two policies at once, which is worse
   * than either behaviour applied consistently. A per-shim test cannot see that; only a
   * simultaneous read of all of them can.
   */
  const snapshot = (dep: FixtureDep, family: "captured" | "fresh"): Record<string, boolean> =>
    Object.fromEntries(SHIMS.map((s) => [s.name, denied(dep, family, s)]));

  const allSame = (row: Record<string, boolean>, value: boolean): boolean =>
    Object.values(row).every((v) => v === value);

  it("keeps every captured shim, and every fresh one, on the same side of the swap", () => {
    const first = track(install(loose(PORT), "enforce", OPTS));
    const dep = loadFixtureFresh();

    expect(allSame(snapshot(dep, "captured"), false)).toBe(true);
    expect(allSame(snapshot(dep, "fresh"), false)).toBe(true);

    const second = track(install(tight(), "enforce", OPTS)); // nested: innermost wins
    expect(snapshot(dep, "captured")).toEqual(snapshot(dep, "fresh"));
    expect(allSame(snapshot(dep, "captured"), true)).toBe(true);

    second.uninstall();
    open.pop();
    // Loosening applies too — a live policy, not a one-way ratchet.
    expect(snapshot(dep, "captured")).toEqual(snapshot(dep, "fresh"));
    expect(allSame(snapshot(dep, "captured"), false)).toBe(true);

    first.uninstall();
    open.pop();
    // Torn down: EVERY capture denies and EVERY fresh access is un-mediated. The asymmetry is
    // uniform across shims, which is the property that matters — a shim that failed OPEN on the
    // capture side, or CLOSED on the fresh side, would break this row alone.
    expect(allSame(snapshot(dep, "captured"), true)).toBe(true);
    expect(allSame(snapshot(dep, "fresh"), false)).toBe(true);
  });

  it("re-exposes the outer install for every shim when a nested one unwinds, in any order", () => {
    const outer = track(install(loose(PORT), "enforce", OPTS));
    const dep = loadFixtureFresh();
    const inner = track(install(tight(), "enforce", OPTS));
    expect(allSame(snapshot(dep, "captured"), true)).toBe(true);

    // Remove the OUTER install first — it is not on top, so nothing about the live policy may
    // change. This is the `_load` chain's #22 contract, asserted here for every shim at once.
    outer.uninstall();
    expect(allSame(snapshot(dep, "captured"), true)).toBe(true);
    outer.uninstall(); // idempotent — must not pop the survivor
    expect(allSame(snapshot(dep, "captured"), true)).toBe(true);

    inner.uninstall();
    open.length = 0;
    expect(allSame(snapshot(dep, "captured"), true)).toBe(true); // torn down → fail closed
    expect(allSame(snapshot(loadFixtureFresh(), "fresh"), false)).toBe(true); // …loader restored
  });
});

describe("#90 — a reinstall reuses the same shim objects (no forwarder, no stranded capture)", () => {
  /**
   * The structural counterpart of the behavioural assertions above. `liveRegistry` builds each
   * registry exactly once and re-points `liveCtx`'s FIELDS instead, so a policy swap inserts
   * nothing between the caller and the guard. If a swap were ever implemented with a per-install
   * forwarder or a registry rebuild, these identities would have to change — and every existing
   * capture would be stranded on the old objects, which is #62/#87 all over again.
   */
  const MODULES = [
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
  ] as const;

  it("hands back identical module objects across uninstall + reinstall, for every specifier", () => {
    const first = track(install(loose(PORT), "enforce", OPTS));
    const before = MODULES.map((m) => requireCjs(m) as object);
    first.uninstall();
    open.pop();
    track(install(tight(), "enforce", OPTS));
    const after = MODULES.map((m) => requireCjs(m) as object);
    for (let i = 0; i < MODULES.length; i++) {
      expect(after[i], `${MODULES[i]} was rebuilt across a policy swap`).toBe(before[i]);
    }
  });

  it("keeps handing out mutable shims by default across the swap (graceful-fs compatibility)", () => {
    const first = track(install(loose(PORT), "enforce", OPTS));
    first.uninstall();
    open.pop();
    track(install(tight(), "enforce", OPTS));
    for (const m of MODULES) {
      expect(Object.isFrozen(requireCjs(m) as object), `${m} froze without hardened mode`).toBe(
        false,
      );
    }
  });
});

describe("#90 — teardown restores every interception POINT, not just the loader", () => {
  /**
   * `InstallHandle.uninstall` names four: `Module._load`, `process.env`, `process.dlopen` and
   * the egress globals. `loader-uninstall.test.ts` pins the first. The other three are asserted
   * here, together, because "one of the four was left patched" is exactly the shape that made
   * the env guard and the global-egress guard leak under an out-of-order teardown — a bug this
   * matrix found and `composition-matrix.test.ts` § S11/S12 regression-tests.
   */
  it("restores process.env, process.dlopen, globalThis.fetch and Module._load together", () => {
    const NodeModule = requireCjs("node:module") as { _load: unknown };
    const before = {
      env: process.env,
      dlopen: (process as unknown as { dlopen: unknown }).dlopen,
      fetch: (globalThis as { fetch?: unknown }).fetch,
      load: NodeModule._load,
      compile: (requireCjs("node:module") as { prototype: Record<string, unknown> }).prototype[
        "_compile"
      ],
    };

    const handle = install(loose(PORT), "enforce", OPTS);
    // Every one of them is actually different while installed — otherwise the restore assertion
    // below would pass vacuously.
    expect(process.env).not.toBe(before.env);
    expect((process as unknown as { dlopen: unknown }).dlopen).not.toBe(before.dlopen);
    expect((globalThis as { fetch?: unknown }).fetch).not.toBe(before.fetch);
    expect(NodeModule._load).not.toBe(before.load);

    handle.uninstall();
    expect(process.env).toBe(before.env);
    expect((process as unknown as { dlopen: unknown }).dlopen).toBe(before.dlopen);
    expect((globalThis as { fetch?: unknown }).fetch).toBe(before.fetch);
    expect(NodeModule._load).toBe(before.load);
    expect(
      (requireCjs("node:module") as { prototype: Record<string, unknown> }).prototype["_compile"],
    ).toBe(before.compile);
  });

  it("keeps them ALL patched while any install is still active, and restores them all at once", () => {
    const NodeModule = requireCjs("node:module") as { _load: unknown };
    const realEnv = process.env;
    const realLoad = NodeModule._load;

    const outer = track(install(loose(PORT), "enforce", OPTS));
    const inner = track(install(tight(), "enforce", OPTS));
    outer.uninstall();
    // A single surface restoring early would be the divergence this file exists to catch.
    expect(process.env).not.toBe(realEnv);
    expect(NodeModule._load).not.toBe(realLoad);
    inner.uninstall();
    open.length = 0;
    expect(process.env).toBe(realEnv);
    expect(NodeModule._load).toBe(realLoad);
  });
});

describe("#90 — a torn-down install's decision sink is dropped for EVERY shim", () => {
  /**
   * #87 found the CJS half still firing `onDecision` into the torn-down install's collector —
   * a use-after-free of somebody else's state, and for the CLI a decision belonging to no
   * install landing in the previous run's gen-policy trace. `install-lifecycle.test.ts` pins it
   * for `fs` and `env`; the cross-shim form is what proves no surface kept its own sink.
   */
  it("records nothing into the old sink after teardown, from any captured shim", () => {
    const recorded: string[] = [];
    const handle = track(
      install(loose(PORT), "enforce", {
        ...OPTS,
        onDecision: (pkg, decision) => recorded.push(`${pkg}:${decision.observed.kind}`),
      }),
    );
    const dep = loadFixtureFresh();
    for (const shim of SHIMS) denied(dep, "captured", shim);
    expect(recorded.length).toBeGreaterThan(0);

    handle.uninstall();
    open.pop();
    const settled = recorded.length;
    for (const shim of SHIMS) {
      // Still denies (fail-closed) — but silently, into no collector at all.
      expect(denied(dep, "captured", shim), `${shim.name} did not fail closed`).toBe(true);
    }
    expect(recorded.length).toBe(settled);
  });
});
