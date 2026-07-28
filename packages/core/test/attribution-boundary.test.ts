/**
 * Issue #143 — the `captureStackTrace` boundary fast path, applied to every guarded surface.
 *
 * WHAT CHANGED. `guard()` used to attribute by materializing up to `maxFrames` (25) V8 CallSites
 * from its own frame. It now takes the shim's ENTRY POINT — the `fs.readFileSync` a dependency
 * holds, the guarded `ReadStream` class, `net.connect`, `spawnSync`, `fetch`, the patched
 * `_compile` — and hands it to `Error.captureStackTrace` as the boundary, so V8 builds 3
 * CallSites starting at the caller's own frame. #132 measured attribution as ~70% of capwall's
 * added latency; #133 proved the shape on the `process.env` traps and this is the same lever on
 * the rest of the surface.
 *
 * WHY THIS FILE EXISTS, SEPARATELY FROM `attribution-fast-path.test.ts`. That file is the
 * adversary's side of the claim for the ENV traps. This one is the same two claims for every
 * OTHER surface, because the argument is per-surface: it rests on "the calling package's frame is
 * directly below the entry point", and that is a fact about each shim's own call chain, not a
 * property of the attribution module. A shim that hands in the wrong frame, or a Node release
 * that inserts an internal hop, must degrade to SLOWER — never to a different principal.
 *
 *   1. EQUIVALENCE. For every stack shape a caller can choose — direct, behind a native builtin
 *      frame, 40 frames of its own, from inside nested `eval`s — the surface charges the same
 *      principal it charged before, and denies the same calls.
 *   2. NO NEW AUTHORITY. `fixture-envpeek` is granted NOTHING in every policy below. Any
 *      assertion that comes back `fixture-dep`, `<app>`, or `allowed: true` for an envpeek call is
 *      a live capability-escalation hole, not a stale expectation. In particular the trust root
 *      `<app>` must remain unreachable through opaque code, which is the property the FALLBACK
 *      path carries — a fast path that answered instead of declining would break exactly here.
 *
 * The mutants `fastpath-declines-to-full-walk`, `fastpath-min-budget` and `walk-skips-capwall`
 * in `scripts/mutants.json` are the structural proof that these assertions bite; see
 * `packages/core/test/mutation-catalog.test.ts`.
 */
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  APP_ROOT,
  UNATTRIBUTED,
  install,
  loadPolicyFromObject,
  type Decision,
  type Policy,
} from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURES = path.join(here, "fixtures");
const DEP = path.join(FIXTURES, "node_modules", "fixture-dep");
const PEEK = path.join(FIXTURES, "node_modules", "fixture-envpeek");
/** A real, readable file inside the fixture tree — granted to `fixture-dep` and nobody else. */
const DATA = path.join(DEP, "data.txt");

interface Dep {
  readData(): string;
  connect(host: string, port: number): string;
  spawn(): { status: number | null };
  runVm(code: string): unknown;
}
interface Peek {
  readFile(target: string): string;
  readFileThroughBuiltin(target: string): string;
  readFileAtDepth(depth: number, target: string): string;
  readFileThroughEvals(target: string, depth: number): string;
  existsFile(target: string): boolean;
  readViaStreamClass(target: string): string;
  connect(host: string, port: number): string;
  connectThroughEvals(host: string, port: number, depth: number): string;
  spawn(): number | null;
  spawnThroughEvals(depth: number): number | null;
  runVm(code: string): unknown;
  runVmThroughEvals(code: string, depth: number): unknown;
  udpSend(host: string, port: number): string;
}

function loadFresh<T>(dir: string): T {
  const resolved = requireCjs.resolve(dir);
  delete requireCjs.cache[resolved];
  return requireCjs(dir) as T;
}

type Recorded = { pkg: string; decision: Decision };

/**
 * `fixture-dep` may read its own tree, connect to loopback, spawn and use `vm`.
 * `fixture-envpeek` appears nowhere, so every one of its calls is deny-by-default.
 */
function policy(): Policy {
  return loadPolicyFromObject(
    {
      version: 1,
      mode: "enforce",
      packages: {
        "fixture-dep": {
          fs: { read: [DEP, `${DEP}/**`], write: [] },
          net: { hosts: ["127.0.0.1"], ports: ["*"] },
          child_process: true,
          vm: true,
        },
      },
    },
    { projectRoot: here },
  );
}

let uninstall: (() => void) | null = null;

function boot(options: { maxFrames?: number } = {}): {
  dep: Dep;
  peek: Peek;
  decisions: Recorded[];
} {
  const decisions: Recorded[] = [];
  const handle = install(policy(), "enforce", {
    projectRoot: here,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
    ...(options.maxFrames !== undefined ? { attribution: { maxFrames: options.maxFrames } } : {}),
  });
  uninstall = () => handle.uninstall();
  return { dep: loadFresh<Dep>(DEP), peek: loadFresh<Peek>(PEEK), decisions };
}

/** Decisions of one capability kind, in order. Noise from other surfaces is not the subject. */
function ofKind(decisions: readonly Recorded[], kind: string): Recorded[] {
  return decisions.filter((d) => d.decision.observed?.kind === kind);
}

/** Run `fn`, swallowing the enforce-mode `CapabilityError` a denial raises. */
function attempt(fn: () => unknown): void {
  try {
    fn();
  } catch {
    /* a denial is the expected outcome for every `peek` call below */
  }
}

afterEach(() => {
  uninstall?.();
  uninstall = null;
});

describe("#143 the boundary fast path charges the caller through every stack shape it can choose", () => {
  /*
   * Each row is ONE capability reached through a DIFFERENT arrangement of frames between the
   * ungranted package and the shim's entry point. That arrangement is the only thing an attacker
   * controls about the capture, so it is the whole attack surface the change adds. Every row must
   * come back charged to `fixture-envpeek` and denied.
   *
   * The `eval` rows are the ones that matter most: three nested direct evals fill the entire
   * 3-frame prefix with OPAQUE frames, so the fast path finds nothing it may believe and must
   * fall back to the full walk. A fast path that answered from a prefix like that — or that
   * treated "found nothing" as `<app>` — would hand the trust root's authority to any dependency
   * willing to call `eval` three times.
   */
  const shapes: Array<[string, (peek: Peek) => void, string]> = [
    ["fs.readFileSync, direct", (p) => p.readFile(DATA), "fs"],
    ["fs.readFileSync, behind a native frame", (p) => p.readFileThroughBuiltin(DATA), "fs"],
    ["fs.readFileSync, 40 own frames", (p) => p.readFileAtDepth(40, DATA), "fs"],
    ["fs.readFileSync, through 3 evals", (p) => p.readFileThroughEvals(DATA, 3), "fs"],
    ["fs.existsSync (non-throwing probe)", (p) => p.existsFile(DATA), "fs"],
    ["new fs.ReadStream (guarded class)", (p) => p.readViaStreamClass(DATA), "fs"],
    ["net.connect, direct", (p) => p.connect("127.0.0.1", 9), "net"],
    ["net.connect, through 3 evals", (p) => p.connectThroughEvals("127.0.0.1", 9, 3), "net"],
    ["dgram send", (p) => p.udpSend("127.0.0.1", 9), "net"],
    ["child_process.spawnSync, direct", (p) => p.spawn(), "child_process"],
    ["child_process.spawnSync, through 3 evals", (p) => p.spawnThroughEvals(3), "child_process"],
    ["vm.runInNewContext, direct", (p) => p.runVm("1 + 1"), "vm"],
    ["vm.runInNewContext, through 3 evals", (p) => p.runVmThroughEvals("1 + 1", 3), "vm"],
  ];

  for (const [label, run, kind] of shapes) {
    it(`charges an ungranted ${label} to the caller, and denies it`, () => {
      const { peek, decisions } = boot();
      attempt(() => run(peek));
      const recorded = ofKind(decisions, kind);
      expect(recorded.length, label).toBeGreaterThan(0);
      for (const d of recorded) {
        expect(d.pkg, label).toBe("fixture-envpeek");
        // The three failure modes this change could introduce, named individually so a red run
        // says WHICH one happened rather than just "wrong package".
        expect(d.pkg, `${label}: must not become the trust root`).not.toBe(APP_ROOT);
        expect(d.pkg, `${label}: must not become unattributable`).not.toBe(UNATTRIBUTED);
        expect(d.pkg, `${label}: must not inherit the granted package`).not.toBe("fixture-dep");
        expect(d.decision.allowed, label).toBe(false);
      }
    });
  }

  it("still lets the GRANTED package through on every one of those surfaces", () => {
    // The mirror image, and the reason it is not optional: a fast path that attributed one frame
    // too far DOWN would deny the package that owns the call — the #86 shape, where hardening
    // breaks a legitimate operation instead of leaking one.
    const { dep, decisions } = boot();
    expect(dep.readData()).toContain("");
    dep.connect("127.0.0.1", 9);
    dep.spawn();
    expect(dep.runVm("1 + 1")).toBe(2);
    const charged = [...new Set(decisions.map((d) => d.pkg))];
    expect(charged).toEqual(["fixture-dep"]);
    for (const d of decisions) expect(d.decision.allowed).toBe(true);
  });

  it("keeps `<app>` unreachable through opaque code, on a guarded surface", () => {
    // THE fail-open this change could reintroduce. This file IS application code, so a fast path
    // that answered `<app>` when its prefix reached nothing believable — or that skipped the
    // shared walk's `<app>`-below-opaque rule (#60) — would resolve the trust root here and allow
    // a read the policy never granted. `new Function` gives the same opaque frame as `eval` with
    // none of this file's scope, which is the shape #60's PoC used.
    const { decisions } = boot();
    const readViaOpaque = new Function(
      "fsMod",
      "p",
      "return fsMod.readFileSync(p, 'utf8');",
    ) as (fsMod: typeof import("node:fs"), p: string) => string;
    attempt(() => readViaOpaque(requireCjs("node:fs") as typeof import("node:fs"), DATA));
    const recorded = ofKind(decisions, "fs");
    expect(recorded.length).toBeGreaterThan(0);
    for (const d of recorded) {
      expect(d.pkg).toBe(UNATTRIBUTED);
      expect(d.pkg).not.toBe(APP_ROOT);
      expect(d.decision.allowed).toBe(false);
    }
  });

  it("stands down below the minimum frame budget rather than offering a second opinion", () => {
    // Below FAST_PATH_MIN_BUDGET the fast path never runs, so every guarded surface is bit-for-bit
    // its pre-#143 self. A budget that small cannot see past capwall's own frames, so the call is
    // `<unknown>` — deny-by-default, the direction a starved budget is allowed to be wrong in
    // (#15/#60). What must NOT happen is the fast path answering `fixture-envpeek` (or anything
    // else) on a budget the full walk could not spend.
    const { peek, decisions } = boot({ maxFrames: 4 });
    attempt(() => peek.readFile(DATA));
    const recorded = ofKind(decisions, "fs");
    expect(recorded.length).toBeGreaterThan(0);
    for (const d of recorded) {
      // EXACTLY `<unknown>`, not merely "denied". A 4-frame budget cannot reach past capwall's
      // own frames, so that is the pre-#143 answer for this call — and asserting it exactly is
      // what makes this test fail if the minimum-budget guard is ever removed, since a fast path
      // running here WOULD reach `fixture-envpeek` and the row would still look denied.
      expect(d.pkg).toBe(UNATTRIBUTED);
      expect(d.pkg).not.toBe(APP_ROOT);
      expect(d.decision.allowed).toBe(false);
      expect(d.decision.attributionTruncated).toBe(true);
    }
  });

  it("does not let a granted package's call bleed into the ungranted one that follows it", () => {
    // Nothing is remembered between calls — this is a cheaper computation, not a cache. The
    // interleaving is the observable form of that claim: a per-call memo of "who is calling"
    // would hand `fixture-dep`'s answer to the very next `fixture-envpeek` call.
    const { dep, peek, decisions } = boot();
    for (let i = 0; i < 10; i++) {
      dep.readData();
      attempt(() => peek.readFile(DATA));
    }
    const recorded = ofKind(decisions, "fs");
    expect(recorded).toHaveLength(20);
    for (let i = 0; i < 20; i += 2) {
      expect(recorded[i]?.pkg).toBe("fixture-dep");
      expect(recorded[i]?.decision.allowed).toBe(true);
      expect(recorded[i + 1]?.pkg).toBe("fixture-envpeek");
      expect(recorded[i + 1]?.decision.allowed).toBe(false);
    }
  });

  it("records exactly as many decisions as before — cheaper must not mean fewer", () => {
    // A "fast path" that skipped the guard for a repeat call would look identical on a principal
    // assertion and would silently delete the audit trail. One call, one decision.
    const { peek, decisions } = boot();
    attempt(() => peek.readFile(DATA));
    expect(ofKind(decisions, "fs")).toHaveLength(1);
    decisions.length = 0;
    attempt(() => peek.readFile(path.join(os.tmpdir(), "capwall-143-absent")));
    expect(ofKind(decisions, "fs")).toHaveLength(1);
  });
});
