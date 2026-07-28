/**
 * THE ESM LOADER THREAD'S GRAPH IS MINIMAL, AND STAYS MINIMAL (issue #150).
 *
 * ── WHY THIS IS A GUARD RATHER THAN A PREFERENCE ────────────────────────────────────────────
 * `module.register()` starts Node's module-customization thread and BLOCKS the main thread until
 * that thread has resolved, compiled and evaluated the hook module's entire import graph. So every
 * module reachable from `loader/esm-hooks.ts` is paid for SERIALLY, at startup, on every process
 * capwall mediates — a CLI that shells out, a test runner spawning workers, a serverless cold
 * start. Measured on Node 22 (see `scripts/bench/README.md` § Startup): `registerEsmHook()` was
 * ~93 ms, of which ~40 ms was capwall's own graph on that thread and the rest was Node's worker
 * bootstrap.
 *
 * Two things were on that graph for no reason, and both were invisible in review because both
 * arrived through a barrel import three modules away:
 *
 *  1. **`zod`**, via `@capwall/policy-schema`'s barrel, which builds the whole schema tree at
 *     module scope. The loader thread never parses a policy — it is handed an already-parsed one
 *     in an {@link EsmGateSnapshot} — so it needed the grammar helpers and nothing else. Fixed by
 *     importing `@capwall/policy-schema/host` and `/package-key` directly.
 *  2. **Ten builtins it never uses**, via `real-builtins.cts`, whose whole purpose is to capture all
 *     twelve. The loader thread needs exactly two: `fs` (attribution reads package.json) and
 *     `worker_threads` (the #123 gate's synchronous port drain). Fixed by the narrow captures under
 *     `src/real-builtins/` — see `src/real-builtins/fs.cts` for why that narrowing takes nothing
 *     away from #78.
 *
 * Together: ~93 ms → ~70 ms at the minimum, ~112 ms → ~85 ms at p50.
 *
 * ── WHY IT NEEDS A TEST AT ALL ──────────────────────────────────────────────────────────────
 * Because the regression is a ONE-CHARACTER edit in a file nobody is thinking about the loader
 * thread while editing. Changing `@capwall/policy-schema/host` back to `@capwall/policy-schema` in
 * `policy/evaluate.ts` is the most natural import in the repo, breaks nothing, fails nothing, and
 * silently puts zod back on the blocking startup path of every mediated process. Same for
 * `../real-builtins.cjs` in `attribution/index.ts`. This is the same class of property as #78's own
 * capture rule and #107's process-patch rule, and it gets the same treatment: a scan that fails by
 * name, plus a runtime check that the scan is describing something real.
 *
 * ── THE TWO HALVES ──────────────────────────────────────────────────────────────────────────
 *  - **The static scan** walks the transitive import graph of `src/loader/esm-hooks.ts` over `src`
 *    and fails on any module in it that value-imports the policy-schema barrel or the twelve-wide
 *    capture. It runs on SOURCE, so it fails on the edit rather than on the build.
 *  - **The runtime check** imports the BUILT `dist/loader/esm-hooks.js` in a clean child and asks
 *    Node what it actually loaded, with the aggregate capture as a positive control in the same
 *    child — because a `moduleLoadList` probe that reports "nothing extra" is indistinguishable
 *    from a probe that stopped working.
 */
import * as path from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { blankNonCode } from "./helpers/source-scan.js";
import { assertPreloadBuilt, runNode } from "./helpers/subprocess.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const SRC_ROOT = path.join(here, "..", "src");

/** The hook module Node's loader thread evaluates — the root of the graph under test. */
const HOOK_ENTRY = path.join(SRC_ROOT, "loader", "esm-hooks.ts");

/**
 * Specifiers a module on that thread must not import for a VALUE.
 *
 * `import type` forms are fine and are used freely — `module-read.ts` takes `Mode`/`Policy` from
 * the barrel and `tsc` erases both, loading nothing.
 */
const BANNED = [
  {
    specifier: "@capwall/policy-schema",
    why: "the barrel builds the whole Zod schema tree at module scope; take the grammar from '@capwall/policy-schema/host' or '/package-key', or the type from an `import type`",
  },
  {
    specifier: "../real-builtins.cjs",
    why: "the twelve-wide aggregate; take the one builtin this realm needs from src/real-builtins/ (see its fs.cts header)",
  },
];

/**
 * Resolve a relative specifier as written in `src` (`.js`/`.cjs`, per the ESM extension rule) back
 * to the TypeScript file it came from. Returns `null` for a bare specifier or a `node:` builtin —
 * neither is part of capwall's own graph.
 */
function resolveToSource(fromFile: string, specifier: string): string | null {
  if (!specifier.startsWith(".")) return null;
  const abs = path.resolve(path.dirname(fromFile), specifier);
  const candidates = abs.endsWith(".cjs")
    ? [abs.replace(/\.cjs$/, ".cts")]
    : abs.endsWith(".mjs")
      ? [abs.replace(/\.mjs$/, ".mts")]
      : [abs.replace(/\.js$/, ".ts"), `${abs}.ts`];
  for (const c of candidates) {
    try {
      readFileSync(c);
      return c;
    } catch {
      /* try the next spelling */
    }
  }
  return null;
}

/** Every `from "…"` / bare `import "…"` specifier in `code`, EXCLUDING erased `import type`. */
function valueImportSpecifiers(code: string): string[] {
  const out: string[] = [];
  for (const m of code.matchAll(/\bimport\s+(?!type\b)[^;]*?\bfrom\s*["']([^"']+)["']/g)) {
    out.push(m[1] ?? "");
  }
  for (const m of code.matchAll(/\bimport\s*["']([^"']+)["']/g)) out.push(m[1] ?? "");
  for (const m of code.matchAll(/\bexport\s+(?!type\b)[^;]*?\bfrom\s*["']([^"']+)["']/g)) {
    out.push(m[1] ?? "");
  }
  return out;
}

interface GraphEdge {
  /** `src`-relative file doing the importing. */
  from: string;
  specifier: string;
}

/** The transitive value-import graph rooted at `entry`, as `file → its specifiers`. */
function graphFrom(entry: string): { files: Set<string>; edges: GraphEdge[] } {
  const files = new Set<string>();
  const edges: GraphEdge[] = [];
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop()!;
    if (files.has(file)) continue;
    files.add(file);
    const code = blankNonCode(readFileSync(file, "utf8"), { strings: false });
    for (const specifier of valueImportSpecifiers(code)) {
      edges.push({ from: path.relative(SRC_ROOT, file), specifier });
      const next = resolveToSource(file, specifier);
      if (next !== null) queue.push(next);
    }
  }
  return { files, edges };
}

describe("#150 — the ESM hook's graph carries nothing the loader thread does not use", () => {
  it("value-imports neither the policy-schema barrel nor the twelve-wide capture", () => {
    const { edges } = graphFrom(HOOK_ENTRY);
    const offenders = edges.filter((e) => BANNED.some((b) => b.specifier === e.specifier));
    expect(
      offenders,
      `A module on the ESM loader thread's graph imports something that realm does not use. ` +
        `module.register() BLOCKS the main thread while that graph is resolved, compiled and ` +
        `evaluated, so this is serial startup cost on every mediated process (#150). Offenders:\n` +
        offenders
          .map(
            (o) =>
              `  ${o.from} imports ${o.specifier}\n      ${BANNED.find((b) => b.specifier === o.specifier)?.why}`,
          )
          .join("\n"),
    ).toEqual([]);
  });

  it("is a scan that actually fires — and does not fire on an erased type import", () => {
    // Worth nothing unless it catches the exact edits it forbids. Both offenders are the shape a
    // reviewer would wave through, which is the whole reason the scan exists.
    const guilty = `
      import { ANY_HOST } from "@capwall/policy-schema";
      import { realFs } from "../real-builtins.cjs";
    `;
    const banned = new Set(BANNED.map((b) => b.specifier));
    expect(valueImportSpecifiers(guilty).filter((s) => banned.has(s))).toEqual([
      "@capwall/policy-schema",
      "../real-builtins.cjs",
    ]);

    const innocent = `
      import type { Mode, Policy } from "@capwall/policy-schema";
      import { ANY_HOST } from "@capwall/policy-schema/host";
      import { realFs } from "../real-builtins/fs.cjs";
      /** Not this: import { z } from "@capwall/policy-schema"; */
    `;
    const code = blankNonCode(innocent, { strings: false });
    expect(valueImportSpecifiers(code).filter((s) => banned.has(s))).toEqual([]);
  });

  it("reaches the modules it claims to — the graph walk is not silently empty", () => {
    // A walk that resolved nothing would pass the check above for the worst possible reason.
    const { files } = graphFrom(HOOK_ENTRY);
    const rel = [...files].map((f) => path.relative(SRC_ROOT, f).split(path.sep).join("/")).sort();
    expect(rel).toContain("loader/module-read.ts");
    expect(rel).toContain("policy/evaluate.ts");
    expect(rel).toContain("attribution/index.ts");
    expect(rel).toContain("attribution/link-map.ts");
    expect(rel).toContain("shims/runtime.ts");
    expect(rel).toContain("real-builtins/worker_threads.cts");
    expect(rel).toContain("real-builtins/fs.cts");
  });
});

/**
 * The runtime half. One child, shared between the two claims it supports: the probe is a pure
 * function of (argv, cwd, env), so `share: true` is sound here — see helpers/subprocess.ts.
 */
const PROBE = path.join(here, "fixtures", "loader-thread-graph.mjs");
const probe = (): Promise<{ code: number; stdout: string; stderr: string }> =>
  runNode([PROBE], { cwd: here, share: true });

describe("#150 — what the built hook module actually loads, measured in a clean process", () => {
  beforeAll(() => {
    assertPreloadBuilt();
  });

  it("pulls in no mediated builtin beyond fs and worker_threads", async () => {
    const r = await probe();
    expect(r.stderr, r.stderr).toBe("");
    const out = JSON.parse(r.stdout) as { hook: string[]; aggregate: string[] };
    // `fs` is already resident from Node's own bootstrap in most builds, so it is allowed rather
    // than required; `worker_threads` is the one the hook genuinely brings in.
    expect(out.hook.filter((m) => m !== "fs" && m !== "worker_threads")).toEqual([]);
  });

  it("has a working probe — the aggregate capture DOES pull the rest in", async () => {
    // The positive control. Without it, "the hook loaded nothing extra" and "moduleLoadList stopped
    // reporting" are the same green.
    //
    // `net` and `http` are deliberately NOT in this list: whether they are already resident before
    // any user code runs depends on how the child's stdio was set up (a piped stdio loads `net`
    // during bootstrap, which is exactly how this test is run), and a control that flakes on the
    // harness's own plumbing is worse than a narrower one. The four below have no such route.
    const r = await probe();
    const out = JSON.parse(r.stdout) as { hook: string[]; aggregate: string[] };
    for (const m of ["tls", "http2", "dgram", "child_process", "vm"]) {
      expect(out.aggregate, `${m} should appear once the aggregate capture is loaded`).toContain(m);
    }
  });

  it("keeps zod off the loader thread's graph entirely", async () => {
    const r = await probe();
    const out = JSON.parse(r.stdout) as { zodAfterHook: number; zodAfterPolicyLoad: number };
    expect(out.zodAfterHook, "zod must not be reachable from the ESM hook module").toBe(0);
    // Control again: zod is not gone from the product, it is off ONE graph. `policy/load.ts` still
    // needs it, on the main thread, where a policy is actually parsed.
    expect(out.zodAfterPolicyLoad, "policy/load.ts still parses with zod").toBeGreaterThan(0);
  });
});
