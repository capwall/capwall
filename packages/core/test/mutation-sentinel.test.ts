/**
 * THE DISARMED-TREE DETECTOR ACTUALLY FIRES — issue #184.
 *
 * #184 is a mutated `packages/core/dist/loader/module-read.js` sitting in the tree with `git
 * status` clean, silently turning an enforcement gate off and invalidating a batch of an audit's
 * measurements. `scripts/mutation-sentinel.mjs` is what now stands between that state and
 * `pnpm bench` / `pnpm canary` / `pnpm ci:local` / `pnpm mutation:gate` producing numbers.
 *
 * A detector nobody has watched fail is the same hollow-test shape #112 found six of, so every
 * case here PLANTS the bad state and asserts the tool refuses — sentinel in `dist`, sentinel in
 * `src`, a stamp from a run that is still alive, a stamp from a run that died. Each also asserts
 * the message carries the recovery command, because the cost of a gate that fires without saying
 * what to do next is that people disable it (#149).
 *
 * It runs the tool as a CHILD PROCESS against a THROWAWAY TREE, never against this repository:
 * `mutation-sentinel.mjs` derives its root from its own location, so copying the single file into
 * `<tmp>/scripts/` makes `<tmp>` the root it scans. Planting a stamp or a mutation in the real
 * working tree from inside `pnpm test` would be the exact hazard this file is about.
 */
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, "..", "..", "..");
const REAL_TOOL = path.join(REPO_ROOT, "scripts", "mutation-sentinel.mjs");

/** The marker the tool is keyed on. Spelled out rather than imported: this is the contract. */
const SENTINEL = "AUDIT MUTANT";

const trees: string[] = [];
afterEach(() => {
  for (const dir of trees.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/** A throwaway repo root containing only the tool and an empty `packages/core/{src,dist}`. */
function makeTree(): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "capwall-sentinel-"));
  trees.push(root);
  mkdirSync(path.join(root, "scripts"), { recursive: true });
  copyFileSync(REAL_TOOL, path.join(root, "scripts", "mutation-sentinel.mjs"));
  for (const kind of ["src", "dist"]) {
    mkdirSync(path.join(root, "packages", "core", kind), { recursive: true });
    writeFileSync(
      path.join(root, "packages", "core", kind, "module-read.js"),
      "export function guard() { return true; }\n",
    );
  }
  return root;
}

function run(root: string, args: string[] = ["--scan", "src,dist", "--label", "the test"]) {
  const r = spawnSync(process.execPath, [path.join(root, "scripts", "mutation-sentinel.mjs"), ...args], {
    encoding: "utf8",
  });
  return { status: r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

function plantStamp(root: string, pid: number): void {
  writeFileSync(
    path.join(root, ".capwall-mutation-guard.json"),
    `${JSON.stringify({
      pid,
      startedAt: "2026-07-27T00:00:00.000Z",
      holding: { id: "module-read-gate-at-proto-load", file: "packages/core/src/loader/module-read.ts" },
      files: {},
    })}\n`,
  );
}

describe("mutation-sentinel refuses a tree that may be disarmed (#184)", () => {
  it("passes silently on a clean tree — a gate that narrates its successes gets scrolled past", () => {
    const root = makeTree();
    const { status, out } = run(root);
    expect({ status, out }).toEqual({ status: 0, out: "" });
  });

  it("catches a mutation compiled into the GITIGNORED dist — the #184 case exactly", () => {
    const root = makeTree();
    writeFileSync(
      path.join(root, "packages", "core", "dist", "module-read.js"),
      `export function guard() { if (1) return; /* ${SENTINEL} #123 CJS half removed */ return true; }\n`,
    );
    const { status, out } = run(root);
    expect(status).toBe(1);
    // Names the artifact, the line, and the way out.
    expect(out).toContain("packages/core/dist/module-read.js:1");
    expect(out).toContain("DISARMED");
    expect(out).toContain("pnpm mutation:recover");
  });

  it("catches a mutation left in src", () => {
    const root = makeTree();
    writeFileSync(
      path.join(root, "packages", "core", "src", "module-read.js"),
      `export function guard() { return false; /* ${SENTINEL} some-id */ }\n`,
    );
    const { status, out } = run(root);
    expect(status).toBe(1);
    expect(out).toContain("packages/core/src/module-read.js:1");
  });

  it("scans only what it is asked to scan, so `--scan src` cannot be fooled into a false red", () => {
    const root = makeTree();
    writeFileSync(
      path.join(root, "packages", "core", "dist", "module-read.js"),
      `/* ${SENTINEL} in dist only */\n`,
    );
    expect(run(root, ["--scan", "src"]).status).toBe(0);
    expect(run(root, ["--scan", "dist"]).status).toBe(1);
  });

  it("refuses while a mutation-guard run is ALIVE — the ci:local/mutation:gate interlock", () => {
    const root = makeTree();
    plantStamp(root, process.pid); // this vitest process is unambiguously alive
    const { status, out } = run(root);
    expect(status).toBe(1);
    expect(out).toContain("running RIGHT NOW");
    expect(out).toContain("Wait for it to finish");
  });

  it("refuses on a stamp whose process is gone — an interrupted run left the artifact mutated", () => {
    const root = makeTree();
    // A pid that cannot be running: max_pid+1 on Linux is not allocatable, and the tool treats
    // anything it cannot signal as dead unless the kernel says EPERM.
    plantStamp(root, 0x7ffffffe);
    const { status, out } = run(root);
    expect(status).toBe(1);
    expect(out).toContain("did not tear down");
    expect(out).toContain("pnpm mutation:recover");
  });

  it("the stamp wins over the sentinel scan, because it can say WHICH run and WHICH file", () => {
    const root = makeTree();
    plantStamp(root, 0x7ffffffe);
    writeFileSync(path.join(root, "packages", "core", "dist", "x.js"), `/* ${SENTINEL} id */\n`);
    const { out } = run(root);
    expect(out).toContain("module-read-gate-at-proto-load");
  });

  it("--status reports without failing, so it is safe to run from anywhere", () => {
    const root = makeTree();
    const clean = run(root, ["--status"]);
    expect(clean.status).toBe(0);
    expect(clean.out).toContain("no sentinels");
    plantStamp(root, 0x7ffffffe);
    const dirty = run(root, ["--status"]);
    expect(dirty.status).toBe(0);
    expect(dirty.out).toContain("DEAD");
  });
});

describe("this repository is armed", () => {
  it("has no mutation sentinel in any package's src or dist", () => {
    const { status, out } = run(REPO_ROOT, ["--scan", "src,dist", "--label", "pnpm test"]);
    expect({ status, out }).toEqual({ status: 0, out: "" });
  });
});
