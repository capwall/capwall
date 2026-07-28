/**
 * THE PROCESS-PATCH RULE, ENFORCED (issue #107).
 *
 * #103 found three separate lifecycle bugs in three separate process-level patches, and every
 * one of them was the same defect: a bare save/restore, which silently assumes capwall is the
 * only patcher of that location and that teardown is LIFO. Both assumptions are false the moment
 * a second `install()` exists. #103 fixed the three sites; #107 is the ticket that says the
 * FOURTH site must not be able to repeat them.
 *
 * `lifecycle/process-patch.ts` is the shared shape. This file is what makes using it mandatory
 * rather than customary, in three independent ways — a new patch site has to get past all three:
 *
 *   1. **THE SOURCE SCAN.** Every write to a process-level location in `packages/core/src` —
 *      `process.*`, `globalThis.*`, a `Module` prototype, or any local alias of those — must be
 *      inside `lifecycle/process-patch.ts`. A patch site cannot reach a global without going
 *      through a slot, and it cannot hold a slot without going through one of the two lifecycle
 *      helpers. This is the half that catches somebody hand-rolling a save/restore.
 *
 *   2. **THE INVENTORY.** The set of registered sites must match a reviewed list, the same
 *      canary shape `global-egress-inventory.test.ts` uses for `globalThis`. Adding a patch is
 *      then a deliberate act with a reviewer attached, and the list records which sites STACK
 *      and which are single — the one axis on which the sites genuinely differ (see #100).
 *
 *   3. **THE CONFORMANCE RUN.** Every registered site is put through the lifecycle sequence #103
 *      wrote by hand for `process.env` and `globalThis.fetch`: nested install, OUT-OF-LIFO-ORDER
 *      teardown, idempotent double-uninstall, full restore. A new site is enrolled by the act of
 *      registering, so nobody has to remember to add it here.
 *
 * Plus the third bug, which is not about any one site: a teardown that throws must not strand the
 * others. Asserted both as a property of the helper (below) and end-to-end in a subprocess, on
 * the real shape that produced it — an egress global some un-mediated code made non-configurable.
 */
import { execFile } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
// Importing the public entry point is what evaluates every module that defines a patch site;
// the registry below is empty without it.
import { install, loadPolicyFromObject } from "../src/index.js";
import { liveCtx } from "../src/loader/live-context.js";
import {
  defineSharedPatch,
  processPatchSites,
  type PatchKind,
} from "../src/lifecycle/process-patch.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const SRC_ROOT = path.join(here, "..", "src");
const HELPER_REL = path.join("lifecycle", "process-patch.ts");

/**
 * The sites as they stand after `src/index.js` is evaluated — snapshotted at module load so a
 * site a TEST defines later (see the failure-isolation section) cannot pollute the inventory.
 */
const SITES = [...processPatchSites()];

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 1. THE SOURCE SCAN — no process-level write outside the helper.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

/** Identifiers that name a process-level object. An alias of one of these is one of these. */
const PROCESS_ROOTS = ["globalThis", "process", "Module", "realModule"] as const;

/**
 * Blank out comments and string/template bodies, PRESERVING OFFSETS so line numbers still
 * compute. Without this the scan trips over prose — `global-egress.ts` discusses
 * `globalThis.fetch = evil` three times in its header, which is the thing it exists to prevent.
 */
function blankNonCode(src: string): string {
  const out = src.split("");
  const blank = (from: number, to: number): void => {
    for (let i = from; i < to && i < out.length; i++) if (out[i] !== "\n") out[i] = " ";
  };
  let i = 0;
  // Depth of `${` interpolations we are inside, so a template can contain code containing a
  // template. `0` means "not in a template".
  const templateStack: number[] = [];
  while (i < src.length) {
    const two = src.slice(i, i + 2);
    if (two === "//") {
      const end = src.indexOf("\n", i);
      const stop = end === -1 ? src.length : end;
      blank(i, stop);
      i = stop;
      continue;
    }
    if (two === "/*") {
      const end = src.indexOf("*/", i + 2);
      const stop = end === -1 ? src.length : end + 2;
      blank(i, stop);
      i = stop;
      continue;
    }
    const ch = src[i];
    if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < src.length && src[j] !== ch) j += src[j] === "\\" ? 2 : 1;
      blank(i + 1, j);
      i = j + 1;
      continue;
    }
    if (ch === "`") {
      let j = i + 1;
      while (j < src.length) {
        if (src[j] === "\\") {
          j += 2;
          continue;
        }
        if (src[j] === "`") break;
        if (src[j] === "$" && src[j + 1] === "{") break;
        j++;
      }
      blank(i + 1, j);
      if (src[j] === "$") {
        templateStack.push(1);
        i = j + 2;
        continue;
      }
      i = j + 1;
      continue;
    }
    if (templateStack.length > 0 && ch === "}") {
      // Close the interpolation and resume the template literal.
      templateStack.pop();
      let j = i + 1;
      while (j < src.length) {
        if (src[j] === "\\") {
          j += 2;
          continue;
        }
        if (src[j] === "`") break;
        if (src[j] === "$" && src[j + 1] === "{") break;
        j++;
      }
      blank(i + 1, j);
      if (src[j] === "$") {
        templateStack.push(1);
        i = j + 2;
        continue;
      }
      i = j + 1;
      continue;
    }
    i++;
  }
  return out.join("");
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Local names bound to a process-level object, e.g. `const g = globalThis as unknown as …`.
 *
 * Deliberately generous: over-capturing a name only makes the scan stricter, and a scan that is
 * too strict fails loudly at the moment somebody writes the code, which is when it is cheap.
 */
function processAliases(code: string): Set<string> {
  const aliases = new Set<string>(PROCESS_ROOTS);
  const rootStart = new RegExp(`^[\\s(]*(?:<[^>]*>\\s*)?(?:${PROCESS_ROOTS.join("|")})\\b`);
  const decl = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]*)?=\s*([^;\n]*)/g;
  for (const m of code.matchAll(decl)) {
    const name = m[1];
    if (name !== undefined && rootStart.test(m[2] ?? "")) aliases.add(name);
  }
  return aliases;
}

interface Finding {
  file: string;
  line: number;
  text: string;
}

/** Assignments and `defineProperty`/`assign`/`Reflect.set` calls that MUTATE a process global. */
function processWrites(file: string, source: string): Finding[] {
  const code = blankNonCode(source);
  const chain = String.raw`(?:\.[A-Za-z_$][\w$]*|\[[^\]\n]*\])+`;
  const findings: Finding[] = [];
  for (const alias of processAliases(code)) {
    const a = escapeRe(alias);
    const patterns = [
      // `alias.prop = …`, `alias["prop"] = …`, `alias.a.b = …`. `=(?![=>])` skips `==`/`===`/`=>`.
      new RegExp(String.raw`\b${a}\s*${chain}\s*=(?![=>])`, "g"),
      new RegExp(String.raw`(?:Object|Reflect)\.define(?:Property|Properties)\(\s*${a}\b`, "g"),
      new RegExp(String.raw`(?:Object\.assign|Reflect\.set|Reflect\.deleteProperty)\(\s*${a}\b`, "g"),
    ];
    for (const re of patterns) {
      for (const m of code.matchAll(re)) {
        const line = code.slice(0, m.index).split("\n").length;
        findings.push({ file, line, text: (source.split("\n")[line - 1] ?? "").trim() });
      }
    }
  }
  return findings;
}

/** `.cts`/`.mts` too — `src/real-builtins.cts` (#78) is source like any other and must not escape
 *  the scan on a filename technicality. */
function tsFilesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...tsFilesUnder(full));
    else if (/\.[cm]?ts$/.test(entry.name)) out.push(full);
  }
  return out.sort();
}

describe("#107 — every process-level write goes through lifecycle/process-patch.ts", () => {
  it("finds no process-global mutation anywhere else in packages/core/src", () => {
    const offenders: Finding[] = [];
    for (const file of tsFilesUnder(SRC_ROOT)) {
      const rel = path.relative(SRC_ROOT, file);
      if (rel === HELPER_REL) continue; // the one file allowed to write a process global
      offenders.push(...processWrites(rel, readFileSync(file, "utf8")));
    }
    expect(
      offenders,
      `A process-level location is written outside lifecycle/process-patch.ts. Every such write ` +
        `must go through a PatchSlot held by defineRelinkedPatch (stacking) or defineSharedPatch ` +
        `/ definePropertyPatch (single, refcounted) — see issue #107 for the three lifecycle bugs ` +
        `a bare save/restore produced. Offenders:\n` +
        offenders.map((o) => `  ${o.file}:${o.line}  ${o.text}`).join("\n"),
    ).toEqual([]);
  });

  it("is a scan that actually fires — a hand-rolled save/restore is detected", () => {
    // The scan is only worth anything if it catches the shape it exists to forbid. This is the
    // pre-#107 `installEnvGuard` in miniature, and the pre-#107 egress restore.
    const handRolled = `
      const saved = process.env;
      process.env = new Proxy(saved, {});
      const g = globalThis as unknown as Record<string, unknown>;
      Object.defineProperty(g, "fetch", { value: wrapped, configurable: true });
      g["WebSocket"] = Guarded;
    `;
    expect(processWrites("fake.ts", handRolled).length).toBe(3);
  });

  it("does not fire on prose, or on a READ of a process global", () => {
    // `global-egress.ts` discusses `globalThis.fetch = evil` in its header three times, and
    // `preload.ts` reads `process.env["CAPWALL_MODE"]`. Neither is a write.
    const benign = `
      /** A dependency doing \`globalThis.fetch = evil\` no longer removes mediation. */
      // process.env = whatever
      const mode = process.env["CAPWALL_MODE"];
      if (process.env["CAPWALL_ALLOW_LOADER_HOOKS"] === "1") return;
      const cwd = process.cwd();
      const patch = (link) => process.dlopen;
      const message = \`set \${process.env["X"]} = 1\`;
    `;
    expect(processWrites("fake.ts", benign)).toEqual([]);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 2. THE INVENTORY — which sites exist, and which of them stack.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

/**
 * Every process-level patch capwall installs, and its lifecycle.
 *
 * `"relinked"` STACKS: each install adds a link and every link's guard runs. `"shared"` does NOT:
 * one patch per process, reference counted. That axis is the whole reason #107 shipped two named
 * helpers instead of one with a flag, and it is not interchangeable —
 *
 *  - `Module._load` and `process.dlopen` MUST stack. Two installs may hold different contexts and
 *    each one's routing / gate has to fire.
 *  - `Module.prototype._compile` MUST NOT (#100). It asks who called it exactly one frame up; a
 *    second patch in front of it means the inner patch sees capwall's own frame rather than
 *    `node:internal/modules/…`, decides a user called `_compile`, and gates EVERY `require` in
 *    the process. A second `install()` would make `require` a denied capability.
 *  - `process.env` and the egress globals MUST NOT either: a stacked Proxy / wrapper double-gates
 *    and double-records every read, and the second `installEnvGuard` captured the FIRST guard's
 *    proxy as the "un-proxied" environment — which handed a GRANTED `spawn` an empty child
 *    environment (#103).
 *  - `Module._findPath` (#127) is the one site that is not a gate at all: it OBSERVES resolutions
 *    so a symlinked `node_modules` entry can be attributed to the package it was reached through
 *    rather than to `<app>`. Shared, because two installs would record identical facts into the
 *    same process-wide map and pay a second `lstat` per resolution to do it.
 *
 * Changing an entry here is changing an enforcement property. Adding one means a new
 * process-global mutation exists; say why in the PR.
 */
const REVIEWED_SITES: ReadonlyArray<{ name: string; kind: PatchKind }> = [
  { name: "Module._findPath", kind: "shared" },
  { name: "Module._load", kind: "relinked" },
  { name: "Module.prototype._compile", kind: "shared" },
  { name: "process.dlopen", kind: "relinked" },
  { name: "process.env", kind: "shared" },
  { name: "globalThis egress (fetch/WebSocket/EventSource)", kind: "shared" },
];

describe("#107 — the registered patch sites match the reviewed inventory", () => {
  it("registers exactly the reviewed sites, with the reviewed lifecycle", () => {
    const actual = SITES.map((s) => ({ name: s.name, kind: s.kind })).sort((a, b) =>
      a.name.localeCompare(b.name),
    );
    const reviewed = [...REVIEWED_SITES].sort((a, b) => a.name.localeCompare(b.name));
    expect(
      actual,
      "A process-level patch site was added, removed or changed lifecycle. Update " +
        "REVIEWED_SITES above and explain the change — 'relinked' vs 'shared' is an " +
        "enforcement property, not a style choice (see #100, #107).",
    ).toEqual(reviewed);
  });

  it("is not decorative — a real install() engages EVERY registered site, and releases them all", () => {
    // The registry only enforces anything if the sites in it are the sites `install()` actually
    // uses. A patch that registered but was never wired in would pass the conformance run below
    // and mediate nothing in production.
    for (const site of SITES) expect(site.depth(), `${site.name} leaked before`).toBe(0);
    const handle = install(
      loadPolicyFromObject({ version: 1, mode: "enforce", packages: {} }, { projectRoot: here }),
      "enforce",
      { projectRoot: here },
    );
    for (const site of SITES) {
      expect(site.depth(), `install() did not engage ${site.name}`).toBeGreaterThan(0);
    }
    handle.uninstall();
    for (const site of SITES) expect(site.depth(), `${site.name} survived uninstall`).toBe(0);
  });

  it("names every interception point InstallHandle.uninstall promises to restore", () => {
    // The doc comment on `InstallHandle.uninstall` names four by hand. A site that stopped being
    // registered would leave that promise unbacked by anything.
    const names = SITES.map((s) => s.name).join(" ");
    for (const point of ["Module._load", "process.env", "process.dlopen", "egress"]) {
      expect(names, `${point} is no longer a registered patch site`).toContain(point);
    }
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 3. THE CONFORMANCE RUN — #103's lifecycle sequence, over every site, automatically.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

/** Identity comparison, element by element. `toEqual` would compare the `process.env` Proxy
 * STRUCTURALLY against the real object and find them equal — which is exactly the bug. */
const sameIdentity = (a: readonly unknown[], b: readonly unknown[]): boolean =>
  a.length === b.length && a.every((v, i) => Object.is(v, b[i]));

describe("#107 — every registered site survives a nested, out-of-LIFO-order teardown", () => {
  afterEach(() => {
    // A site left installed would contaminate every later test in this worker.
    for (const site of SITES) expect(site.depth(), `${site.name} leaked`).toBe(0);
  });

  for (const site of SITES) {
    it(`${site.name} (${site.kind}) — nest, remove the OUTER first, then the inner`, () => {
      expect(site.depth()).toBe(0);
      const before = site.probe();

      const outer = site.install(liveCtx);
      const inner = site.install(liveCtx);
      // NO "the site declined" ESCAPE HATCH (#112). This used to early-return when
      // `site.depth() === 0`, asserting only "nothing changed" — which is trivially true of a
      // site that never patched, so a site that silently STOPPED patching took the quiet branch
      // and reported green. That is the one regression this whole file exists to catch, and
      // "is not decorative" above already establishes that every registered site engages, so
      // declining here is a failure, not a runtime variation.
      expect(site.depth(), `${site.name} declined to install`).toBeGreaterThan(0);
      expect(site.depth(), "a second install must be counted").toBe(2);
      expect(sameIdentity(site.probe(), before), `${site.name} did not patch`).toBe(false);

      // NOT LIFO — the shape that left capwall's proxy on `process.env` and capwall's wrapper on
      // `globalThis.fetch` permanently, reading the deny-all torn-down policy forever (#103).
      outer.uninstall();
      expect(site.depth()).toBe(1);
      expect(
        sameIdentity(site.probe(), before),
        `${site.name} restored while an install was still active`,
      ).toBe(false);

      outer.uninstall(); // idempotent: must not release the survivor's activation
      expect(site.depth(), `${site.name}'s uninstall() is not idempotent`).toBe(1);

      inner.uninstall();
      expect(site.depth()).toBe(0);
      expect(
        sameIdentity(site.probe(), before),
        `${site.name} was not restored by the last uninstall`,
      ).toBe(true);

      inner.uninstall(); // idempotent after full teardown too
      expect(site.depth()).toBe(0);
      expect(sameIdentity(site.probe(), before)).toBe(true);
    });
  }

  it("re-installs cleanly after a full teardown, for every site", () => {
    // A refcount that under- or over-counted would leave the second install ungated (silent) or
    // double-patched (the `_compile` hazard, #100).
    for (const site of SITES) {
      const before = site.probe();
      site.install(liveCtx).uninstall();
      const again = site.install(liveCtx);
      // Unconditional, for the same reason as the nesting row above: `if (site.depth() > 0)`
      // let a site that stopped patching skip the only assertion that says it re-patched (#112).
      expect(site.depth(), `${site.name} declined to re-install`).toBeGreaterThan(0);
      expect(sameIdentity(site.probe(), before), `${site.name} did not re-patch`).toBe(false);
      again.uninstall();
      expect(sameIdentity(site.probe(), before)).toBe(true);
    }
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 4. FAILURE ISOLATION — bug 3: one handle throwing must not strand the others.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("#107 — a restore that cannot succeed is isolated", () => {
  it("swallows a throwing restore and still drops the reference count", () => {
    let restores = 0;
    const exploding = defineSharedPatch<{ n: number }>("test:exploding", {
      apply: () => ({ n: 1 }),
      restore() {
        restores++;
        throw new TypeError("Cannot redefine property: fetch");
      },
      probe: () => [],
    });
    const a = exploding.install(liveCtx);
    const b = exploding.install(liveCtx);
    expect(() => b.uninstall()).not.toThrow();
    expect(restores).toBe(0); // an install is still active
    expect(() => a.uninstall()).not.toThrow();
    expect(restores).toBe(1);
    // …and the site is genuinely released, so a later install re-applies rather than jamming.
    const c = exploding.install(liveCtx);
    expect(() => c.uninstall()).not.toThrow();
    expect(restores).toBe(2);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 5. FAILURE ISOLATION, END TO END — on the real shape that produced bug 3.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

const CORE_DIST = createRequire(import.meta.url).resolve("../dist/index.js");
let tmpDir: string;

/** Run `source` against the BUILT core in a subprocess. A subprocess because the scenario
 *  PERMANENTLY breaks `globalThis.fetch` — that is the whole point of the scenario. */
async function runScript(source: string): Promise<{ code: number; stdout: string; stderr: string }> {
  const dir = await mkdtemp(path.join(tmpDir, "run-"));
  const file = path.join(dir, "script.mjs");
  await writeFile(file, source);
  return new Promise((resolve, reject) => {
    execFile(process.execPath, [file], { cwd: dir }, (err, stdout, stderr) => {
      if (err && typeof err.code !== "number") return reject(err);
      resolve({ code: err ? (err.code as number) : 0, stdout, stderr });
    });
  });
}

beforeAll(async () => {
  expect(
    existsSync(CORE_DIST),
    `built core not found — run 'pnpm build' before 'pnpm test'`,
  ).toBe(true);
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-process-patch-"));
});
afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

describe("#107 — an unrestorable egress global does not strand the other patches", () => {
  it("restores process.env, Module._load, process.dlopen and _compile anyway", async () => {
    // BUG 3, on its original shape. Un-mediated code is allowed to make a global
    // NON-CONFIGURABLE after capwall installed its (configurable) replacement, and then the
    // restore is impossible for anyone. Before #103 that `TypeError` escaped `uninstall()`;
    // #107 makes it impossible for it to escape at all — the slot never throws — and
    // `releaseAll` isolates whatever a non-patch handle might still raise.
    const r = await runScript(`
import { install, loadPolicyFromObject } from ${JSON.stringify(pathToFileURL(CORE_DIST).href)};
import Module from "node:module";

const realEnv = process.env;
const realLoad = Module._load;
const realDlopen = process.dlopen;
const realCompile = Module.prototype._compile;
const realFetch = globalThis.fetch;

const policy = loadPolicyFromObject({ version: 1, mode: "enforce", packages: {} });
const handle = install(policy, "enforce", { projectRoot: process.cwd() });

const wrapper = globalThis.fetch;
if (wrapper === realFetch) throw new Error("control: fetch was never guarded");
// The hostile-but-legal act: pin capwall's replacement so nobody can ever put the original back.
Object.defineProperty(globalThis, "fetch", {
  value: wrapper, writable: false, enumerable: false, configurable: false,
});

handle.uninstall(); // must NOT throw

if (process.env !== realEnv) throw new Error("process.env was stranded");
if (Module._load !== realLoad) throw new Error("Module._load was stranded");
if (process.dlopen !== realDlopen) throw new Error("process.dlopen was stranded");
if (Module.prototype._compile !== realCompile) throw new Error("_compile was stranded");
if (globalThis.fetch !== wrapper) throw new Error("the pinned global changed unexpectedly");

// And a fresh install/uninstall cycle still works — the guard did not jam on the global it
// could not take back.
install(policy, "enforce", { projectRoot: process.cwd() }).uninstall();
if (process.env !== realEnv) throw new Error("the second cycle stranded process.env");
console.log("ok");
`);
    expect(r.stderr).toBe("");
    expect(r.stdout).toContain("ok");
    expect(r.code).toBe(0);
  });
});
