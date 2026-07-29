/**
 * FORWARD-PATH ARITY — issue #128.
 *
 * #99/#104/#105 are about capwall mirroring Node's argument NORMALIZATION on the inbound side
 * ("which host is this really going to?"). This file is the same discipline one level up, on the
 * OUTBOUND side: when capwall wraps a Node primitive it must hand the real primitive **exactly
 * the arguments it was given**, not a hand-written parameter list that happened to match on the
 * Node it was written against.
 *
 * The bug that motivated it. `Module.prototype._compile` was wrapped as `(content, filename)`,
 * with a comment asserting "Node passes exactly `(content, filename)`". Node 22.18 added a third
 * parameter, `format`, and `Module._extensions` passes `"commonjs-typescript"` through it for a
 * `.ts`/`.cts` file — it is what triggers Node's built-in type stripping. Dropping it handed raw
 * TypeScript to `wrapSafe`, so `require("./x.ts")` threw `SyntaxError` **under every policy, in
 * both modes**, with capwall's own frame in the stack. Enabling a defense-in-depth tool looked
 * like it had corrupted the source tree.
 *
 * WHY THESE TESTS ARE WRITTEN ARITY-AGNOSTICALLY. Asserting "three arguments are forwarded" would
 * re-commit the original mistake in the test suite: it would pass today, and the day Node adds a
 * fourth parameter it would keep passing while the wrapper silently dropped it. So each case
 * asserts the PROPERTY — `arguments.length` and every element arrive unchanged, for any count,
 * including counts no current Node uses — which no future Node signature can invalidate.
 *
 * A subprocess per case, because every patch site here is a process global
 * (`Module.prototype._compile`, `Module._load`, `Module.prototype.load`, `Module._findPath`) and a
 * leaked patch would contaminate every later test file in the same worker.
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { initialize as initEsmHooks, resolve as esmResolve } from "../src/loader/esm-hooks.js";
import { MEDIATED_MODULES } from "../src/loader/require.js";
import { runNode, type NodeRunResult } from "./helpers/subprocess.js";

const CORE_DIST = createRequire(import.meta.url).resolve("../dist/index.js");
const CORE_URL = JSON.stringify(pathToFileURL(CORE_DIST).href);

/**
 * Built-in TypeScript type stripping — Node ≥22.18 (and ≥23).
 *
 * THIS PREDICATE SURVIVED THE NODE 20 DROP, and deliberately. The supported floor is ≥22.15
 * (chosen for `module.registerHooks()`, not for this), so 22.15–22.17 satisfy `engines` without
 * having type stripping, and the guard is still reachable. It does NOT skip on any leg of the CI
 * matrix — 22.latest, 24 and 26 all have it — so this is coverage that runs everywhere CI looks,
 * with a guard that stays honest about the range `engines` actually claims.
 *
 * Raising the floor to 22.18 purely to delete this `skipIf` would be the tail wagging the dog:
 * capwall REQUIRES `registerHooks`, it merely must-not-break type stripping.
 *
 * Evaluated at module scope so the dependent test can `skipIf`, which the reporter shows, rather
 * than `return` mid-body, which it does not (#112).
 */
const HAS_TYPE_STRIPPING = ((): boolean => {
  const [major, minor] = process.versions.node.split(".").map(Number) as [number, number];
  return major >= 23 || (major === 22 && minor >= 18);
})();

let tmpDir: string;

beforeAll(async () => {
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-arity-"));
});
afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

async function run(
  source: string,
  files: Record<string, string> = {},
): Promise<NodeRunResult> {
  const dir = await mkdtemp(path.join(tmpDir, "run-"));
  for (const [name, content] of Object.entries(files)) {
    await writeFile(path.join(dir, name), content);
  }
  const file = path.join(dir, "script.mjs");
  await writeFile(file, source);
  return runNode([file], { cwd: dir });
}

/** A deny-all `enforce` install — the point being that NONE of this is about a grant. */
const INSTALL = `
import { install, loadPolicyFromObject } from ${CORE_URL};
const policy = loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: process.cwd() });
const handle = install(policy, "enforce", { projectRoot: process.cwd(), globalEgress: false });
`;

/** The same install with the ESM hooks live — the half `resolve` belongs to. */
const INSTALL_ESM = `
import { install, loadPolicyFromObject } from ${CORE_URL};
const policy = loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: process.cwd() });
const handle = install(policy, "enforce", { projectRoot: process.cwd(), globalEgress: false, esm: true });
`;

/**
 * ISSUE #183 — the other half of "capwall did not change what Node does": not what reaches a
 * primitive, but what a RESOLVER hands back.
 *
 * `module.registerHooks()`'s `resolve` is consulted for `require()` too, and on Node ≥24.18
 * `require.resolve()` goes through the same chain where on 22 it does not. capwall short-circuits
 * every mediated builtin specifier to a synthetic `capwall-esm:` URL, so on ≥24.18 the answer a
 * caller SAW became `"capwall-esm:fs"`: `Module.isBuiltin` went false for all 24 mediated
 * spellings and `require(require.resolve("fs"))` threw `MODULE_NOT_FOUND`. Not a security hole,
 * and worse than one — it is the shape AGENTS.md § availability is about, where the user's fix is
 * to remove capwall.
 *
 * WRITTEN AS A DIFFERENTIAL, deliberately. Each row records Node's own answer BEFORE `install()`
 * and compares the answer under capwall against it, so the assertion is "capwall changed nothing"
 * rather than a hard-coded string that would have to be per-version — the version split is exactly
 * what let this sit unnoticed (22 was correct, ≥24.18 was not). It therefore needs no `skipIf` and
 * asserts the same property on every leg of the matrix.
 */
describe("#183 — capwall does not change what Node's resolvers return", () => {
  it("require.resolve() of every mediated builtin answers exactly as un-mediated Node does", async () => {
    const r = await run(`
import Module, { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const SPECS = ${JSON.stringify(MEDIATED_MODULES)};
// Node's own answers, taken before capwall exists in this process.
const before = SPECS.map((s) => require.resolve(s));
${INSTALL_ESM}
const after = SPECS.map((s) => require.resolve(s));
const builtin = after.map((u) => Module.isBuiltin(u));
// The round trip the ecosystem actually performs: resolve, then require the result.
const roundTrip = SPECS.map((s) => {
  try { require(require.resolve(s)); return "ok"; } catch (e) { return String(e && e.code); }
});
console.log(JSON.stringify({ before, after, builtin, roundTrip }));
handle.uninstall();
`);
    expect(r.stderr).toBe("");
    const out = JSON.parse(r.stdout.trim()) as {
      before: string[];
      after: string[];
      builtin: boolean[];
      roundTrip: string[];
    };
    // Not vacuous: the whole mediated set, both spellings of each builtin.
    expect(out.before.length).toBe(MEDIATED_MODULES.length);
    expect(out.after).toEqual(out.before);
    expect(out.after.filter((u) => u.startsWith("capwall-esm:"))).toEqual([]);
    expect(out.builtin.filter((b) => !b)).toEqual([]);
    expect(out.roundTrip.filter((x) => x !== "ok")).toEqual([]);
  });

  it("…and the require path is still MEDIATED — the URL changed, the enforcement did not", async () => {
    // The obligation the row above creates. `Module._load` returns the shim for every mediated
    // specifier before Node's resolver is reached, so declining to rewrite a `require` resolution
    // gives up nothing — but that is an argument, and this is the check.
    const r = await run(`
${INSTALL_ESM}
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const out = [];
for (const spec of ["fs", "node:fs"]) {
  for (const get of [() => require(spec), () => require(require.resolve(spec))]) {
    try { get().readFileSync("/etc/hostname"); out.push("RAW"); }
    catch (e) { out.push(e && e.name === "CapabilityError" ? "BLOCKED" : "ERR:" + (e && e.code)); }
  }
}
console.log(JSON.stringify(out));
handle.uninstall();
`);
    expect(JSON.parse(r.stdout.trim())).toEqual(["BLOCKED", "BLOCKED", "BLOCKED", "BLOCKED"]);
  });

  it("records what `import.meta.resolve` still answers — a KNOWN deviation, pinned not hidden", async () => {
    // NOT fixed, and the test says so rather than omitting the case. Measured on 22.23.1 /
    // 24.18.0 / 26.5.0: an `import.meta.resolve` reaches the hook with a context byte-for-byte
    // identical to a static `import` of the same specifier, so there is no signal to branch on;
    // the only shape that would fix it (mediating a raw `node:` URL in `load` instead) would cache
    // `node:fs` as the synthetic module and bring back the #152 teardown asymmetry on every
    // mediated builtin. See `loader/esm-hooks.ts` § THE SYNTHETIC URL IS AN `import`-PATH ANSWER.
    //
    // Pinned WITH its round trip, which is the part that keeps this cosmetic: the URL is odd but
    // importing it works and yields the enforcing shim, where `require.resolve`'s did not.
    const r = await run(`
${INSTALL_ESM}
const url = import.meta.resolve("fs");
let mediated;
try { (await import(url)).readFileSync("/etc/hostname"); mediated = "RAW"; }
catch (e) { mediated = e && e.name === "CapabilityError" ? "BLOCKED" : "ERR:" + (e && e.code); }
console.log(JSON.stringify({ url, mediated }));
handle.uninstall();
`);
    expect(JSON.parse(r.stdout.trim())).toEqual({ url: "capwall-esm:fs", mediated: "BLOCKED" });
  });
});

/**
 * The same rule as the differential above, asserted directly on the hook — because the
 * subprocess rows can only see it where Node routes `require.resolve` through the chain, which is
 * **≥24.18 only**. This one runs the hook itself, so it pins the rule on every leg of the matrix
 * and the version split stops being what decides whether the property is covered. (Safe in
 * process: vitest isolates each test file in its own fork, and no other file imports this module.)
 */
describe("#183 — a `require` resolution never gets capwall's synthetic URL", () => {
  /** Node's answer, stubbed: a bare builtin name resolves to its `node:` URL. */
  const nextResolve = (specifier: string): { url: string } => ({
    url: specifier.startsWith("node:") ? specifier : `node:${specifier}`,
  });
  const ctx = (...conditions: string[]) => ({
    conditions,
    importAttributes: {},
    parentURL: pathToFileURL(path.join(process.cwd(), "importer.mjs")).href,
  });

  beforeAll(() => {
    initEsmHooks({ bridgeUrl: "file:///bridge.js", exports: { fs: ["readFileSync"], "node:fs": ["readFileSync"] } });
  });

  it("answers Node's URL for the CJS resolver and the synthetic one for `import`", () => {
    // Both spellings, both loaders. The `import` half is asserted alongside so a mutation that
    // simply stopped mediating would fail here rather than looking like the #183 fix.
    for (const spec of ["fs", "node:fs"]) {
      expect(esmResolve(spec, ctx("require", "node"), nextResolve).url).toBe(nextResolve(spec).url);
      expect(esmResolve(spec, ctx("node", "import"), nextResolve).url).toBe(`capwall-esm:${spec}`);
    }
  });

  it("does not rewrite a `require` resolution that LANDS on a builtin either", () => {
    // The slow path (#59): a specifier that does not name a builtin but resolves to one. Same
    // rule — the answer a `require` sees is Node's.
    const landsOnFs = (): { url: string } => ({ url: "node:fs" });
    expect(esmResolve("#x", ctx("require", "node"), landsOnFs).url).toBe("node:fs");
    // `node:fs` is itself a registry key, so the direct hit answers and the synthetic URL carries
    // the `node:`-prefixed spelling — the same one the real registry produces.
    expect(esmResolve("#x", ctx("node", "import"), landsOnFs).url).toBe("capwall-esm:node:fs");
  });
});

describe("wrappers over Node primitives forward arguments verbatim (#128)", () => {
  it("Module.prototype._compile forwards any argument count, unchanged", async () => {
    // The recorder is installed UNDER capwall's gate: capwall patches whatever `_compile` it
    // finds, so the recorder sees exactly what capwall forwarded. Calling `_compile` through a
    // Module whose own filename is the app's is the `<app>` fast path, so no denial is involved
    // — the question is purely what reached the primitive.
    const r = await run(`
import Module from "node:module";
const seen = [];
const real = Module.prototype._compile;
Module.prototype._compile = function (...args) { seen.push(args); return undefined; };
${INSTALL}
const patched = Module.prototype._compile;
const m = new Module("x", null);
// Deliberately spanning counts no current Node uses, in both directions: the property under
// test is "whatever you pass arrives", not "three arguments arrive".
patched.call(m);
patched.call(m, "a");
patched.call(m, "a", process.cwd() + "/b.js");
patched.call(m, "a", process.cwd() + "/b.js", "commonjs-typescript");
patched.call(m, "a", process.cwd() + "/b.js", "module", "future-4th", 5);
console.log(JSON.stringify(seen));
handle.uninstall();
`);
    expect(r.stderr).toBe("");
    const seen = JSON.parse(r.stdout.trim()) as unknown[][];
    expect(seen.map((a) => a.length)).toEqual([0, 1, 2, 3, 5]);
    expect(seen[3]![2]).toBe("commonjs-typescript");
    expect(seen[4]!.slice(2)).toEqual(["module", "future-4th", 5]);
  });

  it("Module._load forwards any argument count, unchanged", async () => {
    // `Module._load`'s call arity is not a fixed fact about "Node ≥22" — it has OSCILLATED, and
    // within a major as well as across them. Read off the live function: 3 arguments on 20.19.4,
    // 4 on 22.23.1 (`options = kEmptyObject`), back to 3 on 23.9.0 and 24.5.0, and 4 again on
    // 24.18.0 and 26.5.0 under a new name and a new payload (`internalOptions`, carrying
    // `requireResolveOptions` as well as `shouldSkipModuleHooks`). `_load.length` reports 3 on
    // every one of them, because it stops at the first defaulted parameter — which is exactly
    // why the old hand-written signature looked right (#135).
    //
    // So this row passes counts Node has used, counts it has stopped using, and counts it has
    // never used, and asserts only that they arrive unchanged.
    const r = await run(`
import Module from "node:module";
const seen = [];
const real = Module._load;
Module._load = function (...args) { seen.push(args.length); return Reflect.apply(real, this, args); };
${INSTALL}
Module._load("node:path", null, false, { shouldSkipModuleHooks: true });
Module._load("node:os", null, false);
console.log(JSON.stringify(seen));
handle.uninstall();
`);
    expect(r.stderr).toBe("");
    expect(JSON.parse(r.stdout.trim())).toEqual([4, 3]);
  });

  it("Module.prototype.load forwards any argument count, unchanged", async () => {
    // THE FOURTH WRAPPER SITE, added by #177 when the module-read gate (#123) moved here from
    // inside the `Module._load` wrapper. It is the one internal in this file whose signature has
    // NOT moved — `(filename)` on 20/22/23/24/26 — and that is exactly why it needs the row:
    // "it has always been one argument" is the reasoning that produced #128 in the first place.
    //
    // The gate reads `args[0]` positionally and forwards the whole list, so a Node that adds a
    // second parameter (a `format`, as `_compile` gained in 22.18) changes what is forwarded
    // without changing what is gated.
    //
    // Loading the app's OWN file, so the `<app>` fast path applies and no denial is involved —
    // the question here is purely what reached the primitive.
    const r = await run(
      `
import Module from "node:module";
import * as path from "node:path";
const seen = [];
const real = Module.prototype.load;
Module.prototype.load = function (...args) { seen.push(args.length); return Reflect.apply(real, this, args); };
${INSTALL}
const patched = Module.prototype.load;
const f = path.join(process.cwd(), "target.js");
// Counts spanning the only signature Node has ever used plus two it never has. A fresh Module
// per call because \`load\` asserts it has not already loaded.
for (const extra of [[], ["future-2nd"], ["future-2nd", 3]]) {
  const m = new Module(f, null);
  m.paths = [];
  patched.call(m, f, ...extra);
}
console.log(JSON.stringify(seen));
handle.uninstall();
`,
      { "target.js": "module.exports = 1;\n" },
    );
    expect(r.stderr).toBe("");
    // The install itself loads modules, so the recorder sees Node's own calls too; assert on the
    // tail, which is the three this row made.
    const seen = JSON.parse(r.stdout.trim()) as number[];
    expect(seen.slice(-3)).toEqual([1, 2, 3]);
  });

  it("Module._findPath forwards any argument count, unchanged", async () => {
    // The third wrapper site over a Node internal, and the one whose parameter list has ALREADY
    // moved under it without anyone noticing: `(request, paths, isMain)` on Node 20.19.4, and
    // `(request, paths, isMain, conditions = getCjsConditions())` — four arguments passed on
    // every call — on 22.23.1, 24.18.0 and 26.5.0. `.length` is 3 on all four, so nothing about
    // the function object says it changed.
    //
    // `loader/linked-packages.ts` was written variadic on the #128 rule and so needed no change,
    // which is precisely the property worth locking down: the site reads args 0 and 1
    // POSITIONALLY (specifier and search-path list) and forwards the whole list, so a Node that
    // adds a fifth parameter changes what is forwarded without changing what is observed.
    const r = await run(`
import Module from "node:module";
const seen = [];
const real = Module._findPath;
Module._findPath = function (...args) { seen.push(args.length); return Reflect.apply(real, this, args); };
${INSTALL}
const patched = Module._findPath;
// Counts spanning both real signatures plus one no Node has ever used.
patched("./nope-a", [process.cwd()]);
patched("./nope-b", [process.cwd()], false);
patched("./nope-c", [process.cwd()], false, new Set(["node", "require"]));
patched("./nope-d", [process.cwd()], false, new Set(["node", "require"]), "future-5th");
console.log(JSON.stringify(seen));
handle.uninstall();
`);
    expect(r.stderr).toBe("");
    // The install itself resolves modules, so the recorder sees Node's own calls too; assert on
    // the tail, which is the four this row made.
    const seen = JSON.parse(r.stdout.trim()) as number[];
    expect(seen.slice(-4)).toEqual([2, 3, 4, 5]);
  });

  it.skipIf(!HAS_TYPE_STRIPPING)("keeps require() of a TypeScript file working — the user-visible half of #128", async () => {
    // The failure mode that gets a defense-in-depth tool uninstalled: no denial, no policy, no
    // attribution — just a SyntaxError from Node's own loader with capwall's frame in the stack.
    // Skipped on a Node without built-in type stripping (22.15–22.17 — inside `engines`, below
    // every leg of the CI matrix), where the third argument does not exist and there is nothing
    // to drop. Via `skipIf`, so such a runtime REPORTS the gap rather than hiding it: two stacked
    // `if (…) return;` lines used to make this a green no-op, and it is the only coverage of
    // #128's user-visible half (#112).
    const r = await run(
      `
${INSTALL}
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
console.log("esm-shaped ts:", require("./lib.ts").greet({ who: "world" }));
console.log("cjs-shaped ts:", JSON.stringify(require("./cjslib.ts")));
handle.uninstall();
`,
      {
        "lib.ts": `export interface Greeting { who: string }
export function greet(g: Greeting): string { return "hello " + g.who }
`,
        "cjslib.ts": `const n: number = 41;
module.exports = { n: n + 1 };
`,
      },
    );
    expect(r.stderr).not.toContain("SyntaxError");
    expect(r.stdout).toContain("esm-shaped ts: hello world");
    expect(r.stdout).toContain('cjs-shaped ts: {"n":42}');
    expect(r.code).toBe(0);
  });
});
