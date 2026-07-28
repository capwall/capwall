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
 * A subprocess per case, because both patch sites are process globals (`Module.prototype._compile`,
 * `Module._load`) and a leaked patch would contaminate every later test file in the same worker.
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
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
