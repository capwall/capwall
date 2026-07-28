/**
 * THE MODULE SYSTEM AS A READ CHANNEL — issue #123.
 *
 * Under a deny-all `enforce` policy with zero grants — no `eval`, no `vm`, no `compile`, no write
 * — a dependency read any file on disk through `require()` / `import()` with **no decision
 * recorded at all**. `Module._extensions['.json']` reads through Node's internals and
 * `JSON.parse`s the result; the ESM side goes through Node's JSON translator. Neither touched
 * capwall's `fs` shim, so `enforce` printed nothing, `observe` recorded nothing, and
 * `capwall diff` had nothing to compare.
 *
 * WHAT THIS FILE HOLDS IN PLACE, and the shape of the gate it is testing (see
 * `src/loader/module-read.ts` for the full reasoning):
 *
 *   A module load is FREE when the resolved file belongs to an installed package (any
 *   `node_modules` tree) or when the loader is the application. Otherwise it is an `fs.read`
 *   decision on the resolved path.
 *
 * So the file is organized around the four quadrants that rule creates — {CJS, ESM} × {inside the
 * dependency graph, outside it} — plus the two things that must NOT change: an application
 * loading its own files, and a package loading its own. The last of those is the whole
 * compatibility argument: a gate that made ordinary `require` a capability would be unusable, and
 * `examples/express-app` running clean under its unchanged committed policy (see
 * `packages/cli/test/express-app-policy.test.ts`) is the end-to-end proof that it does not.
 *
 * Subprocess per case: the gate is on the LOADER and decisions are cached per process
 * (`Module._cache`, the ESM registry), neither of which is isolatable in-process. Requires
 * `pnpm build` (CI does build → test).
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import Module from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  decideEsmModuleRead,
  forgetHostRootTargets,
  isHostRootTarget,
  moduleLoadNeedsDecision,
  recordHostRootTarget,
} from "../src/loader/module-read.js";
import { parsePolicy } from "@capwall/policy-schema";
import {
  assertPreloadBuilt,
  PRELOAD_IMPORT_FLAG,
  runNode,
  type NodeRunResult,
} from "./helpers/subprocess.js";

const here = path.dirname(fileURLToPath(import.meta.url));

/** The string that must never reach stdout through any channel under a deny-all policy. */
const SECRET = "AKIA-MODULE-READ-CHANNEL";

/**
 * Does THIS Node's `Module._load` accept `{ requireResolveOptions }` as its fourth argument and
 * resolve through it?
 *
 * FEATURE-DETECTED, NOT VERSION-GATED, because the feature's history is exactly why the gap it
 * guards existed: `Module._load` grew a fourth parameter in 22, lost it again in 23 and early 24,
 * and regained it in a 24 MINOR (24.18) under a new name and a new payload. Any `major >= N` test
 * written against that would have been wrong for two of the five majors. The probe below asks the
 * runtime, so it is right on releases that do not exist yet.
 *
 * The probe asks for `./package.json` from a parent whose OWN directory does not exist, so the
 * relative fallback (`dirname(parent.filename)`, which is what a Node without the feature uses)
 * cannot answer it — only `options.paths` can. Un-mediated: this file installs nothing at module
 * scope.
 */
const HONOURS_REQUIRE_RESOLVE_OPTIONS: boolean = ((): boolean => {
  const load = (Module as unknown as { _load?: (...args: unknown[]) => unknown })._load;
  if (typeof load !== "function") return false;
  const dir = path.join(here, ".."); // packages/core, which has a package.json
  const parent = new Module("capwall-require-resolve-options-probe", undefined);
  parent.filename = path.join(dir, "capwall-no-such-directory", "probe.js");
  parent.paths = [];
  try {
    const loaded = load("./package.json", parent, false, {
      requireResolveOptions: { paths: [dir] },
    });
    return typeof loaded === "object" && loaded !== null;
  } catch {
    return false;
  }
})();

let root: string;
let proj: string;
let vault: string;
let denyPolicy: string;
let vaultGrantPolicy: string;

/**
 * `NODE_OPTIONS` rather than an argv flag, because several entries below are themselves spawned
 * as `node <entry>` by the fixture and must inherit the preload. Identical (entry, env) pairs run
 * once and are shared (#145) — the CJS and ESM halves of a claim are separate `it`s asserting
 * different things about the same run.
 */
function runEntry(entry: string, env: Record<string, string>): Promise<NodeRunResult> {
  return runNode([entry], {
    // Sound to share: the whole fixture tree and both policy files are built in `beforeAll` and
    // are read-only for the rest of the file.
    share: true,
    cwd: proj,
    env: { NODE_OPTIONS: PRELOAD_IMPORT_FLAG, CAPWALL_PROJECT_ROOT: proj, ...env },
  });
}

const deny = (entry: string): Promise<NodeRunResult> =>
  runEntry(entry, { CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy });

/**
 * Build the fixture tree. `vault` sits OUTSIDE the project root entirely (the `~/.aws`,
 * `~/.docker/config.json` shape); `proj/config` is inside the project but belongs to no package
 * (the `package-lock.json`, app-local `secrets.json` shape); `friend` is a sibling dependency.
 */
async function buildFixture(): Promise<void> {
  const evil = path.join(proj, "node_modules", "evil");
  const friend = path.join(proj, "node_modules", "friend");
  await mkdir(vault, { recursive: true });
  await mkdir(evil, { recursive: true });
  await mkdir(friend, { recursive: true });
  await mkdir(path.join(proj, "config"), { recursive: true });

  await writeFile(path.join(vault, "secrets.json"), JSON.stringify({ key: SECRET }));
  // Reached ONLY through `Module._load`'s four-argument `requireResolveOptions` form — see the
  // "every spelling of Module._load" block.
  await writeFile(path.join(vault, "other-secrets.json"), JSON.stringify({ key: SECRET }));
  await writeFile(
    path.join(vault, "payload.js"),
    `console.log("PAYLOAD:cjs-executed");\nmodule.exports = { key: ${JSON.stringify(SECRET)} };\n`,
  );
  await writeFile(
    path.join(vault, "payload.mjs"),
    `console.log("PAYLOAD:esm-executed");\nexport default { key: ${JSON.stringify(SECRET)} };\n`,
  );

  await writeFile(path.join(proj, "package.json"), JSON.stringify({ name: "proj", version: "1.0.0" }));
  await writeFile(path.join(proj, "config", "inside.json"), JSON.stringify({ key: SECRET }));

  await writeFile(
    path.join(friend, "package.json"),
    JSON.stringify({ name: "friend", version: "1.0.0", main: "index.js" }),
  );
  await writeFile(path.join(friend, "index.js"), "module.exports = {};\n");
  await writeFile(path.join(friend, "data.json"), JSON.stringify({ shipped: "by friend" }));

  await writeFile(
    path.join(evil, "package.json"),
    JSON.stringify({ name: "evil", version: "1.0.0", main: "index.js" }),
  );
  await writeFile(path.join(evil, "own.json"), JSON.stringify({ mine: "yes" }));
  await writeFile(path.join(evil, "lib.js"), "module.exports = { mine: true };\n");

  // The CJS prober. Every target is reported as OK (with its value) or ERR (with the error name),
  // so a single run answers the whole quadrant at once and a regression names itself.
  await writeFile(
    path.join(evil, "index.js"),
    `const TARGETS = ${JSON.stringify([
      ["outside-json", path.join(vault, "secrets.json")],
      ["outside-js", path.join(vault, "payload.js")],
      ["inside-project-json", path.join(proj, "config", "inside.json")],
      ["own-json", "./own.json"],
      ["own-js", "./lib.js"],
      ["sibling-package-json", "friend/data.json"],
    ])};
module.exports = function run() {
  for (const [name, target] of TARGETS) {
    try {
      console.log("CJS:" + name + ":OK:" + JSON.stringify(require(target)));
    } catch (err) {
      console.log("CJS:" + name + ":ERR:" + err.name);
    }
  }
};
`,
  );

  // The ESM prober, inside `evil` so `context.parentURL` names it. Import attributes are written
  // as \`with\` (Node ≥20.10 for dynamic import); a Node that rejects them reports ERR here, which
  // the assertions treat the same as a denial — either way the bytes did not reach the caller.
  await writeFile(
    path.join(evil, "probe.mjs"),
    `const url = (p) => new URL("file://" + p).href;
const TARGETS = ${JSON.stringify([
      ["outside-json", path.join(vault, "secrets.json"), true],
      ["outside-mjs", path.join(vault, "payload.mjs"), false],
      ["inside-project-json", path.join(proj, "config", "inside.json"), true],
    ])};
export default async function probe() {
  for (const [name, target, json] of TARGETS) {
    try {
      const m = await (json
        ? import(url(target), { with: { type: "json" } })
        : import(url(target)));
      console.log("ESM:" + name + ":OK:" + JSON.stringify(m.default));
    } catch (err) {
      console.log("ESM:" + name + ":ERR:" + err.name);
    }
  }
  try {
    const own = await import("./own.json", { with: { type: "json" } });
    console.log("ESM:own-json:OK:" + JSON.stringify(own.default));
  } catch (err) {
    console.log("ESM:own-json:ERR:" + err.name);
  }
}
`,
  );

  // THE `require(esm)` LAUNDERING ROUTE (#152). `require("./inner.mjs")` loads an ES module
  // SYNCHRONOUSLY, so the whole ESM subgraph below it — including this JSON import of a file
  // outside every package — is resolved inside ONE `Module._load` call. That matters because
  // `loader/require.ts` marks the extent of a load it has already decided, so the ESM `resolve`
  // hook does not decide it twice; a mark that covered the nested imports too would silently
  // disarm the gate for exactly this shape. `inner.mjs` lives inside `evil`, so the require of
  // it is free and the JSON import is the only decision in play.
  //
  // A STATIC import, not a dynamic one: `require(esm)` refuses a module with top-level `await`
  // (`ERR_REQUIRE_ASYNC_MODULE`), so a `try`/`await import()` inside `inner.mjs` would never get
  // as far as the gate. The denial therefore surfaces on the OUTER `require`, which is also the
  // more adversarial shape — the JSON is a static dependency of the module being required.
  await writeFile(
    path.join(evil, "inner.mjs"),
    `import data from ${JSON.stringify(pathToFileURL(path.join(vault, "secrets.json")).href)} with { type: "json" };
export default "OK:" + JSON.stringify(data);
`,
  );
  await writeFile(
    path.join(evil, "require-esm.js"),
    `module.exports = function run() {
  try {
    console.log("REQESM:inner:" + require("./inner.mjs").default);
  } catch (err) {
    console.log("REQESM:inner:OUTER-ERR:" + err.name);
  }
};
`,
  );
  await writeFile(path.join(proj, "app-require-esm.js"), `require("evil/require-esm.js")();\n`);

  // `require()` of a MEDIATED BUILTIN, from a dependency. Since #152 the hooks see `require` too,
  // so this is the assertion that they do not intercept it: `Module._load` gets there first and
  // hands back the CJS shim OBJECT, not the ESM synthetic module's namespace.
  await writeFile(
    path.join(evil, "builtin-require.js"),
    `module.exports = function run() {
  const a = require("node:fs");
  const b = require("fs");
  console.log("BUILTIN:same-object:" + (a === b));
  console.log("BUILTIN:has-readFileSync:" + (typeof a.readFileSync === "function"));
  console.log("BUILTIN:is-namespace:" + (a[Symbol.toStringTag] === "Module"));
};
`,
  );
  await writeFile(
    path.join(proj, "app-builtin-require.js"),
    `require("evil/builtin-require.js")();\n`,
  );

  // Entry points. The application is the trust root, so its OWN loads of the very same files must
  // stay free — that is half the compatibility argument and it is asserted, not assumed.
  await writeFile(path.join(proj, "app.js"), `require("evil")();\n`);
  await writeFile(
    path.join(proj, "app-esm.mjs"),
    `const { default: probe } = await import("evil/probe.mjs");\nawait probe();\n`,
  );
  await writeFile(
    path.join(proj, "app-selfload.js"),
    `const TARGETS = ${JSON.stringify([
      ["app-outside-json", path.join(vault, "secrets.json")],
      ["app-inside-json", path.join(proj, "config", "inside.json")],
    ])};
for (const [name, target] of TARGETS) {
  try {
    require(target);
    console.log("APP:" + name + ":OK");
  } catch (err) {
    console.log("APP:" + name + ":ERR:" + err.name);
  }
}
`,
  );
  await writeFile(
    path.join(proj, "app-selfload.mjs"),
    `const url = (p) => new URL("file://" + p).href;
try {
  await import(url(${JSON.stringify(path.join(vault, "payload.mjs"))}));
  console.log("APP:app-outside-mjs:OK");
} catch (err) {
  console.log("APP:app-outside-mjs:ERR:" + err.name);
}
`,
  );

  // The `Module._load` INTERNAL-OPTIONS prober — see the describe block at the bottom of this
  // file. Two loads of the same file by the same dependency: one through the plain three-argument
  // call, one through the four-argument form that carries `requireResolveOptions`. They must be
  // decided identically; a Node minor made them differ.
  await writeFile(
    path.join(evil, "internal-options.js"),
    `const Module = require("node:module");
const VAULT = ${JSON.stringify(vault)};
const ABS = ${JSON.stringify(path.join(vault, "secrets.json"))};
// A DIFFERENT file for the four-argument form, so the two reads are distinguishable in the
// trace: the preload deduplicates identical decisions per process, and the substance of the
// claim is that the gate names the file this spelling actually opens — not merely that
// something threw.
function parent() {
  const m = new Module("evil-internal-options", null);
  m.filename = __filename;
  m.paths = Module._nodeModulePaths(__dirname);
  return m;
}
function report(name, fn) {
  try {
    console.log("LOAD:" + name + ":OK:" + JSON.stringify(fn()));
  } catch (err) {
    console.log("LOAD:" + name + ":ERR:" + err.name);
  }
}
module.exports = function run() {
  report("plain", () => Module._load(ABS, parent(), false));
  report("require-resolve-options", () =>
    Module._load("./other-secrets.json", parent(), false, { requireResolveOptions: { paths: [VAULT] } }));
};
`,
  );
  await writeFile(path.join(proj, "app-internal-options.js"), `require("evil/internal-options.js")();\n`);

  await buildGroundTruthFixture();
}

/**
 * THE #177/#178/#179/#180 FIXTURE — every load capwall decides is decided on the filename NODE
 * resolved, never on an argument the caller supplied.
 *
 * Each probe gets its OWN vault file, because the preload deduplicates identical decisions per
 * process (`preload.ts`): a shared target would let one `DENY` line satisfy an assertion about a
 * different route. `decoy` is a real installed package holding a file with the same relative
 * name as each target, so #178's steered re-resolution had somewhere graph-exempt to land.
 */
async function buildGroundTruthFixture(): Promise<void> {
  const evil = path.join(proj, "node_modules", "evil");
  const decoy = path.join(proj, "node_modules", "decoy");
  await mkdir(decoy, { recursive: true });
  await writeFile(
    path.join(decoy, "package.json"),
    JSON.stringify({ name: "decoy", version: "1.0.0" }),
  );

  for (const name of GROUND_TRUTH_TARGETS) {
    await writeFile(path.join(vault, `${name}.json`), JSON.stringify({ key: SECRET }));
    // The decoy copy is HARMLESS and inside the dependency graph — resolving to it is exactly
    // what "no decision was taken" looked like in #178.
    await writeFile(path.join(decoy, `${name}.json`), JSON.stringify({ harmless: true }));
  }

  // Shared preamble: a forged `parent` record (the object `guardCjsModuleRead` refuses to trust),
  // a bag whose getters throw (which used to make capwall's own re-resolution fail while Node's
  // succeeded), and the reporter every probe prints through.
  const preamble = `const Module = require("node:module");
const VAULT = ${JSON.stringify(vault)};
const DECOY = ${JSON.stringify(decoy)};
const abs = (n) => require("node:path").join(VAULT, n + ".json");
// A module record whose \`filename\` is any string the caller likes — createRequire builds one of
// these for free. #180 is what happens when a gate believes it.
function rec(filename) {
  const m = new Module("forged", null);
  m.filename = filename;
  m.paths = [];
  return m;
}
const honest = () => rec(__filename);
// Getters that throw: capwall's deleted re-resolution died on these, and read "nothing to decide".
const hostileBag = () => ({ get paths() { throw new Error("x"); } });
function report(name, fn) {
  try {
    const v = fn();
    console.log("GT:" + name + ":OK:" + JSON.stringify(v));
  } catch (err) {
    console.log("GT:" + name + ":ERR:" + err.name + ":" + err.pkg);
  }
}
`;

  // ── #177 ────────────────────────────────────────────────────────────────────────────────
  // `isMain` is the caller's third argument, and `parent: undefined` is the caller's second.
  // Passing both waived the CJS half and the ESM half at once. `proto-load-direct` is the route
  // that never reaches `Module._load` AT ALL — the old gate could not see it even in principle.
  await writeFile(
    path.join(evil, "gt-177.js"),
    `${preamble}module.exports = function run() {
  report("177-baseline", () => require(abs("gt-177-baseline")));
  report("177-ismain", () => Module._load(abs("gt-177-ismain"), undefined, true));
  report("177-ismain-honest-parent", () => Module._load(abs("gt-177-ismain2"), honest(), true));
  report("177-proto-load-direct", () => {
    const f = abs("gt-177-proto");
    const m = new Module(f, module);
    m.load(f);
    return m.exports;
  });
};
`,
  );
  await writeFile(path.join(proj, "app-gt-177.js"), `require("evil/gt-177.js")();\n`);

  // ── #178 ────────────────────────────────────────────────────────────────────────────────
  // Three constructions of `Module._load`'s fourth argument, all of which steered capwall's
  // re-resolution to `decoy` (graph-exempt, no decision) while Node opened the vault file.
  // A works on 22/24/26; B is the getter read three times; C is the 22-specific unwrap.
  await writeFile(
    path.join(evil, "gt-178.js"),
    `${preamble}// A parent whose directory is the VAULT, so a relative specifier resolves there — and a
// \`paths\`/\`requireResolveOptions\` that points at the decoy package instead.
const vaultParent = () => rec(require("node:path").join(VAULT, "parent.js"));
module.exports = function run() {
  report("178-a-static-paths", () =>
    Module._load("./gt-178-a.json", vaultParent(), false, { paths: [DECOY] }));
  let reads = 0;
  const getterBag = {
    get requireResolveOptions() {
      reads += 1;
      return reads <= 2 ? { paths: [DECOY] } : undefined;
    },
  };
  report("178-b-getter", () => Module._load("./gt-178-b.json", vaultParent(), false, getterBag));
  console.log("GT:178-b-reads:" + reads);
  report("178-c-unwrap", () =>
    Module._load("./gt-178-c.json", vaultParent(), false, { requireResolveOptions: { paths: [DECOY] } }));
};
`,
  );
  await writeFile(path.join(proj, "app-gt-178.js"), `require("evil/gt-178.js")();\n`);

  // ── #179 ────────────────────────────────────────────────────────────────────────────────
  // The SAME call, twice: once from a module body (which runs inside its own `Module._load`, so
  // the deleted depth counter was non-zero) and once from a `setImmediate` (counter at zero).
  // The whole point is that the two answers must be identical.
  await writeFile(
    path.join(evil, "gt-179.js"),
    `${preamble}// TOP LEVEL — this file's body is being evaluated inside its own Module._load right now.
report("179-during-eval", () => Module._load(abs("gt-179-during"), module, false, hostileBag()));
setImmediate(() => {
  report("179-after-eval", () => Module._load(abs("gt-179-after"), module, false, hostileBag()));
});
`,
  );
  await writeFile(path.join(proj, "app-gt-179.js"), `require("evil/gt-179.js");\n`);

  // ── #180 ────────────────────────────────────────────────────────────────────────────────
  // Principal selection. `setImmediate` so the deleted depth counter was at zero and the ESM hook
  // was genuinely armed — which is the configuration in which it charged whoever the caller named.
  // `node_modules/impostor/` DOES NOT EXIST; that it was accepted as a principal is the finding.
  await writeFile(
    path.join(evil, "gt-180.js"),
    `${preamble}const path = require("node:path");
const APP = ${JSON.stringify(proj)};
module.exports = function run() {
  setImmediate(() => {
    report("180-honest", () => Module._load(abs("gt-180-honest"), module, false, hostileBag()));
    report("180-forged-app", () =>
      Module._load(abs("gt-180-app"), rec(path.join(APP, "app.js")), false, hostileBag()));
    report("180-forged-impostor", () =>
      Module._load(abs("gt-180-impostor"), rec(path.join(APP, "node_modules", "impostor", "index.js")), false, hostileBag()));
  });
};
`,
  );
  await writeFile(path.join(proj, "app-gt-180.js"), `require("evil/gt-180.js")();\n`);

  // ── THE ENTRY POINT, spelled the three ways an operator spells it ───────────────────────
  // The gate now runs for the entry point too, so "which file is the process root" has to be a
  // HOST fact. `process.argv[1]` answers the first spelling exactly and neither of the other two;
  // the `resolve` hook's root resolution answers all three. Every one of these must start.
  await mkdir(path.join(proj, "entrydir"), { recursive: true });
  await writeFile(
    path.join(proj, "entrydir", "package.json"),
    JSON.stringify({ name: "entrydir", version: "1.0.0", main: "index.js" }),
  );
  await writeFile(path.join(proj, "entrydir", "index.js"), `console.log("ENTRY:dir-main:OK");\n`);
  await writeFile(path.join(proj, "entry-plain.js"), `console.log("ENTRY:plain:OK");\n`);
}

/** One vault file per probe — see {@link buildGroundTruthFixture} on why they cannot be shared. */
const GROUND_TRUTH_TARGETS = [
  "gt-177-baseline",
  "gt-177-ismain",
  "gt-177-ismain2",
  "gt-177-proto",
  "gt-178-a",
  "gt-178-b",
  "gt-178-c",
  "gt-179-during",
  "gt-179-after",
  "gt-180-honest",
  "gt-180-app",
  "gt-180-impostor",
] as const;

beforeAll(async () => {
  assertPreloadBuilt();
  root = await mkdtemp(path.join(os.tmpdir(), "capwall-modread-"));
  proj = path.join(root, "proj");
  vault = path.join(root, "vault");
  await buildFixture();

  denyPolicy = path.join(root, "deny.json");
  vaultGrantPolicy = path.join(root, "grant.json");
  await writeFile(
    denyPolicy,
    JSON.stringify({ version: 1, mode: "enforce", default: {}, packages: {} }),
  );
  await writeFile(
    vaultGrantPolicy,
    JSON.stringify({
      version: 1,
      mode: "enforce",
      packages: { evil: { fs: { read: [path.join(vault, "**")], write: [] } } },
    }),
  );
}, 60_000);

afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// CJS — `require()` of a path specifier.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("#123 CJS — require() is not a way around fs.read", () => {
  it("denies a dependency requiring a .json OUTSIDE the project, and the bytes never appear", async () => {
    const r = await deny(path.join(proj, "app.js"));
    expect(r.stdout).toContain("CJS:outside-json:ERR:CapabilityError");
    expect(r.stdout).not.toContain(SECRET);
    expect(r.stderr).toMatch(/DENY 'evil' fs:read .*secrets\.json/);
  }, 30_000);

  it("denies a dependency requiring a .js outside the project — and it never RUNS", async () => {
    // The executable half. Before #123 this both ran the code and gave whatever it defined a
    // `<app>` identity, because a file under no `node_modules` attributes to the trust root.
    const r = await deny(path.join(proj, "app.js"));
    expect(r.stdout).toContain("CJS:outside-js:ERR:CapabilityError");
    expect(r.stdout).not.toContain("PAYLOAD:cjs-executed");
  }, 30_000);

  it("denies a dependency requiring a project file that belongs to no package", async () => {
    // `<project>/config/inside.json` — the `package-lock.json` / app-local `secrets.json` shape.
    // Inside the project root is not the same as inside the dependency graph.
    const r = await deny(path.join(proj, "app.js"));
    expect(r.stdout).toContain("CJS:inside-project-json:ERR:CapabilityError");
  }, 30_000);

  it("leaves a package loading ITS OWN files completely free", async () => {
    // The compatibility case. No grant, no decision, no log line — because gating this would
    // make every policy grant every package its own directory.
    const r = await deny(path.join(proj, "app.js"));
    expect(r.stdout).toContain('CJS:own-json:OK:{"mine":"yes"}');
    expect(r.stdout).toContain('CJS:own-js:OK:{"mine":true}');
    expect(r.stderr).not.toMatch(/fs:read .*own\.json/);
  }, 30_000);

  it("leaves a cross-package load inside node_modules free (the documented residual)", async () => {
    // `require("mime-db")` resolving to `node_modules/mime-db/db.json` is the dependency graph,
    // not a file read. This is the concession the graph exemption makes; it is bounded to
    // published artifacts of packages the project already installed. See docs/threat-model.md.
    const r = await deny(path.join(proj, "app.js"));
    expect(r.stdout).toContain('CJS:sibling-package-json:OK:{"shipped":"by friend"}');
  }, 30_000);

  it("allows the outside read once the policy grants it — the observe→enforce round trip", async () => {
    const r = await runEntry(path.join(proj, "app.js"), {
      CAPWALL_MODE: "enforce",
      CAPWALL_POLICY_FILE: vaultGrantPolicy,
    });
    expect(r.stdout).toContain(`CJS:outside-json:OK:{"key":"${SECRET}"}`);
    expect(r.stdout).toContain("PAYLOAD:cjs-executed");
    // The grant covers the vault and nothing else, so the in-project target is still denied —
    // which is the point: the decision is per-path, exactly like every other `fs.read`.
    expect(r.stderr).not.toMatch(/DENY 'evil' fs:read \S*vault/);
    expect(r.stdout).toContain("CJS:inside-project-json:ERR:CapabilityError");
  }, 30_000);

  it("leaves the APPLICATION's own loads free — it is the trust root, as in every other gate", async () => {
    const r = await deny(path.join(proj, "app-selfload.js"));
    expect(r.stdout).toContain("APP:app-outside-json:OK");
    expect(r.stdout).toContain("APP:app-inside-json:OK");
    expect(r.stderr).not.toMatch(/DENY '<app>'/);
  }, 30_000);
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// The four-argument `Module._load` form — a live bypass a Node MINOR opened under the gate.
//
// #157's HISTORY, because the shape of the fix changed twice. The gate used to need to know which
// file a load would open, so it RE-RAN `Module._resolveFilename` before delegating — first by
// forwarding `_load`'s own argument list verbatim (wrong: `_load`'s fourth argument is an internal
// bag, `_resolveFilename`'s is `ResolveFilenameOptions`, and on 24.18/26 resolution therefore
// THREW and the gate read that as "nothing to decide"), then by CLASSIFYING that bag by the fields
// it carried. #178 is what the second attempt cost: the fields are the attacker's, so the
// classifier could be steered, and capwall re-resolved to a decoy inside `node_modules` while Node
// opened the real file. There is no classifier any more and no second resolution — see the
// `#178` block below, and `loader/module-read.ts` § WHICH OF THE GATES DECIDES A GIVEN LOAD.
//
// #176's CONCERN, ANSWERED PROPERLY. The two rows here need a `Module._load` that honours
// `requireResolveOptions`, which arrived in a 24 MINOR, so they skip on the FLOOR — and `engines`
// is `>=22.15.0`, which meant `pnpm test` on the version this repo tells adopters to run exercised
// none of the fix. #176 answered that by unit-testing the classifier on every runtime. Deleting
// the classifier deletes those rows with it; what replaces them is better, because it is
// end-to-end rather than a unit test of an internal: the `#178` block reaches the identical
// four-argument bypass on 22, 24 and 26 with NO feature probe and NO skip, by giving the forged
// `parent` a directory the relative specifier actually resolves in.
//
// These two rows stay because they assert the property on a runtime that reaches this spelling of
// it: **the same read by the same package is decided the same way whichever spelling of
// `Module._load` reaches it.** They deliberately do not assert an argument count.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("#123 — every spelling of Module._load reaches the same decision", () => {
  it.skipIf(!HONOURS_REQUIRE_RESOLVE_OPTIONS)(
    "denies the `requireResolveOptions` form exactly as it denies the plain one",
    async () => {
      const r = await deny(path.join(proj, "app-internal-options.js"));
      expect(r.stdout).toContain("LOAD:plain:ERR:CapabilityError");
      expect(r.stdout).toContain("LOAD:require-resolve-options:ERR:CapabilityError");
      expect(r.stdout).not.toContain(SECRET);
    },
    30_000,
  );

  it.skipIf(!HONOURS_REQUIRE_RESOLVE_OPTIONS)(
    "names the file THAT spelling opens, so observe and `capwall diff` see the reach",
    async () => {
      // Same (entry, env) as the row above, so `share: true` reuses that one child (#145).
      const r = await deny(path.join(proj, "app-internal-options.js"));
      // Two DIFFERENT files, so neither line can stand in for the other and the preload's
      // per-process decision dedup cannot collapse them. Pre-fix, `other-secrets.json` never
      // appeared here at all — resolution failed inside capwall and the gate declined.
      expect(r.stderr).toMatch(/DENY 'evil' fs:read [^\n]*[/\\]secrets\.json/);
      expect(r.stderr).toMatch(/DENY 'evil' fs:read [^\n]*[/\\]other-secrets\.json/);
    },
    30_000,
  );
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// ESM — `import()`, including `with { type: "json" }`, which is the same disclosure by another
// route: Node's JSON translator, not capwall's fs shim.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("#123 ESM — import() is not a way around fs.read either", () => {
  it("denies a dependency importing a JSON module OUTSIDE the project", async () => {
    const r = await deny(path.join(proj, "app-esm.mjs"));
    expect(r.stdout).toMatch(/ESM:outside-json:ERR:/);
    expect(r.stdout).not.toContain(SECRET);
  }, 30_000);

  it("denies a dependency importing an ESM module outside the project — and it never RUNS", async () => {
    const r = await deny(path.join(proj, "app-esm.mjs"));
    expect(r.stdout).toContain("ESM:outside-mjs:ERR:CapabilityError");
    expect(r.stdout).not.toContain("PAYLOAD:esm-executed");
    expect(r.stderr).toMatch(/DENY 'evil' fs:read .*payload\.mjs/);
  }, 30_000);

  it("denies a dependency importing a project file that belongs to no package", async () => {
    const r = await deny(path.join(proj, "app-esm.mjs"));
    expect(r.stdout).toMatch(/ESM:inside-project-json:ERR:/);
  }, 30_000);

  it("leaves a package importing ITS OWN files free", async () => {
    const r = await deny(path.join(proj, "app-esm.mjs"));
    // Either it worked, or this Node does not support the import attribute at all — never a
    // capwall denial, which is the property under test.
    expect(r.stdout).not.toContain("ESM:own-json:ERR:CapabilityError");
  }, 30_000);

  it("allows the outside import once granted", async () => {
    const r = await runEntry(path.join(proj, "app-esm.mjs"), {
      CAPWALL_MODE: "enforce",
      CAPWALL_POLICY_FILE: vaultGrantPolicy,
    });
    expect(r.stdout).toContain("ESM:outside-mjs:OK:");
    expect(r.stdout).toContain("PAYLOAD:esm-executed");
    expect(r.stderr).not.toMatch(/DENY 'evil' fs:read \S*vault/);
  }, 30_000);

  it("leaves the APPLICATION's own imports free", async () => {
    const r = await deny(path.join(proj, "app-selfload.mjs"));
    expect(r.stdout).toContain("APP:app-outside-mjs:OK");
    expect(r.stderr).not.toMatch(/DENY '<app>'/);
  }, 30_000);
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// WHICH GATE DECIDES (#152). `module.registerHooks()` is consulted for `require()` as well as
// `import()`, so from the moment the ESM path moved onto it there are TWO gates that can see the
// same load — and both failure modes are real. Deciding twice is noisy and would double every
// grant `observe` emits; declining twice is a silent bypass. `loader/require.ts` wins, and it
// hands the hook the exact extent of what it decided.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("#152 — the CJS gate and the ESM hook decide each load exactly once, between them", () => {
  it("still gates an out-of-graph import reached through require(esm)", async () => {
    // THE LAUNDERING VECTOR the arbitration creates, and the reason the hook's stand-down test
    // is a conjunction rather than "am I inside a Module._load". `require("./inner.mjs")` pulls
    // the whole ES subgraph in synchronously, so the vault JSON three lines down resolves inside
    // that one `Module._load` — which `loader/require.ts` has already marked. The `require`
    // EXPORT CONDITION is what separates them: measured on 22/24/26, the direct
    // `require("./inner.mjs")` resolves with `["require", …]` and the nested `import` with
    // `["node", "import", …]`.
    const r = await deny(path.join(proj, "app-require-esm.js"));
    expect(r.stdout).toContain("REQESM:inner:OUTER-ERR:CapabilityError");
    expect(r.stdout).not.toContain(SECRET);
    expect(r.stderr).toMatch(/DENY 'evil' fs:read .*secrets\.json/);
  }, 30_000);

  it("records ONE decision for one require, not one per gate", async () => {
    // The other direction, and the one that would have shipped quietly: a duplicate decision is
    // not a security defect, it is an AUDIT defect — two `DENY` lines for one read, two entries
    // in the trace `capwall gen-policy` reads, and a `capwall diff` that reports drift that is
    // not there. Counted rather than matched, because `toMatch` is satisfied by either count.
    const trace = path.join(root, "trace-once.jsonl");
    const r = await runEntry(path.join(proj, "app.js"), {
      CAPWALL_MODE: "observe",
      CAPWALL_TRACE_FILE: trace,
    });
    const recorded = r.stderr
      .split("\n")
      .filter((l) => /observe: recorded fs:read .*[/\\]secrets\.json/.test(l));
    expect(recorded, `one require, ${recorded.length} decisions:\n${recorded.join("\n")}`).toHaveLength(1);
  }, 30_000);

  it("leaves require() of a mediated builtin on the CJS path — the hook does not steal it", async () => {
    // `Module._load` intercepts every mediated builtin before Node's loader is reached, so the
    // ESM hook's `capwall-esm:` rewrite must never be what a `require` gets. If it ever were, the
    // caller would receive an ES module NAMESPACE where it asked for the CJS shim object — a
    // whole-ecosystem break, and one that would not look like a security failure. Asserted by
    // identity against a second `require` of the other spelling, which only holds for the shim.
    const r = await runEntry(path.join(proj, "app-builtin-require.js"), {
      CAPWALL_MODE: "enforce",
      CAPWALL_POLICY_FILE: denyPolicy,
    });
    expect(r.stdout).toContain("BUILTIN:same-object:true");
    expect(r.stdout).toContain("BUILTIN:has-readFileSync:true");
    expect(r.stdout).toContain("BUILTIN:is-namespace:false");
  }, 30_000);
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// GROUND TRUTH (#177, #178, #179, #180) — the gate decides on the filename NODE resolved.
//
// Four CRITICAL/HIGH findings, one root cause. The CJS half used to live inside the
// `Module._load` wrapper and RE-RESOLVE the load from `Module._load`'s own argument list, then
// mark the load "decided" for the dynamic extent of that call. Every input to that was the
// caller's:
//
//   #177  `Module._load(secret, undefined, true)` — `isMain` waived the CJS half and the missing
//         `parent` waived the ESM half. One line, deny-all enforce policy, ZERO decisions.
//   #178  the fourth argument steered capwall's re-resolution to a decoy inside `node_modules`
//         (graph-exempt) while Node opened the real file — three constructions, 22/24/26.
//   #179  the "already decided" mark was a DEPTH COUNTER over a whole `Module._load`, and a
//         module body runs inside one, so the identical call was allowed during module
//         evaluation and denied after it.
//   #180  on the `require()` side of the `resolve` hook, `parentURL` comes from the `parent`
//         record the caller passed — so the caller chose the principal, including `<app>` and
//         including `node_modules/impostor/`, a directory that does not exist.
//
// The gate is now at `Module.prototype.load`, which is handed the filename Node resolved, so
// none of these has an input to steer. These rows run on EVERY supported Node — no feature
// probe, no skip (#176): all four reproduce on 22.22.3 as well as on 24.18.0 and 26.5.0.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("#177 — `isMain` and a missing `parent` are claims, not identities", () => {
  it("denies `Module._load(secret, undefined, true)` and charges the calling package", async () => {
    const r = await deny(path.join(proj, "app-gt-177.js"));
    // The control: the ordinary spelling was always denied. That it and the bypass now agree is
    // the property — it is what made the bypass invisible that they did not.
    expect(r.stdout).toContain("GT:177-baseline:ERR:CapabilityError:evil");
    expect(r.stdout).toContain("GT:177-ismain:ERR:CapabilityError:evil");
    expect(r.stdout).toContain("GT:177-ismain-honest-parent:ERR:CapabilityError:evil");
    expect(r.stdout).not.toContain(SECRET);
  }, 30_000);

  it("gates `new Module(f).load(f)`, which never reaches `Module._load` at all", async () => {
    // Not in the original report, and the reason the chokepoint moved rather than being patched:
    // a gate on `Module._load` cannot see this load even in principle.
    const r = await deny(path.join(proj, "app-gt-177.js"));
    expect(r.stdout).toContain("GT:177-proto-load-direct:ERR:CapabilityError:evil");
  }, 30_000);

  it("records every one of them, so `observe` and `capwall diff` see the reach", async () => {
    // The compounding cost #123 was filed about: a policy generated from a poisoned `observe`
    // run under-reports the package's real reach. Four distinct files, four `DENY` lines.
    const r = await deny(path.join(proj, "app-gt-177.js"));
    for (const target of ["gt-177-baseline", "gt-177-ismain", "gt-177-ismain2", "gt-177-proto"]) {
      expect(r.stderr, `no decision recorded for ${target}`).toContain(`${target}.json`);
    }
  }, 30_000);
});

describe("#178 — Module._load's fourth argument cannot steer the decision", () => {
  /*
   * WHAT IS AND IS NOT VERSION-UNIFORM HERE, because getting this wrong is #176 in the other
   * direction — an assertion that is merely TRUE ON MY MACHINE is as bad as one that skips.
   *
   * The DEFECT is uniform: on 22, 24 and 26, all three constructions handed the vault file's
   * bytes to the caller with zero decisions recorded. So `not.toContain(SECRET)` is the
   * regression signal and it is the same on every supported Node.
   *
   * The OUTCOME is not, and cannot be made so, because Node itself differs: `requireResolveOptions`
   * is honoured from 24.18, so on 24/26 NODE resolves B and C to `node_modules/decoy` and opens a
   * harmless file there, while on 22 Node ignores the field and opens the vault file. Both are
   * correct results for the same rule — *capwall decides about the file Node opened* — and
   * asserting `CapabilityError` for all three would be asserting a Node version, not a property.
   * Construction A is the one that is uniform in outcome as well, and #178 calls it the important
   * one for exactly that reason: no released Node reads `paths` off `_load`'s fourth argument, so
   * A always resolves to the vault and must always be denied.
   */
  it("never hands the caller the vault file, by any of the three constructions", async () => {
    const r = await deny(path.join(proj, "app-gt-178.js"));
    expect(r.stdout).not.toContain(SECRET);
    // Each construction ends in one of exactly two legitimate states: capwall denied the vault
    // read, or Node itself resolved to the graph-exempt decoy and the caller got its harmless
    // contents. What is excluded is the third state, which is what #178 was: the decoy decided
    // and the vault opened.
    for (const t of ["178-a-static-paths", "178-b-getter", "178-c-unwrap"]) {
      expect(r.stdout, `${t} reached neither a denial nor the decoy`).toMatch(
        new RegExp(`GT:${t}:(ERR:CapabilityError:evil|OK:\\{"harmless":true\\})`),
      );
    }
  }, 30_000);

  it("denies the static `paths` construction on EVERY supported Node", async () => {
    // A needs no getter and no version knowledge, and it worked because the fallback branch #157
    // added was forward-compatibility for a Node that does not exist — while on every Node that
    // does, it made the gate decide about a file Node was not opening.
    const r = await deny(path.join(proj, "app-gt-178.js"));
    expect(r.stdout).toContain("GT:178-a-static-paths:ERR:CapabilityError:evil");
    expect(r.stderr).toMatch(/DENY 'evil' fs:read [^\n]*[/\\]vault[/\\]gt-178-a\.json/);
  }, 30_000);

  it("never reads the caller's options bag — there is no second opinion to answer differently", async () => {
    // #178-B was a TOCTOU: capwall read `requireResolveOptions` twice and Node read it a third
    // time, so a getter could hand capwall a decoy and Node the real thing. The durable fix is
    // not to snapshot the bag, it is to have no opinion about it. At most ONE read remains and it
    // is Node's own (24.18+; on 22 Node does not look either, so the count is 0). Pre-fix this was
    // 2 on the floor and 3 on 24/26 — so the bound catches the regression on every version
    // without asserting which one is running.
    const r = await deny(path.join(proj, "app-gt-178.js"));
    const reads = Number(/GT:178-b-reads:(\d+)/.exec(r.stdout)?.[1] ?? NaN);
    expect(
      reads,
      `capwall must not read the caller's options bag (${reads} total reads; >1 means capwall looked)`,
    ).toBeLessThanOrEqual(1);
  }, 30_000);

  it("never records a decision about a file Node did not open", async () => {
    // The half of #178 that is an AUDIT defect rather than a read: capwall's trace named the
    // decoy, so `observe` and `capwall diff` reported a reach that had not happened and missed
    // the one that had. A decoy load is graph-exempt, so a decision naming it is proof the gate
    // decided about a resolution of its own.
    //
    // HONEST ABOUT WHAT THIS ROW IS: unlike the other ten in this section it also passes against
    // the PRE-FIX build, because there the decoy resolution was graph-exempt and therefore
    // recorded nothing at all — the audit defect was the silence, which the row above pins. This
    // is a forward guard: a future gate that reintroduces a second resolution would most likely
    // reintroduce it against a path that IS out of graph, and this is what would fail then.
    const r = await deny(path.join(proj, "app-gt-178.js"));
    expect(r.stderr).not.toMatch(/fs:read [^\n]*decoy/);
  }, 30_000);
});

describe("#179 — the same call decides the same way inside and outside a module body", () => {
  it("denies during module evaluation exactly as it denies after it", async () => {
    // The disarm used to belong to the ENCLOSING load, not the load being decided: `require`ing
    // any module opened a dynamic extent that covered its whole body, which is where a
    // supply-chain payload runs. The two rows below differ ONLY in that.
    const r = await deny(path.join(proj, "app-gt-179.js"));
    expect(r.stdout).toContain("GT:179-during-eval:ERR:CapabilityError:evil");
    expect(r.stdout).toContain("GT:179-after-eval:ERR:CapabilityError:evil");
    expect(r.stdout).not.toContain(SECRET);
  }, 30_000);

  it("records both, not just the one that happened to be outside the extent", async () => {
    const r = await deny(path.join(proj, "app-gt-179.js"));
    expect(r.stderr).toMatch(/DENY 'evil' fs:read [^\n]*gt-179-during\.json/);
    expect(r.stderr).toMatch(/DENY 'evil' fs:read [^\n]*gt-179-after\.json/);
  }, 30_000);
});

describe("#180 — the principal is the stack walk's answer, never the caller's `parent`", () => {
  it("charges the real package for a forged `<app>` and a forged package name alike", async () => {
    const r = await deny(path.join(proj, "app-gt-180.js"));
    // The honest control, and the two forgeries, must be indistinguishable in the OUTCOME and in
    // the SUBJECT. `<app>` is the trust root and short-circuits before `evaluate`, so naming it
    // was an unlogged read; `impostor` names a directory that does not exist, so any name in the
    // policy could be worn instead.
    expect(r.stdout).toContain("GT:180-honest:ERR:CapabilityError:evil");
    expect(r.stdout).toContain("GT:180-forged-app:ERR:CapabilityError:evil");
    expect(r.stdout).toContain("GT:180-forged-impostor:ERR:CapabilityError:evil");
    expect(r.stdout).not.toContain(SECRET);
  }, 30_000);

  it("never records a decision against a principal the caller named", async () => {
    const r = await deny(path.join(proj, "app-gt-180.js"));
    expect(r.stderr).not.toMatch(/DENY 'impostor'/);
    expect(r.stderr).not.toMatch(/DENY '<app>'/);
    expect(r.stderr).toMatch(/DENY 'evil' fs:read [^\n]*gt-180-impostor\.json/);
  }, 30_000);
});

describe("#177 — the process entry point is a HOST fact, and every spelling of it still starts", () => {
  // The gate now runs for the entry point too (it used to be skipped on the caller's word), so
  // "which file is the process root" has to come from somewhere no caller can reach. Two
  // independent sources answer it — `process.argv[1]`, and the `resolve` hook's root resolution
  // — and these are the spellings that separate them: only the second answers the last two.
  it("starts when the entry is spelled with its extension", async () => {
    const r = await deny(path.join(proj, "entry-plain.js"));
    expect(r.stdout).toContain("ENTRY:plain:OK");
    expect(r.stderr).not.toMatch(/DENY/);
  }, 30_000);

  it("starts when the entry is spelled WITHOUT its extension — argv[1] is not the filename", async () => {
    const r = await deny(path.join(proj, "entry-plain"));
    expect(r.stdout).toContain("ENTRY:plain:OK");
    expect(r.stderr).not.toMatch(/DENY/);
  }, 30_000);

  it("starts when the entry is a DIRECTORY resolved through its package.json main", async () => {
    const r = await deny(path.join(proj, "entrydir"));
    expect(r.stdout).toContain("ENTRY:dir-main:OK");
    expect(r.stderr).not.toMatch(/DENY/);
  }, 30_000);
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// OBSERVE. "observe cannot record what it never sees" was half of #123's cost: a generated
// policy under-reported the package's real filesystem reach, on both module systems.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("#123 observe — the reach is now recorded, on both module systems", () => {
  it("never blocks, and records the CJS module read as an ordinary fs:read", async () => {
    const trace = path.join(root, "trace-cjs.jsonl");
    const r = await runEntry(path.join(proj, "app.js"), {
      CAPWALL_MODE: "observe",
      CAPWALL_TRACE_FILE: trace,
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(`CJS:outside-json:OK:{"key":"${SECRET}"}`);
    expect(r.stderr).toMatch(/observe: recorded fs:read .*secrets\.json for 'evil'/);
    // …and the trace is what `capwall gen-policy` turns into a grant, so the round trip closes.
    const traced = (await import("node:fs")).readFileSync(trace, "utf8");
    expect(traced).toMatch(/"pkg":"evil"/);
    expect(traced).toContain("secrets.json");
  }, 30_000);

  it("records the ESM module read too — the resolve hook reports to onDecision", async () => {
    const trace = path.join(root, "trace-esm.jsonl");
    const r = await runEntry(path.join(proj, "app-esm.mjs"), {
      CAPWALL_MODE: "observe",
      CAPWALL_TRACE_FILE: trace,
    });
    expect(r.code).toBe(0);
    expect(r.stderr).toMatch(/observe: recorded fs:read .*payload\.mjs for 'evil'/);
  }, 30_000);
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// THE DECISION FUNCTIONS, in process. Cheap, and they pin the shape of the rule itself rather
// than one of its consequences — including the two carve-outs, which a subprocess test would
// only exercise by accident.
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("#123 the rule itself", () => {
  const PROJECT = path.join(here, "fixtures", "modread-unit");
  const p = (...parts: string[]): string => path.join(PROJECT, ...parts);

  it("needs a decision only for files outside every node_modules tree", () => {
    expect(moduleLoadNeedsDecision(p("config", "secrets.json"), PROJECT)).toBe(true);
    expect(moduleLoadNeedsDecision(path.join(path.sep, "etc", "x.json"), PROJECT)).toBe(true);
    expect(moduleLoadNeedsDecision(p("node_modules", "a", "index.js"), PROJECT)).toBe(false);
    expect(
      moduleLoadNeedsDecision(p("node_modules", "a", "node_modules", "b", "x.json"), PROJECT),
    ).toBe(false);
    expect(moduleLoadNeedsDecision(p("node_modules", "@scope", "a", "index.js"), PROJECT)).toBe(
      false,
    );
  });

  it("is a property of the PATH, not of the declared project root", () => {
    // `packageForPath` answers a similar-looking question RELATIVE TO `projectRoot`: it strips
    // the root before scanning, and since #127 reports `<unknown>` for anything outside it.
    // Either behaviour would turn an installed package's file into "not part of the graph" purely
    // because of how the root was declared, so an ordinary `require("some-dep")` would be gated in
    // exactly the setups where a mis-declared root has already made everything fragile.
    // `test/install-option-parity.test.ts` runs that configuration for real — it roots an install
    // AT its own `node_modules` — and caught this when the derivation went through
    // `packageForPath`.
    // Rooted AT the tree's own `node_modules`, which is what the parity test does. Under
    // `packageForPath` alone this file is `<app>` (the root is stripped before scanning) and the
    // load was denied; the literal-path half is what keeps it in the graph.
    const rootedAtNodeModules = p("node_modules");
    expect(moduleLoadNeedsDecision(p("node_modules", "a", "index.js"), rootedAtNodeModules)).toBe(
      false,
    );
    // …and rooted somewhere else entirely, which is the same mis-declaration seen from the
    // other side.
    expect(moduleLoadNeedsDecision(p("node_modules", "a", "index.js"), path.sep)).toBe(false);
  });

  it("never fires for a builtin name, which is not a path at all", () => {
    expect(moduleLoadNeedsDecision("path", PROJECT)).toBe(false);
    expect(moduleLoadNeedsDecision("node:fs", PROJECT)).toBe(false);
  });

  it("carves out .node, which the `native` gate already covers more strictly (#49)", () => {
    // Charging one addon load to both `native` and `fs.read` would emit two grants from
    // `observe` and change no outcome — `native` already requires BOTH the caller and the
    // addon's owner to hold it, and an addon outside the project owns to `<unknown>`.
    expect(moduleLoadNeedsDecision(p("build", "Release", "x.node"), PROJECT)).toBe(false);
    expect(moduleLoadNeedsDecision(p("build", "Release", "x.NODE"), PROJECT)).toBe(false);
  });

  it("never fires for capwall's own tree", () => {
    // The ESM runtime bridge every synthetic module imports lives there. Gating it would deny
    // the mediated-builtin machinery in any layout where capwall is not itself under a
    // node_modules — this repo's own tests, a linked working copy.
    expect(moduleLoadNeedsDecision(path.join(here, "..", "src", "index.js"), PROJECT)).toBe(false);
  });

  const snapshot = (packages: Record<string, unknown>) => ({
    installed: true,
    policy: parsePolicy({ version: 1, mode: "enforce", default: {}, packages }),
    mode: "enforce" as const,
    projectRoot: PROJECT,
  });

  it("charges an ESM load to the IMPORTING module's package", () => {
    const outcome = decideEsmModuleRead(
      snapshot({}),
      pathToFileURL(p("node_modules", "evil", "index.mjs")).href,
      pathToFileURL(p("config", "secrets.json")).href,
    );
    expect(outcome?.pkg).toBe("evil");
    expect(outcome?.decision.allowed).toBe(false);
  });

  it("charges an importer with no filesystem identity to <unknown>, never to the trust root", () => {
    // #60's rule on this path: a `data:` URL module is exactly the laundering primitive that
    // turned "unattributable" into "ungated" everywhere else in capwall.
    const outcome = decideEsmModuleRead(
      snapshot({}),
      "data:text/javascript,export%20default%201",
      pathToFileURL(p("config", "secrets.json")).href,
    );
    expect(outcome?.pkg).toBe("<unknown>");
    expect(outcome?.decision.allowed).toBe(false);
  });

  it("takes no decision for the process entry point, which has no importer", () => {
    expect(
      decideEsmModuleRead(snapshot({}), undefined, pathToFileURL(p("app.mjs")).href),
    ).toBeNull();
  });

  it("RECORDS that entry point as a host root, which is the CJS half's only way to know", () => {
    // #177's two halves were symmetric claims: `isMain` on one side, "no importer" on the other,
    // both selectable by the caller. The ESM half's version is the one that survives, because on
    // the `import` path `parentURL === undefined` really is the host speaking — so it is not a
    // free pass any more, it is the RECORD the CJS half consults. Nothing else can write it:
    // every resolution a caller can drive through `Module._load` carries the `require` condition
    // and `loader/esm-hooks.ts` declines those before this function is reached.
    forgetHostRootTargets();
    const entry = p("some-entry.mjs");
    expect(isHostRootTarget(entry)).toBe(false);
    decideEsmModuleRead(snapshot({}), undefined, pathToFileURL(entry).href);
    expect(isHostRootTarget(entry)).toBe(true);
    // …and a load WITH an importer records nothing, however out-of-graph it is.
    const notARoot = p("config", "secrets.json");
    decideEsmModuleRead(
      snapshot({}),
      pathToFileURL(p("node_modules", "evil", "index.mjs")).href,
      pathToFileURL(notARoot).href,
    );
    expect(isHostRootTarget(notARoot)).toBe(false);
    forgetHostRootTargets();
  });

  it("only records absolute paths, and stops recording long before the set can grow", () => {
    // A bound, not a policy: a real process records two or three roots. Without one, anything
    // that ever drove a parentless resolution could grow a process-lifetime Set.
    forgetHostRootTargets();
    recordHostRootTarget("relative/not/absolute.js");
    expect(isHostRootTarget("relative/not/absolute.js")).toBe(false);
    for (let i = 0; i < 100; i++) recordHostRootTarget(p(`root-${i}.js`));
    expect(isHostRootTarget(p("root-0.js"))).toBe(true);
    expect(isHostRootTarget(p("root-99.js"))).toBe(false);
    forgetHostRootTargets();
  });

  it("takes no decision for a non-file: target — there are no bytes to read", () => {
    const importer = pathToFileURL(p("node_modules", "evil", "index.mjs")).href;
    expect(decideEsmModuleRead(snapshot({}), importer, "node:fs")).toBeNull();
    expect(decideEsmModuleRead(snapshot({}), importer, "data:text/javascript,1")).toBeNull();
  });

  it("is INERT when no install is active — an unremovable hook must not outlive capwall", () => {
    // Node cannot fully unregister a module-customization hook, so this code survives
    // `uninstall()`. Falling back to the deny-all torn-down policy here would mean "capwall was
    // uninstalled, so the host may no longer import its own files".
    const inert = { ...snapshot({}), installed: false };
    expect(
      decideEsmModuleRead(
        inert,
        pathToFileURL(p("node_modules", "evil", "index.mjs")).href,
        pathToFileURL(p("config", "secrets.json")).href,
      ),
    ).toBeNull();
  });

  it("allows the ESM load when the importing package is granted", () => {
    const outcome = decideEsmModuleRead(
      snapshot({ evil: { fs: { read: [p("config", "**").split(path.sep).join("/")], write: [] } } }),
      pathToFileURL(p("node_modules", "evil", "index.mjs")).href,
      pathToFileURL(p("config", "secrets.json")).href,
    );
    expect(outcome?.decision.allowed).toBe(true);
  });
});
