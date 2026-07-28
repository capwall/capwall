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
 * Subprocess per case: the gate is on the LOADER, decisions are cached per process
 * (`Module._cache`, the ESM registry), and the ESM half lives on Node's loader thread — none of
 * which is isolatable in-process. Requires `pnpm build` (CI does build → test).
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import Module from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { moduleLoadNeedsDecision, decideEsmModuleRead } from "../src/loader/module-read.js";
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
}

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
// The gate has to know which file a load will open, so `loader/require.ts` re-runs
// `Module._resolveFilename` before delegating. It used to do that by forwarding `_load`'s OWN
// argument list verbatim, on the stated reasoning that the two take the same arguments. They do
// not, and Node 24.18 made that observable: `_load`'s fourth argument became an INTERNAL bag
// (`CJSModuleLoadInternalOptions`), and Node unwraps its `requireResolveOptions` field before
// handing it to `_resolveFilename`. capwall passed the bag itself, `_resolveFilename` found no
// `paths` in it, resolution FAILED, and `resolveQuietly` returned `null` — which the gate reads
// as "nothing to decide".
//
// Measured, not reasoned about: on Node 24.18.0 and 26.5.0, before the fix, a dependency reading
// a file outside the project through this form under a DENY-ALL enforce policy got the bytes and
// produced ZERO decisions — no throw, no stderr line, nothing for `observe` or `capwall diff` to
// see. The three-argument spelling of the identical read was denied correctly, which is what kept
// it invisible. Node 22 and earlier reject the form outright, so it never showed there.
//
// These rows assert the PROPERTY that makes that class of defect impossible to reintroduce
// quietly: **the same read by the same package is decided the same way whichever spelling of
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

  it("records the ESM module read too — the loader thread reports back to onDecision", async () => {
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
