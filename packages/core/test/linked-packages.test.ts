/**
 * LINKED AND WORKSPACE DEPENDENCIES — issue #127.
 *
 * Node resolves module paths through `realpath`, so a dependency installed as a SYMLINK into
 * `node_modules` reports a file path with no `node_modules` segment in it. capwall derived the
 * principal from those segments, so such a package was `<app>` — the trust root, which the
 * `process.env`, `dgram` and loader-hook gates exempt *before* the decision is recorded, and whose
 * `_compile` exemption is identity-granting. It needed no attacker action and no grant: it is the
 * default on-disk shape of `npm i file:…`, of `npm link`, and of every workspace tool.
 *
 * ── WHY THESE LAYOUTS ARE THE REAL ONES ─────────────────────────────────────────────────────
 * The trees below are built with `fs.symlinkSync` rather than by shelling out to a package
 * manager — a test that runs `npm install` is a test that can fail because of a registry, a proxy
 * or a cache, and this suite runs in Docker on two Node versions. What it does NOT do is invent a
 * shape: each `linkLayout` below reproduces, link for link, what the real tools produce. Recorded
 * from actual runs of npm 10 and pnpm 10 while investigating #127:
 *
 *   npm i file:../filedep   fileproj/node_modules/filedep            -> ../../filedep
 *   npm link                linkproj/node_modules/linkme             -> ../../linkme
 *                           (with a global prefix in play, via <global>/lib/node_modules/linkme)
 *   npm workspaces          npmws/node_modules/@nws/lib              -> ../../packages/lib
 *   pnpm workspaces         pnpmws/packages/app/node_modules/@ws/lib -> ../../../lib
 *
 * The last two differ in the way that matters: **npm hoists the workspace link to the repo root,
 * pnpm puts it in the importing package's own `node_modules`.** That is why capwall observes the
 * link at resolution time (`loader/linked-packages.ts`) instead of scanning a directory at
 * startup — under pnpm there is no directory it could scan.
 *
 * Everything runs in a SUBPROCESS against the built `dist`, through the real preload, because the
 * behaviour under test is Node's own resolution: an in-process `install()` cannot make vitest's
 * transformed module graph resolve through a symlink the way `require` does.
 */
import { mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { APP_ROOT, UNATTRIBUTED, packageForPath } from "../src/attribution/index.js";
import { assertPreloadBuilt, runPreloaded, type NodeRunResult } from "./helpers/subprocess.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const ATTRIBUTION = createRequire(import.meta.url).resolve("../dist/attribution/index.js");

let tmpDir: string;

beforeAll(async () => {
  assertPreloadBuilt();
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-linked-"));
});
afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

/* ── fixture construction ─────────────────────────────────────────────────────────────────── */

function write(file: string, content: string): void {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, content);
}

/**
 * A package whose CJS and ESM entry points both report the principal capwall gives them.
 *
 * The attribution call is made FROM the package's own file on purpose: capwall's policy is
 * nearest-package, so a shared helper doing the call would (correctly) be charged instead.
 */
function makePackage(dir: string, name: string, label: string): void {
  write(path.join(dir, "package.json"), JSON.stringify({ name, version: "1.0.0", main: "index.js" }));
  const report = (kind: string): string =>
    `console.log(${JSON.stringify(`${label} (${kind}) ->`)}, attributeCaller({ projectRoot: process.env.CAPWALL_PROJECT_ROOT }));`;
  write(
    path.join(dir, "index.js"),
    `const { attributeCaller } = require(${JSON.stringify(ATTRIBUTION)});\n` +
      `module.exports = { run: () => { ${report("cjs")} } };\n`,
  );
  write(
    path.join(dir, "esm.mjs"),
    `import { createRequire } from "node:module";\n` +
      `const { attributeCaller } = createRequire(import.meta.url)(${JSON.stringify(ATTRIBUTION)});\n` +
      `export const run = () => { ${report("esm")} };\n`,
  );
}

/** A deny-all policy — nothing here is about a grant. */
function writePolicy(dir: string): void {
  write(path.join(dir, "capabilities.json"), JSON.stringify({ version: 1, mode: "enforce", packages: {} }));
}

/** `entry` is `.cjs` or `.mjs`; the layout decides which spelling reaches the package. */
function runUnderCapwall(projectRoot: string, entry: string): Promise<NodeRunResult> {
  return runPreloaded([entry], {
    cwd: projectRoot,
    env: {
      CAPWALL_MODE: "enforce",
      CAPWALL_POLICY_FILE: path.join(projectRoot, "capabilities.json"),
      CAPWALL_PROJECT_ROOT: projectRoot,
    },
  });
}

/** The principal a probe line reported, e.g. `lib (cjs) -> @w/lib`. */
function principal(stdout: string, label: string, kind: "cjs" | "esm"): string {
  const line = stdout.split("\n").find((l) => l.startsWith(`${label} (${kind}) ->`));
  expect(line, `no probe output for ${label} (${kind}) in:\n${stdout}`).toBeTruthy();
  return (line as string).slice(`${label} (${kind}) ->`.length).trim();
}

let layoutCounter = 0;
/** A fresh root for one layout, so no two fixtures can resolve into each other. */
function newRoot(name: string): string {
  const root = path.join(tmpDir, `${name}-${layoutCounter++}`);
  mkdirSync(root, { recursive: true });
  return root;
}

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * The four layouts, each in the shape its package manager really produces.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("#127 — a symlinked node_modules entry is its package, not <app>", () => {
  it("npm i file:../filedep — the dependency is `filedep`, and every gate applies to it", async () => {
    // The reported PoC, verbatim in shape. Before #127 this package read all 84 environment
    // variables, minted an arbitrary principal through `_compile`, and installed a loader hook
    // ahead of capwall's, under this exact deny-all policy, with no `[capwall]` line for any of it.
    const root = newRoot("file");
    const proj = path.join(root, "fileproj");
    makePackage(path.join(root, "filedep"), "filedep", "filedep");
    writePolicy(proj);
    write(path.join(proj, "package.json"), JSON.stringify({ name: "fileproj", version: "1.0.0" }));
    mkdirSync(path.join(proj, "node_modules"), { recursive: true });
    symlinkSync(path.join(root, "filedep"), path.join(proj, "node_modules", "filedep"));

    // The gate probe lives in the dependency, so what it exercises is the dependency's authority.
    write(
      path.join(root, "filedep", "gates.js"),
      `const Module = require("node:module");
module.exports = function () {
  console.log("env ->", process.env["AWS_SECRET_ACCESS_KEY"]);
  try {
    new Module("x", null)._compile("module.exports = 1;", process.cwd() + "/node_modules/trusted/f.js");
    console.log("compile -> ALLOWED");
  } catch { console.log("compile -> DENIED"); }
  // Both registration entry points are gated (shims/module.ts § GUARDED_APIS). \`registerHooks\`
  // is Node >= 22.15, which is exactly the supported floor, so it is present on every leg of the
  // matrix; the fallback is kept because this fixture probes the runtime rather than trusting a
  // version table, and \`register\` is gated too.
  try {
    if (typeof Module.registerHooks === "function") Module.registerHooks({ resolve: (s, c, n) => n(s, c) });
    else Module.register("data:text/javascript,");
    console.log("loaderHook -> ALLOWED");
  } catch { console.log("loaderHook -> DENIED"); }
};
`,
    );
    write(
      path.join(proj, "main.cjs"),
      `require("filedep").run(); require("filedep/gates.js")();\n`,
    );
    write(path.join(proj, "main.mjs"), `(await import("filedep/esm.mjs")).run();\n`);

    const cjs = await runUnderCapwall(proj, path.join(proj, "main.cjs"));
    expect(principal(cjs.stdout, "filedep", "cjs")).toBe("filedep");
    // The half that actually matters: `<app>`'s exemptions are gone, and the decisions are LOGGED.
    expect(cjs.stdout).toContain("env -> undefined");
    expect(cjs.stdout).toContain("compile -> DENIED");
    expect(cjs.stdout).toContain("loaderHook -> DENIED");
    expect(cjs.stderr).toContain("DENY 'filedep' env:AWS_SECRET_ACCESS_KEY");
    expect(cjs.stderr).toContain("DENY 'filedep' compile");
    expect(cjs.stderr).toMatch(/DENY 'filedep' module\.(register|registerHooks)\(\)/);

    const esm = await runUnderCapwall(proj, path.join(proj, "main.mjs"));
    expect(principal(esm.stdout, "filedep", "esm")).toBe("filedep");
  });

  it("npm link — a two-hop link through a global prefix still names the package", async () => {
    // `npm link` interposes the global root: proj/node_modules/x -> <global>/lib/node_modules/x
    // -> the working copy. `realpath` collapses both hops at once, so the frame path is the
    // working copy and nothing in it says `node_modules` at all.
    const root = newRoot("link");
    const src = path.join(root, "linkme");
    const globalNm = path.join(root, "global", "lib", "node_modules");
    const proj = path.join(root, "linkproj");
    makePackage(src, "linkme", "linkme");
    mkdirSync(globalNm, { recursive: true });
    symlinkSync(src, path.join(globalNm, "linkme"));
    writePolicy(proj);
    mkdirSync(path.join(proj, "node_modules"), { recursive: true });
    symlinkSync(path.join(globalNm, "linkme"), path.join(proj, "node_modules", "linkme"));
    write(path.join(proj, "main.cjs"), `require("linkme").run();\n`);
    write(path.join(proj, "main.mjs"), `(await import("linkme/esm.mjs")).run();\n`);

    expect(principal((await runUnderCapwall(proj, path.join(proj, "main.cjs"))).stdout, "linkme", "cjs")).toBe("linkme");
    expect(principal((await runUnderCapwall(proj, path.join(proj, "main.mjs"))).stdout, "linkme", "esm")).toBe("linkme");
  });

  it("npm workspaces — the root-hoisted link names the workspace member", async () => {
    // npm hoists every workspace package into the repo root's `node_modules`.
    const root = newRoot("npmws");
    const repo = path.join(root, "repo");
    makePackage(path.join(repo, "packages", "lib"), "@nws/lib", "lib");
    write(path.join(repo, "package.json"), JSON.stringify({ name: "repo", private: true }));
    mkdirSync(path.join(repo, "node_modules", "@nws"), { recursive: true });
    symlinkSync(path.join(repo, "packages", "lib"), path.join(repo, "node_modules", "@nws", "lib"));
    writePolicy(repo);
    write(path.join(repo, "packages", "app", "package.json"), JSON.stringify({ name: "@nws/app" }));
    write(path.join(repo, "packages", "app", "main.cjs"), `require("@nws/lib").run();\n`);

    const r = await runUnderCapwall(repo, path.join(repo, "packages", "app", "main.cjs"));
    expect(principal(r.stdout, "lib", "cjs")).toBe("@nws/lib");
  });

  it("pnpm workspaces — the link in the IMPORTING package's node_modules is found too", async () => {
    // pnpm's shape, and the reason the mechanism observes resolution rather than scanning: the
    // link lives under `packages/app`, so nothing under the repo root would have revealed it.
    // Project root is `packages/app`, which is what `pnpm --filter app <script>` produces.
    const root = newRoot("pnpmws");
    const repo = path.join(root, "repo");
    const app = path.join(repo, "packages", "app");
    makePackage(path.join(repo, "packages", "lib"), "@ws/lib", "lib");
    write(path.join(app, "package.json"), JSON.stringify({ name: "@ws/app" }));
    mkdirSync(path.join(app, "node_modules", "@ws"), { recursive: true });
    symlinkSync(path.join(repo, "packages", "lib"), path.join(app, "node_modules", "@ws", "lib"));
    writePolicy(app);
    write(path.join(app, "main.cjs"), `require("@ws/lib").run();\n`);
    write(path.join(app, "main.mjs"), `(await import("@ws/lib/esm.mjs")).run();\n`);

    expect(principal((await runUnderCapwall(app, path.join(app, "main.cjs"))).stdout, "lib", "cjs")).toBe("@ws/lib");
    // ESM too: capwall's `resolve` hook does not write the map (see link-map.ts § discovery), so
    // this one is recovered by `link-map.ts`'s verified discovery rather than observed.
    expect(principal((await runUnderCapwall(app, path.join(app, "main.mjs"))).stdout, "lib", "esm")).toBe("@ws/lib");
  });

  it("a workspace package reached THROUGH another is a chain principal, not the top-level install", async () => {
    // The pnpm shape one level deeper: app -> lib -> util, each link in the importer's own
    // `node_modules`. Rewriting is iterative, so `util` composes onto `lib` exactly as an ordinary
    // nested install does (#92) — `@ws/util` reached through `@ws/lib` is `@ws/lib>@ws/util`, a
    // principal distinct from a top-level `@ws/util` and holding none of its grants.
    const root = newRoot("chain");
    const repo = path.join(root, "repo");
    const app = path.join(repo, "packages", "app");
    const lib = path.join(repo, "packages", "lib");
    makePackage(path.join(repo, "packages", "util"), "@ws/util", "util");
    write(path.join(lib, "package.json"), JSON.stringify({ name: "@ws/lib", main: "index.js" }));
    write(path.join(lib, "index.js"), `module.exports = { run: () => require("@ws/util").run() };\n`);
    mkdirSync(path.join(lib, "node_modules", "@ws"), { recursive: true });
    symlinkSync(path.join(repo, "packages", "util"), path.join(lib, "node_modules", "@ws", "util"));
    write(path.join(app, "package.json"), JSON.stringify({ name: "@ws/app" }));
    mkdirSync(path.join(app, "node_modules", "@ws"), { recursive: true });
    symlinkSync(lib, path.join(app, "node_modules", "@ws", "lib"));
    writePolicy(app);
    write(path.join(app, "main.cjs"), `require("@ws/lib").run();\n`);

    const r = await runUnderCapwall(app, path.join(app, "main.cjs"));
    expect(principal(r.stdout, "util", "cjs")).toBe("@ws/lib>@ws/util");
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * The other half: `<app>` must stay a POSITIVE identification (#60), and must not be the
 * fallback for a file capwall cannot place.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("#127 — <app> stays positive, and out-of-project code fails closed", () => {
  it("the application's own entry is still <app>, even in a workspace repo", async () => {
    // The regression this fix must not cause. `packages/app` is the project root's own package
    // here; it is not reached through any `node_modules` entry, so it is the application.
    const root = newRoot("appself");
    const app = path.join(root, "app");
    writePolicy(app);
    write(path.join(app, "package.json"), JSON.stringify({ name: "the-app" }));
    write(
      path.join(app, "main.cjs"),
      `const { attributeCaller } = require(${JSON.stringify(ATTRIBUTION)});\n` +
        `console.log("app (cjs) ->", attributeCaller({ projectRoot: process.env.CAPWALL_PROJECT_ROOT }));\n`,
    );
    const r = await runUnderCapwall(app, path.join(app, "main.cjs"));
    expect(principal(r.stdout, "app", "cjs")).toBe(APP_ROOT);
  });

  it("packageForPath: a file outside the project and under no node_modules is <unknown>", () => {
    // Being outside the project is not evidence of being the project. Before #127 this returned
    // `<app>`, the trust root — which is exactly how a `file:` dependency inherited the app's
    // authority. `loader/native.ts` has made this move for `.node` files since #49.
    expect(packageForPath("/elsewhere/vendor/lib/index.js", "/proj")).toBe(UNATTRIBUTED);
    expect(packageForPath("/proj/src/server.js", "/proj")).toBe(APP_ROOT);
  });

  it("packageForPath: with no project root configured, the pre-#127 answer stands", () => {
    // There is nothing to judge "inside the project" against. Reachable only through the public
    // export and in tests — `install()` always defaults `projectRoot` to `process.cwd()`.
    expect(packageForPath("/elsewhere/vendor/lib/index.js")).toBe(APP_ROOT);
  });

  it("packageForPath: a path that merely SHARES A PREFIX with the root is not inside it", () => {
    // `/proj-backup` must not pass a `startsWith("/proj")` test.
    expect(packageForPath("/proj-backup/src/a.js", "/proj")).toBe(UNATTRIBUTED);
  });

  it("this test file, under its own project root, is still <app>", () => {
    // A real source file rather than a constructed string — the same assertion attribution.test.ts
    // makes, repeated here because the out-of-project rule is the thing most likely to break it.
    expect(packageForPath(fileURLToPath(import.meta.url), here)).toBe(APP_ROOT);
  });
});
