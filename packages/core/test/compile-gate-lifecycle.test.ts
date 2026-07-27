/**
 * `Module.prototype._compile` gate lifecycle (issue #93, meeting #87's nested installs).
 *
 * THE HAZARD THIS PINS. The other install-time guards — `process.dlopen` (loader/native.ts) and
 * `process.env` (shims/env.ts) — let nested installs STACK: each patch wraps the previous one and
 * they all forward. The `_compile` gate must not, and the reason is specific to how it tells
 * Node's own module loading apart from a user's call. It asks who called it, one frame up:
 *
 *   Node loader -> P2 -> P1 -> real            (two installs, P2 patched second)
 *
 * P2 looks up and sees `node:internal/modules/…` — correct, not gated. P1 then looks up and sees
 * *P2's frame*, which lives in capwall's own tree, so P1 concludes a user called `_compile` and
 * gates it. A second `install()` would turn every `require` in the process into a denied
 * `compile` capability. Since #87 every guard reads the live context — one box whose fields the
 * install stack re-points — so one patch already tracks whichever install is in force, and the
 * reference count only decides when to put the real method back.
 *
 * Nothing else in the suite nests an install AND compiles a module inside the nested window, so
 * without this file the failure would have surfaced in someone's application instead.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const CORE_DIST = createRequire(import.meta.url).resolve("../dist/index.js");

let tmpDir: string;

/**
 * Run `source` in a subprocess with capwall's BUILT core available, printing `ok` on success.
 *
 * A subprocess rather than an in-process `install()` because the gate patches a process-global
 * (`Module.prototype`) and the assertion is about that global's state — a leaked patch would
 * otherwise contaminate every later test file in the same worker.
 */
async function runScript(
  source: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  // A fresh directory per run: each script builds its own `node_modules` fixture tree, and the
  // second test asserts on a module CACHE miss, which a shared cwd would quietly turn into a hit.
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

/**
 * Preamble: the built core, a deny-all policy, and a two-package fixture tree.
 *
 * `requireFresh()` deliberately does NOT run from this script. It runs inside
 * `node_modules/loader-dep`, requiring a brand-new file inside `node_modules/other-dep`, and
 * that detail is what makes the first test discriminate. `guardCompile` waves through two cases
 * before consulting the policy — the caller is `<app>` (the trust root), and the caller is
 * compiling under its OWN principal — so a compile issued by the test script, or by a package
 * into its own directory, is allowed no matter how badly the loader discriminator misbehaves. A
 * dependency requiring a file that belongs to a DIFFERENT package is the only shape where a
 * wrongly-gated `require` actually fails, and it is also the ordinary shape of every transitive
 * require in a real tree.
 */
function preamble(): string {
  return `
import { install, loadPolicyFromObject } from ${JSON.stringify(pathToFileURL(CORE_DIST).href)};
import { createRequire } from "node:module";
import * as fs from "node:fs";
import * as path from "node:path";

const root = process.cwd();
const loaderDir = path.join(root, "node_modules", "loader-dep");
const otherDir = path.join(root, "node_modules", "other-dep");
fs.mkdirSync(loaderDir, { recursive: true });
fs.mkdirSync(otherDir, { recursive: true });
fs.writeFileSync(path.join(loaderDir, "package.json"), '{"name":"loader-dep","main":"index.cjs"}');
fs.writeFileSync(path.join(otherDir, "package.json"), '{"name":"other-dep"}');
// loader-dep's own code issues the require, so attribution charges it — not \`<app>\`.
fs.writeFileSync(path.join(loaderDir, "index.cjs"), \`
  let n = 0;
  module.exports = function requireFresh(files) { return require(files[n++]); };
\`);
// Pre-create every module the run will require, BEFORE capwall installs. Writing them lazily
// from inside \`loader-dep\` would trip the fs gate first and never reach the compile at all.
const files = [];
for (let i = 0; i < 8; i++) {
  const file = path.join(otherDir, "mod" + i + ".cjs");
  fs.writeFileSync(file, "module.exports = 42;");
  files.push(file);
}
const require_ = createRequire(path.join(root, "harness.cjs"));
const requireFresh = () => require_("loader-dep")(files);

// Deny-all: \`loader-dep\` holds nothing, so if the gate ever mistakes Node's own loading for a
// user call, this require is denied and the script exits non-zero.
const policy = loadPolicyFromObject({ version: 1, mode: "enforce", packages: {} });
const OPTS = { projectRoot: root, globalEgress: false, env: false };
`;
}

beforeAll(async () => {
  expect(
    existsSync(CORE_DIST),
    `built core not found — run 'pnpm build' before 'pnpm test'`,
  ).toBe(true);
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-compile-gate-"));
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

describe("#93 — the compile gate installs exactly once, however many installs nest", () => {
  it("does not gate Node's own module loading while TWO installs are active", async () => {
    // The regression. With a stacking patch the inner one sees capwall's own frame as its
    // caller, decides a user called `_compile`, and denies an ordinary `require` under a
    // deny-all policy — every module load in the process.
    //
    // The single-install case is asserted FIRST, in the same run: it is the control that says
    // the require is legal in the first place, so a failure in the nested case can only be the
    // nesting.
    const r = await runScript(`${preamble()}
const solo = install(policy, "enforce", OPTS);
if (requireFresh() !== 42) throw new Error("control: one install already gates require()");
solo.uninstall();

const a = install(policy, "enforce", OPTS);
const b = install(policy, "enforce", OPTS);
if (requireFresh() !== 42) throw new Error("wrong value");
b.uninstall();
if (requireFresh() !== 42) throw new Error("wrong value after inner uninstall");
a.uninstall();
console.log("ok");
`);
    expect(r.stderr).not.toMatch(/DENY .* compile /);
    expect(r.stdout).toContain("ok");
    expect(r.code).toBe(0);
  });

  it("restores the real _compile only when the LAST install goes", async () => {
    // Reference counting, observed from outside: the prototype method must be capwall's while
    // any install is active and the original once none is. Compared by identity against the
    // method captured before the first install.
    const r = await runScript(`${preamble()}
import Module from "node:module";
const original = Module.prototype._compile;
const a = install(policy, "enforce", OPTS);
const b = install(policy, "enforce", OPTS);
if (Module.prototype._compile === original) throw new Error("gate did not install");
b.uninstall();
if (Module.prototype._compile === original) throw new Error("inner uninstall dropped the gate");
a.uninstall();
if (Module.prototype._compile !== original) throw new Error("last uninstall did not restore");
console.log("ok");
`);
    expect(r.stdout).toContain("ok");
    expect(r.code).toBe(0);
  });

  it("re-installs cleanly after a full teardown", async () => {
    // install → uninstall → install must gate again. A refcount that under- or over-counted
    // would leave the second install ungated (silent) or double-patched (the hazard above).
    const r = await runScript(`${preamble()}
import Module from "node:module";
const original = Module.prototype._compile;
install(policy, "enforce", OPTS).uninstall();
const again = install(policy, "enforce", OPTS);
if (Module.prototype._compile === original) throw new Error("second install did not gate");
if (requireFresh() !== 42) throw new Error("ordinary require broke on re-install");
again.uninstall();
if (Module.prototype._compile !== original) throw new Error("did not restore after re-install");
console.log("ok");
`);
    expect(r.stdout).toContain("ok");
    expect(r.code).toBe(0);
  });
});
