/**
 * Regression tests for issues #92 and #93 — the two halves of one root cause: **package
 * identity was inferred from a path string and never verified.**
 *
 * #92, A VENDORED DIRECTORY. `packageForPath` read the package name from the LAST
 * `node_modules/<name>` segment, so `node_modules/evil/node_modules/lodash/x.js` was flatly
 * `lodash`. A dependency that ships a directory named after a granted package inside its own
 * tree — `bundledDependencies` puts one in a published tarball, and a git/tarball dependency is
 * unrestricted — ran with that package's grants. No `eval`, no `vm`, no `fs` write, nothing
 * self-reported: ordinary frames, a real file.
 *
 * #93, A CHOSEN FILENAME. `Module.prototype._compile(source, filename)` compiles code under a
 * caller-chosen filename, and V8 reports it as `getFileName()` on every resulting frame.
 * `isEval()` is false, there is no eval origin, and the path need not exist. `node:module` was
 * mediated, but only `register`/`registerHooks` (#61) were guarded; compilation and the `Module`
 * class itself passed straight through.
 *
 * THE FIXES ARE DIFFERENT IN SHAPE, and this file keeps them apart on purpose.
 *
 *   #93 is closed. A direct `_compile` under a filename that is not the caller's own is a gated
 *   capability (`compile`), recognized apart from Node's own loader calls.
 *
 *   #92 is closed AS AN IMPERSONATION, not as a verification. The identity is now the whole
 *   install chain — `evil>lodash`, a principal distinct from `lodash` — so a vendored directory
 *   grants nothing. capwall still does not know whether `node_modules/lodash` is really lodash.
 *   The tests below assert the first and deliberately do not claim the second.
 *
 * The compatibility cost is real and is pinned here too: a LEGITIMATE nested version conflict
 * (`legit-host/node_modules/legit-nested@2` alongside the hoisted `legit-nested@1`) is now a
 * separate principal and needs its own policy key. Its fixture layout is byte-identical to the
 * attack's, which is exactly why capwall cannot separate them and does not pretend to.
 *
 * These run the built `dist/preload.js` in a subprocess (`pnpm build` first — CI does build →
 * test), because the vectors depend on real CJS loading.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const APP_DIR = path.join(here, "fixtures", "pkg-identity");
const APP = path.join(APP_DIR, "app.cjs");
const PRELOAD = createRequire(import.meta.url).resolve("../dist/preload.js");
const SECRET_VALUE = "forge-fixture-placeholder-not-a-real-secret";
const SECRET_FILE = path.join(APP_DIR, "secret.txt");

/** The full read of the fixture tree, as a reusable grant body. */
const FULL_GRANT = { env: ["FORGE_FIXTURE_SECRET"], fs: { read: ["./**"] } } as const;

/**
 * The baseline policy. `forge-dep` has NO entry at all, so every capability it appears to hold
 * in a vector below has been obtained by making capwall read a name out of a path.
 */
const BASE_PACKAGES: Record<string, unknown> = {
  "forge-target": FULL_GRANT,
  "legit-nested": FULL_GRANT,
  "legit-host>legit-nested": FULL_GRANT,
  "transform-dep": { fs: { read: ["./**"] }, compile: true },
};

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

let tmpDir: string;
let policySeq = 0;

/** Write a one-off policy file and run `vector` against it under enforce. */
async function runVector(
  vector: string,
  packages: Record<string, unknown> = BASE_PACKAGES,
): Promise<RunResult> {
  const policyFile = path.join(tmpDir, `capabilities-${policySeq++}.json`);
  await writeFile(
    policyFile,
    JSON.stringify({ version: 1, mode: "enforce", default: {}, packages }),
  );
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      [`--import=${pathToFileURL(PRELOAD).href}`, APP, vector],
      {
        cwd: APP_DIR,
        env: {
          ...process.env,
          CAPWALL_MODE: "enforce",
          CAPWALL_POLICY_FILE: policyFile,
          CAPWALL_PROJECT_ROOT: APP_DIR,
          FORGE_FIXTURE_SECRET: SECRET_VALUE,
        },
      },
      (err, stdout, stderr) => {
        if (err && typeof err.code !== "number") return reject(err);
        resolve({ code: err ? (err.code as number) : 0, stdout, stderr });
      },
    );
  });
}

/** Assert the vector obtained NEITHER capability, and that both denials were recorded. */
function expectDenied(r: RunResult, pkg: string): void {
  // The env read is soft (the value is hidden, the caller is not crashed) …
  expect(r.stdout).toContain("env=undefined");
  // … and the file read throws `CapabilityError`, which the fixture reports by principal.
  expect(r.stdout).toContain(`fs=DENIED:${pkg}`);
  // Neither secret may appear anywhere in the output.
  expect(r.stdout).not.toContain(SECRET_VALUE);
  // "no log line at all" was half of both findings — both denials must be on the record, and
  // recorded against the REAL principal rather than the one the path named.
  expect(r.stderr).toContain(`DENY '${pkg}' env:FORGE_FIXTURE_SECRET`);
  expect(r.stderr).toContain(`DENY '${pkg}' fs:read ${SECRET_FILE}`);
}

/** Assert the vector got BOTH capabilities — the shape of a working legitimate use. */
function expectAllowed(r: RunResult): void {
  expect(r.stdout).toContain(`env=${SECRET_VALUE}`);
  expect(r.stdout).toContain(`fs=${SECRET_VALUE}`);
  expect(r.stdout).toContain("done");
}

beforeAll(async () => {
  expect(
    existsSync(PRELOAD),
    `built preload not found at ${PRELOAD} — run 'pnpm build' before 'pnpm test'`,
  ).toBe(true);
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-pkg-identity-"));
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

describe("#92 — a vendored node_modules/<granted-pkg>/ directory impersonates nothing", () => {
  it("charges the issue's PoC to the install chain, not to the name it vendored", async () => {
    // Before the fix this printed the secret twice with NO log line whatsoever: attribution
    // read `forge-target` out of `…/forge-dep/node_modules/forge-target/vendored.cjs`.
    expectDenied(await runVector("vendored"), "forge-dep>forge-target");
  });

  it("does not let a vendored `.pnpm` directory launder the chain back to a bare name", async () => {
    // The virtual-store skip is the one segment the derivation ignores, so it is the one that
    // could become a forgery primitive by rename. It applies to the first link only.
    expectDenied(await runVector("vendored-pnpm"), "forge-dep>.pnpm>forge-target");
  });

  it("charges the dependency by name when it calls honestly (control)", async () => {
    // Discriminates nothing on its own — it is here so a future change that broke ordinary
    // attribution could not pass this file by denying everything.
    expectDenied(await runVector("honest"), "forge-dep");
  });
});

describe("#92 — what it costs a LEGITIMATE nested install", () => {
  it("keeps a genuine nested version conflict working under its chain key", async () => {
    // `legit-host` needs `legit-nested@2` while the project uses `legit-nested@1`, so npm
    // installs a real second copy. This is the case the fix must not break, and the fixture
    // layout is byte-for-byte the attack's.
    expectAllowed(await runVector("legit-nested"));
  });

  it("keeps the top-level copy of the same package working under its bare key", async () => {
    expectAllowed(await runVector("legit-toplevel"));
  });

  it("does NOT let a bare key reach the nested copy — the compatibility cost, stated", async () => {
    // THE COST, pinned rather than described. `"legit-nested": {…}` covers the top-level
    // install only. An author who means "the library wherever npm put it" writes both keys.
    const onlyBare = { "legit-nested": FULL_GRANT };
    expectDenied(await runVector("legit-nested", onlyBare), "legit-host>legit-nested");
    expectAllowed(await runVector("legit-toplevel", onlyBare));
  });

  it("grants a nested install through the explicit `*>name` / `**>name` keys", async () => {
    // The documented widening, in the same one-vs-many spelling `net.hosts` uses. It is
    // deliberately not implicit: writing it says "any package in the tree may ship a directory
    // called legit-nested and receive these grants", which is true, and is the #92 hole
    // re-opened for that one name by choice.
    //
    // `legit-host>legit-nested` is one level deep, so BOTH forms cover it.
    for (const key of ["*>legit-nested", "**>legit-nested"]) {
      const wildcard = { [key]: FULL_GRANT };
      expectAllowed(await runVector("legit-nested", wildcard));
      // And neither reaches the top-level install, which has no chain to widen.
      expectDenied(await runVector("legit-toplevel", wildcard), "legit-nested");
    }
  });
});

describe("#93 — Module.prototype._compile cannot choose a frame's package", () => {
  /** Assert the compile itself was refused, and refused against the REAL caller. */
  function expectCompileDenied(r: RunResult, pkg: string): void {
    expect(r.stdout).toContain("env=undefined");
    expect(r.stdout).toContain(`fs=COMPILEDENIED:${pkg}`);
    expect(r.stdout).not.toContain(SECRET_VALUE);
    expect(r.stderr).toContain(`DENY '${pkg}' compile `);
  }

  it("refuses the issue's PoC — a dep naming a granted package's real installed file", async () => {
    // Before the fix both capabilities succeeded, with no log line, against a `forge-dep` that
    // holds no grant of any kind.
    expectCompileDenied(await runVector("compile"), "forge-dep");
  });

  it("refuses a dep naming <app>, the trust root", async () => {
    // The worse half: `<app>`'s `process.env` reads are exempted BEFORE the decision is
    // recorded, so this forgery was invisible to `observe` and `capwall diff` as well.
    expectCompileDenied(await runVector("compile-app"), "forge-dep");
  });

  it("refuses a filename that does not exist — nothing ever reads the path", async () => {
    expectCompileDenied(await runVector("compile-ghost"), "forge-dep");
  });

  it("cannot bootstrap past the gate by compiling under a `node:` name first", async () => {
    // The gate recognizes Node's loader by its caller frame's `node:internal/modules/…` file
    // name. Manufacturing such a frame requires passing the gate first, and a non-absolute
    // filename is never the caller's own package, so the first hop is denied. The gate's
    // safety rests on this, so it is pinned rather than argued.
    expectCompileDenied(await runVector("compile-nodename"), "forge-dep");
  });

  it("still lets a package compile source under its OWN name, with no grant at all", async () => {
    // The legitimate self-compilation case — a template engine, `require-from-string`, a
    // package materializing generated source. It gains no identity it did not have, so it is
    // not gated; the capability calls it then makes are charged to it exactly as usual.
    const r = await runVector("compile-self");
    expect(r.stderr).not.toContain("compile ");
    expectDenied(r, "forge-dep");
  });
});

describe("#93 — what gating _compile costs real tooling", () => {
  it("lets a require.extensions transform hook compile app source WITH a compile grant", async () => {
    // `transform-dep` is the shape of every real `_compile` caller: `ts-node`, `tsx`'s CJS
    // half, `@babel/register`, `@swc/register`, `pirates` (and thus `nyc`), and
    // `require-in-the-middle` (and thus `dd-trace`). All of them compile ANOTHER package's or
    // the app's file by design, so a blanket deny would break them and the gate has to be a
    // grant rather than a refusal.
    const r = await runVector("transform");
    expect(r.code).toBe(0);
    // The compiled file is app source, so the code it runs attributes to `<app>` exactly as it
    // would have if the file had been plain `.js`. That is the property a transform tool needs:
    // instrumenting a module must not relabel it as the instrumenter.
    expect(r.stdout).toContain(`env=${SECRET_VALUE}`);
    expect(r.stderr).toContain(`DENY '<app>' fs:read ${SECRET_FILE}`);
    expect(r.stdout).toContain("fs=DENIED:<app>");
  });

  it("refuses the same hook WITHOUT a compile grant, naming the tool", async () => {
    // The escape hatch is the policy, not an env var: `observe` records this and
    // `capwall gen-policy` writes `"transform-dep": { "compile": true }`.
    const r = await runVector("transform", { "transform-dep": { fs: { read: ["./**"] } } });
    expect(r.stderr).toContain("DENY 'transform-dep' compile ");
    expect(r.stdout).not.toContain(SECRET_VALUE);
  });

  it("makes a `compile` grant identity-granting, exactly as the docs say", async () => {
    // NOT a bug — the documented consequence, pinned so the claim in `policy-format.md` §
    // `compile` and in `threat-model.md` cannot drift away from the behaviour. Given the grant,
    // `forge-dep` DOES execute as `forge-target` and collects its env and fs grants. That is
    // why the docs say granting `compile` grants every other grant in the file, and why the
    // generated line must be reviewed rather than kept.
    const r = await runVector("compile", {
      ...BASE_PACKAGES,
      "forge-dep": { compile: true },
    });
    expect(r.stdout).toContain(`env=${SECRET_VALUE}`);
    expect(r.stdout).toContain(`fs=${SECRET_VALUE}`);
    // And the capability calls that follow are charged to the package it named, with no denial
    // anywhere — which is what "identity-granting" means concretely.
    expect(r.stderr).not.toContain("DENY 'forge-dep'");
    // The compile decision itself IS reported to `onDecision`, so `observe` prints it and
    // `capwall diff`/`gen-policy` see it (pinned in the CLI round-trip). Enforce-mode stderr
    // only prints DENIALS, so an allowed compile is silent there — worth knowing before
    // relying on the log to notice one.
  });

  it("never gates Node's own loading of an ordinary module", async () => {
    // Node calls `_compile` once per CJS module it loads. If those were gated, `require` would
    // be a capability and nothing would start. `app-plain` loads five fixture packages.
    const r = await runVector("app-plain");
    expect(r.code).toBe(0);
    expect(r.stderr).not.toContain("compile ");
    expect(r.stdout).toContain("done");
  });
});
