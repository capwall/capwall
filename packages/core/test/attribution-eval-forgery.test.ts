/**
 * Regression tests for issue #84 — attribution forgery through V8's `getEvalOrigin()`.
 *
 * THE BUG. `evalOriginPath()` trusted `getEvalOrigin()` whenever the string began with the
 * literal `"eval at "`, reasoning that a `//# sourceURL=` could not forge that prefix because a
 * `sourceURL` may not contain whitespace. The whitespace half is true; the conclusion was not.
 * For a NESTED eval, V8 synthesizes the `eval at <fn> (…)` wrapper itself, around the outer
 * script's name — and the outer script's name is exactly what its own `sourceURL` set. Append
 * `:1:1` to the sourceURL (still no whitespace anywhere) and the string V8 produces is
 * character-for-character a genuine depth-1 origin whose path the attacker chose:
 *
 *   "eval at <anonymous> (/proj/node_modules/forge-target/index.cjs:1:1)"
 *
 * A dependency with ZERO grants thereby ran with any granted package's capabilities — or with
 * `<app>`'s, the trust root, whose `process.env` reads are exempted *before* the decision is
 * recorded, so the exfiltration produced no log line at all and was invisible to `observe` and
 * `capwall diff` as well.
 *
 * THE FIX. `getEvalOrigin()` is no longer consulted. An `eval`/`new Function` frame has no
 * filesystem identity, so it is opaque — the same treatment `data:` modules already get — and
 * the walk continues to the nearest frame that has a real file name. See the SECURITY block on
 * `frameSource` in `src/attribution/index.ts` for why no stricter parse of the origin string
 * can work.
 *
 * These run the built `dist/preload.js` in a subprocess (`pnpm build` first — CI does build →
 * test), because the vectors depend on real CJS loading and real timer detachment.
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
const APP_DIR = path.join(here, "fixtures", "eval-forge");
const APP = path.join(APP_DIR, "app.cjs");
const PRELOAD = createRequire(import.meta.url).resolve("../dist/preload.js");
const SECRET_VALUE = "forge-fixture-placeholder-not-a-real-secret";
const SECRET_FILE = path.join(APP_DIR, "secret.txt");

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** `forge-dep` has NO entry at all, so every grant it appears to hold has been forged. */
let policyFile: string;
let tmpDir: string;

function runVector(vector: string): Promise<RunResult> {
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
  // "no log line at all" was half the finding — both denials must be on the record, and
  // recorded against the REAL principal rather than the one the forgery named.
  expect(r.stderr).toContain(`DENY '${pkg}' env:FORGE_FIXTURE_SECRET`);
  expect(r.stderr).toContain(`DENY '${pkg}' fs:read ${SECRET_FILE}`);
}

beforeAll(async () => {
  expect(
    existsSync(PRELOAD),
    `built preload not found at ${PRELOAD} — run 'pnpm build' before 'pnpm test'`,
  ).toBe(true);
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-eval-forge-"));
  policyFile = path.join(tmpDir, "capabilities.json");
  await writeFile(
    policyFile,
    JSON.stringify({
      version: 1,
      mode: "enforce",
      default: {},
      packages: {
        // The IMPERSONATION TARGET, and the only package with any grant. `forge-dep` has none.
        "forge-target": { env: ["FORGE_FIXTURE_SECRET"], fs: { read: ["./**"] } },
      },
    }),
  );
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

describe("#84 — a dependency cannot forge its identity through getEvalOrigin()", () => {
  it("charges the dependency, not the package it names, for the issue's PoC", async () => {
    // The PoC verbatim: nested eval, `//# sourceURL=<real path of a granted package>:1:1`.
    // Before the fix BOTH capabilities succeeded with no log line whatsoever.
    expectDenied(await runVector("forge-pkg"), "forge-dep");
  });

  it("cannot name <app>, the trust root, either", async () => {
    // The nastier half. `<app>` is exempt from the env gate *before* `evaluate()`/`onDecision()`
    // run, so a successful forgery here reads any env var with no decision recorded at all —
    // ungated AND invisible to `observe` and `capwall diff`. It needs no granted package in the
    // policy, so no policy is too tight to stop it.
    const r = await runVector("forge-app");
    expectDenied(r, "forge-dep");
    expect(r.stderr).not.toContain("DENY '<app>'");
  });

  it("is not a matter of nesting depth", async () => {
    // Three levels. The innermost parenthesised group is attacker-chosen at every depth, and a
    // forged depth-2 origin is indistinguishable from a genuine depth-1 one, so no "count the
    // `eval at ` tokens" or "take the outermost match" parse separates them.
    expectDenied(await runVector("forge-deep"), "forge-dep");
  });

  it("cannot name a granted package through a unicode look-alike path", async () => {
    // `forge\u2011target` (non-breaking hyphen) renders as `forge-target`. Two properties: the
    // forgery itself does not work, and — the reason this is worth its own case — a look-alike
    // is NOT normalized onto the granted name anywhere on the policy-lookup path, so it could
    // not have inherited `forge-target`'s grants even if some other route produced it.
    expectDenied(await runVector("forge-unicode"), "forge-dep");
  });

  it("cannot name a granted package through a Windows-style path", async () => {
    // `C:\…\node_modules\forge-target\index.cjs`. On POSIX `packageForPath` splits on `path.sep`,
    // so a backslash path has no `/node_modules/` segment and would resolve to `<app>` — the
    // trust root — rather than to nothing at all. Unreachable via the eval origin either way.
    expectDenied(await runVector("forge-winpath"), "forge-dep");
  });

  it("cannot name a granted package through mixed path separators", async () => {
    // Absolute on POSIX, but the package segment spelled with a backslash: this one forged
    // `<app>` before the fix, by the same accident — the backslash hides the `node_modules`
    // segment, and "not under node_modules" means the application.
    expectDenied(await runVector("forge-mixedsep"), "forge-dep");
  });

  it("cannot choose its own frame's filename through vm, having no vm grant", async () => {
    // `vm.runInNewContext(code, { filename })` sets `getFileName()` directly — a forgery route
    // that never touches `getEvalOrigin()`. It is closed one layer earlier: `vm` is a gated
    // capability and `forge-dep` holds no grant, so nothing is compiled. (WITH a `vm` grant it
    // does work; that is the residual `docs/threat-model.md` names, and it is a grant the
    // operator made deliberately.)
    const r = await runVector("forge-vm");
    expect(r.stdout).toContain("env=undefined");
    expect(r.stdout).toContain("fs=VMDENIED:forge-dep");
    expect(r.stdout).not.toContain(SECRET_VALUE);
    expect(r.stderr).toContain("DENY 'forge-dep' vm");
  });

  it("charges the dependency by name when it calls honestly (control)", async () => {
    expectDenied(await runVector("honest"), "forge-dep");
  });
});

/**
 * The chosen semantics, pinned. Making eval frames opaque is a behavior change for legitimate
 * users of `eval`/`new Function`, and the shape of that change is the whole cost of the fix, so
 * it is asserted rather than left to drift.
 */
describe("#84 — what legitimate eval'd code attributes to now", () => {
  it("still charges a dependency's own synchronous eval to that dependency BY NAME", async () => {
    // The common benign case — a template engine, `ajv`, anything that compiles and immediately
    // runs its own code. The dependency's own frame sits directly beneath the eval frames, so
    // the walk finds it and #60's benefit is kept in full: no loss of precision, and no push
    // toward granting `<unknown>` (a grant shared with every unattributable caller, including
    // an attacker's).
    expectDenied(await runVector("dep-eval-sync"), "forge-dep");
  });

  it("charges DETACHED eval'd code to <unknown>, not to the compiling dependency", async () => {
    // This is what the fix costs. `eval("setTimeout(payload)")` leaves no real frame on the
    // stack when the payload runs, and the origin string that used to supply the name is no
    // longer trustworthy. #60's fail-CLOSED half survives — this is `<unknown>`, an ordinary
    // deny-by-default principal, never `<app>` — but #60's by-name precision does not.
    expectDenied(await runVector("dep-eval-detached"), "<unknown>");
  });

  it("charges the application's own eval to <unknown>, not <app>", async () => {
    // The other half of the cost, and deliberate. `<app>` is the trust root and carries
    // exemptions, so it may only be claimed when nothing without a filesystem identity ran
    // above it — otherwise a dependency that gets the app to `eval` a string it supplied
    // inherits the app's authority. Fails closed; grantable as `"<unknown>"` if a real
    // application genuinely evals its own code and needs it.
    const r = await runVector("app-eval");
    expectDenied(r, "<unknown>");
    expect(r.stderr).not.toContain("DENY '<app>'");
  });

  it("leaves ordinary application code alone", async () => {
    // No eval anywhere: still `<app>`, still exempt from the env gate with no policy entry.
    const r = await runVector("app-plain");
    expect(r.stdout).toContain(`env=${SECRET_VALUE}`);
    expect(r.stdout).toContain("fs=DENIED:<app>");
    expect(r.stderr).not.toContain("DENY '<unknown>' env:FORGE_FIXTURE_SECRET");
    expect(r.code).toBe(0);
  });
});
