/**
 * Tests for the process.env read shim (roadmap M4, issue #8): the anti-exfiltration control.
 *
 * install() replaces process.env with a read-gating Proxy. A dependency (attributed to
 * "fixture-dep") reading a non-granted env key is denied in enforce / logged in observe;
 * reads attributed to <app> pass through ungated by design.
 *
 * Since #60 that exemption requires a POSITIVELY identified application frame. A read the
 * walk cannot attribute at all is `<unknown>` and is gated like any dependency — see the two
 * `<unknown>` cases below, and `attribution-laundering.test.ts` for the end-to-end vectors.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  install,
  loadPolicyFromObject,
  UNATTRIBUTED,
  type Decision,
  type Policy,
} from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");

interface FixtureDep {
  readEnv(key: string): string | undefined;
}

function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

type Recorded = { pkg: string; decision: Decision };

/** Install with env gating, run fn, always uninstall (restore process.env). */
function withCapwall<T>(
  policy: Policy,
  mode: "observe" | "enforce",
  fn: (dep: FixtureDep) => T,
): { result: T; decisions: Recorded[] } {
  const decisions: Recorded[] = [];
  const handle = install(policy, mode, {
    projectRoot: here,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
  });
  try {
    return { result: fn(loadFixtureFresh()), decisions };
  } finally {
    handle.uninstall();
  }
}

/** Like `withCapwall`, but keeps the install up across awaits (the #60 cases need timers). */
async function withCapwallAsync<T>(
  policy: Policy,
  mode: "observe" | "enforce",
  fn: () => Promise<T>,
): Promise<{ result: T; decisions: Recorded[] }> {
  const decisions: Recorded[] = [];
  const handle = install(policy, mode, {
    projectRoot: here,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
  });
  try {
    return { result: await fn(), decisions };
  } finally {
    handle.uninstall();
  }
}

/**
 * Read `key` from a stack with NO caller frame — the #60 shape. `Object.assign` is a native
 * reader (it leaves no JS frame of its own) and is handed straight to `setTimeout`, so when
 * the env proxy's `get` trap fires, every frame on the stack is a Node internal.
 */
async function unattributedRead(key: string): Promise<unknown> {
  const stash: Record<string, unknown> = {};
  // NOT `setTimeout(() => Object.assign(...))` — that arrow would be a frame in THIS file, and
  // the walk would attribute the read to the app. Passing the native function itself, with its
  // arguments, is the whole point: the timer invokes it with nothing of ours on the stack.
  setTimeout(Object.assign, 0, stash, process.env);
  await sleep(5);
  return stash[key];
}

const SECRET = "FIXTURE_SECRET_XYZ";
process.env[SECRET] = "s3cr3t";
process.env["FIXTURE_OK"] = "fine";

afterEach(() => {
  // Guard: process.env must be restored to the real object after each test.
  expect(typeof process.env[SECRET]).toBe("string");
});

const enforce = (env: string[] = []): Policy =>
  loadPolicyFromObject(
    { version: 1, mode: "enforce", packages: { "fixture-dep": { env } } },
    { projectRoot: here },
  );

describe("env shim — enforce (soft deny: hide value, never throw)", () => {
  it("hides an env key a dependency was not granted (returns undefined, no throw)", () => {
    const { decisions } = withCapwall(enforce([]), "enforce", (dep) => {
      expect(dep.readEnv(SECRET)).toBeUndefined();
    });
    const rec = decisions.find((d) => d.pkg === "fixture-dep");
    expect(rec?.decision.allowed).toBe(false); // the denial is still recorded/logged
  });

  it("allows a granted key and hides a different one", () => {
    const { decisions } = withCapwall(enforce(["FIXTURE_OK"]), "enforce", (dep) => {
      expect(dep.readEnv("FIXTURE_OK")).toBe("fine");
      expect(dep.readEnv(SECRET)).toBeUndefined();
    });
    expect(decisions.some((d) => d.decision.allowed)).toBe(true);
    expect(decisions.some((d) => !d.decision.allowed)).toBe(true);
  });

  it("honors the '*' wildcard grant", () => {
    withCapwall(enforce(["*"]), "enforce", (dep) => {
      expect(dep.readEnv(SECRET)).toBe("s3cr3t");
    });
  });

  it("does NOT gate app reads (attributed to <app>)", () => {
    // Deny-by-default policy, but a read from THIS test file attributes to <app>.
    withCapwall(enforce([]), "enforce", () => {
      expect(process.env[SECRET]).toBe("s3cr3t"); // not gated, not thrown
    });
  });

  it("DOES gate an unattributable read, and records it (#60)", async () => {
    // `Object.assign` copies the env from a NATIVE frame; handed straight to a timer, there
    // is no caller frame on the stack at all. That used to attribute to `<app>` and be
    // exempted here — a two-line path around the anti-exfiltration control, needing no
    // `data:` URL and no `eval`. It is now `<unknown>`: evaluated, recorded, soft-denied.
    const { result, decisions } = await withCapwallAsync(enforce([]), "enforce", () =>
      unattributedRead(SECRET),
    );
    expect(result).toBeUndefined(); // soft deny — value hidden
    const rec = decisions.find(
      (d) => d.pkg === UNATTRIBUTED && d.decision.observed.kind === "env",
    );
    expect(rec?.decision.allowed).toBe(false);
  });

  it("allows an unattributable read when the policy grants <unknown> (escape hatch)", async () => {
    // The documented escape hatch: legitimate path-less frames exist, so `<unknown>` is
    // grantable — explicitly, in capabilities.json, never by silent exemption. (The example
    // that used to be here, Node's ESM loader reading WATCH_REPORT_DEPENDENCIES, is no longer
    // one: a read Node itself initiated is not recorded since #119. See env-node-origin.test.ts.)
    const policy = loadPolicyFromObject(
      { version: 1, mode: "enforce", packages: { [UNATTRIBUTED]: { env: ["*"] } } },
      { projectRoot: here },
    );
    const { result } = await withCapwallAsync(policy, "enforce", () => unattributedRead(SECRET));
    expect(result).toBe("s3cr3t");
  });

  it("closes the getOwnPropertyDescriptor(...).value exfiltration path", () => {
    withCapwall(enforce([]), "enforce", (dep) => {
      const dep2 = dep as unknown as { readEnvDescriptor(k: string): PropertyDescriptor | undefined };
      const desc = dep2.readEnvDescriptor(SECRET);
      expect(desc?.value).toBeUndefined(); // value hidden, not leaked
    });
  });

  it("never gates or records CAPWALL_* plumbing keys", () => {
    process.env["CAPWALL_FAKE_PLUMBING"] = "internal";
    const { decisions } = withCapwall(enforce([]), "enforce", (dep) => {
      expect(dep.readEnv("CAPWALL_FAKE_PLUMBING")).toBe("internal"); // passed through
    });
    expect(decisions.some((d) => d.decision.observed.kind === "env")).toBe(false);
    delete process.env["CAPWALL_FAKE_PLUMBING"];
  });
});

describe("env shim — observe never blocks", () => {
  it("allows the read but records the attributed env request", () => {
    const { result, decisions } = withCapwall(enforce([]), "observe", (dep) =>
      dep.readEnv(SECRET),
    );
    expect(result).toBe("s3cr3t");
    const rec = decisions.find((d) => d.pkg === "fixture-dep");
    expect(rec?.decision.observed).toMatchObject({ kind: "env", key: SECRET });
  });
});

describe("env shim — uninstall restores process.env", () => {
  it("after uninstall, a dependency read is no longer gated", () => {
    withCapwall(enforce([]), "enforce", () => undefined);
    const dep = loadFixtureFresh();
    expect(dep.readEnv(SECRET)).toBe("s3cr3t"); // would throw if proxy still installed
  });
});

/* ------------------------------------------------------------------------------------------- */
/* CAPWALL_ENV — the preload channel for `install({ env: false })` (#125).                       */

/**
 * `env` was the ONE install option with no environment-variable channel: `projectRoot`, `esm`,
 * `globalEgress`, `hardened` and `attribution.maxFrames` all had one, so the escape hatch
 * `install()` documents was unreachable from the CLI. #125 asked whether that was deliberate —
 * "an env-var switch for the anti-exfiltration control hands an attacker a one-line disable" —
 * and it is not: the whole configuration channel is the environment, so anyone who can set
 * `CAPWALL_ENV` already has `CAPWALL_MODE=observe`, a substituted `CAPWALL_POLICY_FILE`, or
 * dropping the `--import` altogether, each strictly more powerful. It was an omission.
 *
 * Runs against the built `dist/preload.js` in a subprocess, because that IS the channel under
 * test. The probe reads through the dependency: `<app>` is exempt from the env gate either way.
 */
const PRELOAD = requireCjs.resolve("../dist/preload.js");
const ENV_APP = path.join(here, "fixtures", "env-preload-app.cjs");

interface PreloadRun {
  code: number;
  stdout: string;
  stderr: string;
}

function runPreload(env: Record<string, string>): Promise<PreloadRun> {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      [ENV_APP, SECRET],
      {
        cwd: path.join(here, "fixtures"),
        env: {
          ...process.env,
          NODE_OPTIONS: `--import ${pathToFileURL(PRELOAD).href}`,
          CAPWALL_PROJECT_ROOT: path.join(here, "fixtures"),
          [SECRET]: "s3cr3t",
          ...env,
        },
      },
      (err, stdout, stderr) => {
        if (err && typeof err.code !== "number") return reject(err);
        resolve({ code: err ? (err.code as number) : 0, stdout, stderr });
      },
    );
  });
}

describe("#125 — CAPWALL_ENV is the preload channel for env: false", () => {
  let tmpDir: string;
  let denyPolicy: string;

  beforeAll(async () => {
    expect(existsSync(PRELOAD), `built preload not found at ${PRELOAD} — run 'pnpm build'`).toBe(true);
    tmpDir = await mkdtemp(path.join(os.tmpdir(), "capwall-env-preload-"));
    denyPolicy = path.join(tmpDir, "deny.json");
    await writeFile(denyPolicy, JSON.stringify({ version: 1, mode: "enforce", packages: {} }));
  });
  afterAll(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it("gates a dependency's read by default, exactly as before", async () => {
    const r = await runPreload({ CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy });
    expect(r.stdout).toContain("ENV:undefined");
    expect(r.stderr).toContain(`DENY 'fixture-dep' env:${SECRET}`);
  });

  it("CAPWALL_ENV=0 leaves process.env un-proxied — the read succeeds and is not recorded", async () => {
    const r = await runPreload({
      CAPWALL_MODE: "enforce",
      CAPWALL_POLICY_FILE: denyPolicy,
      CAPWALL_ENV: "0",
    });
    expect(r.stdout).toContain("ENV:s3cr3t");
    expect(r.stderr).not.toContain(`env:${SECRET}`);
  });

  it("warns loudly when it is set, because the process still looks enforced", async () => {
    // The reason this switch warns and `CAPWALL_GLOBAL_EGRESS=0` does not: turning the env guard
    // off makes every `env` grant in the policy decorative and records nothing, while `enforce`
    // keeps printing DENY lines for the other capabilities. Silence there is the "looks guarded,
    // isn't" shape.
    const off = await runPreload({
      CAPWALL_MODE: "enforce",
      CAPWALL_POLICY_FILE: denyPolicy,
      CAPWALL_ENV: "0",
    });
    expect(off.stderr).toContain("CAPWALL_ENV=0");
    const on = await runPreload({ CAPWALL_MODE: "enforce", CAPWALL_POLICY_FILE: denyPolicy });
    expect(on.stderr).not.toContain("CAPWALL_ENV=0");
  });

  it("only the exact value '0' disables it — any other value leaves the guard on", async () => {
    // Same contract as CAPWALL_ESM / CAPWALL_GLOBAL_EGRESS: a typo must not silently disarm the
    // anti-exfiltration control, so the comparison is `!== "0"` rather than a truthiness test.
    for (const value of ["", "false", "off", "1"]) {
      const r = await runPreload({
        CAPWALL_MODE: "enforce",
        CAPWALL_POLICY_FILE: denyPolicy,
        CAPWALL_ENV: value,
      });
      expect(r.stdout, `CAPWALL_ENV=${JSON.stringify(value)} must not disable the guard`).toContain(
        "ENV:undefined",
      );
    }
  });
});
