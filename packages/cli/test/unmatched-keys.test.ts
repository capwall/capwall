/**
 * Issue #118 — a `packages` key that matches no principal is no longer silent.
 *
 * The mistake is not exotic: the name in `package.json` is `nested-dep`, but the principal for
 * a nested install is the chain `trace-dep>nested-dep` (#92). Writing the name you know
 * produces a policy that loads without a murmur, grants nothing, and then — the part that made
 * this worth an issue — `explain nested-dep …` answers ALLOW, confirming the belief that caused
 * the denial. The author has to already know the answer to ask the question that reveals it.
 *
 * Load-time validation cannot close this (whether a key matches is a runtime fact, and a key
 * legitimately matches nothing on a path a given run does not take), so the report happens
 * where the evidence is: after a run, in `observe` and `diff`, against the principals seen.
 * It is a WARNING — a dead key fails closed, and `--strict` is the opt-in for CI.
 *
 * Runs against the BUILT cli + core (dist/) — `pnpm build` first, as CI does.
 */
import { existsSync } from "node:fs";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { runNode, type NodeRunResult } from "../../core/test/helpers/subprocess.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(here, "..", "dist", "index.js");
const FIXTURE_APP = path.join(here, "fixtures", "app");

function runCli(args: string[], cwd: string): Promise<NodeRunResult> {
  return runNode([CLI, ...args], { cwd });
}

let appDir: string;

beforeAll(() => {
  expect(
    existsSync(CLI),
    `built CLI not found at ${CLI} — run 'pnpm build' before 'pnpm test'`,
  ).toBe(true);
});

afterEach(async () => {
  if (appDir) await rm(path.dirname(appDir), { recursive: true, force: true });
});

async function freshAppDir(): Promise<string> {
  const dir = path.join(await mkdtemp(path.join(os.tmpdir(), "capwall-unmatched-")), "app");
  await cp(FIXTURE_APP, dir, { recursive: true });
  // The entrypoint: the NESTED install reads its own file, so the only principal that shows up
  // for that read is the chain `trace-dep>nested-dep`.
  await writeFile(path.join(dir, "nested.js"), `console.log(require("trace-dep").readNested());\n`);
  return dir;
}

/** Write a policy granting the nested read under `key` — correct or mistaken. */
async function writePolicy(dir: string, packages: Record<string, unknown>): Promise<void> {
  await writeFile(
    path.join(dir, "capabilities.json"),
    JSON.stringify({ version: 1, mode: "enforce", default: {}, packages }, null, 2),
  );
}

const NESTED_READ = {
  fs: { read: ["./node_modules/trace-dep/node_modules/nested-dep/nested.txt"], write: [] },
};

describe("capwall diff — a policy key that matched nothing (#118)", () => {
  it("names the dead key and suggests the principal the author meant", async () => {
    appDir = await freshAppDir();
    // The mistake, exactly as an author makes it: the bare name from package.json.
    await writePolicy(appDir, { "nested-dep": NESTED_READ });

    const r = await runCli(["diff", "--", "node", "nested.js"], appDir);

    // The denial is still reported as drift — this changes no verdict…
    expect(r.stderr).toContain("DRIFT");
    expect(r.stderr).toContain("trace-dep>nested-dep");
    // …but the reader is no longer sent to look at the dependency for a problem that is in
    // their own key.
    expect(r.stderr).toContain(`"nested-dep" — did you mean "trace-dep>nested-dep"?`);
    expect(r.code).toBe(1);
  }, 60_000);

  it("says nothing when every key matched", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, { "trace-dep>nested-dep": NESTED_READ });

    const r = await runCli(["diff", "--", "node", "nested.js"], appDir);
    expect(r.stderr).toContain("no drift");
    expect(r.stderr).not.toContain("matched no package");
    expect(r.code).toBe(0);
  }, 60_000);

  it("is non-gating by default and gating under --strict", async () => {
    appDir = await freshAppDir();
    // A correct grant plus one key for a dependency this run never loaded: no drift at all,
    // so the exit code is the only thing the dead key can affect.
    await writePolicy(appDir, {
      "trace-dep>nested-dep": NESTED_READ,
      "long-gone-dep": { vm: true },
    });

    const lax = await runCli(["diff", "--", "node", "nested.js"], appDir);
    expect(lax.stderr).toContain("no drift");
    expect(lax.stderr).toContain(`"long-gone-dep"`);
    expect(lax.code).toBe(0);

    const strict = await runCli(["diff", "--strict", "--", "node", "nested.js"], appDir);
    expect(strict.code).toBe(1);
  }, 60_000);
});

describe("capwall observe — the same report, at the moment the policy is written (#118)", () => {
  it("warns about a pre-existing key the run proved dead, and not about what it just wrote", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, { "nested-dep": NESTED_READ });

    const r = await runCli(["observe", "--", "node", "nested.js"], appDir);
    expect(r.code).toBe(0);
    // observe merges what it saw, so the chain key is now in the file…
    const merged = JSON.parse(
      await readFile(path.join(appDir, "capabilities.json"), "utf8"),
    ) as { packages: Record<string, unknown> };
    expect(Object.keys(merged.packages)).toContain("trace-dep>nested-dep");
    // …and the hand-written key that matched nothing is called out, once, with the fix.
    expect(r.stderr).toContain(`"nested-dep" — did you mean "trace-dep>nested-dep"?`);
    expect(r.stderr).not.toContain(`"trace-dep>nested-dep" —`);
  }, 60_000);
});

describe("capwall explain — no longer confirms the wrong belief (#118)", () => {
  it("answers the literal question but says it cannot vouch for the principal existing", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, { "nested-dep": NESTED_READ });

    const r = await runCli(
      [
        "explain",
        "nested-dep",
        "fs:read",
        "./node_modules/trace-dep/node_modules/nested-dep/nested.txt",
      ],
      appDir,
    );
    // The verdict and the exit code are unchanged — this is a note, not a new answer.
    expect(r.stdout).toMatch(/^ALLOW:/);
    expect(r.code).toBe(0);
    expect(r.stderr).toContain("cannot know whether any code actually runs as 'nested-dep'");
    expect(r.stderr).toContain("TOP-LEVEL install only");
  }, 30_000);

  it("lists the keys that DO exist when the principal has no entry", async () => {
    appDir = await freshAppDir();
    await writePolicy(appDir, { "nested-dep": NESTED_READ });

    const r = await runCli(
      [
        "explain",
        "trace-dep>nested-dep",
        "fs:read",
        "./node_modules/trace-dep/node_modules/nested-dep/nested.txt",
      ],
      appDir,
    );
    expect(r.stdout).toMatch(/^DENY:/);
    expect(r.code).toBe(1);
    // The one line that breaks the loop: the author sees their own `nested-dep` in the list.
    expect(r.stderr).toContain(`no "trace-dep>nested-dep" key`);
    expect(r.stderr).toContain("keys in this policy: nested-dep");
  }, 30_000);
});
