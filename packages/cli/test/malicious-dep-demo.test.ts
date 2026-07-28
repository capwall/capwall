/**
 * The DEFINITION-OF-DONE gate for `examples/malicious-dep-demo` (issue #164).
 *
 * AGENTS.md § 6 lists "the `malicious-dep-demo` fixture is blocked in `enforce` mode and
 * allowed (only logged) in `observe` mode" as a condition for a feature being done. It is the
 * artifact that demonstrates the product's central claim and the thing a first-time reader runs
 * to decide whether any of this works. Until this file existed, **nothing mechanical checked it
 * ran at all**: `rm -rf` on the committed `node_modules/sneaky-dep` fixture left `pnpm test`,
 * `pnpm mutation:gate`, `pnpm bench:gate` and `pnpm ci:local` green on all three Node versions.
 * Three separate agents deleted it by accident — the third time was the merge of #173, which is
 * how the tree looked when this test was written.
 *
 * The fixture is COMMITTED, under a `.gitignore` negation, because capwall's attribution only
 * treats it as a dependency if it sits inside a `node_modules/` tree. `pnpm install` does not
 * put it back. That is exactly why its absence has to fail loudly here.
 *
 * WHAT IS ASSERTED, AND WHY EACH LINE CAN FAIL
 *
 * The observable outcome, not the existence of files:
 *
 *   - `enforce`: the env read SOFT-denies (the dependency observes `undefined`, so the fake
 *     value is hidden rather than the process being crashed), the fs read is HARD-denied before
 *     any bytes are read (the file's contents never appear on stdout), both `[capwall] enforce:
 *     DENY 'sneaky-dep' …` lines are printed, and the runner exits non-zero.
 *   - `observe`: nothing is blocked — both values DO appear on stdout — and the generated
 *     starter policy lists exactly the two capabilities the dependency attempted and nothing
 *     else. In particular it holds no `net` grant, which is the mechanical form of AGENTS.md
 *     § 8's "malicious fixtures must stay obviously inert": the socket line is a `console.log`
 *     and would show up as a `net` entry the moment somebody made it real.
 *
 * Note what is deliberately NOT load-bearing on its own: a non-zero exit code. A demo with its
 * fixture deleted ALSO exits non-zero — with `MODULE_NOT_FOUND` — so `expect(code).not.toBe(0)`
 * is an assertion the un-guarded outcome satisfies (AGENTS.md § 7). The DENY lines and the
 * hidden values are what carry the claim.
 *
 * PROVING THE TEST CAN FAIL. The last test runs the demo with the fixture absent and asserts
 * that (a) the enforce assertions above genuinely stop holding, and (b) the failure a developer
 * sees is {@link assertFixturePresent}'s message naming the directory and the command that
 * restores it — not the raw `Error: Cannot find module 'sneaky-dep'` stack, which says nothing
 * about a committed fixture. It runs against a COPY of the demo with the fixture left out
 * rather than moving the real directory aside: `scripts/ci-local.sh` streams its Docker context
 * from the working tree, and a crashed or SIGKILLed run that never reached its `finally` would
 * leave the repository in precisely the state this issue is about.
 *
 * Child budget (#149/#145): one subprocess per test, three tests, well inside
 * `MAX_CHILDREN_PER_TEST`.
 */
import { existsSync } from "node:fs";
import { cp, mkdtemp, readFile, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Policy } from "@capwall/policy-schema";
import { runNode, type NodeRunResult } from "../../core/test/helpers/subprocess.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(here, "..", "dist", "index.js");
const DEMO = path.resolve(here, "..", "..", "..", "examples", "malicious-dep-demo");

/** Every file the demo needs from the committed fixture, relative to the demo root. */
const FIXTURE_FILES = [
  path.join("node_modules", "sneaky-dep", "package.json"),
  path.join("node_modules", "sneaky-dep", "index.js"),
  path.join("node_modules", "sneaky-dep", "fake-secret.txt"),
] as const;

/** The fake credential the fixture's `fake-secret.txt` holds — never read under `enforce`. */
const FIXTURE_SECRET = "this-is-not-a-real-secret";
/** The fake env value the demo runner sets — hidden from the dependency under `enforce`. */
const FIXTURE_ENV_VALUE = "FAKE-not-a-real-secret-fixture-value";

/**
 * Fail with a message that names the fixture and how to get it back.
 *
 * This is the whole difference between a legible failure and an opaque one. Without it the
 * symptom is `Error: Cannot find module 'sneaky-dep'` inside a subprocess stack, in a test whose
 * name mentions `enforce` — which reads as a capwall regression rather than as "a committed
 * fixture was deleted". The `pnpm install` line matters too: this directory is not an installed
 * dependency and reinstalling does nothing.
 */
function assertFixturePresent(root: string): void {
  const missing = FIXTURE_FILES.filter((f) => !existsSync(path.join(root, f)));
  if (missing.length === 0) return;
  throw new Error(
    [
      `examples/malicious-dep-demo is missing its committed fixture: ${missing.join(", ")}`,
      "",
      "`node_modules/sneaky-dep` is VENDORED AND COMMITTED (see the `!examples/malicious-dep-demo/",
      "node_modules/` negation in .gitignore) so capwall's attribution treats it as a dependency",
      "rather than as application code. `pnpm install` will NOT put it back.",
      "",
      "It is the artifact AGENTS.md § 6 names as part of the definition of done — a malicious",
      "dependency blocked in `enforce` and only logged in `observe`. Restore it with:",
      "",
      "    git checkout -- examples/malicious-dep-demo/node_modules",
    ].join("\n"),
  );
}

/**
 * Run the built CLI against a demo tree. `CAPWALL_*` is scrubbed so an ambient variable in the
 * developer's shell cannot change the mode, the policy or the guards under test.
 */
function runDemo(args: string[], cwd: string): Promise<NodeRunResult> {
  return runNode([CLI, ...args], {
    cwd,
    env: {
      CAPWALL_MODE: undefined,
      CAPWALL_POLICY_FILE: undefined,
      CAPWALL_TRACE_FILE: undefined,
      CAPWALL_HARDENED: undefined,
      CAPWALL_ESM: undefined,
      CAPWALL_ENV: undefined,
      CAPWALL_GLOBAL_EGRESS: undefined,
    },
  });
}

/**
 * The `enforce` half of AGENTS.md § 6, as one reusable assertion — reused verbatim by the
 * fixture-removed test, which asserts it THROWS. A claim and its falsification test have to be
 * the same code or the falsification proves nothing about the claim.
 */
function assertBlockedUnderEnforce(r: NodeRunResult): void {
  // Soft deny: the dependency keeps running, but never sees the value.
  expect(r.stderr).toMatch(/\[capwall\] enforce: DENY 'sneaky-dep' env:AWS_SECRET_ACCESS_KEY/);
  expect(r.stdout).toContain("read process.env.AWS_SECRET_ACCESS_KEY => undefined");
  expect(r.stdout).not.toContain(FIXTURE_ENV_VALUE);
  // Hard deny: thrown BEFORE the read, so the file's contents never reach the dependency.
  expect(r.stderr).toMatch(/\[capwall\] enforce: DENY 'sneaky-dep' fs:read .*fake-secret\.txt/);
  expect(r.stdout).not.toContain(FIXTURE_SECRET);
  expect(r.stdout).toContain("[demo] BLOCKED by capwall");
  // Weakest of the assertions on its own — a missing fixture also exits non-zero — but it is the
  // exit code the README documents, so it is checked alongside the ones that carry the claim.
  expect(r.code).not.toBe(0);
}

beforeAll(() => {
  assertFixturePresent(DEMO);
  expect(
    existsSync(CLI),
    `built CLI not found at ${CLI} — run 'pnpm build' before 'pnpm test'`,
  ).toBe(true);
});

let scratch: string | undefined;

afterAll(async () => {
  if (scratch !== undefined) await rm(scratch, { recursive: true, force: true });
});

describe("examples/malicious-dep-demo (AGENTS.md § 6 definition of done, #164)", () => {
  it("enforce blocks the dependency: env soft-denied, fs read denied before any bytes", async () => {
    assertBlockedUnderEnforce(await runDemo(["enforce", "--", "node", "src/index.js"], DEMO));
  });

  it("observe blocks nothing and records exactly the capabilities the dependency attempted", async () => {
    scratch ??= await mkdtemp(path.join(os.tmpdir(), "capwall-malicious-demo-"));
    // Never the demo's own default output path: that would overwrite the committed
    // deny-everything `capabilities.json` the enforce test runs against.
    const out = path.join(scratch, "observed.json");
    const r = await runDemo(["observe", "-o", out, "--", "node", "src/index.js"], DEMO);

    expect(r.stderr).not.toMatch(/DENY/);
    expect(r.stderr).toMatch(/observe: recorded env:AWS_SECRET_ACCESS_KEY for 'sneaky-dep'/);
    expect(r.stderr).toMatch(/observe: recorded fs:read .*fake-secret\.txt for 'sneaky-dep'/);
    // Nothing blocked means both values reach the dependency, which is the whole contrast.
    expect(r.stdout).toContain(`read process.env.AWS_SECRET_ACCESS_KEY => "${FIXTURE_ENV_VALUE}"`);
    expect(r.stdout).toContain(`read its fake credentials file: "${FIXTURE_SECRET}"`);
    expect(r.code).toBe(0);

    const policy = JSON.parse(await readFile(out, "utf8")) as Policy;
    // EXACTLY the capabilities it attempted: one principal, two grants, nothing inferred.
    expect(Object.keys(policy.packages)).toEqual(["sneaky-dep"]);
    const grant = policy.packages["sneaky-dep"];
    expect(grant?.env).toEqual(["AWS_SECRET_ACCESS_KEY"]);
    expect(grant?.fs?.read).toEqual(["./node_modules/sneaky-dep/fake-secret.txt"]);
    expect(grant?.fs?.write).toEqual([]);
    // AGENTS.md § 8, mechanically: the "would open TCP socket" line is a console.log. If anyone
    // ever made it real, observe would record a `net` grant here and this would go red.
    expect(grant?.net).toBeUndefined();
    expect(grant?.child_process).toBeUndefined();
  });

  it("fails — legibly — when the committed fixture is gone", async () => {
    scratch ??= await mkdtemp(path.join(os.tmpdir(), "capwall-malicious-demo-"));
    const stripped = path.join(scratch, "demo-without-fixture");
    // A copy WITHOUT `node_modules`, which is what an over-eager `rm -rf` leaves behind.
    await cp(DEMO, stripped, {
      recursive: true,
      filter: (src) => path.basename(src) !== "node_modules",
    });

    // (a) The guard turns the absence into a message that says what is missing and how to fix it.
    expect(() => assertFixturePresent(stripped)).toThrow(
      /git checkout -- examples\/malicious-dep-demo\/node_modules/,
    );
    expect(() => assertFixturePresent(stripped)).toThrow(/VENDORED AND COMMITTED/);

    // (b) …and the enforce claim genuinely stops holding, using the SAME assertion the passing
    // test uses. Without this the first test could be green for any reason at all.
    const r = await runDemo(["enforce", "--", "node", "src/index.js"], stripped);
    expect(() => assertBlockedUnderEnforce(r)).toThrow();
    expect(r.stderr).not.toMatch(/DENY 'sneaky-dep'/);
    // The opaque symptom the guard exists to replace — asserted so the contrast is not a claim.
    expect(r.stderr).toContain("Cannot find module 'sneaky-dep'");
    expect(r.code).not.toBe(0);
  });
});
