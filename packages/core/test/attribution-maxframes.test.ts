/**
 * Configurable attribution frame budget (issue #15).
 *
 * capwall attributes a mediated call to the nearest package frame it can find, walking at most
 * `maxFrames` frames. When the owning dependency's frame sits deeper than that budget — deep
 * promise chains, dynamically-compiled wrappers, async_hooks-heavy frameworks — the walk runs
 * out of frames and cannot find the owner. Before #60 that fell back to `<app>`, the trust
 * root, which usually holds broad grants — a wrongly-ALLOW. It now falls back to `<unknown>`,
 * which is deny-by-default, so the remaining failure mode is a wrongly-DENY: a dependency's
 * legitimate, granted call is refused because capwall could not see whose it was. Same
 * mis-attribution, failing closed instead of open; the fix is still to raise the budget.
 *
 * These tests prove: (a) the knob actually changes the outcome for one and the same call,
 * (b) garbage config falls back to the default instead of throwing or silently capturing zero
 * frames, and (c) the `CAPWALL_MAX_FRAMES` env path works through the real preload.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_MAX_FRAMES,
  UNATTRIBUTED,
  install,
  loadPolicyFromObject,
  resolveMaxFrames,
  type Decision,
  type Policy,
} from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURES = path.join(here, "fixtures");
const FIXTURE = path.join(FIXTURES, "node_modules", "fixture-dep");

/**
 * Wrapper depth. Comfortably past the 25-frame default (a handful of which capwall's own
 * frames consume) and comfortably inside the raised budget used below, so neither case is
 * sitting on the boundary where an extra V8 frame would flip the result.
 */
const DEEP = 60;
const RAISED = 200;

interface FixtureDep {
  readData(): string;
  readDataViaDeepStack(depth: number): string;
}

/** Require the fixture fresh (cache cleared) so its top-level require("fs") re-runs. */
function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

type Recorded = { pkg: string; decision: Decision };

const observePolicy = (): Policy =>
  loadPolicyFromObject({ version: 1 }, { projectRoot: FIXTURES });

/** Grants fixture-dep (and ONLY fixture-dep) read access to its own tree. */
const grantFixtureDep = (): Policy =>
  loadPolicyFromObject(
    {
      version: 1,
      mode: "enforce",
      packages: { "fixture-dep": { fs: { read: ["./node_modules/fixture-dep/**"], write: [] } } },
    },
    { projectRoot: FIXTURES },
  );

/** Run `fn` inside a tight install window, collecting every decision. */
function withCapwall<T>(
  policy: Policy,
  mode: "observe" | "enforce",
  maxFrames: number | undefined,
  fn: (dep: FixtureDep) => T,
): { result: T; decisions: Recorded[] } {
  const decisions: Recorded[] = [];
  const handle = install(policy, mode, {
    projectRoot: FIXTURES,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
    ...(maxFrames !== undefined ? { attribution: { maxFrames } } : {}),
  });
  try {
    return { result: fn(loadFixtureFresh()), decisions };
  } finally {
    handle.uninstall();
  }
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("attribution maxFrames — the knob changes the outcome", () => {
  it("mis-attributes a deep dependency stack to <unknown> at the default budget", () => {
    const { decisions } = withCapwall(observePolicy(), "observe", undefined, (dep) => {
      expect(dep.readDataViaDeepStack(DEEP)).toContain("fixture data");
    });
    expect(decisions).toHaveLength(1);
    // The read really came from fixture-dep; the walk never got there. Since #60 that lands
    // on `<unknown>` rather than the trust root, so it fails closed instead of open.
    expect(decisions[0]!.pkg).toBe(UNATTRIBUTED);
  });

  it("attributes the same call to fixture-dep when maxFrames is raised", () => {
    const { decisions } = withCapwall(observePolicy(), "observe", RAISED, (dep) => {
      expect(dep.readDataViaDeepStack(DEEP)).toContain("fixture data");
    });
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.pkg).toBe("fixture-dep");
  });

  it("flags the capped fallback as truncated, and does not flag a normal attribution", () => {
    // Item 3 of #15: "exhausted the budget" must be distinguishable from every other
    // unattributable call, so an operator knows to raise the budget rather than to grant
    // `<unknown>`.
    const capped = withCapwall(observePolicy(), "observe", undefined, (dep) =>
      dep.readDataViaDeepStack(DEEP),
    );
    expect(capped.decisions[0]!.decision.attributionTruncated).toBe(true);

    const raised = withCapwall(observePolicy(), "observe", RAISED, (dep) =>
      dep.readDataViaDeepStack(DEEP),
    );
    expect(raised.decisions[0]!.decision.attributionTruncated).toBeUndefined();

    // A shallow, correctly-attributed call is never flagged either.
    const shallow = withCapwall(observePolicy(), "observe", undefined, (dep) => dep.readData());
    expect(shallow.decisions[0]!.pkg).toBe("fixture-dep");
    expect(shallow.decisions[0]!.decision.attributionTruncated).toBeUndefined();
  });

  it("enforces against the WRONG package when the budget is too low (the security bug)", () => {
    // Same policy, same call, two budgets. At the default budget the granted dependency's read
    // is charged to `<unknown>`, which has no entry and is therefore denied — a false deny.
    // Before #60 it was charged to `<app>`, where the same call would be ALLOWED outright in
    // the (normal) case that the app holds a broad grant: a false allow of a dependency's
    // call. Failing closed is the deliberate trade.
    const capped = withCapwall(grantFixtureDep(), "enforce", undefined, (dep) => {
      expect(() => dep.readDataViaDeepStack(DEEP)).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expect(capped.decisions[0]!.pkg).toBe(UNATTRIBUTED);
    expect(capped.decisions[0]!.decision.allowed).toBe(false);

    const raised = withCapwall(grantFixtureDep(), "enforce", RAISED, (dep) => {
      expect(dep.readDataViaDeepStack(DEEP)).toContain("fixture data");
    });
    expect(raised.decisions[0]!.pkg).toBe("fixture-dep");
    expect(raised.decisions[0]!.decision.allowed).toBe(true);
  });
});

describe("attribution maxFrames — validation falls back to the default", () => {
  /** Capture stderr so the warning is asserted instead of polluting the test output. */
  function captureStderr(): { lines: () => string } {
    let out = "";
    vi.spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => {
      out += String(chunk);
      return true;
    });
    return { lines: () => out };
  }

  it("accepts positive integers, as numbers or numeric strings (the env channel)", () => {
    expect(resolveMaxFrames(1)).toBe(1);
    expect(resolveMaxFrames(200)).toBe(200);
    expect(resolveMaxFrames("120")).toBe(120);
  });

  it("treats unset/empty as 'not configured' — default, no warning", () => {
    const err = captureStderr();
    expect(resolveMaxFrames(undefined)).toBe(DEFAULT_MAX_FRAMES);
    expect(resolveMaxFrames("")).toBe(DEFAULT_MAX_FRAMES);
    expect(err.lines()).toBe("");
  });

  it.each([
    ["zero", 0],
    ["negative", -5],
    ["fractional", 12.5],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["unsafe integer", Number.MAX_SAFE_INTEGER + 2],
    ["garbage string", "lots"],
    ["boolean", true],
    ["object", { maxFrames: 100 }],
  ])("falls back to the default on a %s value, with a warning", (_label, value) => {
    const err = captureStderr();
    expect(resolveMaxFrames(value, "CAPWALL_MAX_FRAMES")).toBe(DEFAULT_MAX_FRAMES);
    expect(err.lines()).toMatch(/ignoring invalid CAPWALL_MAX_FRAMES=/);
  });

  it("install() never throws on a bad maxFrames and keeps working at the default", () => {
    const err = captureStderr();
    // Cast: the type system already rejects this, but config crossing a JSON/env boundary is
    // untyped at runtime, and capwall must not crash the host app over a typo (fail-open).
    const { decisions } = withCapwall(observePolicy(), "observe", "nope" as unknown as number, (dep) =>
      dep.readData(),
    );
    expect(err.lines()).toMatch(/ignoring invalid attribution\.maxFrames="nope"/);
    expect(decisions[0]!.pkg).toBe("fixture-dep"); // shallow call: default budget is enough
  });

  it("a bad maxFrames does not silently disable attribution", () => {
    // The failure mode this guards: NaN/0 reaching Error.stackTraceLimit captures ZERO frames,
    // so EVERY call would attribute to <unknown> — capwall would look installed while
    // attributing nothing (and, since #60, denying everything). A shallow dependency call must
    // still resolve to the dependency.
    captureStderr();
    const { decisions } = withCapwall(observePolicy(), "observe", 0, (dep) => dep.readData());
    expect(decisions[0]!.pkg).toBe("fixture-dep");
  });
});

describe("CAPWALL_MAX_FRAMES env path (preload)", () => {
  // Runs the built preload the way the CLI does (NODE_OPTIONS=--import). Requires `pnpm build`
  // first, like esm.test.ts.
  const PRELOAD = requireCjs.resolve("../dist/preload.js");
  const APP = path.join(FIXTURES, "deep-stack-app.cjs");

  function runApp(env: Record<string, string>): Promise<{ code: number; stdout: string; stderr: string }> {
    const nodeOptions = `--import ${pathToFileURL(PRELOAD).href}`;
    return new Promise((resolve, reject) => {
      execFile(
        process.execPath,
        [APP, String(DEEP)],
        {
          cwd: FIXTURES,
          env: {
            ...process.env,
            NODE_OPTIONS: nodeOptions,
            CAPWALL_MODE: "observe",
            CAPWALL_PROJECT_ROOT: FIXTURES,
            CAPWALL_MAX_FRAMES: "",
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

  it("mis-attributes the deep read to <unknown> with no CAPWALL_MAX_FRAMES set", async () => {
    expect(existsSync(PRELOAD), `built preload not found at ${PRELOAD} — run 'pnpm build' first`).toBe(true);
    const r = await runApp({});
    expect(r.stdout).toContain("READ_OK:fixture data");
    expect(r.stderr).toMatch(/observe: recorded fs:read .* for '<unknown>'/);
    // The one-time warning is the operator's signal that this <unknown> is a capped walk, not
    // genuinely unattributable code.
    expect(r.stderr).toContain(`attribution hit the ${DEFAULT_MAX_FRAMES}-frame budget`);
    expect(r.code).toBe(0);
  });

  it("attributes it to fixture-dep when CAPWALL_MAX_FRAMES is raised", async () => {
    const r = await runApp({ CAPWALL_MAX_FRAMES: String(RAISED) });
    expect(r.stdout).toContain("READ_OK:fixture data");
    expect(r.stderr).toMatch(/observe: recorded fs:read .* for 'fixture-dep'/);
    expect(r.stderr).not.toContain("frame budget");
    expect(r.code).toBe(0);
  });

  it("warns and uses the default on a garbage CAPWALL_MAX_FRAMES, without crashing the app", async () => {
    const r = await runApp({ CAPWALL_MAX_FRAMES: "twenty-five" });
    expect(r.stderr).toContain('ignoring invalid CAPWALL_MAX_FRAMES="twenty-five"');
    expect(r.stdout).toContain("READ_OK:fixture data"); // fail-open: the app still ran
    expect(r.stderr).toMatch(/observe: recorded fs:read .* for '<unknown>'/);
    expect(r.code).toBe(0);
  });
});
