/**
 * Issue #119 — a read Node ITSELF initiated is not a read by the package underneath it.
 *
 * `process.env` is the one mediated surface Node's own code shares with dependencies (every
 * other shim is handed out through `require`, which Node's internals do not use to reach `fs`
 * or `net`). Attribution skips `node:` frames because they carry no package identity, so a
 * variable Node reads while some dependency's frame happens to sit below it was charged to
 * that dependency — half of a stock express+pino policy, describing Node rather than any
 * dependency it was supposed to be about.
 *
 * The rule under test: the nearest frame above the read, after capwall's own, decides whether
 * the event is RECORDED. It never decides whether the read is allowed — that is the half this
 * file pins hardest, because a "Node did it, let it through" rule would be a one-call
 * laundering route around the anti-exfiltration control (`util.inspect(process.env)` runs in
 * `node:internal/util/inspect`).
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import * as vm from "node:vm";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { attributeCallerDetailed, type Attribution } from "../src/attribution/index.js";
import { install, loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-nodeorigin");

interface Fixture {
  readEnv(key: string): string | undefined;
  loadSourceMapped(): string;
  callFromForgedNodeFrame(fn: () => Attribution): Attribution;
}

type Recorded = { pkg: string; decision: Decision };

function loadFixtureFresh(): Fixture {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as Fixture;
}

function withCapwall<T>(
  policy: Policy,
  mode: "observe" | "enforce",
  fn: (dep: Fixture) => T,
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

const policyFor = (env: string[]): Policy =>
  loadPolicyFromObject(
    { version: 1, mode: "enforce", packages: { "fixture-nodeorigin": { env } } },
    { projectRoot: here },
  );

/** Env keys recorded in the trace, in order. */
function envKeys(decisions: Recorded[]): string[] {
  return decisions
    .filter((d) => d.decision.observed.kind === "env")
    .map((d) => (d.decision.observed as { key: string }).key);
}

/**
 * A caller whose frame reports a `node:` script name, without waiting for Node to read
 * something for us. `vm` compiles under a caller-chosen filename, and a `vm` frame is not an
 * eval frame, so this is the one way in-process to produce the frame shape deterministically.
 * (It is therefore also the residual: a package holding a `vm` grant — already documented as
 * identity-granting — can silence its own env reads in the trace. It cannot make one ALLOWED,
 * which is what the enforce cases below are for.)
 */
const CALL_FROM_NODE_FRAME = vm.runInThisContext("(f, args) => f(...args)", {
  filename: "node:internal/fake-caller",
}) as <A extends unknown[], R>(fn: (...args: A) => R, args: A) => R;

function viaNodeFrame<A extends unknown[], R>(fn: (...args: A) => R): (...args: A) => R {
  // The wrapper frame is this file's, but it sits BELOW the vm frame, and only the nearest
  // frame decides — which is exactly the property being tested.
  return (...args: A) => CALL_FROM_NODE_FRAME(fn, args);
}

describe("attribution — who INITIATED the call (#119)", () => {
  it("is not Node when the nearest frame is ordinary code", () => {
    expect(attributeCallerDetailed().initiatedByNode).toBe(false);
  });

  it("is Node when the nearest frame is a `node:` script", () => {
    expect(viaNodeFrame(attributeCallerDetailed)().initiatedByNode).toBe(true);
  });

  it("is NOT Node for a native frame — no file name is not a claim of identity", () => {
    // `Array.prototype.map` is native: it leaves a frame with a function name and no script
    // name at all. That is the #60 shape (a native reader on a detached stack), and it must
    // fail closed here, or detaching would become a way to go unrecorded.
    // The cast only drops `map`'s (value, index, array) arguments, which attribution ignores.
    const asMapper = attributeCallerDetailed as unknown as (value: number) => Attribution;
    const [attribution] = [0].map(asMapper);
    expect(attribution?.initiatedByNode).toBe(false);
  });

  it("is NOT Node for an eval frame that NAMES itself node: — #84's forgery, closed", () => {
    // `//# sourceURL=` is the one string the running code chooses. An eval frame is OPAQUE
    // before its name is ever consulted, so the claim never reaches the classifier — and the
    // caller is charged as itself, not silenced.
    const dep = loadFixtureFresh();
    const attribution = dep.callFromForgedNodeFrame(attributeCallerDetailed);
    expect(attribution.initiatedByNode).toBe(false);
    expect(attribution.pkg).toBe("fixture-nodeorigin");
  });
});

describe("env shim — a read Node initiated is decided but not recorded (#119)", () => {
  it("hides a non-granted value exactly as before: suppression is of RECORDING, not gating", () => {
    const { result, decisions } = withCapwall(policyFor([]), "enforce", () =>
      viaNodeFrame((env: NodeJS.ProcessEnv, key: string) => env[key])(
        process.env,
        "FIXTURE_NODEORIGIN_SECRET",
      ),
    );
    // The read came from a `node:`-named frame, but the principal below it holds no grant, so
    // the value is still hidden. This is the assertion that must never be relaxed.
    expect(result).toBeUndefined();
    // …and the denial is not in the trace, so it neither widens a generated policy nor prints
    // a DENY line about something no package asked for.
    expect(envKeys(decisions)).toEqual([]);
  });

  it("returns a granted value, still without recording it", () => {
    process.env["FIXTURE_NODEORIGIN_OK"] = "fine";
    const { result, decisions } = withCapwall(
      policyFor(["FIXTURE_NODEORIGIN_OK"]),
      "enforce",
      () =>
        viaNodeFrame((env: NodeJS.ProcessEnv, key: string) => env[key])(
          process.env,
          "FIXTURE_NODEORIGIN_OK",
        ),
    );
    expect(result).toBe("fine");
    expect(envKeys(decisions)).toEqual([]);
    delete process.env["FIXTURE_NODEORIGIN_OK"];
  });

  it("still records a read the package makes from its OWN frame — the whole point", () => {
    process.env["FIXTURE_NODEORIGIN_OK"] = "fine";
    const { decisions } = withCapwall(policyFor(["FIXTURE_NODEORIGIN_OK"]), "observe", (dep) => {
      expect(dep.readEnv("FIXTURE_NODEORIGIN_OK")).toBe("fine");
    });
    expect(envKeys(decisions)).toEqual(["FIXTURE_NODEORIGIN_OK"]);
    expect(decisions[0]?.pkg).toBe("fixture-nodeorigin");
    delete process.env["FIXTURE_NODEORIGIN_OK"];
  });

  it("drops NODE_V8_COVERAGE that Node's source-map cache reads while compiling a dependency", () => {
    // The measured case, end to end through real Node internals rather than a synthesized
    // frame: requiring a file with a `//# sourceMappingURL=` sends
    // `node:internal/source_map/source_map_cache` through `process.env.NODE_V8_COVERAGE`.
    // Pre-#119 this produced `"fixture-nodeorigin": { "env": ["NODE_V8_COVERAGE"] }` — a grant
    // for a variable that does not appear anywhere in the fixture's source.
    const { result, decisions } = withCapwall(policyFor([]), "observe", (dep) =>
      dep.loadSourceMapped(),
    );
    expect(result).toBe("mapped"); // the require really happened
    expect(envKeys(decisions)).not.toContain("NODE_V8_COVERAGE");
  });

  it("keeps a package's OWN read of NODE_V8_COVERAGE — the name is not the discriminator", () => {
    // `thread-stream` really does read this variable, in its own `index.js`, to work around
    // nodejs/node#49344. A denylist of `NODE_*` names would delete that true positive along
    // with the three false ones; the stack origin separates them.
    process.env["NODE_V8_COVERAGE"] = "";
    const { decisions } = withCapwall(policyFor([]), "observe", (dep) => {
      dep.readEnv("NODE_V8_COVERAGE");
    });
    expect(envKeys(decisions)).toEqual(["NODE_V8_COVERAGE"]);
    delete process.env["NODE_V8_COVERAGE"];
  });
});
