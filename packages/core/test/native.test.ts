/**
 * Native-addon (`.node`) load gate — roadmap S2, issue #49.
 *
 * capwall mediates JS builtins. A native addon makes all of that moot at once: once compiled
 * code is `dlopen`ed it has raw libc and can open files, open sockets and read the
 * environment without touching a single shim. So these tests are about ONE question — is the
 * load itself attributed and gated — and deliberately not about anything the addon does
 * afterwards, which capwall does not and will not confine (docs/threat-model.md).
 *
 * ON TESTING A GATE WITHOUT A COMPILER. The CI image is `node:{20,22}-bookworm-slim` with no
 * toolchain and no network, so building an addon at test time is not an option. Two things
 * make that a non-problem:
 *
 *  1. The gate runs BEFORE `process.dlopen` touches the file, so every denial path is fully
 *     observable against a placeholder `.node` file. And the ALLOW path is observable too,
 *     precisely because the file is not a real addon: when the gate passes, dlopen is reached
 *     and fails with the platform loader's own error. `CapabilityError` vs. "not an ELF file"
 *     is an unambiguous "gate fired" vs. "gate passed" signal — no faked pass.
 *  2. For a genuinely loadable addon, {@link findRealAddon} borrows one out of the installed
 *     dependency tree (pnpm pulls platform-keyed native bindings for `rollup`/`oxlint`). That
 *     covers the end-to-end "granted, and the addon really loads" case on the platforms where
 *     such a binding exists, and skips with an explicit message where it does not.
 */
import { createRequire } from "node:module";
import * as nodeFs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  install,
  isGranted,
  loadPolicyFromObject,
  type Decision,
  type Policy,
} from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, "..", "..", "..");
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");
const FIXTURE_ADDON = path.join(FIXTURE, "build", "Release", "fixture-addon.node");
/** A `.node` path OUTSIDE any node_modules tree — owner attributes to `<app>`. */
const OUTSIDE_ADDON = path.join(here, "fixtures", "outside-addon.node");

interface FixtureDep {
  NATIVE_ADDON: string;
  loadNativeAddon(target?: string): unknown;
  loadNativeViaResolver(): unknown;
  loadNativeViaDlopen(target?: string): unknown;
  loadNativeViaBadArg(target: string): void;
}

function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  // The resolver-wrapper fixture caches the addon's module too; clear it so each window
  // actually re-runs the load rather than replaying a cached `module.exports`.
  for (const key of Object.keys(requireCjs.cache)) {
    if (key.endsWith(".node") || key.includes("fixture-native-loader")) {
      delete requireCjs.cache[key];
    }
  }
  return requireCjs(FIXTURE) as FixtureDep;
}

type Recorded = { pkg: string; decision: Decision };

interface Outcome {
  decisions: Recorded[];
  /** The error the call threw, if any. */
  error: Error | undefined;
}

/**
 * Run `fn` inside a tight install window and report both the decisions and whatever the call
 * threw. Every native load in this file is EXPECTED to throw something — either
 * `CapabilityError` (gate fired) or the platform loader's error (gate passed, placeholder
 * file) — so the error is returned for inspection rather than asserted away here.
 */
function withCapwall(
  policyObject: Record<string, unknown>,
  mode: "observe" | "enforce",
  fn: (dep: FixtureDep) => void,
): Outcome {
  const decisions: Recorded[] = [];
  const policy: Policy = loadPolicyFromObject(policyObject, { projectRoot: here });
  const handle = install(policy, mode, {
    projectRoot: here,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
  });
  let error: Error | undefined;
  try {
    fn(loadFixtureFresh());
  } catch (err) {
    error = err as Error;
  } finally {
    handle.uninstall();
  }
  return { decisions, error };
}

const nativeDecisions = (o: Outcome): Recorded[] =>
  o.decisions.filter((d) => d.decision.observed.kind === "native");

/** Package names a native decision was recorded against, in order. */
const subjects = (o: Outcome): string[] => nativeDecisions(o).map((d) => d.pkg);

const DENY_ALL = { version: 1, mode: "enforce" };
const GRANT = (packages: Record<string, unknown>): Record<string, unknown> => ({
  version: 1,
  mode: "enforce",
  packages,
});
const OBSERVE = { version: 1, mode: "observe" };

/**
 * Borrow a real, loadable `.node` from the installed dependency tree.
 *
 * pnpm materializes platform-keyed native bindings (e.g. `@rollup/rollup-linux-x64-gnu`,
 * `@oxlint/binding-linux-x64-gnu`) under `node_modules/.pnpm`, and those package directory
 * names embed `process.platform` — which is what keeps this scan cheap and targeted rather
 * than a walk of the whole store. Returns `null` when no such binding is installed (a
 * different package manager's layout, or a platform with no prebuilt binding), in which case
 * the dependent test skips loudly instead of pretending to pass.
 */
function findRealAddon(): string | null {
  const store = path.join(REPO_ROOT, "node_modules", ".pnpm");
  let budget = 3000;
  const walk = (dir: string, depth: number): string | null => {
    if (depth > 4 || budget <= 0) return null;
    let entries: nodeFs.Dirent[];
    try {
      entries = nodeFs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return null;
    }
    for (const entry of entries) {
      if (--budget <= 0) return null;
      const full = path.join(dir, entry.name);
      if (entry.isFile() && entry.name.endsWith(".node")) return full;
      if (entry.isDirectory()) {
        const hit = walk(full, depth + 1);
        if (hit) return hit;
      }
    }
    return null;
  };
  let candidates: nodeFs.Dirent[];
  try {
    candidates = nodeFs.readdirSync(store, { withFileTypes: true });
  } catch {
    return null;
  }
  for (const entry of candidates) {
    if (!entry.isDirectory() || !entry.name.includes(process.platform)) continue;
    const hit = walk(path.join(store, entry.name), 0);
    if (hit) return hit;
  }
  return null;
}

const REAL_ADDON = findRealAddon();

describe("native gate — the grant itself", () => {
  it("is deny-by-default and ignores the addon path (the grant is a boolean)", () => {
    const req = { kind: "native", path: "/anywhere/foo.node" } as const;
    expect(isGranted({}, req)).toBe(false);
    expect(isGranted({ native: false }, req)).toBe(false);
    expect(isGranted({ native: true }, req)).toBe(true);
    // Same grant, a completely different addon path: still allowed. That is the point — an
    // addon path is a platform/arch/ABI-specific build artifact, so a path-shaped grant would
    // not survive a change of machine (#27/#57). See PackagePolicy.native.
    expect(isGranted({ native: true }, { kind: "native", path: "/elsewhere/bar.node" })).toBe(
      true,
    );
  });
});

describe("native gate — enforce mode denies by default", () => {
  it("denies `require('*.node')` and attributes it to the requiring package", () => {
    const o = withCapwall(DENY_ALL, "enforce", (dep) => dep.loadNativeAddon());
    expect(o.error?.name).toBe("CapabilityError");
    expect(nativeDecisions(o)).toHaveLength(1);
    const [only] = nativeDecisions(o);
    // Attribution DOES reach the requiring package: every frame between `process.dlopen` and
    // the requiring module is `node:internal/modules/*`, which the stack walk already skips
    // as a non-filesystem path. Verified rather than assumed (#49 asked for exactly this).
    expect(only!.pkg).toBe("fixture-dep");
    expect(only!.decision.allowed).toBe(false);
    expect(only!.decision.observed).toEqual({ kind: "native", path: FIXTURE_ADDON });
    expect(only!.decision.reason).toContain("deny-by-default");
  });

  it("denies a DIRECT process.dlopen call — not just the require path", () => {
    // If only `Module._extensions['.node']` (or the `require` specifier) were hooked, this
    // would sail straight through and the whole gate would be decorative.
    const o = withCapwall(DENY_ALL, "enforce", (dep) => dep.loadNativeViaDlopen());
    expect(o.error?.name).toBe("CapabilityError");
    expect(subjects(o)).toEqual(["fixture-dep"]);
  });

  it("denies a dlopen whose filename argument is not a string, ON THE FILE IT WOULD OPEN (#99)", () => {
    // `process.dlopen` is a C++ binding that reads its second argument as `node::Utf8Value` —
    // it STRINGIFIES whatever it is handed, so `{ toString: () => "/…/fixture-addon.node" }`
    // loads that addon for real. capwall used to require `typeof raw === "string"` and record
    // `<unknown>`, which skipped the OWNER half of the two-subject check: the half that stops a
    // package holding its own `native` grant from loading a `.node` belonging to someone else.
    const o = withCapwall(DENY_ALL, "enforce", (dep) => dep.loadNativeViaBadArg(FIXTURE_ADDON));
    expect(o.error?.name).toBe("CapabilityError");
    expect(nativeDecisions(o)[0]!.decision.observed).toEqual({
      kind: "native",
      path: FIXTURE_ADDON,
    });
  });

  it("denies before the addon is opened (the file is never touched)", () => {
    // A denial must be a decision, not a consequence of the file being unloadable: point the
    // gate at a path that does not exist at all. A CapabilityError (not ENOENT) proves the
    // gate ran first.
    const o = withCapwall(DENY_ALL, "enforce", (dep) =>
      dep.loadNativeViaDlopen(path.join(here, "fixtures", "no-such-addon.node")),
    );
    expect(o.error?.name).toBe("CapabilityError");
  });
});

describe("native gate — enforce mode, granted", () => {
  it("lets the load through once the package is granted `native`", () => {
    const o = withCapwall(GRANT({ "fixture-dep": { native: true } }), "enforce", (dep) =>
      dep.loadNativeAddon(),
    );
    expect(subjects(o)).toEqual(["fixture-dep"]);
    expect(nativeDecisions(o)[0]!.decision.allowed).toBe(true);
    // The gate passed, so `process.dlopen` really ran — and failed, because the fixture file
    // is a placeholder rather than a real addon. A platform-loader error here (and NOT a
    // CapabilityError) is the proof that the gate stopped being the thing in the way.
    expect(o.error).toBeDefined();
    expect(o.error!.name).not.toBe("CapabilityError");
  });

  it("does not leak the grant to other packages (deny-by-default still holds)", () => {
    const o = withCapwall(GRANT({ "some-other-pkg": { native: true } }), "enforce", (dep) =>
      dep.loadNativeAddon(),
    );
    expect(o.error?.name).toBe("CapabilityError");
  });
});

describe("native gate — resolver wrappers (bindings / node-gyp-build shape)", () => {
  it("records BOTH the loading helper and the addon's owning package", () => {
    const o = withCapwall(OBSERVE, "observe", (dep) => dep.loadNativeViaResolver());
    // Caller first (capwall's normal nearest-frame attribution), then the addon's owner.
    expect(subjects(o)).toEqual(["fixture-native-loader", "fixture-dep"]);
    for (const d of nativeDecisions(o)) {
      expect(d.decision.observed).toEqual({ kind: "native", path: FIXTURE_ADDON });
    }
  });

  it("granting ONLY the helper is not a skeleton key for every native package", () => {
    // This is the case that makes caller-only attribution unsafe for this capability: real
    // packages load through a shared `bindings`/`node-gyp-build`, so an observe run would
    // otherwise tell you to write one grant that unlocks native loading tree-wide.
    const o = withCapwall(
      GRANT({ "fixture-native-loader": { native: true } }),
      "enforce",
      (dep) => dep.loadNativeViaResolver(),
    );
    expect(o.error?.name).toBe("CapabilityError");
    expect(o.error!.message).toContain("fixture-dep");
    // Both subjects are recorded before the throw, so the operator sees the full picture.
    expect(subjects(o)).toEqual(["fixture-native-loader", "fixture-dep"]);
  });

  it("granting ONLY the owning package is not enough either", () => {
    const o = withCapwall(GRANT({ "fixture-dep": { native: true } }), "enforce", (dep) =>
      dep.loadNativeViaResolver(),
    );
    expect(o.error?.name).toBe("CapabilityError");
    expect(o.error!.message).toContain("fixture-native-loader");
  });

  it("granting both lets the load through", () => {
    const o = withCapwall(
      GRANT({ "fixture-native-loader": { native: true }, "fixture-dep": { native: true } }),
      "enforce",
      (dep) => dep.loadNativeViaResolver(),
    );
    expect(nativeDecisions(o).every((d) => d.decision.allowed)).toBe(true);
    expect(o.error!.name).not.toBe("CapabilityError");
  });
});

describe("native gate — addon outside any node_modules tree", () => {
  it("charges a project-local addon to <app> as well as to the loading dependency", () => {
    // A `.node` under the project root but outside node_modules is the project's own build
    // output, so `<app>` is the honest owner — and it is still a second subject that must be
    // granted, because owner-only or caller-only would each miss a real case.
    const o = withCapwall(GRANT({ "fixture-dep": { native: true } }), "enforce", (dep) =>
      dep.loadNativeViaDlopen(OUTSIDE_ADDON),
    );
    expect(subjects(o)).toEqual(["fixture-dep", "<app>"]);
    expect(o.error?.name).toBe("CapabilityError");
    expect(o.error!.message).toContain("<app>");
  });

  it("charges an addon outside the project entirely to <unknown>, not <app> (#60)", () => {
    // The shape that matters most: a payload written to a temp dir and dlopened. It belongs to
    // no package AND is not the project's build output, so charging it to the trust root would
    // reintroduce exactly the fail-open #60 closed for the stack walk.
    const stray = path.join(os.tmpdir(), `capwall-native-test-${process.pid}.node`);
    nodeFs.writeFileSync(stray, "placeholder, not a real addon\n");
    try {
      const o = withCapwall(
        GRANT({ "fixture-dep": { native: true }, "<app>": { native: true } }),
        "enforce",
        (dep) => dep.loadNativeViaDlopen(stray),
      );
      expect(subjects(o)).toEqual(["fixture-dep", "<unknown>"]);
      // Granting `<app>` does NOT cover it — that is the whole point of the distinction.
      expect(o.error?.name).toBe("CapabilityError");
      expect(o.error!.message).toContain("<unknown>");
    } finally {
      nodeFs.rmSync(stray, { force: true });
    }
  });
});

describe("native gate — observe mode", () => {
  it("records the load and never denies it", () => {
    const o = withCapwall(OBSERVE, "observe", (dep) => dep.loadNativeAddon());
    expect(subjects(o)).toEqual(["fixture-dep"]);
    expect(nativeDecisions(o)[0]!.decision.allowed).toBe(true);
    expect(nativeDecisions(o)[0]!.decision.reason).toContain("observe: recorded native");
    // Not a CapabilityError: observe never blocks, so dlopen ran and rejected the placeholder.
    expect(o.error!.name).not.toBe("CapabilityError");
  });
});

describe("native gate — install/uninstall hygiene", () => {
  it("restores the previous process.dlopen and stops gating", () => {
    const before = process.dlopen;
    const handle = install(loadPolicyFromObject(DENY_ALL, { projectRoot: here }), "enforce", {
      projectRoot: here,
    });
    expect(process.dlopen).not.toBe(before);
    handle.uninstall();
    expect(process.dlopen).toBe(before);
    // After uninstall the gate is gone: the load fails on the file, not on the policy.
    let err: Error | undefined;
    try {
      loadFixtureFresh().loadNativeAddon();
    } catch (e) {
      err = e as Error;
    }
    expect(err!.name).not.toBe("CapabilityError");
  });

  it("uninstalling an inner window out of order does not resurrect or drop the gate", () => {
    const outer = install(loadPolicyFromObject(DENY_ALL, { projectRoot: here }), "enforce", {
      projectRoot: here,
    });
    const outerPatched = process.dlopen;
    const inner = install(loadPolicyFromObject(DENY_ALL, { projectRoot: here }), "enforce", {
      projectRoot: here,
    });
    // Remove the OUTER (older) layer first — the relink case loader/require.ts fixed in #22.
    outer.uninstall();
    expect(process.dlopen).not.toBe(outerPatched);
    inner.uninstall();
    // Fully unwound: a load now fails on the file, not on the policy.
    let err: Error | undefined;
    try {
      loadFixtureFresh().loadNativeAddon();
    } catch (e) {
      err = e as Error;
    }
    expect(err!.name).not.toBe("CapabilityError");
  });
});

describe.skipIf(REAL_ADDON === null)("native gate — a REAL, loadable addon", () => {
  it("denies it by default and loads it for real once granted", () => {
    const denied = withCapwall(DENY_ALL, "enforce", (dep) =>
      dep.loadNativeViaDlopen(REAL_ADDON!),
    );
    expect(denied.error?.name).toBe("CapabilityError");

    // Grant every subject (the caller `fixture-dep`, and the binding package that owns the
    // file) and confirm the addon genuinely initializes — the end-to-end proof that the gate
    // is a decision point and not a wall.
    const allowed = withCapwall({ version: 1, mode: "enforce", default: { native: true } }, "enforce", (dep) => {
      const exports = dep.loadNativeViaDlopen(REAL_ADDON!);
      expect(typeof exports).toBe("object");
      expect(Object.keys(exports as object).length).toBeGreaterThan(0);
    });
    expect(allowed.error).toBeUndefined();
    expect(nativeDecisions(allowed).every((d) => d.decision.allowed)).toBe(true);
  });
});
