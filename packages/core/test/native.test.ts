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
 *  2. For a genuinely loadable addon, `helpers/real-addon.ts` borrows one out of the installed
 *     dependency tree (pnpm pulls platform-keyed native bindings for `rollup`/`oxlint`). That
 *     covers the end-to-end "granted, and the addon really loads" case on the platforms where
 *     such a binding exists, and skips with an explicit message where it does not.
 *
 * WHICH FAILURE, NOT JUST "A FAILURE" (#140). Every row here asserts WHY a load failed rather
 * than that it failed, via {@link classifyLoadFailure}. `name !== "CapabilityError"` collapses
 * three different outcomes into one — and the third of them, a real addon built for another
 * architecture (`wrong ELF class`), reads exactly like the "gate passed, placeholder rejected"
 * result these rows claim to prove. That is not hypothetical: `pnpm install --force`
 * materializes every optional binding, and the pre-#140 scan handed this file a 32-bit ARM
 * oxlint binding on an x64 host.
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
import {
  classifyLoadFailure,
  hostBinaryVerdict,
  matchesHostTriple,
  REAL_ADDON,
  REAL_ADDON_SKIP_REASON,
  scanForRealAddon,
  titleWithSkipReason,
} from "./helpers/real-addon.js";

const here = path.dirname(fileURLToPath(import.meta.url));
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

/**
 * Why the call failed, as one of the four outcomes `helpers/real-addon.ts` distinguishes —
 * `"none"` when it did not fail at all. `"loader"` is the expected answer wherever a
 * placeholder `.node` is used: capwall stood aside and the platform loader rejected the FILE.
 * `"arch"` there would mean the test borrowed a binding for another machine (#140), which is
 * neither a capwall answer nor a proof of anything.
 */
const failure = (o: Outcome): string =>
  o.error === undefined ? "none" : classifyLoadFailure(o.error);

/** The message with it, so a surprise reads as itself rather than as `expected 'arch'`. */
const failureDetail = (o: Outcome): string => `${failure(o)}: ${o.error?.message ?? "(no error)"}`;

const DENY_ALL = { version: 1, mode: "enforce" };
const GRANT = (packages: Record<string, unknown>): Record<string, unknown> => ({
  version: 1,
  mode: "enforce",
  packages,
});
const OBSERVE = { version: 1, mode: "observe" };


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
    expect(failure(o), failureDetail(o)).toBe("loader");
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
    // `every()` on an EMPTY array is `true`, and the placeholder addon throws a format error
    // whose name is not `CapabilityError` whether the gate ran or not — so those two assertions
    // alone survive deletion of the whole native gate. Pinning the subjects is what makes this
    // row discriminating, exactly as its four siblings above do (#112).
    expect(subjects(o)).toEqual(["fixture-native-loader", "fixture-dep"]);
    expect(nativeDecisions(o).every((d) => d.decision.allowed)).toBe(true);
    expect(failure(o), failureDetail(o)).toBe("loader");
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
    expect(failure(o), failureDetail(o)).toBe("loader");
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
    expect(classifyLoadFailure(err), err?.message).toBe("loader");
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
    expect(classifyLoadFailure(err), err?.message).toBe("loader");
  });
});

describe.skipIf(REAL_ADDON === null)(
  titleWithSkipReason("native gate — a REAL, loadable addon"),
  () => {
    it("denies it by default and loads it for real once granted", () => {
      const denied = withCapwall(DENY_ALL, "enforce", (dep) =>
        dep.loadNativeViaDlopen(REAL_ADDON!),
      );
      expect(failure(denied), failureDetail(denied)).toBe("gate");

      // Grant every subject (the caller `fixture-dep`, and the binding package that owns the
      // file) and confirm the addon genuinely initializes — the end-to-end proof that the gate
      // is a decision point and not a wall.
      const allowed = withCapwall({ version: 1, mode: "enforce", default: { native: true } }, "enforce", (dep) => {
        const exports = dep.loadNativeViaDlopen(REAL_ADDON!);
        expect(typeof exports).toBe("object");
        expect(Object.keys(exports as object).length).toBeGreaterThan(0);
      });
      // On a failure this prints the loader's own words — `wrong ELF class: ELFCLASS32` says
      // "the borrowed binding is for another machine" (#140), which is a very different report
      // from `file too short` or a `CapabilityError`.
      expect(allowed.error?.message ?? null, `borrowed addon: ${REAL_ADDON}`).toBeNull();
      expect(nativeDecisions(allowed).every((d) => d.decision.allowed)).toBe(true);
    });
  },
);

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * #140 — the borrowed-addon scan itself. A test suite that borrows a binary off the disk is
 * only as good as the choosing, and the choosing used to be "the first `.node` under a store
 * directory whose name contains `linux`".
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("#140 — helpers/real-addon picks a binding for THIS machine", () => {
  it("matches the host triple by token, not by substring", () => {
    const hostArch = process.arch;
    // The real shapes, spelled for whatever host runs this.
    expect(matchesHostTriple(`@oxlint+binding-linux-${hostArch}-gnu/oxlint.node`)).toBe(
      process.platform === "linux",
    );
    expect(matchesHostTriple(`prebuilds/${process.platform}-${hostArch}/node.napi.node`)).toBe(
      true,
    );
    // The #140 regression, both directions of it: `arm64` CONTAINS `arm`, and `x64` does not
    // contain `ia32` — a substring test gets one of those wrong on every host it runs on.
    const foreign = hostArch === "arm64" ? "x64" : "arm64";
    expect(matchesHostTriple(`@oxlint+binding-linux-${foreign}-gnu/oxlint.node`)).toBe(false);
    expect(matchesHostTriple(`@rollup+rollup-linux-arm-gnueabihf/rollup.node`)).toBe(
      hostArch === "arm" && process.platform === "linux",
    );
    // A foreign platform with the host's arch is not a candidate either.
    const otherOs = process.platform === "darwin" ? "win32" : "darwin";
    expect(matchesHostTriple(`@pkg+${otherOs}-${hostArch}/binding.node`)).toBe(false);
    // Names no architecture at all: not preferred, so not taken (skip beats a coin flip).
    expect(matchesHostTriple("some-package/build/Release/binding.node")).toBe(false);
  });

  it("reads the architecture out of the binary, and says 'unknown' rather than guessing", () => {
    // A text file is not a format this can decode — and "unknown" must not reject, or a
    // decoding gap would silently skip every dependent suite.
    const text = path.join(os.tmpdir(), `capwall-verdict-${process.pid}.node`);
    nodeFs.writeFileSync(text, "placeholder, not a real addon\n");
    try {
      expect(hostBinaryVerdict(text)).toBe("unknown");
    } finally {
      nodeFs.rmSync(text, { force: true });
    }
    expect(hostBinaryVerdict(path.join(os.tmpdir(), "capwall-no-such-file.node"))).toBe("unknown");
    // node itself is a binary for this machine by definition — the positive control.
    expect(hostBinaryVerdict(process.execPath)).toBe("host");
    // And a foreign one, synthesized: an ELF64 header claiming aarch64 (or x86-64 on an arm
    // host). This is the file the pre-#140 scan handed the suite.
    const elf = Buffer.alloc(64);
    elf.writeUInt32BE(0x7f454c46, 0);
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // little-endian
    elf.writeUInt16LE(process.arch === "arm64" ? 0x3e : 0xb7, 18);
    const fake = path.join(os.tmpdir(), `capwall-foreign-${process.pid}.node`);
    nodeFs.writeFileSync(fake, elf);
    try {
      expect(hostBinaryVerdict(fake)).toBe("foreign");
    } finally {
      nodeFs.rmSync(fake, { force: true });
    }
  });

  it("does not skip silently — either it found a binding, or it says what it rejected", () => {
    const scan = scanForRealAddon();
    if (scan.file === null) {
      // Skipping is legitimate (a platform with no prebuilt binding, a non-pnpm layout), but it
      // has to be legible: an empty reason is how a suite quietly stops testing anything.
      expect(scan.reason).not.toBe("");
      expect(scan.reason).toContain(`${process.platform}-${process.arch}`);
    } else {
      expect(hostBinaryVerdict(scan.file)).not.toBe("foreign");
      expect(matchesHostTriple(path.relative(here, scan.file))).toBe(true);
      expect(REAL_ADDON_SKIP_REASON).toBe("");
    }
  });

  it("refuses a foreign binding outright, and takes the host one sitting next to it", () => {
    // THE #140 REGRESSION, reproduced: a store where the FIRST `.node` in sort order is a
    // binding for another architecture whose directory name contains `process.platform`. The
    // pre-#140 scan returned it and `native.test.ts` failed with `wrong ELF class`.
    const store = nodeFs.mkdtempSync(path.join(os.tmpdir(), "capwall-fake-store-"));
    const foreignArch = process.arch === "arm64" ? "x64" : "arm64";
    const put = (dir: string, bytes: Buffer): string => {
      const full = path.join(store, dir, "node_modules", dir.split("@")[1] ?? dir);
      nodeFs.mkdirSync(full, { recursive: true });
      const file = path.join(full, "binding.node");
      nodeFs.writeFileSync(file, bytes);
      return file;
    };
    // 32-bit ARM ELF, the exact shape the oxlint optional binding had.
    const foreignElf = Buffer.alloc(64);
    foreignElf.writeUInt32BE(0x7f454c46, 0);
    foreignElf[4] = 1;
    foreignElf[5] = 1;
    foreignElf.writeUInt16LE(0x28, 18);
    try {
      const foreign = put(`@aaa+binding-${process.platform}-${foreignArch}@1.0.0`, foreignElf);
      const only = scanForRealAddon(store);
      // Not "return it and hope": no candidate for this machine means skip, with the reason
      // naming the host triple AND the files that were passed over.
      expect(only.file, `picked a ${foreignArch} binding on ${process.arch}`).toBeNull();
      expect(only.reason).toContain(`${process.platform}-${process.arch}`);
      expect(only.reason).toContain("binding.node");
      expect(only.seen).toContain(foreign);

      // Now add the host's own binding — the first 64 bytes of the running `node` are a header
      // for this machine by construction, whatever format the platform uses.
      const host = put(
        `@zzz+binding-${process.platform}-${process.arch}@1.0.0`,
        nodeFs.readFileSync(process.execPath).subarray(0, 64),
      );
      // `@aaa…` still sorts first. Choosing by order rather than by architecture is the bug.
      expect(scanForRealAddon(store).file).toBe(host);
    } finally {
      nodeFs.rmSync(store, { recursive: true, force: true });
    }
  });

  it("classifies the three ways a load can fail, and does not confuse them", () => {
    // The distinction the native suite is built on. `wrong ELF class` used to read as
    // `loader`, i.e. as "the gate passed and the platform rejected the placeholder".
    const err = (name: string, message: string): Error =>
      Object.assign(new Error(message), { name });
    expect(classifyLoadFailure(err("CapabilityError", "enforce: DENY"))).toBe("gate");
    expect(classifyLoadFailure(err("Error", "/x.node: wrong ELF class: ELFCLASS32"))).toBe("arch");
    expect(classifyLoadFailure(err("Error", "dlopen(/x.node): incompatible architecture"))).toBe(
      "arch",
    );
    expect(classifyLoadFailure(err("Error", "/x.node: file too short"))).toBe("loader");
    expect(classifyLoadFailure(err("Error", "/x.node: invalid ELF header"))).toBe("loader");
    expect(
      classifyLoadFailure(err("Error", "/x.node: cannot open shared object file: No such file")),
    ).toBe("missing");
  });
});
