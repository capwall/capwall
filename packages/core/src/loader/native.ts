/**
 * Native-addon (`.node`) load gate — roadmap S2, issue #49.
 *
 * WHY THIS EXISTS. Every other capwall control mediates a JS builtin. A native addon is the
 * one thing that makes all of them irrelevant at once: once compiled code is `dlopen`ed into
 * the process it has raw libc and can open files, open sockets and read the environment
 * without ever touching a shimmed JS API. So a `.node` load is not "one more capability" —
 * it is the capability that subsumes the rest, and it was previously both unattributed and
 * ungated.
 *
 * **GATING, NOT CONFINEMENT.** This module decides, at load time, whether a given package may
 * bring compiled code into the process. It does not — cannot — constrain what that code does
 * afterwards. There is no runtime sandbox here and none is planned; see
 * docs/threat-model.md § "Native addons (`.node`)". Do not read an allowed addon as a
 * confined one.
 *
 * WHERE WE HOOK: `process.dlopen`, and only there.
 *
 * `Module._extensions[".node"]` is a two-line function whose body is
 * `return process.dlopen(module, path.toNamespacedPath(filename))` — verified by reading the
 * live function on Node 20.20, 22.22 and 24.18. `process.dlopen` is therefore the single
 * JS-reachable chokepoint through which EVERY addon load passes, and it is a plain
 * writable+configurable own property of `process` on all three. Hooking it (rather than
 * `Module._extensions`, or the literal `require("*.node")` specifier) is what makes the gate
 * real instead of decorative: it covers, with one patch,
 *
 *   - `require("./build/Release/foo.node")` — the literal case;
 *   - a DIRECT `process.dlopen(module, file)` call, which bypasses the module system
 *     entirely and would sail past a `Module._extensions` hook;
 *   - `createRequire(...)("…node")` from ESM, which lands back in the same
 *     `_extensions[".node"]`. (A bare `import("./foo.node")` needs no coverage: Node itself
 *     rejects it with `ERR_UNKNOWN_FILE_EXTENSION`, verified on 20/22/24 — `createRequire` is
 *     the only route from ESM.) Hooking `dlopen` rather than a loader is what makes this gate
 *     module-system-independent: it is on whether or not the ESM hook is registered;
 *   - the resolver wrappers real native packages actually use. Confirmed by reading their
 *     published sources: `bindings@1.5.0` ends at `requireFunc(n)` (plain `require`),
 *     `node-gyp-build@4.8.4` at `runtimeRequire(load.resolve(dir))` (plain `require`), and
 *     `@mapbox/node-pre-gyp` only RESOLVES a path — the consuming package `require`s it. All
 *     three are ordinary `require` calls on a `.node` file, so all three land here.
 *
 * Known non-coverage, stated rather than implied: a `worker_threads.Worker` is a fresh Node
 * context with its own `process` object, so this patch does not exist inside it (workers are
 * separately gated by the `worker_threads` capability); a dependency that captured
 * `process.dlopen` BEFORE capwall installed keeps an un-gated reference (the same pre-install
 * capture residual as every shim — install via the `--import` preload); and Node's experimental
 * `require.addon()` is a C++-side loader that may not route through `process.dlopen` — absent
 * on Node 20.20/22.22/24.18 as shipped, but `node-gyp-build` PREFERS it when it exists, so
 * recheck this hook when it stabilizes.
 */
import * as path from "node:path";
import {
  APP_ROOT,
  UNATTRIBUTED,
  attributeCallerDetailed,
  packageForPath,
} from "../attribution/index.js";
import { CapabilityError } from "../errors.js";
import { evaluate, type Decision } from "../policy/evaluate.js";
import { defineRelinkedPatch, valueSlot } from "../lifecycle/process-patch.js";
import { attributionOptionsFor, type ShimContext } from "../shims/runtime.js";

export interface NativeGateHandle {
  /** Restore the previous `process.dlopen` (used by tests and teardown). */
  uninstall(): void;
}

/** `process.dlopen(module, filename[, flags])`. */
type Dlopen = (this: unknown, ...args: unknown[]) => unknown;

/**
 * Recorded path for a `dlopen` call whose filename argument names no file capwall can read —
 * an empty string, or a value whose string conversion threw.
 *
 * The gate still fires (on the caller alone — there is no file to own), because "the argument
 * was garbage" must not become a way to reach an un-gated `dlopen`.
 */
export const UNKNOWN_ADDON = "<unknown>";

/**
 * The filename `dlopen` will actually open, plus the value to forward in its place.
 *
 * `process.dlopen` is a C++ binding that reads its second argument as `node::Utf8Value`, i.e.
 * it STRINGIFIES whatever it is given — `process.dlopen(m, { toString: () => "/tmp/x.node" })`
 * loads `/tmp/x.node`, verified on Node 20 and 22. capwall required `typeof raw === "string"`
 * and recorded `<unknown>` for anything else, which skipped the OWNER half of the two-subject
 * check in {@link gateNativeLoad} — the half that stops a package with its own `native` grant
 * from loading someone else's `.node` (#99).
 *
 * So the conversion happens ONCE, here, and the resulting STRING is what gets forwarded: the
 * same pin the egress shims apply to a URL argument, for the same reason — a `toString` that
 * answered differently on Node's own conversion would otherwise load a file the gate never saw.
 */
interface ResolvedAddon {
  /** Absolute path for attribution and the policy decision. */
  path: string;
  /** The pinned filename argument to forward, or `undefined` to forward the caller's value. */
  forward: string | undefined;
}

/**
 * Normalize the filename `dlopen` was handed into something attributable and loggable.
 *
 * `Module._extensions[".node"]` passes `path.toNamespacedPath(filename)`, which on Windows
 * prefixes `\\?\` — that prefix would defeat the `node_modules` scan in `packageForPath`, so
 * it is stripped before resolving. A direct caller may pass a relative path, so resolve
 * against the cwd the way the OS loader will.
 */
function normalizeAddonPath(raw: string): string {
  if (raw === "") return UNKNOWN_ADDON;
  // Strip the Windows extended-length prefix (`\\?\C:\...`, or `\\?\UNC\server\share`).
  const stripped = raw.startsWith("\\\\?\\UNC\\")
    ? "\\\\" + raw.slice(8)
    : raw.startsWith("\\\\?\\")
      ? raw.slice(4)
      : raw;
  try {
    return path.resolve(stripped);
  } catch {
    return stripped;
  }
}

/**
 * Perform Node's own string conversion of the filename argument ONCE, and report both the path
 * to gate on and the pinned value to forward. See {@link ResolvedAddon}.
 *
 * A conversion that THROWS (a symbol, an object whose `toString` throws) propagates nothing:
 * the load is still gated, on `<unknown>`, and the caller's value is forwarded so the real
 * `dlopen` raises the identical error it would have raised without capwall.
 */
function resolveAddon(raw: unknown): ResolvedAddon {
  if (typeof raw === "string") return { path: normalizeAddonPath(raw), forward: undefined };
  try {
    const converted = String(raw); // the ONE conversion — Node's `node::Utf8Value`, in JS
    return { path: normalizeAddonPath(converted), forward: converted };
  } catch {
    return { path: UNKNOWN_ADDON, forward: undefined };
  }
}

/**
 * Which package OWNS the addon file — the second of the two subjects a load is charged to.
 *
 * `packageForPath` answers "which `node_modules/<pkg>` is this file under", and reports
 * "none" as {@link APP_ROOT}. For a `.node` file that is right for the project's own build
 * output (`./build/Release/x.node`) and WRONG for a file that merely happens to sit somewhere
 * on the disk: an addon written to a temp dir and dlopened would be charged to `<app>`, the
 * trust root — the exact fail-open that issue #60 closed for the stack walk, reappearing by a
 * different route. So an un-owned file OUTSIDE the project root is {@link UNATTRIBUTED}
 * instead, gated like any other principal rather than riding on the app's grants.
 */
function ownerOfAddon(ctx: ShimContext, addonPath: string): string {
  const pkg = packageForPath(addonPath, ctx.projectRoot);
  if (pkg !== APP_ROOT) return pkg;
  const root = ctx.projectRoot;
  if (root === undefined) return UNATTRIBUTED; // no root to judge "inside the project" against
  const rel = path.relative(root, addonPath);
  const insideProject = rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
  return insideProject ? APP_ROOT : UNATTRIBUTED;
}

/**
 * Decide whether this `dlopen` may proceed, recording the decision(s) and throwing a
 * {@link CapabilityError} in enforce mode when it may not.
 *
 * TWO SUBJECTS, BOTH MUST BE GRANTED — and this is the substantive design call in this file.
 *
 * capwall's usual rule is "charge the nearest package frame on the stack". Empirically (see
 * `test/native.test.ts`) that rule DOES reach a real package frame for a native load: the
 * frames between `process.dlopen` and the requiring module are all `node:internal/modules/*`,
 * which the attribution walk already skips as non-filesystem paths. So a package that
 * `require`s its own addon directly is attributed correctly.
 *
 * But that is the minority shape in the real world. Most native packages load through a
 * shared helper — `bindings`, `node-gyp-build` — and those helpers call `require` from THEIR
 * OWN file, so the nearest package frame is the helper, not the package whose addon is being
 * loaded. Under caller-only attribution the generated policy would read
 * `"node-gyp-build": { "native": true }`, a single grant that every native package in the
 * tree then loads through: a skeleton key, and an unusually good one, because it is exactly
 * the grant an `observe` run tells you to write. This is the documented attribution-laundering
 * limitation (docs/threat-model.md), but for this capability it is not an edge case — it is
 * the common path, so it is worth closing here rather than documenting away.
 *
 * The fix uses information this capability has and the others do not: the addon's own file
 * path names a package. So the load is charged to BOTH
 *
 *   1. the CALLER — the nearest package frame, capwall's normal attribution; and
 *   2. the OWNER — see {@link ownerOfAddon}: the package the `.node` file lives in, `<app>`
 *      for the project's own build output, `<unknown>` for a file belonging to neither,
 *
 * and the load proceeds only if BOTH are granted `native`. Neither alone is sufficient, and
 * neither alone is safe: owner-only would let a malicious package launder a load through any
 * granted package's addon path; caller-only is the skeleton-key case above. Both are recorded,
 * so an `observe` run emits both grants and the round-trip still works with no hand editing.
 *
 * Both decisions are recorded BEFORE anything throws, so an enforce-mode denial still shows
 * the operator the full picture (which of the two subjects was missing the grant) instead of
 * only the first.
 *
 * THIS GATE DELIBERATELY DOES NOT USE THE `guard(ctx, hideAbove, req)` FAST PATH (#143). Every
 * other guarded surface hands its own entry frame to `Error.captureStackTrace` so the caller sits
 * at frame 0 and a 3-frame capture answers instead of a 25-frame one. That argument does not hold
 * here, and the frames say so: measured on Node 22, `require('x.node')` reaches `process.dlopen`
 * through SEVEN frames of `node:internal/modules/*` (plus capwall's own `Module._load` link)
 * before the requiring package's frame appears. A 3-frame prefix would therefore find nothing but
 * neutral machinery on every real addon load, decline, and pay the short capture ON TOP OF the
 * full walk — a regression dressed as an optimization. Sizing the shared prefix for this shape
 * instead would make every `fs` and `net` call pay for a gate that fires a handful of times per
 * process and is dominated by `dlopen` itself. So this one stays on the full walk, on purpose.
 */
function gateNativeLoad(ctx: ShimContext, resolved: ResolvedAddon): void {
  const addonPath = resolved.path;
  const { pkg: caller, budgetExhausted } = attributeCallerDetailed(attributionOptionsFor(ctx));
  const owner = addonPath === UNKNOWN_ADDON ? caller : ownerOfAddon(ctx, addonPath);
  // Dedup: the overwhelmingly common shape is a package requiring its own addon, where
  // caller === owner and there is exactly one subject and one recorded decision.
  const subjects = caller === owner ? [caller] : [caller, owner];

  let firstDenial: { pkg: string; decision: Decision } | undefined;
  for (const subject of subjects) {
    const decision = evaluate(ctx.policy, ctx.mode, subject, {
      kind: "native",
      path: addonPath,
    });
    // `attributionTruncated` describes the STACK WALK, so it only ever applies to the caller
    // subject — the owner subject came from the file path and no frame budget was involved.
    ctx.onDecision(
      subject,
      budgetExhausted && subject === caller
        ? { ...decision, attributionTruncated: true }
        : decision,
    );
    if (!decision.allowed && !firstDenial) firstDenial = { pkg: subject, decision };
  }

  if (firstDenial) {
    // A SYNCHRONOUS THROW is both the honest enforcement and the API-faithful one. `require`
    // of a `.node` whose `dlopen` fails throws synchronously in real Node too (a bad ELF, a
    // missing shared library), so a denial arrives through the channel a caller already has
    // to handle — and the resolver wrappers above all `require` inside a try/catch, so a
    // denial surfaces to them as "this candidate did not load", exactly like a missing file.
    // It matches the other boolean gates (`vm`, `child_process`, `worker_threads`), which
    // also throw. Consequence, stated plainly: for a package with no fallback, a denied load
    // usually crashes the app at startup. That is the intended failure mode — silently
    // returning an addon-less module object would hand the caller a broken binding and turn a
    // policy gap into a mysterious runtime error far from its cause.
    throw new CapabilityError(firstDenial.decision.reason, firstDenial.pkg);
  }
}

/**
 * The `process.dlopen` gate, as a shared relink chain (`lifecycle/process-patch.ts`).
 *
 * This site STACKS (`defineRelinkedPatch`), like `Module._load` and unlike the `_compile` gate:
 * each install carries its own `ctx`, so each install's gate must fire. Tests install and
 * uninstall overlapping windows, and an out-of-LIFO-order `uninstall()` relinks around the
 * removed link rather than restoring a stale reference — which would either resurrect a dead
 * gate or drop a live one (#22, made structural by #107).
 */
const dlopenPatch = defineRelinkedPatch<Dlopen>("process.dlopen", {
  slot: valueSlot<Dlopen>("process.dlopen", () => process, "dlopen"),
  patch: (ctx, link) =>
    function (this: unknown, ...args: unknown[]) {
      const resolved = resolveAddon(args[1]); // the ONE string conversion (#99)
      gateNativeLoad(ctx, resolved); // throws on enforce-deny, before the addon is mapped in
      // Forward with the ORIGINAL arity. `process.dlopen`'s third parameter has a default
      // (`RTLD_LAZY`); passing an explicit `undefined` in its place defeats the default and the
      // real call fails with "invalid mode for dlopen()" — an accidental denial-of-service on
      // every native package. Spreading `args` preserves arity exactly.
      if (resolved.forward === undefined) return Reflect.apply(link.next, this, args);
      // A non-string filename: forward the PINNED conversion so the file the OS loader opens is
      // provably the one the gate decided about, not whatever a second `toString` returns.
      const pinnedArgs = args.slice();
      pinnedArgs[1] = resolved.forward;
      return Reflect.apply(link.next, this, pinnedArgs);
    },
});

/**
 * Install the native-addon load gate for the current process by patching `process.dlopen`.
 *
 * Called from `install()`; there is deliberately no opt-out flag. Unlike the `process.env`
 * Proxy (which has a measurable cost on a hot read path and can therefore be disabled),
 * `dlopen` is called a handful of times per process at most, so the gate is free — and a
 * gate against arbitrary compiled code is not one to make convenient to switch off.
 */
export function installNativeGate(ctx: ShimContext): NativeGateHandle {
  return dlopenPatch.install(ctx);
}
