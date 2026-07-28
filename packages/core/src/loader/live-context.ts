/**
 * THE LIVE INSTALL CONTEXT — one long-lived box every mediated surface reads, plus the install
 * stack that decides what it points at (issues #62 / #87).
 *
 * WHY THIS EXISTS. capwall's shims are handed out once and then CAPTURED: a CJS module does
 * `const fs = require("node:fs")` at load time, an ESM synthetic module binds `getEsmShim()`'s
 * result into `const` export bindings that can never be revisited, and `process.env` /
 * `globalThis.fetch` are routinely stashed in a module-level variable. Whatever those captures
 * point at is what enforces policy for the rest of the process.
 *
 * So if each `install()` builds its own shims against its own context object, the policy a
 * dependency is subject to is decided by WHEN it happened to first touch the capability, not by
 * which install is currently in force. `uninstall()` + `install(tighterPolicy)` then changes
 * nothing for anything already captured — fail-OPEN with respect to the new policy — while a
 * freshly-required builtin correctly denies, so one process enforces two different policies at
 * once. That was #62 on the ESM path and #87 on the CJS path; the CJS half also kept firing
 * `onDecision` into the torn-down install's collector.
 *
 * THE FIX — mutability one level down. Every shim already reads `ctx.policy` / `ctx.mode` /
 * `ctx.onDecision` / `ctx.projectRoot` / `ctx.maxFrames` at CALL time (see `shims/runtime.ts`
 * `guard`), never at build time. So the registries are built exactly ONCE against {@link liveCtx},
 * whose IDENTITY never changes and whose FIELDS are re-pointed on every install/uninstall. Every
 * capture — old or new, CJS or ESM — follows the live policy. Cost per intercepted call: zero. No
 * proxy, no forwarder, no extra indirection; the shims stay plain objects a `graceful-fs`-style
 * monkey-patcher can work with.
 *
 * ONE BOX FOR THE WHOLE PROCESS, not one per interception path. The CJS loader, the ESM runtime
 * bridge, the `process.env` guard, the global-egress guard and the native-addon gate all read
 * this same context, so they cannot disagree about which policy is in force. #87 found exactly
 * that disagreement: `process.env` rebuilt its proxy per install (and so DID tighten) while the
 * CJS `fs` shim did not, which is worse than either behaviour applied consistently.
 *
 * WHAT IS *NOT* LIVE, and why: `hardened` (#17) is consumed at shim-BUILD time — it freezes the
 * objects as they are created, and a frozen object cannot be un-frozen. A capture therefore keeps
 * the hardening of the install that first built it. {@link liveRegistry} honours the live
 * hardened-ness for FRESHLY handed-out shims by memoizing one registry per hardened-ness.
 *
 * HARDENED IS A RATCHET, NOT A PER-INSTALL SETTING (issue #129). This is the precedence rule the
 * memoization note used to leave unstated, and getting it wrong was a real downgrade: `hardened`
 * was taken from whichever install was NEWEST, so with a `hardened: true` install still active, a
 * later `install({ hardened: false })` made every subsequent `require("node:fs")` hand back an
 * UNFROZEN shim — which a dependency can then monkey-patch, process-wide and unlogged, which is
 * the exact one-liner hardened mode exists to close. `install({ hardened: true })` had verified
 * its post-condition (#103) and returned a handle; nothing revoked or re-checked that promise,
 * and nothing warned.
 *
 * It was also inconsistent with the OTHER HALF OF THE SAME OPTION. The egress globals are already
 * a ratchet: `GlobalPropertySlot.pin` is applied by `refresh` on every install and nothing
 * un-pins until the last install restores the saved descriptors (`shims/global-egress.ts` §
 * `pinGlobalEgress`). One `install({ hardened: false })` therefore left the process HALF-hardened,
 * and which half you saw depended on which surface you looked at — so a reader could not tell
 * which of the two behaviours was the bug.
 *
 * THE RULE, now uniform across every surface: **hardened engages when any install asks for it and
 * lifts only when capwall fully uninstalls.** Deliberately matching the egress ratchet rather than
 * the narrower "while the hardened install is active", because the whole complaint in #129 is the
 * asymmetry, and because un-hardening while capwall is still mediating would hand a dependency a
 * window in which a still-mediated surface became patchable again. #97's principle drives the
 * direction: a security option accepted and then silently revoked is worse than one refused.
 *
 * WHAT IT STILL DOES NOT DO, and this is a property of freezing rather than of precedence: a
 * reference captured BEFORE the hardened install arrived stays unfrozen forever. `install({
 * hardened: true })` freezes what it hands out from then on; it cannot reach back into a `const fs
 * = require("node:fs")` some module already holds. Install capwall early — that is what the
 * `--import` preload is for.
 */
import { buildShimRegistry } from "../shims/index.js";
import type { ShimContext, ShimRegistry } from "../shims/runtime.js";
import type { Policy } from "@capwall/policy-schema";

/**
 * The policy in force when NO install is active. Deny-by-default under `enforce`, so a shim that
 * some module captured while capwall WAS installed fails CLOSED after teardown rather than
 * continuing to serve the torn-down install's grants.
 *
 * This is deliberately NOT "pass through to the real builtin". A capture cannot be revoked — an
 * ESM `const` binding is immutable and a CJS module's `const fs = require(...)` is private to it
 * — so "capwall is off again for code that already captured a shim" is not on the menu; the only
 * choices are the dead policy or a deny-all one. Refusing is the honest one, and it matches what
 * a FRESH access sees after teardown closely enough to be predictable: fresh access is
 * un-mediated because `Module._load` / `process.env` / the globals are genuinely restored, while a
 * stale capture is mediated by a policy that grants nothing. Neither one silently keeps enforcing
 * grants that were revoked.
 */
export const TORN_DOWN_POLICY: Policy = { version: 1, mode: "enforce", default: {}, packages: {} };

/**
 * Installs in order, oldest first; the last entry is the one whose policy is in force. A STACK
 * rather than a single slot, mirroring the `_load` chain `patchRequire` maintains, so an
 * out-of-order `uninstall()` falls back to whatever install is still active instead of tearing
 * everything down. Nested installs mean "the innermost one wins"; unwinding one re-exposes the
 * one below it, and unwinding the last one hits {@link TORN_DOWN_POLICY}.
 */
const installs: ShimContext[] = [];

/**
 * The live box's OWN type: every optional {@link ShimContext} field is present-but-possibly-
 * `undefined` rather than absent.
 *
 * WHY, and this is a measurement rather than a style preference. Re-pointing the box used to
 * `delete` the fields an install did not set, and repeated add/delete cycles push an object into
 * V8's DICTIONARY (slow-properties) mode — `%HasFastProperties(liveCtx)` flips to `false` after a
 * few hundred install/uninstall pairs. That would put a slow property load on `ctx.policy`,
 * `ctx.mode` and `ctx.onDecision`, which EVERY guarded call reads: exactly the per-call cost this
 * whole design exists to avoid. A fixed shape keeps the box in fast properties forever.
 *
 * Writing `undefined` is behaviourally identical to deleting, because every consumer already
 * tests `!== undefined` (`attributionOptionsFor`, `native.ts`) or `=== true` (`harden.ts`,
 * `global-egress.ts`) — none uses `in`, `Object.keys` or a spread of the context. The only thing
 * that objects is `exactOptionalPropertyTypes`, a type-level rule about the PUBLIC
 * `ShimContext`; this local type is the internal view that the rule does not apply to.
 */
interface LiveContext extends Omit<ShimContext, "projectRoot" | "maxFrames" | "hardened"> {
  projectRoot: string | undefined;
  maxFrames: number | undefined;
  hardened: boolean | undefined;
}

/**
 * The single context object every shim closes over. Its identity never changes; only its fields
 * do. Never export a way to REPLACE it — anything holding it could re-point the live policy — but
 * it is handed to the guards that need to read it (see `index.ts`).
 */
const liveBox: LiveContext = {
  policy: TORN_DOWN_POLICY,
  mode: "enforce",
  onDecision: () => {},
  projectRoot: undefined,
  maxFrames: undefined,
  hardened: undefined,
};

/** The same object, seen through the public shim-facing type. */
export const liveCtx = liveBox as ShimContext;

/** True while at least one install is active. */
let installed = false;

/**
 * Hardened mode's ratchet state (#129): has any install in the CURRENT install era asked for it?
 *
 * Reset only when the stack empties, which is the same moment `shims/global-egress.ts` lets the
 * egress pin go — that alignment is the point. Not derived from `installs.some(…)` on each call,
 * because that would silently un-harden the moment the hardened install unwound while another was
 * still mediating, re-opening the downgrade one step later.
 */
let hardenedRatchet = false;

/**
 * Subscribers notified whenever {@link liveCtx} is re-pointed (issue #123).
 *
 * WHY THIS EXISTS, given that the whole design is "everyone reads the same live box". It existed
 * for ONE consumer that could not read the box: while capwall's module-customization hooks ran on
 * Node's separate loader thread (`module.register()`), they held a COPY of the policy and it had
 * to be re-sent whenever the original changed. #152 moved them to `module.registerHooks()`, which
 * runs them in this realm reading `liveCtx` directly, so that consumer is gone and this has no
 * subscribers in `src` today.
 *
 * KEPT RATHER THAN DELETED, and the reason is the rule rather than the API: an out-of-realm or
 * out-of-process mediator is a shape capwall may need again (a permission-model sandbox, a second
 * realm), and this is the only place that knows when the live context was re-pointed. Nothing
 * IN-realm may use it to cache policy state — a consumer that reads `liveCtx` directly is always
 * correct and never needs a notification, and a cache here is how #62/#87 came back.
 */
type LiveContextListener = (ctx: ShimContext, installed: boolean) => void;
const contextListeners = new Set<LiveContextListener>();

/**
 * Subscribe to live-context changes, and receive the CURRENT state immediately — so a subscriber
 * registered mid-install never has to reconstruct what it missed. Returns an unsubscribe function.
 */
export function onLiveContextChange(listener: LiveContextListener): () => void {
  contextListeners.add(listener);
  notifyOne(listener);
  return () => contextListeners.delete(listener);
}

/**
 * Re-point {@link liveCtx} at the newest install, or at the torn-down policy if there is none.
 *
 * ONE FIELD IS NOT THE NEWEST INSTALL'S: `hardened` is a ratchet over every install in the current
 * era (#129), not last-writer-wins. Everything else is the top of the stack. Adding a field means
 * deciding which of those two it is — "newest wins" is right for a POLICY (that is #62/#87's whole
 * point) and wrong for a SECURITY FLOOR, which is what #129 was.
 *
 * EVERY field of {@link LiveContext} must be assigned on BOTH branches. A field added to
 * `ShimContext` and not mirrored here would silently keep the PREVIOUS install's value — which is
 * the #62/#87 bug in miniature, one field at a time. Deliberately not written as a loop or an
 * `Object.assign`: the explicit list is what a reviewer can check against `ShimContext`, and
 * `Object.assign` would also copy any junk key an install object happened to carry.
 */
function applyTopOfStack(): void {
  const top = installs[installs.length - 1];
  if (top === undefined) {
    liveBox.policy = TORN_DOWN_POLICY;
    liveBox.mode = "enforce";
    // Drop the sink with the install that owned it: reporting a post-teardown denial into a
    // torn-down embedder's collector (or the CLI's trace file) would be a use-after-free of
    // someone else's state — a decision belonging to no install, landing in the previous one's
    // gen-policy trace. The denial still THROWS, which is the visible, actionable part.
    liveBox.onDecision = () => {};
    liveBox.projectRoot = undefined;
    liveBox.maxFrames = undefined;
    liveBox.hardened = undefined;
    // The last install is gone and everything it patched is restored, so the ratchet releases
    // here and only here — the same boundary the egress pin uses.
    hardenedRatchet = false;
    installed = false;
    notifyContextListeners();
    return;
  }
  liveBox.policy = top.policy;
  liveBox.mode = top.mode;
  liveBox.onDecision = top.onDecision;
  liveBox.projectRoot = top.projectRoot;
  liveBox.maxFrames = top.maxFrames;
  // `hardened` is the ONE field that is not taken from the top of the stack (#129). It is a
  // ratchet over every active install, not the newest install's opinion; see the header.
  if (!hardenedRatchet && installs.some((ctx) => ctx.hardened === true)) hardenedRatchet = true;
  liveBox.hardened = hardenedRatchet;
  installed = true;
  notifyContextListeners();
}

/**
 * Run every subscriber, ISOLATING FAILURES. A listener that throws must not abort an install or
 * an `uninstall()` partway through — that is #107's bug 3 in a new place, and the cure is the
 * same: report and carry on, because a half-applied lifecycle transition is strictly worse than
 * a noisy one.
 */
function notifyContextListeners(): void {
  for (const listener of contextListeners) notifyOne(listener);
}

function notifyOne(listener: LiveContextListener): void {
  try {
    listener(liveCtx, installed);
  } catch (err) {
    process.stderr.write(
      `[capwall] WARN a live-context listener threw and was ignored: ` +
        `${err instanceof Error ? err.message : String(err)}\n`,
    );
  }
}

/** Activate `ctx`. The newest install wins, exactly as the newest `_load` patch does. */
export function pushInstall(ctx: ShimContext): void {
  installs.push(ctx);
  applyTopOfStack();
}

/**
 * Deactivate ONE activation of `ctx`. Removing an install that is not on top relinks to whatever
 * remains active; removing the last one puts the process into the fail-closed torn-down state.
 * A context pushed twice (the CJS patch and the ESM hook each activate the install they belong
 * to) needs two pops, which is exactly what `install()`'s handle list does. Idempotent: popping a
 * context that is no longer on the stack is a no-op.
 */
export function popInstall(ctx: ShimContext): void {
  const idx = installs.lastIndexOf(ctx);
  if (idx === -1) return;
  installs.splice(idx, 1);
  applyTopOfStack();
}

/** True while at least one install is active; drives the ESM bridge's fail-closed error. */
export function isInstalled(): boolean {
  return installed;
}

/**
 * Registries, memoized by interception path and hardened-ness. Built lazily and then reused
 * forever, because reuse is the whole point: a rebuilt registry would hand out NEW shim objects
 * and leave every existing capture pinned to the policy of the install that built the old ones.
 *
 * CJS and ESM get SEPARATE registries even though they share {@link liveCtx}: `buildShimRegistry`
 * makes fresh shim objects, so enforcement is identical (same context) but a monkey-patch a
 * dependency applies to the CJS `fs` shim is not visible on the ESM one, and vice versa. That
 * split predates this module and is documented in `esm-runtime.ts`.
 */
const registries = new Map<string, ShimRegistry>();

/**
 * The shim registry for one interception path, built against {@link liveCtx} (see above).
 *
 * Keyed by hardened-ness because a frozen shim cannot be un-frozen, so the two populations have to
 * be separate objects. Which key is live is decided by the RATCHET, not by the newest install
 * (#129): with a hardened install active this returns the frozen registry no matter what options
 * a later install passed.
 */
export function liveRegistry(path: "cjs" | "esm"): ShimRegistry {
  const key = `${path}:${liveBox.hardened === true ? "hardened" : "plain"}`;
  let reg = registries.get(key);
  if (reg === undefined) {
    reg = buildShimRegistry(liveCtx);
    registries.set(key, reg);
  }
  return reg;
}
