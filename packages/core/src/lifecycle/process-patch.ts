/**
 * PROCESS-PATCH LIFECYCLE — the one shape every process-level patch capwall installs must have
 * (issue #107).
 *
 * THE RULE. Every process-level patch capwall installs is a REFERENCE-COUNTED RELINK CHAIN,
 * never a bare save/restore. A bare save/restore silently assumes two things that stop being
 * true the moment a second `install()` exists:
 *
 *   1. that capwall is the only patcher of that location, and
 *   2. that teardown is LIFO.
 *
 * `Module._load` and `process.dlopen` were written against a relink chain from the start (#22).
 * `process.env`, the egress globals and `Module.prototype._compile` were not, and every omission
 * was its own bug — all three found by #103's lifecycle tests, all fixed pointwise, and #107 is
 * the ticket that says "stop fixing this one site at a time":
 *
 *   - an out-of-LIFO-order `uninstall()` left capwall's proxy on `process.env` and capwall's
 *     wrapper on `globalThis.fetch` PERMANENTLY, reading the deny-all torn-down policy for the
 *     rest of the process — in direct contradiction of `InstallHandle.uninstall`'s own docs;
 *   - a nested `installEnvGuard` captured the FIRST guard's proxy and registered it as the
 *     "un-proxied" environment, so a GRANTED `spawn` launched its child with a completely empty
 *     environment (81 keys → 0, measured). That is #86's shape: the denied path fine, the
 *     ALLOWED path broken;
 *   - `uninstall()` could throw a `TypeError` from a global some other code had made
 *     non-configurable, which aborted `install()`'s teardown loop and stranded the loader patch,
 *     the env proxy and the dlopen gate still installed.
 *
 * Nothing in the type system or a review checklist catches a bare save/restore. So this module
 * makes the correct shape the EASY shape, and `test/process-patch-sites.test.ts` makes the
 * incorrect shape a test failure: **every write to a process-level location in `packages/core/src`
 * lives in this file**, so a new patch site physically cannot mutate a global without coming
 * through here, and coming through here means it is refcounted, relinked, order-independent and
 * failure-isolated by construction.
 *
 * ── TWO PRIMITIVES, BECAUSE THE SITES ARE GENUINELY NOT THE SAME ────────────────────────────
 * They differ on ONE axis — whether a nested install may add a second layer — and that axis is
 * load-bearing, not cosmetic. Hiding it behind a boolean flag on one helper would be a flag
 * nobody reads correctly, so it is two names instead:
 *
 *  - {@link defineRelinkedPatch} — STACKS. Each install adds a link and every install's guard
 *    runs. `Module._load` and `process.dlopen` need this: two installs may hold different
 *    contexts, and a relink is what lets a middle layer be removed without leaking it.
 *
 *  - {@link defineSharedPatch} — DOES NOT STACK. Exactly one patch per process, reference
 *    counted; the count only decides WHEN to put the original back. `Module.prototype._compile`
 *    REQUIRES this and would break loudly under the other one (#100): the gate asks who called
 *    it one frame up, so a second patch in front of it means the inner patch sees capwall's own
 *    frame instead of `node:internal/modules/…`, concludes a user called `_compile`, and gates
 *    EVERY `require` in the process. `process.env` and the egress globals require it too — a
 *    stacked proxy double-gates and double-records every read.
 *
 * Not stacking is safe for all three BECAUSE OF #87: every guard reads `liveCtx`, one box whose
 * identity never changes and whose fields the install stack re-points, so a single patch already
 * tracks whichever install is in force.
 *
 * ── WHAT EVERY HANDLE GUARANTEES ────────────────────────────────────────────────────────────
 *  - `uninstall()` is IDEMPOTENT. Calling it twice removes one activation, never two.
 *  - `uninstall()` NEVER THROWS. Site callbacks that touch a location some other code has made
 *    non-configurable are isolated here, so one handle can never strand another (bug 3 above).
 *  - `uninstall()` is ORDER-INDEPENDENT. Removing the OUTER install first leaves the inner one
 *    in force and restores nothing early; removing the LAST one restores the original.
 *  - A patch is only ever restored if the location still holds the value capwall installed, so a
 *    later legitimate replacement is never clobbered.
 *
 * ── COST ────────────────────────────────────────────────────────────────────────────────────
 * Zero per mediated call. A relinked patch delegates through `link.next`, a plain property read
 * on a monomorphic object — the identical shape the hand-written chains used, deliberately NOT a
 * `next()` accessor, which would have added a call to every non-mediated `require`. A shared
 * patch adds nothing at all: it hands the site the original and gets out of the way. The
 * refcount and the registry are touched only at install/uninstall time.
 */
import type { ShimContext } from "../shims/runtime.js";

/** What every process-level patch hands back. See the guarantees in the header. */
export interface PatchHandle {
  /** Release ONE activation. Idempotent, order-independent, and never throws. */
  uninstall(): void;
}

/** A patch capwall can install into the current process, once per `install()`. */
export interface ProcessPatch {
  install(ctx: ShimContext): PatchHandle;
}

/**
 * The relink node a stacking patch delegates through. `next` is MUTABLE and must be read at
 * CALL time, never captured in a `const` at install time — that is exactly what lets an
 * out-of-LIFO-order removal relink around a middle layer instead of resurrecting a dead one.
 */
export interface Relink<T> {
  readonly next: T;
}

/* ============================================================================================
 * SLOTS — the only code in capwall that writes a process-level location.
 * ========================================================================================== */

/**
 * One replaceable location in the process.
 *
 * WHY THE WRITES LIVE HERE AND NOWHERE ELSE. `test/process-patch-sites.test.ts` scans
 * `packages/core/src` for assignments to `process.*` / `globalThis.*` / a `Module` prototype (and
 * to any local alias of those) and fails on any hit outside this file. That is the mechanism that
 * makes a WRONG new patch site fail automatically rather than being caught in review: there is
 * no way to reach a process global except through a slot, and no way to hold a slot except
 * through {@link defineRelinkedPatch} / {@link defineSharedPatch}.
 *
 * Every method is total — `write` and `restore` report refusal as `false` rather than throwing,
 * because un-mediated code is allowed to make a global non-writable or non-configurable and
 * capwall must degrade rather than crash a host app (or, worse, abort a teardown loop partway).
 */
export interface PatchSlot<T> {
  /** How the location is spelled, for diagnostics and for the site inventory. */
  readonly name: string;
  /** Current value, or `undefined` when the location does not exist on this runtime. */
  read(): T | undefined;
  /** Install `value`. `false` when the location refused it. Never throws. */
  write(value: T): boolean;
  /**
   * Put `original` back, but ONLY if the location still holds `installed` — otherwise something
   * else replaced it after capwall did and restoring would clobber a patch capwall does not own.
   * Never throws.
   */
  restore(original: T, installed: T): boolean;
}

/**
 * A slot backed by a plain writable data property (`Module._load`, `process.dlopen`,
 * `process.env`, `Module.prototype._compile`).
 *
 * `holder` is a THUNK rather than the object itself so a location whose owner is resolved lazily
 * (or is absent on an exotic runtime) reports "nothing to patch" instead of throwing at module
 * evaluation time.
 */
export function valueSlot<T>(
  name: string,
  holder: () => object | undefined,
  key: string,
): PatchSlot<T> {
  const read = (): T | undefined => {
    const obj = holder();
    if (obj === undefined || obj === null) return undefined;
    let value: unknown;
    try {
      value = (obj as Record<string, unknown>)[key];
    } catch {
      return undefined;
    }
    return value === undefined ? undefined : (value as T);
  };
  const write = (value: T): boolean => {
    const obj = holder();
    if (obj === undefined || obj === null) return false;
    try {
      (obj as Record<string, unknown>)[key] = value as unknown;
    } catch {
      // A non-writable / non-configurable property, or a `process` some embedder has frozen.
      return false;
    }
    // Sloppy-mode assignment to a non-writable property fails SILENTLY, so the write is verified
    // rather than assumed. A patch that thinks it installed and did not would be a fail-open.
    return read() === value;
  };
  return {
    name,
    read,
    write,
    restore(original, installed) {
      if (read() !== installed) return false;
      return write(original);
    },
  };
}

/**
 * A capwall-replaced `globalThis` property, with everything needed to put it back exactly as it
 * was. Handed out by {@link globalPropertySlot} and stored in the owning patch's state.
 */
export interface GlobalReplacement {
  readonly name: string;
  /** The descriptor as it stood immediately before capwall wrote — restored verbatim. */
  readonly saved: PropertyDescriptor;
  /** What capwall installed, so a restore can tell "still ours" from "someone else's". */
  readonly installed: unknown;
}

/**
 * A slot for a `globalThis` property (`fetch`, `WebSocket`, `EventSource`).
 *
 * Not a {@link PatchSlot}: a global is replaced through a full property DESCRIPTOR, because the
 * blast radius of writing to `globalThis` makes the restore contract stricter than for a plain
 * data property (see shims/global-egress.ts). The invariants this enforces on every caller:
 *
 *  - capwall never ADDS a global — a location that is absent, or not a function, is declined.
 *  - capwall never installs a NON-CONFIGURABLE global, not even under hardened mode. A
 *    non-configurable global can never be restored by anyone, which would trade a documented
 *    residual for a permanent process-wide mutation that outlives `uninstall()`.
 *  - a location capwall could not restore later is never replaced in the first place.
 */
export interface GlobalPropertySlot {
  readonly name: string;
  /** The value currently on `globalThis`, whatever it is. */
  current(): unknown;
  /** Replace via `make(real)`, or `null` when the global is absent / cannot be restored later. */
  replace(make: (real: unknown) => unknown, pin: boolean): GlobalReplacement | null;
  /** Hardened mode's ratchet (#17): make the installed value non-writable. Never throws. */
  pin(replacement: GlobalReplacement): void;
  /** Is capwall's value still in place AND non-writable? */
  isPinned(replacement: GlobalReplacement): boolean;
  /** Restore the saved descriptor, if capwall's value is still in place. Never throws. */
  restore(replacement: GlobalReplacement): void;
}

/** THE global object, typed for property access. The one alias in capwall that may be written. */
const globals = globalThis as unknown as Record<string, unknown>;

export function globalPropertySlot(name: string): GlobalPropertySlot {
  const current = (): unknown => globals[name];
  return {
    name,
    current,
    replace(make, pin) {
      // Read BEFORE snapshotting the descriptor: some Node globals are installed as one-shot
      // lazy accessors that materialize into a data property on first access, and the descriptor
      // worth restoring is the post-materialization one.
      const real: unknown = globals[name];
      if (typeof real !== "function") return null; // absent on this Node / behind an unset flag
      const saved = Object.getOwnPropertyDescriptor(globals, name);
      // `configurable !== true` means capwall could never put the original back — so it does not
      // take the global at all, rather than taking it irreversibly.
      if (saved === undefined || saved.configurable !== true) return null;
      const installed = make(real);
      try {
        Object.defineProperty(globals, name, {
          value: installed,
          // Hardened mode (#17) closes the one-line `globalThis.fetch = evil`.
          writable: !pin,
          enumerable: saved.enumerable === true,
          configurable: true, // NEVER false — uninstall() must be able to put the original back
        });
      } catch {
        return null;
      }
      return { name, saved, installed };
    },
    pin(replacement) {
      if (globals[name] !== replacement.installed) return; // someone else's value — not ours to pin
      try {
        Object.defineProperty(globals, name, {
          value: replacement.installed,
          writable: false,
          enumerable: replacement.saved.enumerable === true,
          configurable: true, // NEVER false — see above
        });
      } catch {
        // Un-mediated code can pin a global non-configurable, and then nobody — including capwall
        // — can redefine it. Swallowing here is not ignoring it: the caller's hardening self-check
        // still reports the property as un-pinned and `install()` refuses the hardened install
        // rather than running with a security option it could not apply (#97).
      }
    },
    isPinned(replacement) {
      if (globals[name] !== replacement.installed) return true; // not our claim to make
      const desc = Object.getOwnPropertyDescriptor(globals, name);
      return desc !== undefined && desc.writable === false;
    },
    restore(replacement) {
      // Only put the original back if OUR value is still there — otherwise something else
      // replaced the global after us and restoring would clobber it.
      if (globals[name] !== replacement.installed) return;
      try {
        Object.defineProperty(globals, name, replacement.saved);
      } catch {
        // Un-mediated code can make a global NON-CONFIGURABLE after capwall installed its
        // (configurable) replacement, and then the restore is impossible for anyone. Letting the
        // `TypeError` escape would abort `install()`'s teardown loop partway through and leave
        // the loader patch, the env proxy and the dlopen gate installed forever — a failure far
        // worse than the one global capwall cannot take back. `uninstall()` must never throw.
      }
    },
  };
}

/* ============================================================================================
 * THE SITE REGISTRY — what makes a new patch site testable without anyone remembering to.
 * ========================================================================================== */

/** Which lifecycle a site has. See the two primitives in the header. */
export type PatchKind = "relinked" | "shared";

/**
 * One registered process-level patch, as `test/process-patch-lifecycle.test.ts` sees it.
 *
 * The registry is the second half of the enforcement mechanism. The source scan proves a new
 * patch site had to come through this file; the registry proves the resulting site is EXERCISED
 * by the lifecycle suite — nested install, out-of-LIFO-order teardown, idempotent uninstall,
 * full restore — without anyone remembering to add it there. A site that skips the helper fails
 * the scan; a site that uses the helper is automatically enrolled in the tests.
 */
export interface RegisteredProcessPatch {
  readonly name: string;
  readonly kind: PatchKind;
  /** Chain length (relinked) or reference count (shared). `0` when nothing is installed. */
  depth(): number;
  /** The location's current value(s) — an identity snapshot for a before/after assertion. */
  probe(): readonly unknown[];
  install(ctx: ShimContext): PatchHandle;
}

const sites: RegisteredProcessPatch[] = [];

/**
 * Every process-level patch capwall knows how to install, in definition order.
 *
 * Only reachable once the defining module has been evaluated, which is why the lifecycle test
 * imports the whole public entry point first.
 */
export function processPatchSites(): readonly RegisteredProcessPatch[] {
  return sites;
}

/** A handle for a site that declined to patch anything (an absent global, an exotic runtime). */
const DECLINED: PatchHandle = Object.freeze({ uninstall(): void {} });

/* ============================================================================================
 * PRIMITIVE 1 — the stacking relink chain (`Module._load`, `process.dlopen`).
 * ========================================================================================== */

export interface RelinkedPatchSite<T> {
  /** The location to patch. */
  readonly slot: PatchSlot<T>;
  /**
   * Build this install's link. `link.next` MUST be read at call time — see {@link Relink}.
   * `ctx` is this install's context, so each layer keeps its own.
   */
  patch(ctx: ShimContext, link: Relink<T>): T;
}

interface ChainNode<T> {
  /** This link's patched value; its identity is how "am I still on top" is decided. */
  patched: T;
  /** What this link currently delegates to. Mutable — relinked on an out-of-order removal. */
  next: T;
}

/**
 * Define a STACKING process patch: every install adds a link and every link's guard runs.
 *
 * Use this when two concurrent installs must BOTH mediate — `Module._load` (each install may
 * route to a different registry) and `process.dlopen` (each install's gate must fire). Do NOT
 * use it for a patch that inspects its own caller: see {@link defineSharedPatch} and #100.
 */
export function defineRelinkedPatch<T>(name: string, site: RelinkedPatchSite<T>): ProcessPatch {
  /**
   * Every currently-installed link, oldest first. A plain array is enough to relink around an
   * out-of-order removal: the node immediately AFTER the removed one is exactly the node whose
   * `next` pointed at it, because nodes are appended in install order and each one only ever
   * delegates to the node installed immediately before it.
   */
  const chain: ChainNode<T>[] = [];

  const patch: ProcessPatch = {
    install(ctx) {
      const previous = site.slot.read();
      if (previous === undefined) return DECLINED; // nothing to chain onto on this runtime
      const node: ChainNode<T> = { next: previous, patched: undefined as unknown as T };
      node.patched = site.patch(ctx, node);
      if (!site.slot.write(node.patched)) {
        // The location refused the write. Do NOT push the node: a chain entry for a patch that
        // is not actually installed would relink a later uninstall onto a value nobody holds.
        return DECLINED;
      }
      chain.push(node);

      let uninstalled = false;
      return {
        uninstall() {
          if (uninstalled) return; // idempotent
          uninstalled = true;
          const idx = chain.indexOf(node);
          if (idx === -1) return;
          chain.splice(idx, 1);
          // Whatever now sits at `idx` is the node installed immediately AFTER this one — the
          // only node that can be delegating to this node — so repoint it straight at what this
          // node delegated to. That is what makes an out-of-LIFO-order removal safe: a MIDDLE
          // layer does not leak, because the layer above it is repointed regardless of order.
          const newer = chain[idx];
          if (newer !== undefined) {
            newer.next = node.next;
            return;
          }
          // Topmost tracked link. `restore` is a no-op unless the location still holds our
          // value — if something outside this chain repatched it after us, that is an external
          // patch capwall does not own and must not clobber.
          site.slot.restore(node.next, node.patched);
        },
      };
    },
  };

  sites.push({
    name,
    kind: "relinked",
    depth: () => chain.length,
    probe: () => [site.slot.read()],
    install: (ctx) => patch.install(ctx),
  });
  return patch;
}

/* ============================================================================================
 * PRIMITIVE 2 — the single reference-counted patch (`process.env`, `_compile`, the globals).
 * ========================================================================================== */

export interface SharedPatchSite<S> {
  /**
   * Install the patch and return whatever `restore` will need. Called ONLY while the patch is
   * inactive, which is the structural half of the fix for the empty-child-environment bug: what
   * this reads is by construction the UN-PATCHED original, never a previous install's proxy.
   *
   * Returning `null` declines (nothing to patch on this runtime) and the handle is inert.
   */
  apply(ctx: ShimContext): S | null;
  /**
   * Called for EVERY install while the patch is active, including the one that applied it — the
   * hook for a per-install option that must be honoured by an already-built patch (hardened
   * mode's `writable: false` ratchet on the egress globals, #97).
   */
  refresh?(ctx: ShimContext, state: S): void;
  /** Called when the LAST handle releases. May throw; the helper isolates it. */
  restore(state: S): void;
  /** The location's current value(s) — an identity snapshot for the lifecycle test. */
  probe(): readonly unknown[];
}

/**
 * Define a NON-stacking process patch: exactly one patch per process, reference counted, with
 * the count deciding only WHEN the original goes back.
 *
 * Use this whenever a second layer would be wrong rather than merely redundant:
 *  - `Module.prototype._compile`, which asks who called it one frame up and would see capwall's
 *    own frame through a second layer, then gate every `require` in the process (#100);
 *  - `process.env`, where a second Proxy double-gates and double-records every read AND — the
 *    bug that motivated #107 — captures the first proxy as the "real" environment;
 *  - the egress globals, where a second wrapper double-guards and double-records every `fetch`.
 *
 * Safe for all three because every guard reads `liveCtx` (#87): one patch already follows
 * whichever install is in force, so a second one buys nothing and costs correctness.
 */
export function defineSharedPatch<S>(name: string, site: SharedPatchSite<S>): ProcessPatch {
  let installs = 0;
  let state: S | null = null;

  const patch: ProcessPatch = {
    install(ctx) {
      if (state === null) {
        const applied = site.apply(ctx);
        if (applied === null) return DECLINED; // nothing to patch on this runtime
        state = applied;
        installs = 0;
      }
      installs++;
      const held = state;
      if (site.refresh !== undefined) site.refresh(ctx, held);

      let uninstalled = false;
      return {
        uninstall() {
          if (uninstalled) return; // idempotent
          uninstalled = true;
          // A handle held across a FULL teardown and a fresh install belongs to neither: the
          // patch it counted no longer exists, so releasing it must not decrement the new one.
          if (state !== held) return;
          if (--installs > 0) return; // an install that is still active wants the patch
          state = null;
          try {
            site.restore(held);
          } catch {
            // One handle throwing must never strand the others — that was the third of the three
            // bugs #107 is about. The location keeps capwall's value, which after the last
            // uninstall reads the deny-all torn-down policy: fail-closed, not fail-open.
          }
        },
      };
    },
  };

  sites.push({
    name,
    kind: "shared",
    depth: () => installs,
    probe: () => site.probe(),
    install: (ctx) => patch.install(ctx),
  });
  return patch;
}

/* ============================================================================================
 * The common shared case: replace ONE property, keep the original unambiguous.
 * ========================================================================================== */

export interface PropertyPatchSite<T> {
  readonly slot: PatchSlot<T>;
  /**
   * Build the replacement FROM THE ORIGINAL. The original is read by the helper, exactly once,
   * while the patch is provably inactive — so a site can never accidentally build on top of a
   * previous install's replacement. That ambiguity is precisely what handed a granted `spawn` an
   * empty child environment (#103): the second `installEnvGuard` read `process.env`, got the
   * FIRST guard's proxy, and registered it as the "un-proxied" environment.
   *
   * `ctx` is the FIRST install's context. Since #87 that is `liveCtx` for every production call
   * site — one box the install stack re-points — so "the first install's context" and "the
   * context in force" are the same object by construction.
   */
  build(ctx: ShimContext, original: T): T;
  /** Runs immediately after the replacement is installed. `original` IS the real underlying
   *  object — the only place capwall may hand it onward (see `setUnproxiedEnv`). */
  onInstall?(original: T, installed: T): void;
  /** Runs after the last uninstall, whether or not the location accepted the original back. */
  onRestore?(original: T): void;
  refresh?(ctx: ShimContext, original: T, installed: T): void;
}

interface PropertyPatchState<T> {
  original: T;
  installed: T;
}

/**
 * A {@link defineSharedPatch} over a single {@link PatchSlot} — the shape `process.env` and
 * `Module.prototype._compile` both have.
 */
export function definePropertyPatch<T>(name: string, site: PropertyPatchSite<T>): ProcessPatch {
  const refresh = site.refresh;
  return defineSharedPatch<PropertyPatchState<T>>(name, {
    apply(ctx) {
      // Read while INACTIVE: this is the un-patched original, by construction.
      const original = site.slot.read();
      if (original === undefined) return null;
      const installed = site.build(ctx, original);
      if (!site.slot.write(installed)) return null;
      if (site.onInstall !== undefined) site.onInstall(original, installed);
      return { original, installed };
    },
    ...(refresh === undefined
      ? {}
      : { refresh: (ctx: ShimContext, s: PropertyPatchState<T>) => refresh(ctx, s.original, s.installed) }),
    restore(s) {
      site.slot.restore(s.original, s.installed);
      if (site.onRestore !== undefined) site.onRestore(s.original);
    },
    probe: () => [site.slot.read()],
  });
}
