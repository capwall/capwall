/**
 * `child_process` capability shim (roadmap M4, issue #6; env-interaction hardened in #89).
 *
 * Gates whether a package may START a subprocess at all — `spawn`, `exec`, `execFile`,
 * `fork`, and their sync counterparts each call `guard(ctx, { kind: "child_process" })`
 * before delegating, so an enforce-mode denial throws synchronously BEFORE any process is
 * created. The `ChildProcess` class is also wrapped: `new ChildProcess().spawn(opts)` is the
 * low-level launch primitive the module functions are sugar over, so a bare instance's
 * `.spawn()` must be gated too (otherwise it is a trivial bypass, exactly like the
 * fs.ReadStream-class bypass a prior review caught).
 *
 * This is a GATE, not confinement (see docs/threat-model.md): capwall decides whether a
 * package may spawn a subprocess at all; once a child is allowed to start, capwall does not
 * confine what it does — the child is a separate OS process outside capwall's in-process
 * shims, running with the full privileges of the host process.
 *
 * ═══════════════════════════════════════════════════════════════════════════════════════════
 * ENV INTERACTION (issue #89) — read this before touching anything below.
 * ═══════════════════════════════════════════════════════════════════════════════════════════
 *
 * WHAT WENT WRONG. Node reads `process.env` while assembling a child's environment block, and
 * those reads carry the spawning dependency as their nearest stack frame — so the env shim
 * would soft-deny them and the child would launch with no PATH/HOME. The old fix was to bracket
 * the real spawn with a process-wide `suspendEnvGate()`. Two things made that a HIGH-severity
 * hole rather than a scoping quibble:
 *
 *  1. the caller's options object was forwarded UNPINNED, and Node reads it INSIDE that window
 *     — so a getter on `options.cwd` ran with the env gate globally off and copied all 85
 *     values out of `process.env`, with only the `child_process` decision in the trace; and
 *  2. the window was PROCESS-WIDE — a second dependency with no grants at all read env ungated
 *     during it, purely because someone else happened to be inside a spawn.
 *
 * BOTH HALVES ARE FIXED, INDEPENDENTLY.
 *
 * (A) THE OPTIONS OBJECT IS PINNED, exactly as `net` pins its options (#26/#56), through the
 *     SHARED {@link pinAllOwnFields} rather than a second copy of the rule. Every own accessor
 *     is invoked exactly once, on capwall's own stack, BEFORE the real call, and its result is
 *     frozen into a data property; the object handed to Node contains no getters at all. The
 *     PoC's `get cwd()` therefore runs at a moment when nothing has been relaxed, and its
 *     `process.env` read is gated and recorded like any other dependency read.
 *
 * (B) THE WINDOW IS ALMOST ENTIRELY DELETED, not merely narrowed. Node's
 *     `const env = options.env || { ...process.env }` is the read that mattered — the whole
 *     environment, key by key, through the proxy. capwall now always supplies an explicit
 *     `options.env`, built from the UN-PROXIED environment (see {@link resolveSpawnEnv}), so
 *     that branch never runs. What is left is not a window over `process.env` at all but a
 *     fixed, audited allowlist of NON-SECRET keys Node reads BY NAME regardless of what the
 *     caller supplied ({@link SPAWN_INTERNAL_ENV_KEYS}), authorized by exact string match and
 *     only while a real spawn is on the stack. Every other key stays gated and recorded, for
 *     every package, including inside the real call.
 *
 * WHAT NODE ACTUALLY TOUCHES DURING A SPAWN (enumerated against `lib/child_process.js` and
 * `lib/internal/child_process.js` on Node 20/22, and verified empirically — this list is the
 * honest scope statement for (A) and (B), and the reason both were needed):
 *
 *  - `process.env` reads, all of them in `normalizeSpawnArguments`:
 *      · `options.env || { ...process.env }` — the full enumeration. ELIMINATED by (B).
 *      · `copyProcessEnvToEnv(env, "NODE_V8_COVERAGE", options.env)` — reads
 *        `process.env.NODE_V8_COVERAGE` UNCONDITIONALLY, even when the caller supplied an env,
 *        because it is the left operand of an `&&`. Cannot be eliminated from outside Node;
 *        authorized by name.
 *      · the same helper for nine z/OS codepage/redirect variables, on `os390` only.
 *      · `process.env.comspec` — win32 only, and only when `options.shell === true`.
 *    `lib/internal/child_process.js` — where `ChildProcess.prototype.spawn` and `getValidStdio`
 *    live — contains NO `process.env` read at all, which is why the guarded class method below
 *    opens no window whatsoever.
 *
 *  - CALLER-CONTROLLED CODE Node can still invoke during the real call, i.e. what (A) does and
 *    does not reach. (A) flattens the TOP LEVEL of the options bag — `normalizeSpawnArguments`
 *    ends with `{ __proto__: null, ...options }`, so EVERY own enumerable accessor on it runs,
 *    not just the named `cwd`/`shell`/`argv0`/`stdio`/`env`/… reads. After pinning, none do.
 *    NESTED objects are a different matter and are NOT flattened (they are values, not fields):
 *      · `options.env`'s own keys — Node does `for (const key in env)` then `env[key]`. Pinned
 *        anyway: {@link resolveSpawnEnv} snapshots the caller's env with the same `for..in`
 *        Node uses, outside the real call, so those getters run un-privileged too.
 *      · `options.stdio` — array indices and each entry's `fd` / `handle` / `_handle` getters.
 *      · `options.signal` — `aborted` and `addEventListener` on a duck-typed AbortSignal.
 *      · `options.cwd` when it is a `URL` subclass (`protocol`/`hostname`/`pathname`).
 *      · the `args` array — element getters plus `toString`/`Symbol.toPrimitive` per element.
 *    Each of those can still run while a spawn is on the stack. That is precisely why (B) is
 *    key-scoped: all such code can learn from the authorization is whether `NODE_V8_COVERAGE`
 *    is set. (`options.killSignal` is NOT a hook — Node rejects a non string/number before any
 *    coercion, so no `toString` runs.)
 */
import { realChildProcess } from "../real-builtins.cjs"; // never `import … from "node:child_process"` — see #78
import {
  defineGuardedClassIdentity,
  guard,
  unproxiedProcessEnv,
  withAuthorizedEnvKeys,
  type AnyCtor,
  type AnyFn,
  type ShimContext,
  type ShimRegistry,
} from "./runtime.js";
import { harden, hardenClass } from "./harden.js";
import { pinAllOwnFields } from "./pin.js";

/**
 * The ONLY `process.env` keys exempt from the read gate while a real spawn runs, and only then.
 *
 * Every one is read BY NAME by Node's own `copyProcessEnvToEnv` / shell resolution in
 * `lib/child_process.js`, regardless of what the caller passed, so capwall cannot remove the
 * read the way it removes the whole-environment enumeration. None of them is a secret: they name
 * a coverage output directory, z/OS codepage and stream-redirect settings, and the Windows
 * command interpreter. An attacker's accessor running inside the real call gains exactly the
 * ability to learn whether these are set.
 *
 * ADDING A KEY HERE WIDENS THE ONLY REMAINING UNGATED ENV PATH. Add one only for a key Node
 * itself reads during spawn, and only after checking it cannot carry a secret.
 */
const SPAWN_INTERNAL_ENV_KEYS: ReadonlySet<string> = new Set([
  // All platforms: propagated so a spawned program's coverage is still collected.
  "NODE_V8_COVERAGE",
  // z/OS (`process.platform === "os390"`) only — codepage conversion and stream tagging.
  "_BPXK_AUTOCVT",
  "_CEE_RUNOPTS",
  "_TAG_REDIR_ERR",
  "_TAG_REDIR_IN",
  "_TAG_REDIR_OUT",
  "STEPLIB",
  "LIBPATH",
  "_EDC_SIG_DFLT",
  "_EDC_SUSV3",
  // win32 only, and only for `shell: true` — Node's `process.env.comspec || "cmd.exe"`.
  "comspec",
]);

/**
 * Run the real spawn with {@link SPAWN_INTERNAL_ENV_KEYS} — and nothing else — exempt from the
 * env read gate. This replaces the old `suspendEnvGate()`/`resumeEnvGate()` bracket, which
 * exempted every key for every package for the duration (#89).
 */
function withSpawnEnvReads<T>(fn: () => T): T {
  return withAuthorizedEnvKeys(SPAWN_INTERNAL_ENV_KEYS, fn);
}

/** The child_process functions that start a new process; every one of these is gated. */
const GATED_METHODS = [
  "spawn",
  "exec",
  "execFile",
  "fork",
  "spawnSync",
  "execSync",
  "execFileSync",
] as const;

type GatedMethod = (typeof GATED_METHODS)[number];

/**
 * How ONE entry point's argument list is shaped, so the options bag can be located (or created)
 * without changing what Node does with the call. Transcribed from `lib/child_process.js`:
 * `normalizeSpawnArguments` (spawn/spawnSync), `fork`, `normalizeExecFileArgs`
 * (execFile/execFileSync) and `normalizeExecArgs` (exec/execSync).
 *
 * Getting this wrong is a correctness bug in BOTH directions — placing an options object where
 * Node does not look silently drops the caller's settings, and placing one where Node expects a
 * callback breaks the call — so every rule below is exercised in test/child_process.test.ts.
 */
interface EntryShape {
  /**
   * The argument index Node reads options from when `args[1]` is not itself the options bag.
   * `2` for the `(file, args, options)` family, `1` for the `(command, options)` family.
   */
  tail: 1 | 2;
  /**
   * Node treats a FUNCTION in the options position as the callback (`exec`/`execFile` family).
   * When it does, capwall can splice an options object in ahead of that callback; when it does
   * not (`spawn`/`spawnSync`/`fork`), a function there is an argument-type error Node must still
   * raise for itself.
   */
  callbackFollows: boolean;
  /**
   * Node accepts `null` in the options position as "no options". `spawn`/`spawnSync` do NOT —
   * `validateObject(null)` throws — so capwall must leave that call alone and let it throw
   * identically rather than silently repairing it.
   */
  nullIsNoOptions: boolean;
}

const ENTRY_SHAPES: Readonly<Record<GatedMethod, EntryShape>> = {
  // normalizeSpawnArguments: `options === undefined ? kEmptyObject : validateObject(options)`.
  spawn: { tail: 2, callbackFollows: false, nullIsNoOptions: false },
  spawnSync: { tail: 2, callbackFollows: false, nullIsNoOptions: false },
  // fork: `if (options != null) validateObject(options)` — null is accepted.
  fork: { tail: 2, callbackFollows: false, nullIsNoOptions: true },
  // normalizeExecFileArgs: a function at the options position becomes the callback; null is ok.
  execFile: { tail: 2, callbackFollows: true, nullIsNoOptions: true },
  execFileSync: { tail: 2, callbackFollows: true, nullIsNoOptions: true },
  // normalizeExecArgs: `{ __proto__: null, ...options }`, so null/absent are both "no options".
  exec: { tail: 1, callbackFollows: true, nullIsNoOptions: true },
  execSync: { tail: 1, callbackFollows: true, nullIsNoOptions: true },
};

/** Where capwall's pinned options object goes, and which caller object (if any) it pins. */
interface OptionsSlot {
  /** Index in the forwarded argument list. */
  index: number;
  /** Splice in at `index` (shifting later arguments right) rather than replacing it. */
  insert: boolean;
  /** The caller's options object to pin, when the call already has one. */
  source: Record<string, unknown> | undefined;
}

/**
 * Node's own test for "is this argument the options bag": a non-null object that is not an
 * array. An array in that position is the `args` list; `typeof` a function is not `"object"`.
 */
function isOptionsBag(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Locate (or choose a position for) the options bag Node will actually read, or `null` when the
 * call cannot be rewritten safely.
 *
 * `null` means FORWARD THE ARGUMENTS UNTOUCHED. That happens only for shapes Node itself
 * rejects (a function where `spawn` wants options, a primitive where any of them wants an
 * object), and forwarding unchanged is what makes Node raise the identical `ERR_INVALID_ARG_TYPE`
 * it would have raised without capwall. Repairing such a call would hide a caller bug.
 */
function locateOptions(shape: EntryShape, args: unknown[]): OptionsSlot | null {
  if (shape.tail === 2) {
    const first = args[1];
    // `spawn(file, options)` / `execFile(file, options, cb)`: Node's
    // `else { options = args; args = []; }` branch — args[1] IS the options bag, and args[2] is
    // never consulted for options.
    if (isOptionsBag(first)) return { index: 1, insert: false, source: first };
    // `execFile(file, cb)`: Node reads the callback out of args[1] and DISCARDS args[2], so an
    // options object has to go in at index 1 — `execFile(file, options, cb)` is exactly the
    // shape Node collapses that call to.
    if (shape.callbackFollows && typeof first === "function") {
      return { index: 1, insert: true, source: undefined };
    }
  }

  const index = shape.tail;
  const at = args[index];
  if (isOptionsBag(at)) return { index, insert: false, source: at };
  // `execFile(file, args, cb)` / `exec(command, cb)`: splice ours in ahead of the callback.
  if (typeof at === "function") {
    return shape.callbackFollows ? { index, insert: true, source: undefined } : null;
  }
  if (at === undefined) return { index, insert: false, source: undefined };
  if (at === null) return shape.nullIsNoOptions ? { index, insert: false, source: undefined } : null;
  return null; // a primitive Node will reject — forward untouched so it rejects identically
}

/**
 * Snapshot the object Node will enumerate into the child's environment block, reading every key
 * EXACTLY ONCE, here, on capwall's own stack and OUTSIDE the real spawn call.
 *
 * `for..in` — own AND inherited enumerable string keys — is precisely what
 * `normalizeSpawnArguments` does ("Prototype values are intentionally included"), so a caller's
 * env object is reproduced faithfully, including anything it inherits.
 *
 * Null-prototype, matching the `{ __proto__: null, ... }` objects Node builds alongside it: it
 * is enumerated with `for..in` and probed with `hasOwnProperty`, so a polluted `Object.prototype`
 * must not be able to inject variables into a child's environment.
 */
function snapshotEnv(src: object): Record<string, unknown> {
  const out = Object.create(null) as Record<string, unknown>;
  for (const key in src) {
    out[key] = (src as Record<string, unknown>)[key]; // the ONE read of this key
  }
  return out;
}

/**
 * Decide the `env` to forward, reproducing Node's own rule but reading the REAL environment
 * instead of the gated proxy.
 *
 * Node computes `const env = options.env || { ...process.env }` on the SPREAD copy of the
 * options — so only an own ENUMERABLE `env` counts, which is what the descriptor check below
 * reproduces. A falsy `env` (absent, `null`, `undefined`, `""`, `false`, `0`) means "inherit",
 * and `execFile` in particular defaults `env: null`, so this branch is the common one.
 *
 * Supplying the result explicitly is what deletes the old process-wide window: with
 * `options.env` always truthy, Node never enumerates `process.env` at all.
 *
 * `env: process.env` IS "inherit", and must not be snapshotted through the gate. A caller that
 * writes `spawn(f, a, { env: process.env })` — an ordinary, common spelling — hands us the read
 * PROXY. Enumerating it here would evaluate every key as a read by the spawning package: under a
 * deny-by-default policy each one soft-denies to `undefined`, Node drops undefined values from
 * `envPairs`, and the child launches with a nearly EMPTY environment while the audit log fills
 * with ~80 spurious denials. Identity-compare against the live `process.env` and treat it as the
 * inherit case, which is what the caller meant and what Node would have done.
 */
function resolveSpawnEnv(pinned: Record<string, unknown>): Record<string, unknown> {
  const desc = Object.getOwnPropertyDescriptor(pinned, "env");
  const callerEnv = desc !== undefined && desc.enumerable === true ? desc.value : undefined;
  if (callerEnv && callerEnv !== process.env) return snapshotEnv(callerEnv as object);
  // The un-proxied environment — identical to the `{ ...process.env }` Node would have built,
  // minus the trip through the read gate that made every key a decision attributed to the
  // spawning dependency.
  return snapshotEnv(unproxiedProcessEnv());
}

/**
 * Build the argument list to forward: the caller's options bag replaced by an inert, pinned
 * clone carrying an explicit `env`.
 *
 * `injectEnv` is false for `ChildProcess.prototype.spawn`, which consumes the already-built
 * `options.envPairs` and never reads `process.env` — inventing an `env` there would be a
 * behavior change for no benefit.
 */
function pinSpawnArgs(shape: EntryShape, args: unknown[], injectEnv: boolean): unknown[] {
  const slot = locateOptions(shape, args);
  if (slot === null) return args; // Node will reject this call; let it, unchanged
  // Pinning runs BEFORE any authorization is granted, so a getter that reads `process.env` here
  // is gated and recorded exactly like a direct read by the same package. That ordering is the
  // whole point of #89 — do not move this below `withSpawnEnvReads`.
  const pinned = slot.source !== undefined ? pinAllOwnFields(slot.source) : {};
  if (injectEnv) {
    // `defineProperty`, not assignment: the caller may have made `env` non-writable, and a
    // failed assignment would silently leave Node reading `process.env` after all.
    Object.defineProperty(pinned, "env", {
      value: resolveSpawnEnv(pinned),
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }
  const out = args.slice();
  if (slot.insert) out.splice(slot.index, 0, pinned);
  else out[slot.index] = pinned;
  return out;
}

/**
 * Build a shimmed `child_process` module: the process-starting methods above are guarded,
 * the `ChildProcess` class's `.spawn()` is guarded, and everything else passes through.
 */
export function createChildProcessShim(ctx: ShimContext): typeof import("node:child_process") {
  function wrapFn(orig: AnyFn, shape: EntryShape): AnyFn {
    const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
      guard(ctx, { kind: "child_process" }); // throws on enforce-deny, before any spawn
      // Pin FIRST (caller accessors run here, un-privileged), authorize SECOND, and authorize
      // only the handful of keys Node reads by name. See the module header.
      const pinnedArgs = pinSpawnArgs(shape, args, true);
      return withSpawnEnvReads(() => orig.apply(this, pinnedArgs));
    };
    Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
    return harden(ctx, wrapped);
  }

  const real = realChildProcess as unknown as Record<string, unknown>;
  const shim: Record<string, unknown> = {};
  for (const key of Object.keys(real)) {
    shim[key] = real[key];
  }
  for (const name of GATED_METHODS) {
    const orig = real[name];
    if (typeof orig !== "function") continue;
    shim[name] = wrapFn(orig as AnyFn, ENTRY_SHAPES[name]);
  }

  // Gate the ChildProcess class: `new ChildProcess().spawn(options)` is the low-level launch
  // primitive. A guarded SUBCLASS guards `ChildProcess.prototype.spawn` itself — a
  // construct-trap Proxy would be bypassable via `(new ChildProcess()).constructor` and
  // `ChildProcess.prototype.spawn.call(...)`. `defineGuardedClassIdentity` keeps `instanceof`
  // working for real instances WITHOUT leaking that answer down the static chain to a
  // dependency's own `class Mine extends ChildProcess {}` (#71).
  const RealChildProcess = real["ChildProcess"];
  if (typeof RealChildProcess === "function") {
    const RealCP = RealChildProcess as AnyCtor;
    const realSpawn = (RealCP.prototype as Record<string, unknown>)["spawn"];
    const Guarded = class extends RealCP {};
    if (typeof realSpawn === "function") {
      Object.defineProperty(Guarded.prototype, "spawn", {
        value: function (this: unknown, ...spawnArgs: unknown[]) {
          guard(ctx, { kind: "child_process" });
          // NO env authorization window here at all (#89): this primitive takes the
          // already-assembled `options.envPairs` and `lib/internal/child_process.js` contains no
          // `process.env` read, so there is nothing to authorize. The options object is still
          // pinned — its accessors are a re-entrancy and TOCTOU surface regardless of env.
          // `spawn(options)` has a fixed shape (the bag is argument 0, or Node throws
          // `validateObject`), so it needs none of the slot-locating above.
          const forwarded = spawnArgs.slice();
          const bag = spawnArgs[0];
          if (isOptionsBag(bag)) forwarded[0] = pinAllOwnFields(bag);
          return (realSpawn as AnyFn).apply(this, forwarded);
        },
        writable: true,
        configurable: true,
      });
    }
    defineGuardedClassIdentity(Guarded, RealCP);
    // Hardened mode (#17): freeze the subclass + its prototype so
    // `ChildProcess.prototype.spawn = evil` fails instead of removing the gate. See harden.ts.
    hardenClass(ctx, Guarded);
    shim["ChildProcess"] = Guarded;
  }

  return harden(ctx, shim) as typeof import("node:child_process");
}

/** Register the child_process shim's specifiers into the loader registry. */
export function registerChildProcessShim(reg: ShimRegistry, ctx: ShimContext): void {
  const shim = createChildProcessShim(ctx);
  reg.set("child_process", shim);
  reg.set("node:child_process", shim);
}
