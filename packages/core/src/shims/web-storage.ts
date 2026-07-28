/**
 * WEB STORAGE — `globalThis.localStorage` as an `fs` read/write on its backing file (issue #156).
 *
 * ── THE GAP ─────────────────────────────────────────────────────────────────────────────────
 * Node 26 ships Web Storage. `sessionStorage` is in-memory and moves no bytes to disk, so it is
 * not capwall's business. `localStorage` is **persistent and file-backed**: with
 * `--localstorage-file=<path>`, Node performs that file's read and write internally, BELOW the
 * `fs` shim. Before this guard a dependency could read and write that file with no `fs` grant
 * and no recorded decision — nothing denied in `enforce`, nothing in the `observe` trace,
 * nothing for `capwall diff`.
 *
 * That is structurally the same shape as the module-system read channel #123 closed, on a
 * different Node internal, and it is why it is gated rather than documented: #156 named two
 * triggers that would move it into #123's class, and Node 26 becoming LTS on 2026-10-28 makes
 * "flag-gated on a version nobody runs yet" stop being the mitigation it was when the issue was
 * filed.
 *
 * ── IT IS AN `fs` CAPABILITY, NOT A NEW KIND AND NOT `net` ──────────────────────────────────
 * The machinery here is borrowed from `shims/global-egress.ts` — a `globalPropertySlot` under
 * `lifecycle/process-patch.ts`, because this is a global rather than a module surface — but the
 * capability is `fs`, decided on the resolved backing path:
 *
 *   | member                            | decision            |
 *   |-----------------------------------|---------------------|
 *   | `getItem`, `key`, `length`        | `fs` **read**       |
 *   | `setItem`, `removeItem`, `clear`  | `fs` **write**      |
 *
 * A package that may read the file may read it; the API it used to get there is not a separate
 * authority, exactly as `fetch` and `net.connect` are one `net` grant (#80). So every existing
 * policy, `observe` trace, `gen-policy` output and `capwall diff` covers this surface with no
 * schema change.
 *
 * ── WHY THE WHOLE OBJECT AND NOT `Storage.prototype` ────────────────────────────────────────
 * Patching the five methods on `Storage.prototype` would be the smaller intervention and it
 * cannot be complete: `Storage.prototype.length` is a **non-configurable** getter on 26.5.0
 * (measured), so it can never be replaced there — and `length` is a read of the file's state.
 * It would also have to discriminate `localStorage` from `sessionStorage` at every call, since
 * both share that prototype and only one has a file.
 *
 * Replacing `globalThis.localStorage` with capwall's own view covers all six members, leaves
 * `sessionStorage` and `Storage.prototype` untouched, and needs no per-call discrimination. The
 * view's prototype IS `Storage.prototype`, so `localStorage instanceof Storage` still answers
 * true, and every member forwards with `Reflect.apply(realMethod, realStorage, args)` — invoked
 * on the REAL object, so Node's brand checks pass and the arity/coercion behaviour is Node's.
 *
 * The deviation, stated rather than hidden: `Storage.prototype.getItem.call(localStorage, k)`
 * throws `TypeError: Illegal invocation` against the view, because the view is capwall's object
 * and not a branded `Storage`. That is the same class of deviation the guarded `http.globalAgent`
 * view carries (#65) and it fails CLOSED — it cannot be used to reach the file un-gated. Reaching
 * the raw object at all requires having captured it before `install()`, which is the pre-install
 * capture residual every capwall surface has.
 *
 * ── WHY DETECTION IS `Object.keys(globalThis)` AND NOT A READ ───────────────────────────────
 * On Node 26 WITHOUT the flag, reading `globalThis.localStorage` returns `undefined` and prints
 * `ExperimentalWarning: localStorage is not available because --localstorage-file was not
 * provided.` on stderr — the same channel capwall's own DENY lines live on. A guard that probed
 * by reading would put that warning in every mediated process on Node 26, which is the
 * availability-shaped failure #153 was about.
 *
 * The Web IDL exposure flag is observable without touching the value: the property is
 * `enumerable: false` when unavailable and `enumerable: true` when the flag is set, so
 * `Object.keys(globalThis)` answers it and warns nothing. Measured on 26.5.0 both ways. On 22 and
 * 24 the property does not exist at all, so the same check answers `false` and this file installs
 * nothing — no patch site is even registered.
 */
import * as path from "node:path";
import {
  defineSharedPatch,
  globalPropertySlot,
  type GlobalPropertySlot,
  type GlobalReplacement,
  type ProcessPatch,
} from "../lifecycle/process-patch.js";
import { guard, type AnyFn, type ShimContext } from "./runtime.js";

/** `fs` read members of `Storage`, and `fs` write members. Node 26.5.0's full prototype. */
const READ_METHODS = ["getItem", "key"] as const;
const WRITE_METHODS = ["setItem", "removeItem", "clear"] as const;

/**
 * The value the guard uses when the flag is demonstrably ON but capwall cannot recover the path
 * it points at.
 *
 * A decision is ALWAYS taken — declining to decide because the target could not be named would
 * be a silent un-gating, which is the failure mode this whole file exists to remove. The sentinel
 * is grantable like any other path, and it shows up in an `observe` trace as a legible prompt.
 * Same idiom as `<ipc>` in the `net` grant for a unix socket with no host:port (#72).
 */
const UNRESOLVED_BACKING_FILE = "<localstorage>";

/** The flag, in the two channels Node accepts it through. */
const FLAG = "--localstorage-file";

/**
 * Is Web Storage's `localStorage` actually available in this process?
 *
 * `Object.keys` rather than a read — see the header. Node marks the property `enumerable` exactly
 * when the interface is exposed, and reading the value when it is not warns on stderr.
 */
export function localStorageAvailable(): boolean {
  return Object.keys(globalThis).includes("localStorage");
}

/**
 * The path `--localstorage-file` names, resolved the way Node resolves it, or `undefined`.
 *
 * Node accepts the flag from `NODE_OPTIONS` and from the command line, and the command line wins
 * (verified on 26.5.0: `NODE_OPTIONS=--localstorage-file=/tmp/from-env.db node
 * --localstorage-file=rel.db …` writes `rel.db`). Only the command line reaches
 * `process.execArgv`, so both channels are scanned, in Node's own precedence order, and the LAST
 * occurrence wins within each — Node's own behaviour for a repeated option.
 *
 * A relative value resolves against the process's **cwd**, not capwall's `projectRoot`: that is
 * where Node resolves it (verified — `--localstorage-file=rel.db` with cwd `/tmp` wrote
 * `/tmp/rel.db`). Naming a different file than the one Node opens would be worse than naming
 * none.
 */
export function resolveLocalStorageFile(): string | undefined {
  // NODE_OPTIONS first, command line second, so a command-line value overwrites it.
  const nodeOptions = process.env["NODE_OPTIONS"];
  const words = nodeOptions === undefined ? [] : nodeOptions.split(/\s+/).filter((w) => w !== "");
  const found = flagValue(words) ?? undefined;
  const fromArgv = flagValue(process.execArgv);
  const value = fromArgv ?? found;
  return value === undefined ? undefined : path.resolve(process.cwd(), value);
}

/** The last `--localstorage-file=<v>` / `--localstorage-file <v>` value in `words`. */
function flagValue(words: readonly string[]): string | undefined {
  let value: string | undefined;
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    if (word === undefined) continue;
    if (word.startsWith(`${FLAG}=`)) value = word.slice(FLAG.length + 1);
    else if (word === FLAG) value = words[i + 1];
  }
  return value === undefined || value === "" ? undefined : value;
}

/**
 * Build capwall's guarded stand-in for `localStorage`.
 *
 * Each member is an OWN property of the view, so it shadows `Storage.prototype`'s, and each
 * forwards on the real object. Every wrapper hands `guard()` its own function object as the entry
 * frame (#143), so a mediated call materializes three CallSites rather than twenty-five.
 */
function guardedStorage(real: object, backingFile: string, ctx: ShimContext): object {
  const proto: unknown = Object.getPrototypeOf(real);
  const view = Object.create(typeof proto === "object" ? proto : null) as Record<string, unknown>;

  const define = (name: string, access: "read" | "write"): void => {
    const method: unknown = (real as Record<string, unknown>)[name];
    if (typeof method !== "function") return; // a Node whose Storage lacks it — invent nothing
    const realMethod = method as AnyFn;
    const wrapped: AnyFn = function (this: unknown, ...args: unknown[]): unknown {
      guard(ctx, wrapped, { kind: "fs", access, path: backingFile }); // before any I/O
      // Invoked on the REAL storage, never on the view: Node's brand check reads an internal
      // slot the view does not have. Arity is stated nowhere — `Reflect.apply` forwards
      // whatever the caller passed and Node's own coercion applies (AGENTS.md § 8, #128/#135).
      return Reflect.apply(realMethod, real, args);
    };
    Object.defineProperty(wrapped, "name", { value: name, configurable: true });
    Object.defineProperty(wrapped, "length", {
      value: (realMethod as { length: number }).length,
      configurable: true,
    });
    Object.defineProperty(view, name, { value: wrapped, writable: true, configurable: true });
  };

  for (const name of READ_METHODS) define(name, "read");
  for (const name of WRITE_METHODS) define(name, "write");

  // `length` is a getter, and on the REAL prototype it is non-configurable — which is the whole
  // reason this guard replaces the object rather than the prototype. An own accessor here
  // shadows it for anyone holding the view.
  const lengthGetter = function (this: unknown): unknown {
    guard(ctx, lengthGetter, { kind: "fs", access: "read", path: backingFile });
    return Reflect.get(real, "length", real);
  };
  Object.defineProperty(view, "length", { get: lengthGetter, configurable: true });

  return view;
}

/** What the guard holds while it is installed. */
interface WebStorageState {
  readonly slot: GlobalPropertySlot;
  readonly replacement: GlobalReplacement;
  pinned: boolean;
}

let storageState: WebStorageState | null = null;

/**
 * The patch site, created on FIRST USE rather than at module evaluation.
 *
 * Deliberate, and the one place this file departs from `shims/global-egress.ts`. A site
 * registered at module scope is enrolled in `test/process-patch-sites.test.ts`'s inventory and
 * conformance run on every runtime — and that run has no "the site declined" escape hatch, by
 * design (#112): a site that stops patching must fail rather than take a quiet branch. A
 * `localStorage` guard genuinely cannot patch on Node 22, on Node 24, or on Node 26 without the
 * flag, so registering it eagerly would mean either a red suite on three of four configurations
 * or re-introducing exactly the escape hatch #112 removed.
 *
 * So the site exists only in a process where it can actually install, and the ABSENT case is
 * asserted directly instead — see `test/web-storage.test.ts`, which pins both:
 * `localStorageAvailable()` is false and no site is registered, on every runtime the suite
 * ordinarily runs on.
 */
let storagePatch: ProcessPatch | null = null;

function webStoragePatch(): ProcessPatch {
  storagePatch ??= defineSharedPatch<WebStorageState>("globalThis.localStorage", {
    apply(ctx) {
      const backingFile = resolveLocalStorageFile() ?? UNRESOLVED_BACKING_FILE;
      const slot = globalPropertySlot("localStorage");
      const replacement = slot.replace(
        (real) => guardedStorage(real as object, backingFile, ctx),
        ctx.hardened === true,
      );
      if (replacement === null) return null;
      const state: WebStorageState = { slot, replacement, pinned: ctx.hardened === true };
      storageState = state;
      return state;
    },
    // Every install, not just the first: a hardened install stacked on an un-hardened one must
    // still get its pin (#97). Same ratchet as the egress globals.
    refresh(ctx, state) {
      if (ctx.hardened === true && !state.pinned) {
        state.slot.pin(state.replacement);
        const installed = state.replacement.installed;
        if (typeof installed === "object" && installed !== null) Object.freeze(installed);
        state.pinned = true;
      }
    },
    restore(state) {
      state.slot.restore(state.replacement);
      storageState = null;
    },
    probe: () => [globalPropertySlot("localStorage").current()],
  });
  return storagePatch;
}

/**
 * The capwall-installed `localStorage` that hardened mode failed to pin — empty when hardening
 * applied and empty when no guard is installed at all. Read by `install()`'s hardening
 * self-check, which refuses to return a handle for a `hardened: true` it could not honor (#97).
 */
export function webStorageHardeningGaps(): string[] {
  const state = storageState;
  if (state === null) return [];
  return state.slot.isPinned(state.replacement) ? [] : ["globalThis.localStorage"];
}

export interface WebStorageGuardHandle {
  uninstall(): void;
}

/** A handle that does nothing — the shape returned where there is nothing to guard. */
const INERT: WebStorageGuardHandle = { uninstall() {} };

/**
 * Install the Web Storage guard, if this process has Web Storage at all.
 *
 * A clean no-op otherwise: on Node 22 and 24 the global does not exist, and on Node 26 without
 * `--localstorage-file` it is present-but-unavailable. Neither reads the property (which would
 * warn) and neither registers a patch site.
 */
export function installWebStorageGuard(ctx: ShimContext): WebStorageGuardHandle {
  if (!localStorageAvailable()) return INERT;
  return webStoragePatch().install(ctx);
}
