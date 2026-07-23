/**
 * `fs` capability shim — the first shim (roadmap M1): the vertical slice that proves the
 * whole observe→policy→enforce loop end-to-end.
 *
 * On every capability-sensitive call the shim (1) asks `attributeCaller()` who is calling,
 * (2) asks `evaluate()` for a decision, reports it to `onDecision`, then (3) forwards to the
 * real API or throws a `CapabilityError` (enforce mode only). Signatures of the real API are
 * preserved: wrappers forward all arguments verbatim, so correct code is unaffected.
 *
 * Coverage & limits (kept in sync with docs/threat-model.md):
 *  - The path-taking read/write families below are wrapped (sync, callback, and
 *    `fs.promises` variants), PLUS the path-taking stream constructors `ReadStream` /
 *    `WriteStream` (a dependency can `new fs.ReadStream(path)` instead of
 *    `createReadStream` — both must be mediated). Purely fd-based operations (`read`,
 *    `write`, `ftruncate`, `fchmod`, …) are NOT mediated — fd escapes are out-of-scope.
 *  - Denials are delivered via the SAME channel the real API would use, so idiomatic
 *    (try/catch-free) callback code is not crashed by an uncaught synchronous throw:
 *      - `*Sync` methods throw `CapabilityError` synchronously (matches real sync `fs`).
 *      - `fs.promises` methods reject with `CapabilityError` (matches real promise API).
 *      - callback-style async methods (`readFile`, `mkdir`, `access`, …) invoke the
 *        caller's callback as `cb(err)` on `process.nextTick` — exactly how a real async
 *        `fs` error would arrive — instead of throwing. If the call is missing its
 *        callback (a mis-call), we fall back to throwing, same as real Node.
 *      - `createReadStream`/`createWriteStream` return a minimal stream that emits
 *        `'error'` on `setImmediate` (approximating — not exactly reproducing — real Node's
 *        threadpool-timed async stream-error delivery; a handler attached on a much later
 *        macrotask can still miss it, same as real `fs`). Fail-closed: no read/write occurs.
 *      - `watch`/`watchFile` still throw synchronously: real `fs.watch` does too on a bad
 *        path, so no behavior-shape change is needed there.
 *    `exists`/`existsSync` remain bespoke non-throwing probes (see below) — untouched by
 *    the above; a denial there means "does not exist", not an error at all.
 *  - Path checks are lexical on the resolved path; symlink traversal is out of scope.
 */
import realFs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Readable, Writable } from "node:stream";
import { guard, type ShimContext, type ShimRegistry } from "./runtime.js";
import { CapabilityError } from "../errors.js";

export type { DecisionSink, ShimContext } from "./runtime.js";

type Access = "read" | "write";
/** Which positional args of a method are paths, and what access each implies. */
interface PathSpec {
  index: number;
  access: Access;
}
/**
 * `"open"`-kind methods derive read/write from their flags argument; `"access"`-kind
 * methods derive it from their mode bitmask (see {@link accessSpecs}, fix #20).
 */
type MethodSpec = PathSpec[] | "open" | "access";

const R0: MethodSpec = [{ index: 0, access: "read" }];
const W0: MethodSpec = [{ index: 0, access: "write" }];
const COPY: MethodSpec = [
  { index: 0, access: "read" },
  { index: 1, access: "write" },
];
const RENAME: MethodSpec = [
  { index: 0, access: "write" },
  { index: 1, access: "write" },
];
const SYMLINK: MethodSpec = [{ index: 1, access: "write" }];

/** Wrapped methods of the callback/sync `fs` surface. Unlisted methods pass through. */
const FS_METHODS: Record<string, MethodSpec> = {
  readFile: R0,
  readFileSync: R0,
  createReadStream: R0,
  readdir: R0,
  readdirSync: R0,
  readlink: R0,
  readlinkSync: R0,
  realpath: R0,
  realpathSync: R0,
  stat: R0,
  statSync: R0,
  lstat: R0,
  lstatSync: R0,
  statfs: R0,
  statfsSync: R0,
  // access / accessSync: read vs. write is derived from the mode bitmask (fix #20) —
  // see `accessSpecs`. A W_OK probe needs a `write` grant, not `read`.
  access: "access",
  accessSync: "access",
  // exists / existsSync are handled bespoke (they must never throw — see createFsShim).
  opendir: R0,
  opendirSync: R0,
  watch: R0,
  watchFile: R0,
  writeFile: W0,
  writeFileSync: W0,
  appendFile: W0,
  appendFileSync: W0,
  createWriteStream: W0,
  mkdir: W0,
  mkdirSync: W0,
  rmdir: W0,
  rmdirSync: W0,
  rm: W0,
  rmSync: W0,
  unlink: W0,
  unlinkSync: W0,
  truncate: W0,
  truncateSync: W0,
  chmod: W0,
  chmodSync: W0,
  chown: W0,
  chownSync: W0,
  lchown: W0,
  lchownSync: W0,
  utimes: W0,
  utimesSync: W0,
  lutimes: W0,
  lutimesSync: W0,
  mkdtemp: W0,
  mkdtempSync: W0,
  copyFile: COPY,
  copyFileSync: COPY,
  cp: COPY,
  cpSync: COPY,
  rename: RENAME,
  renameSync: RENAME,
  link: COPY,
  linkSync: COPY,
  symlink: SYMLINK,
  symlinkSync: SYMLINK,
  open: "open",
  openSync: "open",
};

/** Wrapped methods of the `fs.promises` surface. */
const PROMISES_METHODS: Record<string, MethodSpec> = {
  readFile: R0,
  readdir: R0,
  readlink: R0,
  realpath: R0,
  stat: R0,
  lstat: R0,
  statfs: R0,
  access: "access",
  opendir: R0,
  watch: R0,
  writeFile: W0,
  appendFile: W0,
  mkdir: W0,
  rmdir: W0,
  rm: W0,
  unlink: W0,
  truncate: W0,
  chmod: W0,
  chown: W0,
  lchown: W0,
  utimes: W0,
  lutimes: W0,
  mkdtemp: W0,
  copyFile: COPY,
  cp: COPY,
  rename: RENAME,
  link: COPY,
  symlink: SYMLINK,
  open: "open",
};

/**
 * Coerce a path-like argument to an absolute, `/`-separated path string, or null when the
 * argument is not a path (an fd number, a FileHandle, …) — those are out of scope.
 *
 * Fix #19: a Buffer path is decoded with `"latin1"`, not `"utf8"`. `latin1` maps every byte
 * 1:1 to a code point (U+0000–U+00FF), so the decode round-trips exactly — including
 * non-UTF-8 bytes, which a `utf8` decode would lossily collapse to U+FFFD. That lossiness
 * previously meant the STRING checked against policy could differ from the bytes actually
 * forwarded to real `fs` (the original Buffer is forwarded verbatim, unchanged by this
 * function). `/` is 0x2F, which is the same code point in latin1 as in ASCII/UTF-8, so
 * segment-splitting on `path.sep` below is unaffected.
 */
function coercePath(arg: unknown): string | null {
  let p: string;
  if (typeof arg === "string") p = arg;
  else if (Buffer.isBuffer(arg)) p = arg.toString("latin1");
  else if (arg instanceof URL) {
    try {
      p = fileURLToPath(arg);
    } catch {
      return null;
    }
  } else return null;
  return path.resolve(p).split(path.sep).join("/");
}

/** Derive the effective PathSpecs for an `open`-kind call from its flags argument. */
function openSpecs(args: unknown[]): PathSpec[] {
  const flags = args[1];
  let access: Access = "read"; // default flags: "r"
  if (typeof flags === "string") {
    access = /[wa+]/.test(flags) ? "write" : "read";
  } else if (typeof flags === "number") {
    const { O_WRONLY, O_RDWR, O_APPEND, O_CREAT } = realFs.constants;
    access = (flags & (O_WRONLY | O_RDWR | O_APPEND | O_CREAT)) !== 0 ? "write" : "read";
  }
  return [{ index: 0, access }];
}

/**
 * Derive the effective PathSpec for an `access`-kind call (`fs.access`/`fs.accessSync`,
 * `fs.promises.access`) from its mode argument (fix #20). `fs.access(path[, mode][, cb])`
 * defaults `mode` to `fs.constants.F_OK` (existence only) when omitted — a `read`-shaped
 * probe. When the caller passes a mode with the `W_OK` bit set, they are probing
 * writability, which should require a `write` grant instead.
 */
function accessSpecs(args: unknown[]): PathSpec[] {
  const mode = args[1];
  const W_OK = realFs.constants.W_OK;
  const access: Access = typeof mode === "number" && (mode & W_OK) !== 0 ? "write" : "read";
  return [{ index: 0, access }];
}

type AnyFn = (...args: unknown[]) => unknown;
type PathClass = abstract new (...a: never[]) => unknown;

/**
 * How a denial is DELIVERED for a given method (fix #16). The guard DECISION is identical in
 * every mode — this only changes how a denial surfaces, so it matches the real API's own
 * error-delivery channel instead of always throwing synchronously:
 *  - `"throw"`    — synchronous throw (real sync `fs`, and `watch`/`watchFile`, which throw
 *                   synchronously on a bad path in real Node too).
 *  - `"reject"`   — a rejected Promise (real `fs.promises`).
 *  - `"callback"` — `cb(err)` on `process.nextTick` (real callback-style async `fs`, which
 *                   never throws synchronously).
 *  - `"streamRead"`/`"streamWrite"` — a stream that emits `error` on `setImmediate`
 *                   (real `createReadStream`/`createWriteStream`, which never throw
 *                   synchronously either).
 */
type Delivery = "throw" | "reject" | "callback" | "streamRead" | "streamWrite";

/**
 * Classify a `FS_METHODS` entry's denial-delivery mode by name (fix #16). `fs.promises`
 * entries are uniformly `"reject"` (passed directly as `() => "reject"` at the call site) —
 * this function only covers the sync/callback/stream `fs` surface.
 */
function fsDeliveryFor(name: string): Delivery {
  if (name.endsWith("Sync")) return "throw";
  if (name === "watch" || name === "watchFile") return "throw"; // real fs.watch throws sync too
  if (name === "createReadStream") return "streamRead";
  if (name === "createWriteStream") return "streamWrite";
  return "callback";
}

/**
 * Build a minimal stream that emits `'error'` with `err` asynchronously, mirroring how real
 * `createReadStream`/`createWriteStream` deliver an async error (fix #16). Constructed but
 * inert until the scheduled `destroy` fires, so `fs.createReadStream(p).on('error', h).on(...)`
 * chains work exactly as they would against a real stream that fails after construction.
 */
// Deny streams emit 'error' on `setImmediate` (not `process.nextTick`): a real fs stream's
// open failure arrives via the libuv threadpool, LATER than nextTick, so setImmediate widens
// the window for a caller that attaches its 'error' handler in a microtask or nextTick before
// the error fires (closer to real Node's timing). `.path` is set so error-logging libraries
// that read `stream.path` see the requested path. Exact threadpool timing is not reproduced
// (a handler attached on a later macrotask can still miss it — same as real fs past a point);
// tracked as a follow-up. This is fail-closed: the read/write never happens regardless.
function denyReadStream(err: CapabilityError, path: unknown): Readable {
  const stream = new Readable({ read() {} }) as Readable & { path?: unknown };
  stream.path = path;
  setImmediate(() => stream.destroy(err));
  return stream;
}
function denyWriteStream(err: CapabilityError, path: unknown): Writable {
  const stream = new Writable({ write(_chunk, _enc, cb) { cb(); } }) as Writable & { path?: unknown };
  stream.path = path;
  setImmediate(() => stream.destroy(err));
  return stream;
}

/**
 * Build a shimmed `fs` module: every method in the tables above is guarded; everything else
 * (constants, fd-based ops, Stats, …) is the real thing, passed through.
 */
export function createFsShim(ctx: ShimContext): typeof import("node:fs") {
  /**
   * Attribute + evaluate one path/access via the shared shim runtime. Skips non-path args
   * (fd / FileHandle — out of scope). Throws `CapabilityError` on an enforce-mode denial;
   * the caller decides whether to propagate, reject, or translate that into a return value.
   */
  function check(access: Access, arg: unknown): void {
    const target = coercePath(arg);
    if (target === null) return;
    guard(ctx, { kind: "fs", access, path: target });
  }

  /** Attribute + evaluate each path of a call; throws CapabilityError on an enforce deny. */
  function guardCall(args: unknown[], spec: MethodSpec): void {
    const specs = spec === "open" ? openSpecs(args) : spec === "access" ? accessSpecs(args) : spec;
    for (const { index, access } of specs) {
      check(access, args[index]);
    }
  }

  /**
   * Bespoke guard for `exists`/`existsSync`, which contractually never throw. On an
   * enforce-mode denial we report "does not exist" instead of throwing: `existsSync` → false,
   * `exists(path, cb)` → `cb(false)`. Observe mode allows and falls through to the real call.
   */
  function isDeniedExistence(pathArg: unknown): boolean {
    try {
      check("read", pathArg);
      return false;
    } catch (err) {
      if (err instanceof CapabilityError) return true;
      throw err;
    }
  }

  /**
   * Wrap a path-taking stream constructor (`ReadStream`/`WriteStream`) so
   * `new fs.ReadStream(path)` is mediated exactly like `createReadStream(path)`. Uses a
   * construct-trap Proxy so `instanceof` and the class identity are preserved.
   */
  function wrapPathClass<T extends abstract new (...a: never[]) => unknown>(
    RealClass: T,
    access: Access,
  ): T {
    return new Proxy(RealClass, {
      construct(target, argArray, newTarget) {
        check(access, argArray[0]); // throws on enforce-deny, before the stream exists
        return Reflect.construct(target, argArray as never[], newTarget);
      },
    });
  }

  function wrapFn(orig: AnyFn, spec: MethodSpec, delivery: Delivery): AnyFn {
    const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
      switch (delivery) {
        case "throw": {
          // Real sync fs throws synchronously — matches, no translation needed.
          guardCall(args, spec);
          return orig.apply(this, args);
        }
        case "reject": {
          // Real fs.promises rejects — matches, no translation needed.
          try {
            guardCall(args, spec);
          } catch (err) {
            return Promise.reject(err);
          }
          return orig.apply(this, args);
        }
        case "callback": {
          // Real callback-style fs NEVER throws synchronously; it delivers errors via the
          // callback. Translate a sync guard throw into an async `cb(err)` so idiomatic
          // (try/catch-free) callback code isn't crashed by an uncaught exception (#16).
          try {
            guardCall(args, spec);
          } catch (err) {
            if (!(err instanceof CapabilityError)) throw err;
            const cb = args[args.length - 1];
            if (typeof cb !== "function") throw err; // mis-call (no cb) — match Node, throw.
            process.nextTick(() => (cb as (e: unknown) => void)(err));
            return undefined;
          }
          return orig.apply(this, args);
        }
        case "streamRead":
        case "streamWrite": {
          // Real createReadStream/createWriteStream never throw synchronously either — the
          // returned stream emits 'error' asynchronously. Mirror that on denial (#16).
          try {
            guardCall(args, spec);
          } catch (err) {
            if (!(err instanceof CapabilityError)) throw err;
            return delivery === "streamRead"
              ? denyReadStream(err, args[0])
              : denyWriteStream(err, args[0]);
          }
          return orig.apply(this, args);
        }
      }
    };
    Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
    // Preserve function-attached variants (realpath.native, realpathSync.native).
    const native = (orig as AnyFn & { native?: AnyFn }).native;
    if (typeof native === "function") {
      (wrapped as AnyFn & { native?: AnyFn }).native = wrapFn(native, spec, delivery);
    }
    return wrapped;
  }

  function wrapSurface<T extends object>(
    real: T,
    table: Record<string, MethodSpec>,
    deliveryFor: (name: string) => Delivery,
  ): T {
    const shim: Record<string, unknown> = {};
    for (const key of Object.keys(real)) {
      shim[key] = (real as Record<string, unknown>)[key];
    }
    for (const [name, spec] of Object.entries(table)) {
      const orig = (real as Record<string, unknown>)[name];
      if (typeof orig !== "function") continue;
      shim[name] = wrapFn(orig as AnyFn, spec, deliveryFor(name));
    }
    return shim as T;
  }

  const shim = wrapSurface(realFs, FS_METHODS, fsDeliveryFor);

  // Path-taking stream constructors: `new fs.ReadStream(path)` must be mediated like
  // `createReadStream` (a dependency using the class directly must not bypass the policy).
  const shimRecord = shim as unknown as Record<string, unknown>;
  const realRecord = realFs as unknown as Record<string, unknown>;
  // ReadStream + its deprecated alias FileReadStream (identical class); same for write.
  for (const name of ["ReadStream", "FileReadStream"]) {
    if (typeof realRecord[name] === "function") {
      shimRecord[name] = wrapPathClass(realRecord[name] as PathClass, "read");
    }
  }
  for (const name of ["WriteStream", "FileWriteStream"]) {
    if (typeof realRecord[name] === "function") {
      shimRecord[name] = wrapPathClass(realRecord[name] as PathClass, "write");
    }
  }

  // Bespoke non-throwing existence probes (deny → "does not exist").
  shimRecord["existsSync"] = function existsSync(p: unknown): boolean {
    if (isDeniedExistence(p)) return false;
    return realFs.existsSync(p as Parameters<typeof realFs.existsSync>[0]);
  };
  shimRecord["exists"] = function exists(p: unknown, cb: unknown): void {
    if (typeof cb !== "function") {
      // Match Node: the callback is required; defer to the real impl for the deprecation path.
      (realFs.exists as (...a: unknown[]) => void)(p, cb);
      return;
    }
    if (isDeniedExistence(p)) {
      (cb as (exists: boolean) => void)(false);
      return;
    }
    (realFs.exists as (...a: unknown[]) => void)(p, cb);
  };

  (shim as { promises: unknown }).promises = wrapSurface(
    realFs.promises,
    PROMISES_METHODS,
    () => "reject",
  );
  return shim;
}

/**
 * Register the fs shim's specifiers into the loader registry. `fs`/`node:fs` return the
 * shim; `fs/promises`/`node:fs/promises` return its `.promises` surface. The shim is built
 * once and shared across specifiers.
 */
export function registerFsShim(reg: ShimRegistry, ctx: ShimContext): void {
  const shim = createFsShim(ctx);
  reg.set("fs", shim);
  reg.set("node:fs", shim);
  reg.set("fs/promises", shim.promises);
  reg.set("node:fs/promises", shim.promises);
}
