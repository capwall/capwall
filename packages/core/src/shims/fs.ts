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
 *    `createReadStream` — both must be mediated). Those classes are guarded via a guarded
 *    SUBCLASS, not a construct-trap Proxy: a Proxy forwards `.prototype` to its target, so
 *    `new (fs.ReadStream.prototype.constructor)(deniedPath)` reached the real class and read
 *    the file unguarded (#64). Purely fd-based operations (`read`, `write`, `ftruncate`,
 *    `fchmod`, …) are NOT mediated — fd escapes are out-of-scope.
 *  - Denials are delivered via the SAME channel the real API would use, so idiomatic
 *    (try/catch-free) callback code is not crashed by an uncaught synchronous throw:
 *      - `*Sync` methods throw `CapabilityError` synchronously (matches real sync `fs`).
 *      - `fs.promises` methods reject with `CapabilityError` (matches real promise API).
 *      - callback-style async methods (`readFile`, `mkdir`, `access`, …) invoke the
 *        caller's callback as `cb(err)` on `process.nextTick` — exactly how a real async
 *        `fs` error would arrive — instead of throwing. If the call is missing its
 *        callback (a mis-call), we fall back to throwing, same as real Node.
 *      - `createReadStream`/`createWriteStream` return a minimal stream that holds the
 *        denial and emits `'error'` as soon as an `'error'` listener is attached — sync,
 *        microtask, `setImmediate`, or `setTimeout(0)` are all caught (fix #40) — with a
 *        safety net that still surfaces (crashes, like real fs) an unhandled denial if no
 *        listener is ever attached. Fail-closed: no read/write occurs either way.
 *      - `watch`/`watchFile` throw synchronously on denial. `fs.watch` also throws
 *        synchronously in real Node (same shape). `fs.watchFile` does NOT (it invokes its
 *        listener with zeroed stats), so the throw there is a deliberate loud-failure choice —
 *        its listener is `(curr, prev)`, not an error-first callback, so there is no faithful
 *        channel to deliver a CapabilityError through. Documented in docs/threat-model.md.
 *    `exists`/`existsSync` remain bespoke non-throwing probes (see below) — untouched by
 *    the above; a denial there means "does not exist", not an error at all.
 *  - Path checks are lexical on the resolved path; symlink traversal is out of scope.
 *  - The shim object is MUTABLE by default: `graceful-fs` and friends legitimately patch
 *    `fs`, and breaking them would violate the no-SES-tax thesis. Opt into
 *    `install(…, { hardened: true })` / `CAPWALL_HARDENED=1` to freeze it instead — see
 *    `harden.ts` for exactly which surfaces that covers and which it does not.
 */
import realFs from "node:fs";
import * as path from "node:path";
import { types } from "node:util";
import { fileURLToPath } from "node:url";
import { Readable, Writable } from "node:stream";
import { isNodeUrlLike } from "./url-snapshot.js";
import {
  guard,
  guardedConstructorSubclass,
  type AnyCtor,
  type ShimContext,
  type ShimRegistry,
} from "./runtime.js";
import { harden } from "./harden.js";
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
  // `openAsBlob` reads the file's CONTENTS (through the Blob it returns), so it is an ordinary
  // read — it was simply missing from this table until the #99 sweep. Present on Node 20 and 22.
  openAsBlob: R0,
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
  // `lchmod`/`lchmodSync` exist only where `O_SYMLINK` does (darwin) — `wrapSurface` skips a
  // name the runtime does not define, so listing them here costs nothing on Linux/Windows and
  // closes the gap on macOS (#99).
  lchmod: W0,
  lchmodSync: W0,
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
  lchmod: W0,
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
 * One path argument, resolved: the string to check against policy AND the value to forward in
 * its place. See {@link coercePath}.
 */
interface ResolvedPathArg {
  /** Absolute, `/`-separated, for the policy glob match. */
  target: string;
  /**
   * What to hand the real `fs` instead of the caller's argument. Identical to the caller's value
   * for the string and `Uint8Array` shapes (neither has an accessor surface Node could re-read);
   * the CONVERTED PATH STRING for a file-URL argument, which is the pin — see {@link coercePath}.
   */
  forward: unknown;
}

/**
 * Coerce a path-like argument to an absolute, `/`-separated path string, or null when the
 * argument is not a path (an fd number, a FileHandle, …) — those are out of scope.
 *
 * WHAT NODE ACCEPTS HERE, exactly (`getValidatedPath` → `toPathIfFileURL` → `validatePath`,
 * `lib/internal/fs/utils.js` + `lib/internal/url.js`, identical on Node 20 and 22). Audited
 * argument-shape by argument-shape under #99 (tracked as #104), because every shape capwall does
 * NOT recognize is
 * a call it returns `null` for — which means the gate is SKIPPED, not failed closed:
 *
 *  - `string` — MATCHES.
 *  - any `Uint8Array` — Node's `validatePath` accepts `isUint8Array(path)`, which is every
 *    `Uint8Array`, not only a `Buffer`. capwall tested `Buffer.isBuffer`, so
 *    `fs.readFileSync(new Uint8Array(Buffer.from("/etc/passwd")))` was an UN-GATED, unlogged read
 *    under a deny-all enforce policy. FIXED — `util.types.isUint8Array`, the same predicate Node
 *    uses (a plain `instanceof` would miss a cross-realm array Node still accepts).
 *  - a file URL — Node's test is the DUCK-TYPED {@link isNodeUrlLike}, not `instanceof URL`, so
 *    `{ href, protocol: "file:", pathname: "/etc/passwd" }` is a real path to `fs`. capwall
 *    tested `instanceof URL` and skipped the gate for that object entirely. FIXED.
 *  - anything else — Node throws `ERR_INVALID_ARG_TYPE`; returning `null` here forwards it
 *    unchanged so it throws identically. (An fd `number` is accepted by `readFile`/`writeFile`
 *    and is the documented out-of-scope fd surface.)
 *
 * PINNING A URL ARGUMENT (the getter-TOCTOU of #26/#56, fs flavor — also #99). `fileURLToPath`
 * reads `protocol`/`hostname`/`pathname` off the object, and the real `fs` call then reads them
 * a SECOND time through its own `toPathIfFileURL`. A caller-supplied URL with an own shadowed
 * `pathname` accessor could legally answer differently the second time: capwall guarded
 * `/tmp/ok` and Node opened `/etc/passwd`. So the converted STRING is what gets forwarded — Node
 * stores exactly that string internally anyway (`this.path = toPathIfFileURL(path)`), so this is
 * a pin, not a behavior change.
 *
 * Fix #19: a Buffer path is decoded with `"latin1"`, not `"utf8"`. `latin1` maps every byte
 * 1:1 to a code point (U+0000–U+00FF), so the decode round-trips exactly — including
 * non-UTF-8 bytes, which a `utf8` decode would lossily collapse to U+FFFD. That lossiness
 * previously meant the STRING checked against policy could differ from the bytes actually
 * forwarded to real `fs` (the byte array is forwarded verbatim, unchanged by this function).
 * `/` is 0x2F, which is the same code point in latin1 as in ASCII/UTF-8, so segment-splitting
 * on `path.sep` below is unaffected.
 */
function coercePath(arg: unknown): ResolvedPathArg | null {
  let p: string;
  let forward: unknown = arg;
  if (typeof arg === "string") p = arg;
  else if (Buffer.isBuffer(arg)) p = arg.toString("latin1");
  else if (types.isUint8Array(arg)) p = Buffer.from(arg).toString("latin1");
  else if (isNodeUrlLike(arg)) {
    try {
      p = fileURLToPath(arg as URL);
    } catch {
      // Not a `file:` URL (or an unconvertible one) — Node's own `fileURLToPath` throws the
      // same way on the same object, so forward it untouched and let it.
      return null;
    }
    forward = p; // THE PIN — never the caller's object, which Node would read a second time
  } else return null;
  return { target: path.resolve(p).split(path.sep).join("/"), forward };
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

/**
 * How a denial is DELIVERED for a given method (fix #16). The guard DECISION is identical in
 * every mode — this only changes how a denial surfaces, so it matches the real API's own
 * error-delivery channel instead of always throwing synchronously:
 *  - `"throw"`    — synchronous throw (real sync `fs`, and `watch`/`watchFile`, which throw
 *                   synchronously on a bad path in real Node too).
 *  - `"reject"`   — a rejected Promise (real `fs.promises`).
 *  - `"callback"` — `cb(err)` on `process.nextTick` (real callback-style async `fs`, which
 *                   never throws synchronously).
 *  - `"streamRead"`/`"streamWrite"` — a stream that emits `error` once an `'error'` listener
 *                   is attached to it (real `createReadStream`/`createWriteStream`, which
 *                   never throw synchronously either — see {@link armDenyStream}, fix #40).
 */
type Delivery = "throw" | "reject" | "callback" | "streamRead" | "streamWrite";

/**
 * Classify a `FS_METHODS` entry's denial-delivery mode by name (fix #16). `fs.promises`
 * entries are uniformly `"reject"` (passed directly as `() => "reject"` at the call site) —
 * this function only covers the sync/callback/stream `fs` surface.
 */
function fsDeliveryFor(name: string): Delivery {
  if (name.endsWith("Sync")) return "throw";
  // `openAsBlob` is the one promise-returning method on the CALLBACK surface — it takes no
  // callback at all, so the `cb(err)` channel does not exist for it and a denial has to be a
  // rejection, exactly like real `fs.openAsBlob` reports every failure (#99).
  if (name === "openAsBlob") return "reject";
  if (name === "watch" || name === "watchFile") return "throw"; // watch throws in Node too; watchFile is a deliberate loud-fail (listener isn't error-first)
  if (name === "createReadStream") return "streamRead";
  if (name === "createWriteStream") return "streamWrite";
  return "callback";
}

/**
 * Arm a deny stream to deliver `err` via `'error'` as soon as a handler is attached to catch
 * it — rather than on a fixed timer (fix #40). A fixed-timer delivery (the previous
 * `setImmediate` approach) has a bounded catch window: a consumer that attaches its `'error'`
 * listener on a LATER macrotask (e.g. `setTimeout(() => s.on('error', h), 0)`) can register
 * after the timer already fired, missing the event entirely — an uncaught `'error'` crash,
 * even though the consumer *did* handle errors, just not fast enough for our arbitrary
 * timer. Real Node doesn't have this problem in practice because its open-failure arrives
 * from the libuv threadpool, a naturally wide window.
 *
 * Fix: hold the error and watch for an `'error'` listener via the stream's own `'newListener'`
 * event; the moment one is attached, deliver on `process.nextTick` (the listener is already
 * registered by then — `EventEmitter#on` emits `'newListener'` *before* pushing to its
 * listener array, but synchronously within the same call, so it has been pushed by the next
 * tick). This catches a handler attached synchronously, on a microtask, on `setImmediate`, or
 * on `setTimeout(0)` — verified empirically; only a listener attached even later than our
 * safety net below (rare, arbitrary) can still miss it, same residual as real `fs` past a
 * point.
 *
 * Safety net: if `'error'` is NEVER listened for, the denial must still surface — silently
 * discarding it would hide a security-relevant denial behind a stream that just hangs forever
 * instead of erroring like real `fs` eventually would. Deliver after `setImmediate` then
 * `setTimeout(0)` (two full loop phases later): empirically this always lands after a single
 * first-round `setImmediate`- or `setTimeout(0)`-scheduled listener attach (Node does not
 * guarantee relative ordering between those two from outside an I/O callback), so it never
 * preempts a legitimate late attach in the timing matrix above, while still guaranteeing an
 * eventual unhandled-`'error'` crash (matching real fs) when nobody ever listens.
 *
 * `.path` is set so error-logging libraries that read `stream.path` see the requested path.
 * Fail-closed regardless of delivery timing: the read/write never happens.
 */
function armDenyStream(stream: Readable | Writable, err: CapabilityError): void {
  let delivered = false;
  const deliver = () => {
    if (delivered) return;
    delivered = true;
    stream.destroy(err);
  };
  const onNewListener = (event: string | symbol) => {
    if (event !== "error") return;
    stream.removeListener("newListener", onNewListener);
    process.nextTick(deliver);
  };
  stream.on("newListener", onNewListener);
  // Safety net if no 'error' listener is ever attached. `.unref()` so these timers never keep
  // an otherwise-idle event loop alive (a program that would exit immediately shouldn't be held
  // open by a denied stream's pending delivery).
  const immediate = setImmediate(() => {
    const timer = setTimeout(() => {
      stream.removeListener("newListener", onNewListener);
      deliver();
    }, 0);
    timer.unref();
  });
  immediate.unref();
}

// `streamPath`, not `path`: the module-scope `node:path` import is what the rest of this file
// resolves paths with, and shadowing it inside a path-security shim is a trap worth avoiding.
function denyReadStream(err: CapabilityError, streamPath: unknown): Readable {
  const stream = new Readable({ read() {} }) as Readable & { path?: unknown };
  stream.path = streamPath;
  armDenyStream(stream, err);
  return stream;
}
function denyWriteStream(err: CapabilityError, streamPath: unknown): Writable {
  const stream = new Writable({ write(_chunk, _enc, cb) { cb(); } }) as Writable & { path?: unknown };
  stream.path = streamPath;
  armDenyStream(stream, err);
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
  function check(access: Access, arg: unknown): ResolvedPathArg | null {
    const resolved = coercePath(arg);
    if (resolved === null) return null;
    guard(ctx, { kind: "fs", access, path: resolved.target });
    return resolved;
  }

  /**
   * Attribute + evaluate each path of a call; throws CapabilityError on an enforce deny.
   *
   * Returns the argument list to FORWARD. It is the caller's own array unless a path argument
   * had to be pinned (a file URL — see {@link coercePath}), in which case a copy carries the
   * converted string in that slot so the real `fs` cannot re-read the caller's object and reach
   * a different file from the one that was guarded (#99).
   */
  function guardCall(args: unknown[], spec: MethodSpec): unknown[] {
    const specs = spec === "open" ? openSpecs(args) : spec === "access" ? accessSpecs(args) : spec;
    let out = args;
    for (const { index, access } of specs) {
      const resolved = check(access, args[index]);
      if (resolved === null || resolved.forward === args[index]) continue;
      if (out === args) out = args.slice();
      out[index] = resolved.forward;
    }
    return out;
  }

  /**
   * Bespoke guard for `exists`/`existsSync`, which contractually never throw. On an
   * enforce-mode denial we report "does not exist" instead of throwing: `existsSync` → false,
   * `exists(path, cb)` → `cb(false)`. Observe mode allows and falls through to the real call.
   */
  function probeExistence(pathArg: unknown): { denied: boolean; forward: unknown } {
    try {
      const resolved = check("read", pathArg);
      return { denied: false, forward: resolved === null ? pathArg : resolved.forward };
    } catch (err) {
      if (err instanceof CapabilityError) return { denied: true, forward: pathArg };
      throw err;
    }
  }

  /**
   * Guard a path-taking stream constructor (`ReadStream`/`WriteStream`) so
   * `new fs.ReadStream(path)` is mediated exactly like `createReadStream(path)`.
   *
   * This is a guarded SUBCLASS, not a construct-trap Proxy (#64). A Proxy left the real class
   * reachable as `fs.ReadStream.prototype.constructor`, which is an unguarded read of any path
   * on disk — see {@link guardedConstructorSubclass} for the full rationale and the residual.
   * Denial is a synchronous throw here (unlike `createReadStream`, which returns a stream that
   * emits `'error'`): a real stream constructor also throws synchronously on a bad argument,
   * so the shapes match. Documented in docs/threat-model.md.
   */
  function guardPathClass(RealClass: AnyCtor, access: Access): AnyCtor {
    return guardedConstructorSubclass(
      RealClass,
      (args) => {
        // Throws on enforce-deny, before super() opens anything. The returned array carries the
        // PINNED path when the caller passed a file URL (#99) — `guardedConstructorSubclass`
        // forwards what the check returns.
        const resolved = check(access, args[0]);
        if (resolved === null || resolved.forward === args[0]) return undefined;
        const out = args.slice();
        out[0] = resolved.forward;
        return out;
      },
      ctx, // hardened mode (#17) freezes the guarded subclass; no-op by default
    );
  }

  function wrapFn(orig: AnyFn, spec: MethodSpec, delivery: Delivery): AnyFn {
    const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
      switch (delivery) {
        case "throw": {
          // Real sync fs throws synchronously — matches, no translation needed.
          return orig.apply(this, guardCall(args, spec));
        }
        case "reject": {
          // Real fs.promises rejects — matches, no translation needed.
          let forwarded: unknown[];
          try {
            forwarded = guardCall(args, spec);
          } catch (err) {
            return Promise.reject(err);
          }
          return orig.apply(this, forwarded);
        }
        case "callback": {
          // Real callback-style fs NEVER throws synchronously; it delivers errors via the
          // callback. Translate a sync guard throw into an async `cb(err)` so idiomatic
          // (try/catch-free) callback code isn't crashed by an uncaught exception (#16).
          let forwarded: unknown[];
          try {
            forwarded = guardCall(args, spec);
          } catch (err) {
            if (!(err instanceof CapabilityError)) throw err;
            const cb = args[args.length - 1];
            if (typeof cb !== "function") throw err; // mis-call (no cb) — match Node, throw.
            process.nextTick(() => (cb as (e: unknown) => void)(err));
            return undefined;
          }
          return orig.apply(this, forwarded);
        }
        case "streamRead":
        case "streamWrite": {
          // Real createReadStream/createWriteStream never throw synchronously either — the
          // returned stream emits 'error' asynchronously. Mirror that on denial (#16).
          let forwarded: unknown[];
          try {
            forwarded = guardCall(args, spec);
          } catch (err) {
            if (!(err instanceof CapabilityError)) throw err;
            return delivery === "streamRead"
              ? denyReadStream(err, args[0])
              : denyWriteStream(err, args[0]);
          }
          return orig.apply(this, forwarded);
        }
      }
    };
    Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
    // Preserve function-attached variants (realpath.native, realpathSync.native).
    const native = (orig as AnyFn & { native?: AnyFn }).native;
    if (typeof native === "function") {
      (wrapped as AnyFn & { native?: AnyFn }).native = wrapFn(native, spec, delivery);
    }
    // Hardened mode: freeze LAST, once `name` and `.native` are in place — otherwise
    // `fs.realpath.native = realRealpathNative` swaps a guarded wrapper for the raw builtin.
    return harden(ctx, wrapped);
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
  // ReadStream + its deprecated alias FileReadStream; same for write. On every supported Node
  // the alias is the SAME class object (`fs.FileReadStream === fs.ReadStream`), so one guarded
  // subclass is built per real class and shared across its names — that preserves the identity
  // relation a dependency can observe, which two independent wrappers would silently break.
  const guardedStreamClasses = new Map<unknown, AnyCtor>();
  const streamClassGroups: ReadonlyArray<readonly [readonly string[], Access]> = [
    [["ReadStream", "FileReadStream"], "read"],
    [["WriteStream", "FileWriteStream"], "write"],
  ];
  for (const [names, access] of streamClassGroups) {
    for (const name of names) {
      const RealClass = realRecord[name];
      if (typeof RealClass !== "function") continue; // alias absent on this Node — skip
      let Guarded = guardedStreamClasses.get(RealClass);
      if (Guarded === undefined) {
        Guarded = guardPathClass(RealClass as AnyCtor, access);
        guardedStreamClasses.set(RealClass, Guarded);
      }
      shimRecord[name] = Guarded;
    }
  }

  // Bespoke non-throwing existence probes (deny → "does not exist").
  shimRecord["existsSync"] = harden(ctx, function existsSync(p: unknown): boolean {
    const probe = probeExistence(p);
    if (probe.denied) return false;
    return realFs.existsSync(probe.forward as Parameters<typeof realFs.existsSync>[0]);
  });
  shimRecord["exists"] = harden(ctx, function exists(p: unknown, cb: unknown): void {
    if (typeof cb !== "function") {
      // Match Node: the callback is required; defer to the real impl for the deprecation path.
      (realFs.exists as (...a: unknown[]) => void)(p, cb);
      return;
    }
    const probe = probeExistence(p);
    if (probe.denied) {
      (cb as (exists: boolean) => void)(false);
      return;
    }
    (realFs.exists as (...a: unknown[]) => void)(probe.forward, cb);
  });

  (shim as { promises: unknown }).promises = harden(
    ctx,
    wrapSurface(realFs.promises, PROMISES_METHODS, () => "reject"),
  );
  // Hardened mode: freeze the namespace LAST, after `.promises` and the class/probe overrides
  // are in place. This is what makes `fs.readFileSync = evil` / `delete fs.readFileSync` fail.
  return harden(ctx, shim);
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
