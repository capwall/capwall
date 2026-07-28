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
 *  - The Node ≥22 ENUMERATION family `glob`/`globSync`/`promises.glob` is mediated as one
 *    `fs.read` decision per pattern, on the directory that pattern's walk is rooted at — see the
 *    block comment above {@link GlobCwd} for the semantics and why they are not per-result
 *    (#106). Absent on Node 20, where `wrapSurface` skips them and the shim is unchanged.
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
// The real `fs` comes from `../real-builtins.cjs`, never a static `import … from "node:fs"` —
// that import would put `node:fs` in the ESM cache before capwall's loader hook registers and
// leave the hook's re-mediation backstop dead (#78). `node:path`/`node:util`/`node:url`/
// `node:stream` are NOT mediated, so they stay ordinary imports.
import { realFs } from "../real-builtins.cjs";
import * as path from "node:path";
import { types } from "node:util";
import { fileURLToPath } from "node:url";
import { Readable, Writable } from "node:stream";
import { isNodeUrlLike } from "./url-snapshot.js";
import { copyOwnFieldsExcept } from "./pin.js";
import { nodeGlobBase } from "../policy/glob.js";
import {
  guard,
  guardedConstructorSubclass,
  withAuthorizedEnvKeys,
  type AnyCtor,
  type ShimContext,
  type ShimRegistry,
} from "./runtime.js";
import { harden } from "./harden.js";
import { CapabilityError } from "../errors.js";

type Access = "read" | "write";
/** Which positional args of a method are paths, and what access each implies. */
interface PathSpec {
  index: number;
  access: Access;
}
/**
 * `"open"`-kind methods derive read/write from their flags argument; `"access"`-kind
 * methods derive it from their mode bitmask (see {@link accessSpecs}, fix #20); `"glob"`-kind
 * methods take a PATTERN rather than a path and are gated on the directory that pattern's walk
 * is rooted at (see {@link guardGlobCall}, issue #106).
 */
type MethodSpec = PathSpec[] | "open" | "access" | "glob";

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
  // Node ≥22 only; `wrapSurface` skips a name the runtime does not define, so these two are a
  // clean no-op on Node 20 (issue #106).
  glob: "glob",
  globSync: "glob",
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
  glob: "glob", // Node ≥22 only — see FS_METHODS (#106)
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
   * for a string (immutable, nothing to re-read); the CONVERTED PATH STRING for a file-URL
   * argument and a private COPY for a byte path — both pins. See {@link coercePath}.
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
 * ─────────────────────────────────────────────────────────────────────────────────────────────
 * WHY A BYTE PATH IS DECODED `latin1` AND NOT `utf8` (#19, re-examined and CONFIRMED under #41)
 * ─────────────────────────────────────────────────────────────────────────────────────────────
 * A POSIX path is BYTES; a policy glob is a JS STRING. Something has to bridge them, and both
 * candidate decodes are lossy in one direction:
 *
 *  - `latin1` (this) maps every byte 1:1 onto U+0000–U+00FF, so it is a BIJECTION between byte
 *    sequences and strings. Cost: a policy author who writes `"./data/café.txt"` (UTF-8 in the
 *    JSON, so `é` is U+00E9 in the loaded string) does not match the latin1 decoding of those
 *    same bytes (`cafÃ©`), so a valid non-ASCII UTF-8 path passed as a Buffer FALSE-DENIES.
 *  - `utf8` (what #19 replaced) matches that author's intent, but is NOT injective: every
 *    maximal invalid subsequence collapses to a single U+FFFD, so MANY distinct byte paths
 *    decode to the SAME string.
 *
 * The asymmetry is what decides it, not the frequency of either case. Under `latin1` the
 * checked string determines the forwarded bytes UNIQUELY, so "the author believes a path is
 * denied but it matches" is not merely unlikely — it is unreachable, because no second byte
 * sequence shares the string that was matched. Under `utf8` it is reachable: granting the one
 * path an `observe` run recorded (`…/na<U+FFFD>ve.txt`) silently grants every other file whose
 * name differs only in the bytes that collapsed, and that aliasing is also what makes the audit
 * trail unable to say which file was actually read. A false-deny is a loud, fail-closed error; a
 * false-allow in an anti-exfiltration control is the failure that matters.
 *
 * The third option #41 raises — normalize BOTH sides into byte space, by UTF-8-encoding policy
 * globs and string paths so a `café` grant matches `café` bytes — was rejected on DX, not on
 * security: it works, but it makes every non-ASCII path in an `observe` trace and in a generated
 * policy a latin1 byte-string, so the COMMON case (a non-ASCII path passed as an ordinary
 * string, readable today) becomes mojibake to fix the RARE one (a non-ASCII path passed as a
 * byte array). Keeping the mismatch confined to the rare case is the better trade.
 *
 * `/` is 0x2F, the same code point in latin1 as in ASCII/UTF-8, so segment-splitting on
 * `path.sep` below is unaffected either way.
 *
 * ONE branch covers every byte path, deliberately. Node's `validatePath` accepts
 * `isUint8Array(path)`; capwall tested `Buffer.isBuffer` and skipped the gate for everything
 * else (#108). A second, narrower predicate alongside the correct one is how that gap happened,
 * so there is now no second predicate to drift — a `Buffer` IS a `Uint8Array` and takes the
 * same branch. The forwarded value is a private COPY of those bytes, on the same pinning rule as
 * the URL case: the caller keeps a reference to the array it passed, and capwall will not check
 * one byte sequence and hand Node an array whose contents could since have changed.
 */
function coercePath(arg: unknown): ResolvedPathArg | null {
  let p: string;
  let forward: unknown = arg;
  if (typeof arg === "string") p = arg;
  else if (types.isUint8Array(arg)) {
    const pinned = Buffer.from(arg); // copies (Buffer.from(<TypedArray>) always does)
    p = pinned.toString("latin1");
    forward = pinned; // THE PIN — the bytes that were checked, not the caller's live array
  } else if (isNodeUrlLike(arg)) {
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

/*
 * ─────────────────────────────────────────────────────────────────────────────────────────────
 * `fs.glob` / `fs.globSync` / `fs.promises.glob` — Node ≥22 (issue #106)
 * ─────────────────────────────────────────────────────────────────────────────────────────────
 *
 * THE SEMANTICS, and why they are these. Every other entry in the tables above takes a PATH;
 * `glob`'s first argument is a PATTERN, so "which path is being read" has no single answer and
 * #106 deferred it out of the #99 sweep as a policy decision rather than a table entry.
 *
 * A glob is an ENUMERATION, and capwall already has a shape for that: `readdir` is gated as
 * `fs.read` on the DIRECTORY, not on each entry it returns. `glob` is `readdir` with a filter and
 * a recursion rule, so it is gated the same way — **one `fs.read` decision per pattern, on the
 * directory that pattern's walk is rooted at.** Concretely, a package needs a read grant covering
 * the base directory, and `dir/**` (which `policy/glob.ts` deliberately matches against `dir`
 * itself) is what grants globbing inside a subtree.
 *
 * WHY NOT CHECK EACH RESULT PATH INSTEAD, which is more precise:
 *  - It cannot be done before the walk, and the walk is the leak. `options.exclude` is a
 *    CALLER-SUPPLIED FUNCTION that Node invokes with entries as it discovers them (verified on
 *    Node 22: a `**` walk handed the callback all 35 entries of the directory it was walking), so
 *    a dependency reads the directory listing through its own callback no matter what capwall
 *    does with the return value afterwards. Post-filtering results would contain the answer and
 *    not the disclosure.
 *  - Filtering results is a SOFT deny on a value-returning API: the caller is told the files do
 *    not exist. capwall does that in exactly one place (`exists`, whose contract is boolean) and
 *    deliberately nowhere else.
 *  - One decision per result would make `observe` output, and therefore every generated policy, a
 *    property of the machine's filesystem rather than of the package — the same reproducibility
 *    failure #67 fixed for `Object.keys(process.env)`.
 *
 * WHAT A GLOB CAN STILL LEARN, stated rather than implied: everything under a directory the
 * package already holds a read grant on. A `fs.read: ["./data/**"]` grant permits enumerating the
 * whole `./data` subtree in one call — but it already permitted reading every file in it, and
 * recursive `readdir` already gave the same listing.
 *
 * PREFIX-ONLY WOULD HAVE BEEN FAIL-OPEN. #106's own inclination was "the non-magic prefix of the
 * pattern". Measured against real `fs.globSync` on Node 22, three shapes escape that prefix:
 * `{/etc,/tmp}/*.conf` (a brace group with absolute alternatives — the prefix is empty, the walk
 * is in `/etc`), `{.,..}/*.conf`, and `**` followed by `..`. So the base directory is computed by
 * `nodeGlobBase` (`policy/glob.ts`), which answers with the FILESYSTEM ROOT for every construct it
 * cannot prove downward-only. That is the fail-closed answer: no reasonable policy grants `/`, and
 * one that does has already said yes to everything else.
 *
 * AND THE PREFIX ITSELF WAS FAIL-OPEN UNTIL #120, for the same reason one level down: it decided
 * where the walk goes by looking for the STRING `..` in the pattern text, and minimatch will
 * happily spell a `..` as `[.][.]`, `..{,}`, `.{.,.}` or `[.-.][.-.]`. `policy/glob.ts` no longer
 * looks for it — it performs the brace expansion the matcher performs and then requires every
 * post-prefix segment to be PROVABLY downward-only, refusing anything it cannot prove. See the
 * `expandBraces` / `segmentIsDownwardOnly` doc comments there, and the property test in
 * `test/fs-glob.test.ts` that checks capwall's answer against where real `fs.globSync` walked.
 */

/**
 * The `process.env` key Node's own glob machinery reads, and the once-per-process load that
 * reads it — moved off every dependency's stack.
 *
 * Node's vendored **minimatch** reads `process.env.__MINIMATCH_TESTING_PLATFORM__` at module
 * scope, and Node `require`s that module LAZILY, from inside the first glob call in the process.
 * The read therefore lands on the stack of whichever dependency happens to glob first and is
 * indistinguishable from that dependency reading the key itself. That is a pure RECORDING defect
 * — a denied env read is a soft deny returning `undefined`, which is exactly what minimatch
 * expects when the key is unset, so nothing misbehaves — but it is the shape #67 fixed for
 * `Object.keys(process.env)`: `observe` would emit an `env` grant for a key no package asked
 * for, attributed by accident, and `enforce` would print a
 * `DENY '<pkg>' env:__MINIMATCH_TESTING_PLATFORM__` line that reads as a dependency probing the
 * environment.
 *
 * WHY A WARM-UP RATHER THAN A WINDOW AROUND THE REAL CALL. `withAuthorizedEnvKeys` is
 * synchronous save/restore, and `fsPromises.glob` returns an async generator whose body does not
 * run until it is stepped — outside any window the wrapper could hold open (measured: the read
 * still landed on the dependency). Forcing the load once, here, covers all three forms with one
 * mechanism instead of one per delivery channel.
 *
 * The empty pattern matches nothing and walks nothing (verified on Node 22); the call exists only
 * to make Node perform its lazy `require`. `withAuthorizedEnvKeys` — the same key-scoped
 * mechanism `shims/child_process.ts` uses for `NODE_V8_COVERAGE` and friends — keeps the one read
 * ungated by exact string match. Nothing else is exempted, for anyone, at any point.
 */
const GLOB_INTERNAL_ENV_KEYS: ReadonlySet<string> = new Set(["__MINIMATCH_TESTING_PLATFORM__"]);

let globInternalsWarmed = false;

function warmGlobInternals(): void {
  if (globInternalsWarmed) return;
  globInternalsWarmed = true;
  const realGlobSync = (realFs as { globSync?: (p: string) => unknown }).globSync;
  if (typeof realGlobSync !== "function") return; // Node 20 — nothing to warm
  try {
    withAuthorizedEnvKeys(GLOB_INTERNAL_ENV_KEYS, () => realGlobSync(""));
  } catch {
    // Best-effort. The worst case is the cosmetic recording defect described above, not a gap.
  }
}

/** One glob call's resolved `cwd`: what the patterns resolve against, and what to forward. */
interface GlobCwd {
  /** Absolute, NATIVE-separator directory the patterns resolve against. */
  dir: string;
  /** The value to put in `options.cwd`; `undefined` leaves the key off the pinned clone. */
  forward: unknown;
  /** False when `cwd` was a shape capwall cannot resolve — every pattern is then unbounded. */
  resolvable: boolean;
}

/**
 * Resolve a single, ALREADY-READ `options.cwd` value. Node accepts a string or a file URL here
 * (it rejects a `Buffer`, unlike a path argument — verified on Node 22), and a URL is converted
 * with the same `fileURLToPath` + forward-the-string pin {@link coercePath} applies.
 *
 * Anything else is `resolvable: false` rather than an assumed `process.cwd()`: Node will throw on
 * it today, and if a future Node accepts a shape capwall does not model, "unbounded" is the
 * answer that fails closed instead of gating a directory the walk was never going to start in.
 */
function resolveGlobCwd(raw: unknown): GlobCwd {
  if (raw === undefined || raw === null) {
    return { dir: path.resolve(), forward: undefined, resolvable: true };
  }
  if (typeof raw === "string") return { dir: path.resolve(raw), forward: raw, resolvable: true };
  if (isNodeUrlLike(raw)) {
    try {
      const converted = fileURLToPath(raw as URL);
      return { dir: path.resolve(converted), forward: converted, resolvable: true };
    } catch {
      // Not a convertible `file:` URL — Node's own conversion throws on the same object.
      return { dir: path.resolve(), forward: raw, resolvable: false };
    }
  }
  return { dir: path.resolve(), forward: raw, resolvable: false };
}

/** Absolute, `/`-separated form — the shape `policy/glob.ts` matches against. */
function toPolicyPath(nativePath: string): string {
  return nativePath.split(path.sep).join("/");
}

/**
 * The directory a single glob pattern's walk is rooted at, resolved against `cwd` — the path the
 * `fs.read` decision is taken on. Falls back to the filesystem ROOT whenever the pattern's reach
 * cannot be bounded (see the block comment above and `nodeGlobBase`).
 */
function globBase(pattern: unknown, cwd: GlobCwd): string {
  if (!cwd.resolvable || typeof pattern !== "string") return toPolicyPath(path.parse(cwd.dir).root);
  // On win32 `\` is a path SEPARATOR in a glob pattern; on POSIX it is minimatch's escape
  // character, which `nodeGlobPrefixes` refuses to model (it returns null → root).
  const normalized = path.sep === "\\" ? pattern.replace(/\\/g, "/") : pattern;
  return nodeGlobBase(normalized, cwd.dir);
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
 *  - `"asyncIterable"` — an async generator that rejects on its FIRST `next()`. This is the one
 *                   `fs.promises` method that does not return a promise: `fsPromises.glob`
 *                   returns an `AsyncGenerator`, and real Node reports even an
 *                   `ERR_INVALID_ARG_TYPE` on it at iteration rather than at the call (verified
 *                   on Node 22). Rejecting at the call instead would hand `for await` a promise
 *                   and crash with a `TypeError` that names the wrong problem (#106).
 */
type Delivery = "throw" | "reject" | "callback" | "streamRead" | "streamWrite" | "asyncIterable";

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
  // `fs.glob` is error-first callback style like the rest of this surface (`(err, matches)`), and
  // real Node does not throw synchronously from it — so the ordinary callback channel is right.
  return "callback";
}

/**
 * Classify a `PROMISES_METHODS` entry's delivery. Uniformly `"reject"` except for `glob`, the
 * single method on that surface that returns an async iterator rather than a promise — see
 * {@link Delivery}. This is a function rather than the `() => "reject"` literal it replaced
 * precisely so the exception is written down where the rule is.
 */
function promisesDeliveryFor(name: string): Delivery {
  return name === "glob" ? "asyncIterable" : "reject";
}

/**
 * A denied `fsPromises.glob`: an async iterator whose first `next()` rejects with `err`, which is
 * exactly where real `fsPromises.glob` reports an invalid argument (its body is a generator, so
 * nothing runs until it is stepped).
 *
 * Hand-built rather than an `async function*` with a bare `throw`, for two reasons: that shape is
 * a generator with no `yield` (which the lint gate rejects, correctly — it reads as a mistake),
 * and `return()` has to resolve rather than reject, so a consumer that abandons the iterator does
 * not get a second, unexpected rejection out of its own `break`.
 */
function denyAsyncIterator(err: CapabilityError): AsyncIterableIterator<never> {
  return {
    async next(): Promise<IteratorResult<never>> {
      throw err;
    },
    async return(): Promise<IteratorResult<never>> {
      return { done: true, value: undefined };
    },
    async throw(): Promise<IteratorResult<never>> {
      throw err;
    },
    [Symbol.asyncIterator]() {
      return this;
    },
  };
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
  /**
   * Attribute + evaluate one `glob`/`globSync`/`promises.glob` call (#106). One `fs.read`
   * decision per pattern, on the directory that pattern's walk is rooted at; see the block
   * comment above {@link GlobCwd} for why that is the guarded target and not the result set.
   *
   * Returns the argument list to FORWARD: the caller's own options bag and pattern array are
   * never handed to Node, because Node re-reads both after capwall has decided.
   */
  function guardGlobCall(args: unknown[]): unknown[] {
    warmGlobInternals(); // before anything else — see the constant's doc for what this is for
    const out = args.slice();

    // OPTIONS SLOT. Node's `glob(pattern[, options], callback)` treats a FUNCTION at args[1] as
    // the callback, so an options bag is present only when args[1] is not one. `globSync` and
    // `fsPromises.glob` take no callback and Node rejects a function as their options bag
    // (`typeof options !== "object"` fails for a function), so one rule serves all three.
    const rawOptions = args.length > 1 && typeof args[1] !== "function" ? args[1] : undefined;

    let cwd: GlobCwd;
    if (rawOptions !== null && typeof rawOptions === "object") {
      // PIN (#26/#56/#89, glob flavor). `options.cwd` decides which directory the walk starts in
      // and Node reads it AFTER capwall does, so a caller accessor could legally answer
      // differently the second time — capwall guards `/tmp/ok`, Node walks `/etc`. Read it
      // EXACTLY ONCE: `copyOwnFieldsExcept` skips the key (so it cannot invoke an own getter) and
      // the single read below covers the own and inherited cases alike. Node then receives a
      // clone in which that one answer is a plain data property, and every other own accessor on
      // the bag has been flattened as well.
      const pinnedOptions: Record<string, unknown> = {};
      copyOwnFieldsExcept(pinnedOptions, rawOptions, ["cwd"]);
      cwd = resolveGlobCwd((rawOptions as Record<string, unknown>)["cwd"]);
      if (cwd.forward !== undefined) pinnedOptions["cwd"] = cwd.forward;
      out[1] = pinnedOptions;
    } else {
      cwd = resolveGlobCwd(undefined);
    }

    // PATTERN(S). Node accepts a string or an array of strings and rejects every other shape.
    // The array is snapshotted for the same reason the options bag is pinned: Node reads each
    // element twice (once in `validateStringArray`, once while walking). A non-string element
    // reaches `globBase` as an unbounded pattern, so a shape capwall does not model is denied
    // rather than skipped (#99's lesson).
    const rawPattern = args[0];
    const patterns: unknown[] = Array.isArray(rawPattern) ? rawPattern.slice() : [rawPattern];
    if (Array.isArray(rawPattern)) out[0] = patterns;

    // ONE decision per pattern: a call naming three patterns performs three enumerations, and an
    // `observe` run has to emit a grant for each. Enforce throws on the first denial, exactly
    // like the other multi-path methods here (`copyFile`, `rename`). An EMPTY array enumerates
    // nothing and correctly records nothing.
    for (const pattern of patterns) {
      guard(ctx, { kind: "fs", access: "read", path: globBase(pattern, cwd) });
    }
    return out;
  }

  function guardCall(args: unknown[], spec: MethodSpec): unknown[] {
    if (spec === "glob") return guardGlobCall(args);
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
        case "asyncIterable": {
          // `fsPromises.glob` returns an async generator; real Node surfaces argument errors on
          // the first `next()`, so a denial does too (#106).
          let forwarded: unknown[];
          try {
            forwarded = guardCall(args, spec);
          } catch (err) {
            if (!(err instanceof CapabilityError)) throw err;
            return denyAsyncIterator(err);
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
    wrapSurface(realFs.promises, PROMISES_METHODS, promisesDeliveryFor),
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
