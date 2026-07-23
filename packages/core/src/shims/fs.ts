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
 *  - Denials throw synchronously (callback-style calls included) and reject for
 *    `fs.promises`. Loud failure is the point of enforce mode — EXCEPT `exists`/`existsSync`,
 *    which are contractually non-throwing: a denied existence probe returns "does not exist"
 *    (`false` / `cb(false)`) rather than throwing, which also avoids leaking existence.
 *  - Path checks are lexical on the resolved path; symlink traversal is out of scope.
 */
import realFs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { attributeCaller } from "../attribution/index.js";
import { evaluate, type Decision } from "../policy/evaluate.js";
import { CapabilityError } from "../errors.js";
import type { Mode, Policy } from "@capwall/policy-schema";

/** Callback capwall invokes on every decision (log sink in observe, collector for gen-policy). */
export type DecisionSink = (pkg: string, decision: Decision) => void;

export interface ShimContext {
  policy: Policy;
  mode: Mode;
  onDecision: DecisionSink;
  /** Absolute project root; used for attribution and policy-glob resolution. */
  projectRoot?: string;
}

type Access = "read" | "write";
/** Which positional args of a method are paths, and what access each implies. */
interface PathSpec {
  index: number;
  access: Access;
}
/** `"open"`-kind methods derive read/write from their flags argument. */
type MethodSpec = PathSpec[] | "open";

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
  access: R0,
  accessSync: R0,
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
  access: R0,
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
 */
function coercePath(arg: unknown): string | null {
  let p: string;
  if (typeof arg === "string") p = arg;
  else if (Buffer.isBuffer(arg)) p = arg.toString("utf8");
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

type AnyFn = (...args: unknown[]) => unknown;
type PathClass = abstract new (...a: never[]) => unknown;

/**
 * Build a shimmed `fs` module: every method in the tables above is guarded; everything else
 * (constants, fd-based ops, Stats, …) is the real thing, passed through.
 */
export function createFsShim(ctx: ShimContext): typeof import("node:fs") {
  /**
   * Attribute + evaluate one path/access. Reports the decision to `onDecision` and returns
   * whether it is allowed. Returns `true` (nothing to check) when `arg` is not a path (fd /
   * FileHandle). Never throws — the caller decides how to signal a denial.
   */
  function check(access: Access, arg: unknown): boolean {
    const target = coercePath(arg);
    if (target === null) return true;
    const pkg = attributeCaller(
      ctx.projectRoot !== undefined ? { projectRoot: ctx.projectRoot } : {},
    );
    const decision = evaluate(ctx.policy, ctx.mode, pkg, { kind: "fs", access, path: target });
    ctx.onDecision(pkg, decision);
    if (!decision.allowed) {
      throw new CapabilityError(decision.reason, pkg);
    }
    return true;
  }

  /** Attribute + evaluate each path of a call; throws CapabilityError on an enforce deny. */
  function guard(args: unknown[], spec: MethodSpec): void {
    const specs = spec === "open" ? openSpecs(args) : spec;
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

  function wrapFn(orig: AnyFn, spec: MethodSpec, rejectOnDeny: boolean): AnyFn {
    const wrapped: AnyFn = function (this: unknown, ...args: unknown[]) {
      if (rejectOnDeny) {
        try {
          guard(args, spec);
        } catch (err) {
          return Promise.reject(err);
        }
      } else {
        guard(args, spec);
      }
      return orig.apply(this, args);
    };
    Object.defineProperty(wrapped, "name", { value: orig.name, configurable: true });
    // Preserve function-attached variants (realpath.native, realpathSync.native).
    const native = (orig as AnyFn & { native?: AnyFn }).native;
    if (typeof native === "function") {
      (wrapped as AnyFn & { native?: AnyFn }).native = wrapFn(native, spec, rejectOnDeny);
    }
    return wrapped;
  }

  function wrapSurface<T extends object>(
    real: T,
    table: Record<string, MethodSpec>,
    rejectOnDeny: boolean,
  ): T {
    const shim: Record<string, unknown> = {};
    for (const key of Object.keys(real)) {
      shim[key] = (real as Record<string, unknown>)[key];
    }
    for (const [name, spec] of Object.entries(table)) {
      const orig = (real as Record<string, unknown>)[name];
      if (typeof orig !== "function") continue;
      shim[name] = wrapFn(orig as AnyFn, spec, rejectOnDeny);
    }
    return shim as T;
  }

  const shim = wrapSurface(realFs, FS_METHODS, false);

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
    true,
  );
  return shim;
}
