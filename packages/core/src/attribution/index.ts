/**
 * Attribution — map "the code currently executing a shimmed call" to the OWNING npm package.
 *
 * Mechanism:
 *   1. Capture a stack trace as structured V8 CallSite objects (temporary
 *      `Error.prepareStackTrace` swap — no string parsing on the hot path).
 *   2. Walk frames from the top, skipping capwall's own frames (anything under this
 *      package's src/dist tree) and Node-internal frames (`node:*`, native, eval).
 *   3. The first remaining frame wins: resolve its file path to a package via the last
 *      `node_modules/<pkg>` segment in the path (memoized per file path).
 *
 * ATTRIBUTION POLICY (documented per AGENTS.md): **nearest-package**. The package that owns
 * the frame closest to the shimmed call is charged with the capability. Chosen because it is
 * cheap (first qualifying frame terminates the walk), deterministic, and matches the
 * NodeShield model. Known blind spots, accepted and documented in docs/threat-model.md and
 * docs/architecture.md:
 *   - Calls funneled through a shared helper (a logger, a promisify wrapper) attribute to
 *     the HELPER, not the initiator. A trusted helper with broad grants is therefore a
 *     laundering target — keep helper grants tight.
 *   - Callbacks a dependency schedules but the app invokes attribute to the dependency
 *     frame if it is nearest, which is usually the desired outcome.
 *
 * Paths not under any `node_modules` (the application's own files, and files `require`d by
 * absolute path) attribute to {@link APP_ROOT}.
 */
import * as path from "node:path";
import { fileURLToPath } from "node:url";

/** Sentinel for a call that could not be attributed to any package (e.g. app-root code). */
export const APP_ROOT = "<app>" as const;

/**
 * Root of the capwall core package tree (…/packages/core/src or …/dist depending on how we
 * were loaded). Frames under it are capwall's own shim/loader machinery — always skipped.
 */
const CAPWALL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export interface AttributionOptions {
  /** Absolute path of the project root, used to distinguish app code from dependencies. */
  projectRoot?: string;
  /** Max stack frames to inspect (bound the hot-path cost). */
  maxFrames?: number;
}

const DEFAULT_MAX_FRAMES = 25;

/** file path → package name, memoized. Attribution is the hot path (<1ms/req target). */
const pathToPackage = new Map<string, string>();

/** Capture the current stack as structured CallSites (no string formatting). */
function captureCallSites(maxFrames: number): NodeJS.CallSite[] {
  const origPrepare = Error.prepareStackTrace;
  const origLimit = Error.stackTraceLimit;
  Error.prepareStackTrace = (_err, sites) => sites;
  Error.stackTraceLimit = maxFrames;
  const holder: { stack?: NodeJS.CallSite[] } = {};
  Error.captureStackTrace(holder as object, captureCallSites);
  const sites = holder.stack ?? [];
  Error.prepareStackTrace = origPrepare;
  Error.stackTraceLimit = origLimit;
  return sites;
}

/** Normalize a CallSite file name (may be a file:// URL under ESM/vitest) to an fs path. */
function toFsPath(fileName: string): string | null {
  if (fileName.startsWith("file://")) {
    try {
      return fileURLToPath(fileName.split("?")[0] ?? fileName);
    } catch {
      return null;
    }
  }
  // Node internals ("node:fs"), native frames, evals — not filesystem paths.
  if (!path.isAbsolute(fileName)) return null;
  return fileName;
}

/**
 * Return the name of the package that owns the current call site (nearest-package policy),
 * or {@link APP_ROOT} when the nearest qualifying frame is application code.
 */
export function attributeCaller(options: AttributionOptions = {}): string {
  const sites = captureCallSites(options.maxFrames ?? DEFAULT_MAX_FRAMES);
  for (const site of sites) {
    const fileName = site.getFileName();
    if (!fileName) continue; // native / anonymous frames
    const fsPath = toFsPath(fileName);
    if (fsPath === null) continue; // node:* internals, evals
    if (fsPath.startsWith(CAPWALL_ROOT + path.sep)) continue; // capwall's own machinery
    return packageForPath(fsPath, options.projectRoot);
  }
  return APP_ROOT;
}

/**
 * Resolve a source file path to the npm package that contains it (or APP_ROOT).
 *
 * Implementation: take the LAST `node_modules/` segment in the path and read the package
 * name from the next one (or two, for `@scope/name`) segments. This handles pnpm's
 * `.pnpm/<pkg>@<v>/node_modules/<pkg>/…` layout for free and never touches the disk.
 * Memoized per file path.
 */
export function packageForPath(filePath: string, _projectRoot?: string): string {
  const cached = pathToPackage.get(filePath);
  if (cached !== undefined) return cached;

  const normalized = filePath.split(path.sep).join("/");
  const marker = "/node_modules/";
  const idx = normalized.lastIndexOf(marker);
  let pkg: string = APP_ROOT;
  if (idx !== -1) {
    const rest = normalized.slice(idx + marker.length).split("/");
    const first = rest[0];
    if (first) {
      if (first.startsWith("@")) {
        const second = rest[1];
        pkg = second ? `${first}/${second}` : APP_ROOT;
      } else {
        pkg = first;
      }
    }
  }
  pathToPackage.set(filePath, pkg);
  return pkg;
}
