/**
 * Attribution — map "the code currently executing a shimmed call" to the OWNING npm package.
 *
 * THIS IS THE CORE RESEARCH RISK of capwall (see docs/architecture.md § Risks). The plan:
 *   1. Capture a stack trace (V8 `Error.captureStackTrace` with a structured
 *      `prepareStackTrace` to get CallSite objects without string-parsing overhead).
 *   2. Walk frames from the top, skipping capwall's own shim frames and Node-internal
 *      frames, to the first frame whose file path resolves into a `node_modules/<pkg>`
 *      (or a workspace package) directory.
 *   3. Return that package's name. Cache file-path → package resolution aggressively; the
 *      stack walk is the dominant cost against the <1ms/req target.
 *
 * KNOWN HARD PROBLEM: calls that pass through a shared helper (lodash, a logger, a promise
 * wrapper) attribute to the HELPER, not the package that initiated the operation — and a
 * malicious package can deliberately launder its call through a trusted helper. The
 * implementing agent must pick and DOCUMENT an attribution policy (nearest-package vs
 * first-non-core vs initiating-app-boundary) and its blind spots.
 */

/** Sentinel for a call that could not be attributed to any package (e.g. app-root code). */
export const APP_ROOT = "<app>" as const;

export interface AttributionOptions {
  /** Absolute path of the project root, used to distinguish app code from dependencies. */
  projectRoot?: string;
  /** Max stack frames to inspect (bound the hot-path cost). */
  maxFrames?: number;
}

/**
 * Return the name of the package that owns the current call site.
 *
 * TODO(capwall): implement the stack-walk described above. Returning APP_ROOT for now means
 * every call attributes to the app; combined with observe mode this is inert, so wiring the
 * shims before attribution lands cannot cause false denials.
 */
export function attributeCaller(_options: AttributionOptions = {}): string {
  // TODO(capwall): capture stack via structured prepareStackTrace, walk to first
  // node_modules frame, resolve to package name, cache the result.
  return APP_ROOT;
}

/**
 * Resolve a source file path to the npm package that contains it (or APP_ROOT).
 * TODO(capwall): walk up from the file to the nearest package.json under node_modules /
 * workspace, read its `name`, and memoize by directory.
 */
export function packageForPath(_filePath: string, _projectRoot?: string): string {
  // TODO(capwall): implement + cache.
  return APP_ROOT;
}
