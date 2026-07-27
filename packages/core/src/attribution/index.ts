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
  /**
   * Max stack frames to inspect (bounds the hot-path cost). Defaults to
   * {@link DEFAULT_MAX_FRAMES}; configurable per-install (`install(..., { attribution: {
   * maxFrames } })`) or via `CAPWALL_MAX_FRAMES` — see {@link resolveMaxFrames} and issue #15.
   */
  maxFrames?: number;
}

/**
 * Default frame budget. Deliberately unchanged from the original hard-coded value so raising
 * the cap is always an explicit, opt-in decision (no silent behavior/perf change on upgrade).
 */
export const DEFAULT_MAX_FRAMES = 25;

/**
 * The outcome of one attribution, including WHY the walk ended.
 *
 * SECURITY (issue #15): "walked the whole stack and found only app frames" and "ran out of
 * frame budget before reaching any package frame" both produce {@link APP_ROOT}, but they are
 * NOT the same event. The second is a possible MIS-attribution: the real owning dependency may
 * sit just past the cap, and charging its call to `<app>` can wrongly ALLOW it (the app is the
 * trust root and usually holds broad grants). Callers get `budgetExhausted` so the difference
 * is observable instead of silent. Enforcement behavior is intentionally unchanged — this is
 * telemetry, not a new deny path (a fail-closed default here would break benign deep stacks).
 */
export interface Attribution {
  /** Owning package name, or {@link APP_ROOT}. */
  pkg: string;
  /**
   * True only when the frame budget was fully consumed AND no qualifying frame was found, so
   * `pkg` is the {@link APP_ROOT} fallback rather than a positively-identified owner.
   */
  budgetExhausted: boolean;
}

/**
 * Coerce a user-supplied frame budget to a usable value, or `null` if it is unusable.
 *
 * Accepts a number or a numeric string (the env-var channel). Requires a POSITIVE SAFE
 * INTEGER: `NaN`/`Infinity`/`0`/negatives/fractions would be handed straight to
 * `Error.stackTraceLimit`, where they silently capture zero or unpredictably few frames —
 * i.e. garbage config would turn into blanket `<app>` mis-attribution. Fail to the default
 * instead. Pure (never warns) so it is safe to call on the hot path.
 */
function coerceMaxFrames(value: unknown): number | null {
  if (value === undefined || value === null || value === "") return null;
  const n = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  if (!Number.isSafeInteger(n) || n < 1) return null;
  return n;
}

/**
 * Validate a configured frame budget, falling back to {@link DEFAULT_MAX_FRAMES}.
 *
 * FAIL-OPEN ON CONFIG TYPOS, BY DESIGN: capwall is installed into someone else's process via
 * a preload, so throwing here would crash a host app over a mistyped env var — a far worse
 * outcome than running with the default. The bad value is reported on stderr (the same
 * channel the preload uses for decisions) so it is not silently ignored.
 *
 * `undefined`/empty means "not configured" and is not a typo — no warning, no noise.
 */
export function resolveMaxFrames(value: unknown, source = "attribution.maxFrames"): number {
  const coerced = coerceMaxFrames(value);
  if (coerced !== null) return coerced;
  if (value !== undefined && value !== null && value !== "") {
    process.stderr.write(
      `[capwall] ignoring invalid ${source}=${JSON.stringify(value)} ` +
        `(want a positive integer); using default ${DEFAULT_MAX_FRAMES}\n`,
    );
  }
  return DEFAULT_MAX_FRAMES;
}

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
 *
 * Convenience wrapper over {@link attributeCallerDetailed} for callers that do not care why
 * the walk ended. Prefer the detailed form in the enforcement path.
 */
export function attributeCaller(options: AttributionOptions = {}): string {
  return attributeCallerDetailed(options).pkg;
}

/**
 * Attribute the current call site, reporting both the owning package and whether the walk
 * ended by exhausting the frame budget (see {@link Attribution}).
 *
 * Note the budget covers ALL captured frames, including the handful of capwall frames between
 * the shim entry point and here — raising `maxFrames` therefore buys slightly fewer usable
 * caller frames than the number suggests.
 */
export function attributeCallerDetailed(options: AttributionOptions = {}): Attribution {
  // Re-coerce even though install()/preload already validated: `attributeCaller` is a public
  // export, and a bogus limit reaching `Error.stackTraceLimit` would silently attribute
  // everything to <app> (a wrongly-ALLOW failure mode). Coercion here is pure and cheap.
  const maxFrames = coerceMaxFrames(options.maxFrames) ?? DEFAULT_MAX_FRAMES;
  const sites = captureCallSites(maxFrames);
  for (const site of sites) {
    const fileName = site.getFileName();
    if (!fileName) continue; // native / anonymous frames
    const fsPath = toFsPath(fileName);
    if (fsPath === null) continue; // node:* internals, evals
    if (fsPath.startsWith(CAPWALL_ROOT + path.sep)) continue; // capwall's own machinery
    return { pkg: packageForPath(fsPath, options.projectRoot), budgetExhausted: false };
  }
  // Fell off the end. If V8 handed back a full budget's worth of frames the stack was almost
  // certainly TRUNCATED (a real stack that short would have yielded fewer sites), so the true
  // owner may lie beyond the cap — flag it rather than passing this off as clean app code.
  return { pkg: APP_ROOT, budgetExhausted: sites.length >= maxFrames };
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
