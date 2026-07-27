/**
 * Attribution — map "the code currently executing a shimmed call" to the OWNING npm package.
 *
 * Mechanism:
 *   1. Capture a stack trace as structured V8 CallSite objects (temporary
 *      `Error.prepareStackTrace` swap — no string parsing on the hot path).
 *   2. Walk frames from the top, skipping capwall's own frames (anything under this
 *      package's src/dist tree) and Node-internal/native frames (`node:*`, no file name).
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
 *
 * THREE OUTCOMES, NOT TWO (issue #60). "This call is the application's own code" and "capwall
 * could not work out whose code this is" used to be the SAME value, {@link APP_ROOT} — the
 * walk simply fell off the end of the stack and returned it. That was a fail-OPEN: `<app>` is
 * the trust root, and two shims (`process.env` reads, `dgram` sends) exempt it from gating
 * entirely, so "unattributable" silently became "ungated". A dependency could reach that
 * state with ~15 lines of ordinary ESM — run its payload from a `data:` URL module (no
 * filesystem path on any frame) and detach one tick through a timer (dropping the last
 * `file://` frames V8's async stack traces would otherwise keep) — and then read any
 * `process.env` key and send UDP with no log line at all. `eval`/`new Function` and simply
 * handing a native function to `setTimeout` reached the same state.
 *
 * So the walk now distinguishes:
 *   1. a **dependency** — a frame under `node_modules` (charged to that package);
 *   2. the **application** ({@link APP_ROOT}) — positively identified by a real source file
 *      that is not under `node_modules`, never by falling off the end of the walk;
 *   3. **unattributable** ({@link UNATTRIBUTED}) — everything else: no qualifying frame at
 *      all, or an app frame reached only THROUGH opaque code (see {@link OPAQUE}).
 *
 * `<unknown>` is an ordinary principal: it is evaluated against the policy like any package
 * name, so it is deny-by-default in enforce, recorded in observe, and grantable by writing an
 * explicit `"<unknown>"` entry in `capabilities.json`. What it is NOT is exempt.
 *
 * NOTHING SELF-REPORTED IS AN IDENTITY (issue #84). Only a frame's `getFileName()` — which V8
 * takes from how the code was LOADED — is used to name a package. The one place capwall read a
 * string the running code could shape, `getEvalOrigin()`, turned out to be forgeable through a
 * nested `eval` and let a dependency with zero grants impersonate any package (or `<app>`). It
 * is no longer consulted; every `eval`/`new Function` frame is {@link OPAQUE}. See
 * {@link frameSource} for the mechanism and the proof that no stricter parse recovers it.
 */
import * as path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Sentinel for the APPLICATION's own code — the trust root.
 *
 * Only returned when a real, non-`node_modules` source file was found on the stack. It is
 * deliberately NOT the "we do not know" value; see {@link UNATTRIBUTED} and issue #60.
 */
export const APP_ROOT = "<app>" as const;

/**
 * Sentinel for a call capwall could not attribute to any source file (issue #60).
 *
 * Returned when the stack walk finds no qualifying frame, or reaches app code only through
 * code with no filesystem identity (a `data:` URL module, any `eval`/`new Function` output, a
 * bundler `sourceURL`). It is treated as an ordinary, untrusted principal — evaluated against
 * the policy, deny-by-default in enforce, recorded in observe — and it never receives the
 * `<app>` exemptions. Grant it explicitly (a `"<unknown>"` entry in the policy) if a legitimate
 * setup genuinely produces path-less frames.
 */
export const UNATTRIBUTED = "<unknown>" as const;

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
 * SECURITY (issues #15 and #60). Two different events used to produce the same {@link APP_ROOT}
 * result: "walked the whole stack and found only app frames" and "ran out of frame budget
 * before reaching any package frame". The second is a possible MIS-attribution — the real
 * owning dependency may sit just past the cap — and charging it to `<app>` wrongly ALLOWED it,
 * since the app is the trust root and usually holds broad grants.
 *
 * Both halves are now addressed, and they compose. #60 made the *outcome* fail closed: a walk
 * that finds no qualifying frame, budget-exhausted or not, returns {@link UNATTRIBUTED}, which
 * is gated like any other principal rather than exempted. #15's `budgetExhausted` remains, and
 * is now diagnostic rather than a warning about a call that already went through: it tells the
 * operator that this particular unattributable call may have a real owner just past the cap,
 * and that raising `maxFrames` (`CAPWALL_MAX_FRAMES`) would find it.
 */
export interface Attribution {
  /** Owning package name, {@link APP_ROOT}, or {@link UNATTRIBUTED}. */
  pkg: string;
  /**
   * True only when the frame budget was fully consumed AND no qualifying frame was found, so
   * `pkg` is the {@link UNATTRIBUTED} fallback and the real owner may lie beyond the cap.
   */
  budgetExhausted: boolean;
}

/**
 * Coerce a user-supplied frame budget to a usable value, or `null` if it is unusable.
 *
 * Accepts a number or a numeric string (the env-var channel). Requires a POSITIVE SAFE
 * INTEGER: `NaN`/`Infinity`/`0`/negatives/fractions would be handed straight to
 * `Error.stackTraceLimit`, where they silently capture zero or unpredictably few frames —
 * i.e. garbage config would turn into blanket `<unknown>` mis-attribution (every mediated call
 * denied in enforce, since #60 made that outcome fail closed). Fail to the default
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
 * A frame whose code has NO filesystem identity: a `data:`/`blob:`/`http:` module, ANY
 * `eval`/`new Function` frame (issue #84 — see {@link frameSource} for why the reported origin
 * cannot be believed), `node -e`/stdin (`[eval]`, `[stdin]`), a `vm` script's default
 * `evalmachine.<anonymous>`, a bundler `//# sourceURL=`.
 *
 * Distinct from a *neutral* frame (a `node:*` internal or a native frame, both of which are
 * capwall's or Node's own machinery and are skipped): an opaque frame is USER-CONTROLLED code
 * running from a source capwall cannot tie to a package, which is exactly the laundering
 * primitive issue #60 exploits. Seeing one means `<app>` can no longer be inferred.
 */
const OPAQUE = Symbol("capwall.opaque-frame");

/**
 * Classify one frame: its filesystem path, `null` if it is neutral machinery to skip
 * (a `node:*` internal or a native frame), or {@link OPAQUE}.
 *
 * SECURITY — `getEvalOrigin()` IS NOT USABLE AS AN IDENTITY (issue #84). Until this commit an
 * eval frame was resolved by parsing `getEvalOrigin()`, on the reasoning that a `//# sourceURL=`
 * could not forge V8's own `eval at <fn> (<file>:L:C)` form because a `sourceURL` may not
 * contain whitespace. The whitespace half of that is true and still verifiable — V8 rejects a
 * `sourceURL` containing a space and reports the genuine origin — but the conclusion did not
 * follow, because for a NESTED eval **V8 synthesizes the `eval at …` wrapper itself**, around
 * the outer script's name, and the outer script's name is exactly what its `sourceURL` set:
 *
 *   inner = "<payload>"
 *   outer = 'eval("<payload>")\n//# sourceURL=/proj/node_modules/lodash/index.js:1:1'
 *   eval(outer)  ->  getEvalOrigin() === "eval at <anonymous> (…/lodash/index.js:1:1)"
 *
 * The attacker never writes the prefix and never writes whitespace; V8 writes the prefix for
 * them, and the `:1:1` they appended to the `sourceURL` completes the shape. A dependency with
 * zero grants thereby named any package in the policy — or `<app>`, the trust root, whose env
 * reads are exempted before the decision is even recorded.
 *
 * NO STRICTER PARSE FIXES THIS, and it is worth being precise about why rather than tightening
 * the regex and hoping. V8's depth-1 origin is `eval at <fn> (<script>:L:C)`; its depth-N origin
 * is `eval at <fn> (` + the *origin of the outer script* + `)`. When the outer script carries a
 * `sourceURL`, its origin is that bare `sourceURL` string — so a forged depth-2 origin is
 * `eval at <fn> (<attacker string>)`, which is character-for-character the shape of a genuine
 * depth-1 origin. Counting `eval at ` tokens, taking the outermost match instead of the
 * innermost, or demanding a trailing `:L:C` all fail on the same input, because the two cases
 * are not distinguishable as strings. V8 exposes the origin only as a formatted string (there is
 * no `getEvalOriginScript()`), so there is nothing else to consult.
 *
 * WHAT WE DO INSTEAD: an eval frame has no filesystem identity, so it is {@link OPAQUE} — the
 * same treatment `data:` modules, `[eval]`/`[stdin]` and bundler `sourceURL`s already get. The
 * walk continues past it to the nearest frame that DOES have a real file name. Nothing an
 * attacker can write is consulted. Costs and residuals are in `docs/threat-model.md`.
 *
 * The `isEval()` test comes FIRST, before `getFileName()` is trusted: on every Node we have
 * checked, an eval frame reports no file name, but ordering it this way means a V8 that ever
 * did surface a `sourceURL` through `getFileName()` fails closed here instead of handing an
 * attacker-chosen path straight to {@link packageForPath}. `vm`-compiled scripts are NOT eval
 * frames (`isEval()` is false and they carry the real `filename` option), so this does not
 * touch them — see the `vm` residual in `docs/threat-model.md`.
 */
function frameSource(site: NodeJS.CallSite): string | null | typeof OPAQUE {
  if (site.isEval()) return OPAQUE;
  const fileName = site.getFileName();
  if (fileName === undefined || fileName === null || fileName === "") {
    // No script name and not eval: a native frame — neutral machinery, skipped like `node:*`.
    return null;
  }
  const fsPath = toFsPath(fileName);
  if (fsPath !== null) return fsPath;
  // A non-path script name. `node:*` is Node's own machinery and is skipped as before;
  // everything else is code loaded from somewhere capwall cannot map to a package.
  return fileName.startsWith("node:") ? null : OPAQUE;
}

/**
 * Return the name of the package that owns the current call site (nearest-package policy),
 * {@link APP_ROOT} when the nearest qualifying frame is application code, or
 * {@link UNATTRIBUTED} when the call cannot be tied to either (issue #60).
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
  // everything to <unknown>. Coercion here is pure and cheap.
  const maxFrames = coerceMaxFrames(options.maxFrames) ?? DEFAULT_MAX_FRAMES;
  const sites = captureCallSites(maxFrames);
  let sawOpaque = false;
  for (const site of sites) {
    const source = frameSource(site);
    if (source === null) continue; // node:* internals, native frames
    if (source === OPAQUE) {
      sawOpaque = true;
      continue;
    }
    if (source.startsWith(CAPWALL_ROOT + path.sep)) continue; // capwall's own machinery
    const pkg = packageForPath(source, options.projectRoot);
    // A dependency frame is a positive identification of untrusted code, so it stands even
    // below opaque code (and is stricter than `<unknown>` would be). `<app>` is the opposite:
    // it is the TRUST ROOT and carries exemptions, so it may only be claimed when nothing
    // opaque ran above it. Otherwise a `data:` module invoked from app code would inherit the
    // app's authority — the same fail-open, one frame up.
    if (pkg === APP_ROOT && sawOpaque) return { pkg: UNATTRIBUTED, budgetExhausted: false };
    return { pkg, budgetExhausted: false };
  }
  // Fell off the end of the walk: no dependency frame, no app frame, nothing to charge.
  //
  // This USED to return APP_ROOT, silently handing the trust root's exemptions to whatever
  // ran with no stack of its own — a detached `data:` module, an eval'd payload on a timer, a
  // native function handed straight to `setTimeout` (issue #60). It is now `<unknown>`, which
  // is gated like any other principal.
  //
  // That also closes the budget-exhaustion fail-open #15/#58 flagged: when V8 handed back a
  // full budget's worth of frames the stack was almost certainly TRUNCATED and the true owner
  // may lie beyond the cap, so `budgetExhausted` still reports it — but the outcome is no
  // longer "charge it to the trust root and hope". The flag now tells the operator WHY the
  // call was unattributable (raise `CAPWALL_MAX_FRAMES`) rather than warning them after the
  // fact that a call may have been wrongly allowed.
  return { pkg: UNATTRIBUTED, budgetExhausted: sites.length >= maxFrames };
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
