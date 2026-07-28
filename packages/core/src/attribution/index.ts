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
 *
 * IDENTITY IS A POSITION IN THE TREE, NOT A NAME (issue #92). A frame's file name is a path,
 * and until this commit the package it named was the LAST `node_modules/<name>` segment of that
 * path — so `node_modules/evil/node_modules/lodash/x.js` was, flatly, `lodash`. A dependency
 * that ships a directory named after a granted package inside its own tree (`bundledDependencies`
 * puts one in a published tarball; a git/tarball dependency is unrestricted) therefore ran with
 * that package's grants. No `eval`, no `vm`, no `fs` write, nothing self-reported: the frames
 * are ordinary and the file is real. The rule was the defect, not the parse.
 *
 * The identity is now the whole INSTALL CHAIN from the project root — every `node_modules/<name>`
 * segment, in order, joined by {@link CHAIN_SEP}. A top-level install is unchanged (`lodash`); a
 * nested one is `evil>lodash`, a principal distinct from `lodash` and therefore holding none of
 * its grants. See {@link packageForPath} for the derivation and for the two things this does and
 * does not buy.
 */
import * as path from "node:path";
import { fileURLToPath } from "node:url";
// Its OWN subpath, not `@capwall/policy-schema`'s barrel: the barrel builds the Zod schema tree at
// module scope, and this file is on the ESM loader thread's graph, where no schema is ever parsed
// (#150 — see the note in `policy/evaluate.ts`).
import { CHAIN_SEP } from "@capwall/policy-schema/package-key";
import {
  discoverPackageLink,
  isUnder,
  linkGeneration,
  normalizeSeparators,
  rewriteThroughLinks,
} from "./link-map.js";
// The NARROW capture, not `../real-builtins.cjs` — never `import … from "node:fs"` (#78), and
// never the twelve-wide aggregate from a module the ESM loader thread evaluates (#150). See
// `src/real-builtins/fs.cts`.
import { realFs } from "../real-builtins/fs.cjs";

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
 * Separator between the links of an INSTALL CHAIN (issue #92) — the principal name for a
 * package that is not installed at the project's top level.
 *
 * `lodash` is the top-level install. `evil>lodash` is the copy of `lodash` installed *under*
 * `evil`, whether npm put it there to resolve a version conflict or `evil` shipped it in its own
 * tarball. capwall cannot tell those two apart from disk (see {@link packageForPath}), so it
 * declines to conflate either of them with the top-level install: they are separate principals
 * and each is granted separately.
 *
 * DEFINED IN `@capwall/policy-schema` and re-exported here, not the other way round: the
 * separator is part of the POLICY grammar (it is what a `packages` key is spelled with, and what
 * `*>name`/`**>name` widen over), and that grammar has to be validated at policy-load time — so
 * it lives next to the host grammar in `package-key.ts`, for the reason #83 gives. Attribution is
 * the producer of these names, not their owner.
 */
export { CHAIN_SEP };

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
  /**
   * True when the NEAREST frame above the mediated call — the first one that is not capwall's
   * own machinery — is Node's own JS (a `node:…` script). The call was therefore *initiated by
   * the runtime*, not written by `pkg`: `pkg` is simply the nearest frame with a package
   * identity, sitting below however many Node frames it took to get here (issue #119).
   *
   * WHY THIS IS A SEPARATE QUESTION FROM `pkg`. Attribution answers "whose code is nearest",
   * and to answer it the walk SKIPS `node:` frames, because Node's internals carry no package
   * identity. That is right for deciding who to charge — Node cannot be held responsible, and
   * something has to be — but it erases the distinction between `express` reading
   * `process.env.NODE_ENV` in `application.js` (its own frame is nearest) and Node's cluster
   * module reading `NODE_CLUSTER_SCHED_POLICY` while `express` happens to be the nearest
   * package on the stack below (`node:internal/cluster/primary` is nearest). Both come back as
   * `express`; only the first is something `express` did.
   *
   * NOT AN EXEMPTION, AND MUST NOT BECOME ONE. This flag is deliberately *not* consulted by any
   * gate: every consumer still evaluates the request against `pkg`'s grants and still enforces
   * the outcome. It exists so a consumer can decide whether the event is worth RECORDING — see
   * `shims/env.ts`, the one mediated surface Node's own code shares with dependencies, and the
   * `hidesWithoutRecording` reasoning #67 established. Treating it as "Node did this, allow it"
   * would hand any code that can arrange a `node:` frame above its call (`util.inspect(env)`)
   * an ungated read, which is precisely the class of hole #60 closed.
   *
   * FAILS CLOSED. Only an explicit `node:`-prefixed script name counts. A native frame (no file
   * name at all), an `eval` frame, and a stack with no frames whatsoever are all `false`, so an
   * attacker who detaches from their own stack gets recorded, not suppressed. A frame reporting
   * a `node:` name cannot be forged for the same reason `calledByNodeLoader` may trust one
   * (`shims/module.ts`): acquiring it means having compiled under that name, which the compile
   * gate denies before the first such frame can exist. That argument covers acquiring a real
   * frame and not the CallSites this module is handed — replacing `Error.captureStackTrace`
   * fabricates them outright, which is the documented primordials bound on all of attribution
   * (docs/threat-model.md § The one assumption every control rests on).
   */
  initiatedByNode: boolean;
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

/**
 * project root → (file path → principal), memoized. Attribution is the hot path (<1ms/req).
 *
 * Keyed by project root as well as by path because the root is part of the derivation now
 * (see {@link packageForPath}): the same file resolves to a different chain under a different
 * root, and a single flat memo would let whichever `install()` ran first decide the answer for
 * the rest of the process. In production there is exactly one root, so this is one extra
 * `Map.get` on a hit and no extra allocation.
 */
const pathToPackage = new Map<string, Map<string, string>>();

/**
 * The link-map generation the memo above was populated under (#127).
 *
 * A path's principal changes the moment a symlinked `node_modules` entry covering it is recorded,
 * so the memo is dropped wholesale when that happens. Links are recorded a handful of times per
 * process (once per linked package, during its resolution, before any of its code can run), so
 * this is not a hot-path concern; it just removes the "was it recorded before or after the first
 * frame?" ordering question entirely.
 */
let memoGeneration = linkGeneration();

/**
 * A function that is on the current stack and marks where a capture should START — everything
 * up to and including its topmost frame is skipped. See {@link attributeCallerVia}.
 */
export type StackBoundary = (...args: never[]) => unknown;

/**
 * Capture the current stack as structured CallSites (no string formatting).
 *
 * `maxFrames` is the number of frames V8 MATERIALIZES, and that count is the dominant cost of
 * attribution — measured on Node 22, a capture costs a ~4 µs fixed floor plus ~1.4 µs per frame,
 * so a 25-frame capture from a 24-deep stack is ~38 µs against ~6 µs for a 1-frame one (#133).
 * The limit applies AFTER the `hideAbove` skip, which is what makes {@link attributeCallerVia}'s
 * fast path cheap: skipped frames are not materialized and do not count against the limit.
 */
function captureCallSites(
  maxFrames: number,
  hideAbove: StackBoundary = captureCallSites,
): NodeJS.CallSite[] {
  const origPrepare = Error.prepareStackTrace;
  const origLimit = Error.stackTraceLimit;
  Error.prepareStackTrace = (_err, sites) => sites;
  Error.stackTraceLimit = maxFrames;
  const holder: { stack?: NodeJS.CallSite[] } = {};
  Error.captureStackTrace(holder as object, hideAbove);
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
 * Is this frame one of Node's OWN scripts (`node:internal/…`, `node:fs`, …)?
 *
 * Only ever asked of a frame {@link frameSource} already classified as neutral machinery, which
 * is what makes the check cheap and total: at that point the frame either has no file name (a
 * native frame — `false`, fail closed) or has a non-path script name that starts with `node:`.
 * `eval` frames never reach here; `frameSource` calls them {@link OPAQUE} first, so a
 * `//# sourceURL=node:internal/x` cannot answer this question. See
 * {@link Attribution.initiatedByNode} for what the answer is used for and why it is not a gate.
 */
function isNodeScriptFrame(site: NodeJS.CallSite): boolean {
  const fileName = site.getFileName();
  return typeof fileName === "string" && fileName.startsWith("node:");
}

/**
 * THE walk — the single definition of nearest-package attribution, shared by the full capture
 * and by {@link attributeCallerDetailedVia}'s short one (#133).
 *
 * `found: null` is "this capture did not reach an answer", NOT "unattributable". The two callers
 * give it different meanings on purpose: the full capture has spent the whole budget, so `null`
 * there is {@link UNATTRIBUTED}; the short capture has only looked at a prefix, so `null` there
 * means "look further" and it re-runs the full walk. Collapsing those would either fail open (a
 * short capture answering `<app>`) or fail loud (a deep stack denied on a budget it never spent).
 *
 * `initiatedByNode` is reported separately because it is meaningful even when nothing qualified:
 * a stack of nothing but `node:` internals has no principal but is still Node's own doing (#119).
 *
 * `budgetExhausted` is always `false` on `found` — only the caller knows whether the frames it
 * handed over were a whole budget or a prefix of one, and guessing from inside would let a
 * 3-frame capture claim a 25-frame budget had been spent.
 */
interface WalkResult {
  found: Attribution | null;
  initiatedByNode: boolean;
}

function walkFrames(sites: readonly NodeJS.CallSite[], projectRoot?: string): WalkResult {
  let sawOpaque = false;
  // Was the FIRST non-capwall frame Node's own JS? Set once, by whichever frame gets there
  // first, and never revised — see `Attribution.initiatedByNode`. `undefined` means the walk
  // has seen nothing but capwall's own frames so far; it resolves to `false` if it stays that
  // way, so "capwall is the only thing on the stack" is not mistaken for "Node initiated it".
  let initiatedByNode: boolean | undefined;
  for (const site of sites) {
    const source = frameSource(site);
    if (source === null) {
      // Neutral machinery: a `node:` internal (Node initiated this) or a native frame (no
      // identity at all — fail closed and call it not-Node).
      initiatedByNode ??= isNodeScriptFrame(site);
      continue; // node:* internals, native frames
    }
    if (source === OPAQUE) {
      initiatedByNode ??= false;
      sawOpaque = true;
      continue;
    }
    if (source.startsWith(CAPWALL_ROOT + path.sep)) continue; // capwall's own machinery
    initiatedByNode ??= false;
    const pkg = packageForPath(source, projectRoot);
    // A dependency frame is a positive identification of untrusted code, so it stands even
    // below opaque code (and is stricter than `<unknown>` would be). `<app>` is the opposite:
    // it is the TRUST ROOT and carries exemptions, so it may only be claimed when nothing
    // opaque ran above it. Otherwise a `data:` module invoked from app code would inherit the
    // app's authority — the same fail-open, one frame up.
    if (pkg === APP_ROOT && sawOpaque) {
      // Opaque code laundering the trust root. Report `initiatedByNode: false` even if a
      // `node:` frame sat on top: the interesting fact about this stack is the laundering, and
      // a consumer that suppresses recording for Node-initiated calls must not be talked out
      // of recording this one.
      return {
        found: { pkg: UNATTRIBUTED, budgetExhausted: false, initiatedByNode: false },
        initiatedByNode: false,
      };
    }
    return {
      found: { pkg, budgetExhausted: false, initiatedByNode: initiatedByNode ?? false },
      initiatedByNode: initiatedByNode ?? false,
    };
  }
  return { found: null, initiatedByNode: initiatedByNode ?? false };
}

/**
 * Frames the {@link attributeCallerVia} fast path materializes before it gives up and falls
 * back to the full walk.
 *
 * Three, and the third one is not padding.
 *
 * THE BOUNDARY CONVENTION THIS NUMBER ASSUMES (#133, extended to every guarded surface by #143):
 * a caller hands in **the frame a dependency actually calls** — the Proxy trap, the shimmed
 * `fs.readFileSync`, the shimmed `net.connect`, the guarded subclass constructor — never an
 * inner helper. V8 then skips capwall's whole call chain (the walk would skip it anyway; skipping
 * it *earlier* is the point), so the calling package sits at frame 0. Measured on Node 20/22
 * with `Error.captureStackTrace(holder, <entry point>)`, frame 0 is the dependency for a direct
 * `fs.readFileSync(p)`, a `.apply(null, …)` of it, `net.connect(opts)`, `spawnSync(…)`,
 * `fetch(url)`, a direct `Module.prototype._compile` call, and an inline `env.K`.
 *
 * The other two frames are the margin, and each is a shape that was measured rather than
 * guessed. Going through a builtin — `Object.assign({}, env)` (dotenv's shape),
 * `JSON.stringify(env)`, `[p].map(fs.readFileSync)` — inserts ONE native frame (no file name,
 * skipped as neutral machinery) above the caller; a call reached through a `node:` internal
 * inserts another. Two would cover every shape observed today; three leaves a frame of margin so
 * a Node release that adds an internal hop degrades to "slightly slower" rather than "fast path
 * never hits".
 *
 * IT IS DELIBERATELY NOT SIZED FOR SURFACES WHOSE CALLER IS FAR AWAY. `require('x.node')` reaches
 * `process.dlopen` through seven `node:internal/modules/*` frames, so a 3-frame prefix there
 * would decline on every real load and cost a short capture on top of the full one. That gate is
 * therefore left on the full walk — see the note in `loader/native.ts`. Raising this constant to
 * cover it would make every other surface pay for it.
 */
const FAST_PATH_FRAMES = 3;

/**
 * Smallest `maxFrames` at which the fast path is allowed to answer at all.
 *
 * The fast path is only sound because it is a PREFIX of what the full walk would examine, and
 * that argument needs the full walk to be able to reach the same frame: its budget is spent on
 * capwall's own frames first (≤8 between any shim entry point and `captureCallSites`) and only
 * then on caller frames. `8 + FAST_PATH_FRAMES` is the point past which "the short capture found
 * it" implies "the full capture would have found it too". Below that — only reachable by
 * deliberately setting `CAPWALL_MAX_FRAMES` very low — the fast path stands down and behavior is
 * bit-for-bit what it was before #133, rather than the two paths disagreeing about a principal.
 */
const FAST_PATH_MIN_BUDGET = 8 + FAST_PATH_FRAMES;

/**
 * Attribute the caller of `hideAbove` — same answer as {@link attributeCallerDetailed}, reached
 * without materializing a full stack's worth of CallSites when the answer is near the top (#133).
 *
 * WHY THIS EXISTS. Attribution's cost is dominated by the NUMBER OF FRAMES V8 materializes, not
 * by the package lookup (which is memoized at ~20 ns). A 25-frame capture from a realistic stack
 * is ~38 µs; a 3-frame one is ~8 µs. That was the whole story for `{...process.env}`, where ONE
 * JS call is two attributions per environment variable — ~160 stack walks, milliseconds, for a
 * single line of `dotenv` (#133). The perf audit (#132) then measured that attribution is ~70% of
 * capwall's added latency on EVERY mediated surface at a realistic stack depth, so #143 pointed
 * the same lever at the rest of them: `fs`, `net`/`http`/`https`/`http2`/`tls`/`dgram`,
 * `child_process`, the global egress guards, `vm`, `worker_threads` and the `_compile` gate all
 * hand in their own entry frame now. Nothing about the ANSWER changes; only how much of the stack
 * V8 is asked to build before the walk finds it.
 *
 * WHAT `hideAbove` IS AND WHY IT IS NOT A TRUST DECISION. It is a function object the CALLER
 * passes and V8 matches against its own frame records; it names where to start materializing,
 * and nothing else. It is not read, not compared against a policy, and never contributes to the
 * principal. Pass the shim's own ENTRY POINT — the trap, the wrapped builtin, the guarded
 * constructor: whatever frame a dependency's own code calls — so the capture starts at the caller
 * itself. capwall's own frames are skipped by the walk anyway, so skipping them earlier costs
 * nothing and saves materializing them; handing in an INNER helper instead is not wrong, merely
 * wasteful, because the frames between it and the entry point are materialized and then
 * discarded (and eat into {@link FAST_PATH_FRAMES}). If `hideAbove` is not on the stack V8 returns NO frames
 * (verified on Node 20 and 22), the walk finds nothing, and this falls back to the full capture:
 * a wrong boundary is slow, never permissive.
 *
 * WHY THE RESULT IS THE SAME PRINCIPAL, NOT A CACHED GUESS. Nothing is remembered between
 * calls. This does not reuse a previous read's answer, does not key anything on an identity the
 * running code could shape, and does not treat a run of reads as one event — the whole class of
 * bug that #84 and #92 were. Every invocation walks a real stack with {@link walkFrames}, the
 * one nearest-package definition, applying the same `node:`/native skip, the same
 * {@link OPAQUE} handling, the same `<app>`-below-opaque rule and the same `initiatedByNode`
 * derivation (#119). The only difference is how many frames were materialized, and the frames it
 * looks at are the same frames, in the same order, that the full walk looks at once capwall's
 * own are skipped — V8 skipping them via `hideAbove` and the loop skipping them via
 * `CAPWALL_ROOT` are the same set. So:
 *
 *   - a hit is exactly what the full walk returns (it is a prefix of the same sequence, and the
 *     walk terminates at the FIRST qualifying frame — see {@link FAST_PATH_MIN_BUDGET} for the
 *     one configuration where the prefix argument needs a guard);
 *   - a miss falls through to the full walk verbatim, including `budgetExhausted` accounting.
 *
 * A dependency therefore cannot become a different principal by controlling how deep it calls
 * from, how many native frames it interposes, or whether it enumerates: the deeper it hides its
 * real frame, the more often the fast path DECLINES, which costs it time and changes nothing.
 * See `test/attribution-fast-path.test.ts` for the adversarial cases run against this.
 */
export function attributeCallerDetailedVia(
  hideAbove: StackBoundary,
  options: AttributionOptions = {},
): Attribution {
  const maxFrames = coerceMaxFrames(options.maxFrames) ?? DEFAULT_MAX_FRAMES;
  if (maxFrames >= FAST_PATH_MIN_BUDGET) {
    const near = walkFrames(captureCallSites(FAST_PATH_FRAMES, hideAbove), options.projectRoot);
    if (near.found !== null) return near.found;
  }
  return attributeCallerDetailed(options);
}

/**
 * {@link attributeCallerDetailedVia} for callers that only want the principal — the same
 * relationship {@link attributeCaller} has to {@link attributeCallerDetailed}.
 */
export function attributeCallerVia(
  hideAbove: StackBoundary,
  options: AttributionOptions = {},
): string {
  return attributeCallerDetailedVia(hideAbove, options).pkg;
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
  const walked = walkFrames(sites, options.projectRoot);
  if (walked.found !== null) return walked.found;
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
  return {
    pkg: UNATTRIBUTED,
    budgetExhausted: sites.length >= maxFrames,
    initiatedByNode: walked.initiatedByNode,
  };
}

/**
 * Package-manager VIRTUAL STORE directories: a `node_modules` child that holds one directory
 * per resolved version, each of which contains its own `node_modules` with the real package.
 *
 *   pnpm         node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/index.js
 *   yarn berry   node_modules/.store/lodash-npm-4.17.21-<hash>/node_modules/lodash/index.js
 *
 * These are the package manager's own bookkeeping, not a containing package, so they do not
 * become a link in the install chain — a store-installed `lodash` is `lodash`, exactly as a
 * hoisted one is. The reset is applied ONLY at the first link (see {@link packageForPath});
 * a `.pnpm` directory found deeper is inside somebody's tarball and is kept in the chain,
 * because otherwise "ship a directory called `.pnpm`" would be the forgery primitive #92 is
 * about, one rename away.
 */
const VIRTUAL_STORE_DIRS: ReadonlySet<string> = new Set([".pnpm", ".store"]);

/** Read the package name a `node_modules/` child directory denotes, or `null` if malformed. */
function packageNameOf(segments: readonly string[]): string | null {
  const first = segments[0];
  if (first === undefined || first === "") return null;
  if (!first.startsWith("@")) return first;
  const second = segments[1];
  // `@scope` with nothing after it is not a package directory.
  return second === undefined || second === "" ? null : `${first}/${second}`;
}

/**
 * Resolve a source file path to the PRINCIPAL that owns it: an install chain
 * (`lodash`, `evil>lodash`), {@link APP_ROOT}, or {@link UNATTRIBUTED}.
 *
 * DERIVATION. Strip `projectRoot` if the path is under it, then read every `node_modules/<name>`
 * segment left to right and join them with {@link CHAIN_SEP}. No `node_modules` segment at all
 * means application code. A leading virtual-store directory ({@link VIRTUAL_STORE_DIRS}) is
 * skipped. Nothing touches the disk; the whole derivation is string work, memoized per path.
 *
 * WHY THE CHAIN AND NOT THE LAST SEGMENT (issue #92). The last segment alone says
 * `node_modules/evil/node_modules/lodash/x.js` **is** `lodash`, so a dependency that ships a
 * directory named after a granted package inside its own tree collects that package's grants,
 * with ordinary frames and a real file, under deny-by-default `enforce`, with no log line.
 *
 * WHAT MAKES #92 HARD, STATED PLAINLY: **legitimate nesting has exactly the same shape.** npm
 * and yarn genuinely create `node_modules/a/node_modules/lodash/` to resolve a version
 * conflict, and that really is lodash. Nothing on disk separates the two cases — not the
 * nested `package.json` (the attacker writes it), not the parent's `dependencies` (likewise),
 * not the directory layout (byte-identical). Only the lockfile records provenance, and capwall
 * cannot depend on one being present, current, or in a format it can parse without a YAML
 * dependency. So capwall does not try to tell them apart. It stops CONFLATING them: the nested
 * copy is a principal of its own, `a>lodash`, and holds whatever the policy grants `a>lodash`.
 *
 * WHAT THIS BUYS. A package can no longer *acquire another principal's grants* by choosing a
 * directory name, because the chain records where the directory actually is and an attacker
 * cannot move its own files to the top level. That closes the #92 PoC.
 *
 * WHAT THIS DOES NOT BUY, AND MUST NOT BE READ AS. It is **not** provenance. `node_modules/lodash`
 * is still whatever is on disk at that path: a typosquat, a compromised publish, or a hand-edited
 * working copy all answer to `lodash`. And anything that can WRITE into the project's top-level
 * `node_modules` — an `fs` grant that covers it, a postinstall script, a lifecycle hook — can
 * still install itself as any name it likes. Verifying that is a different mechanism (see
 * `docs/threat-model.md` § Package identity).
 *
 * COST, STATED HONESTLY: a legitimately nested install is a new principal name, so a
 * hand-written `"lodash": {…}` no longer covers it. `observe`/`capwall gen-policy` emit the
 * chain name automatically, and `"*>lodash"` grants every nested install of `lodash` in one
 * line — see `policyFor` in `policy/evaluate.ts`, where that widening is deliberately explicit
 * because it re-opens exactly this hole for that one package.
 */
export function packageForPath(filePath: string, projectRoot?: string): string {
  if (memoGeneration !== linkGeneration()) {
    pathToPackage.clear();
    memoGeneration = linkGeneration();
  }
  const rootKey = projectRoot ?? "";
  let byPath = pathToPackage.get(rootKey);
  if (byPath === undefined) {
    byPath = new Map<string, string>();
    pathToPackage.set(rootKey, byPath);
  }
  const cached = byPath.get(filePath);
  if (cached !== undefined) return cached;
  const pkg = installChainFor(filePath, projectRoot);
  byPath.set(filePath, pkg);
  return pkg;
}

/**
 * Every spelling of the project root a frame path might match (issue #127).
 *
 * The raw configured value first, then its realpath when that differs. Frames report realpath'd
 * paths, so a project root that is itself reached through a symlink (`/var` on macOS, a checkout
 * under a symlinked home, a container bind-mount) would match NOTHING under a raw comparison and
 * every application file would fall out of the project — which, with the out-of-tree rule below,
 * would deny the whole app. Cached because it costs a syscall and the root never changes.
 */
const rootSpellings = new Map<string, readonly string[]>();
function spellingsOfRoot(projectRoot: string): readonly string[] {
  const cached = rootSpellings.get(projectRoot);
  if (cached !== undefined) return cached;
  let raw = normalizeSeparators(projectRoot);
  while (raw.endsWith("/") && raw.length > 1) raw = raw.slice(0, -1);
  const out = [raw];
  try {
    let real = normalizeSeparators(realFs.realpathSync(projectRoot));
    while (real.endsWith("/") && real.length > 1) real = real.slice(0, -1);
    if (real !== raw) out.push(real);
  } catch {
    // A root that does not exist on disk (a test fixture, a stale config) is used as written.
  }
  rootSpellings.set(projectRoot, out);
  return out;
}

/** The uncached derivation behind {@link packageForPath}. */
function installChainFor(filePath: string, projectRoot?: string): string {
  const raw = normalizeSeparators(filePath);
  const roots =
    projectRoot === undefined || projectRoot === "" ? null : spellingsOfRoot(projectRoot);

  // #127 — UNDO NODE'S REALPATH BEFORE READING POSITION. Node resolves module paths through
  // `realpath`, so a dependency installed as a symlink into `node_modules` (every `npm i file:`,
  // every `npm link`, every workspace package) reports a path with no `node_modules` segment and
  // was therefore `<app>`, the trust root, exempt from four gates before the decision was even
  // recorded. The link map rewrites the path back to the `node_modules` entry it was REACHED
  // from, so the ordinary chain derivation below sees the position rather than the destination.
  let normalized = rewriteThroughLinks(raw);

  const marker = "/node_modules/";
  const insideProject = roots !== null && roots.some((r) => isUnder(normalized, r));
  if (roots !== null && !insideProject && !normalized.includes(marker)) {
    // Out of the project, under no `node_modules`, and no link recorded for it — the shape a
    // linked dependency has when capwall never observed its resolution (an ESM import; see
    // `link-map.ts` on why the loader-thread hook cannot record). Try to recover the entry that
    // links here. This can only turn `<unknown>` into a package NAME; it is never consulted for a
    // path that would have been `<app>`, so the trust-root sentinel stays a positive
    // identification (#60).
    if (discoverPackageLink(normalized, roots[0] as string)) normalized = rewriteThroughLinks(raw);
  }

  // Scan from the project root when the file is under it. Without this, a project that itself
  // lives inside a `node_modules` (capwall applied to a library under test, a monorepo package
  // consumed by a fixture app) would prepend its own containing package to every chain, so its
  // top-level `lodash` would be `thatlib>lodash` and no ordinary policy would match. The root
  // is trusted config, not attacker-controlled.
  let scanFrom = 0;
  if (roots !== null) {
    for (const root of roots) {
      if (normalized.startsWith(root + "/")) {
        scanFrom = root.length;
        break;
      }
    }
  }

  const parts = normalized.slice(scanFrom).split(marker);
  // parts[0] is whatever precedes the first `node_modules`; one part means there is none.
  if (parts.length < 2) return appOrUnattributed(normalized, roots);

  const chain: string[] = [];
  for (let i = 1; i < parts.length; i++) {
    const name = packageNameOf((parts[i] as string).split("/"));
    // Under `node_modules` but not naming a package (`…/node_modules/`, `…/node_modules/@scope`).
    // Deliberately NOT `<app>`: the old code fell back to the trust root here, which is the same
    // fail-open shape as every other bug on this path. `<unknown>` is gated like any principal.
    if (name === null) return UNATTRIBUTED;
    // Only the FIRST link may be a virtual store. See VIRTUAL_STORE_DIRS.
    if (i === 1 && VIRTUAL_STORE_DIRS.has(name)) continue;
    chain.push(name);
  }
  // A file directly inside a virtual store but not inside any package in it.
  if (chain.length === 0) return UNATTRIBUTED;
  return chain.join(CHAIN_SEP);
}

/**
 * The verdict for a file under no `node_modules` and covered by no recorded link: the
 * APPLICATION, or unattributable (issue #127).
 *
 * `<app>` REQUIRES BEING IN THE PROJECT. Before #127 "no `node_modules` segment" was sufficient,
 * so any file anywhere on the disk was the trust root — which is how a `file:`/`link:` dependency
 * whose realpath lives outside the tree became `<app>` and collected exemptions from the
 * `process.env`, `dgram`, loader-hook and `_compile` gates without a single grant. Being outside
 * the project is not evidence of being the project.
 *
 * `loader/native.ts`'s `ownerOfAddon` has made exactly this move since #49, for exactly this
 * reason — an addon written to a temp dir and `dlopen`ed must not be charged to the app — and it
 * was right there while the stack walk kept failing open. This is that rule, applied once, where
 * every caller gets it.
 *
 * WITH NO PROJECT ROOT CONFIGURED there is nothing to judge "inside the project" against, so the
 * pre-#127 answer stands. That path is reachable only through the public `packageForPath` export
 * and in tests; `install()` always defaults `projectRoot` to `process.cwd()`.
 *
 * THE COST, STATED PLAINLY: an application whose own sources live outside its declared project
 * root now attributes to `<unknown>` and is denied by default rather than trusted by default.
 * That is loud (a `DENY '<unknown>'` line naming the capability), and the fixes are to point
 * `CAPWALL_PROJECT_ROOT` at the tree that is actually the application, or to grant `<unknown>`.
 */
function appOrUnattributed(normalized: string, roots: readonly string[] | null): string {
  if (roots === null) return APP_ROOT;
  return roots.some((root) => isUnder(normalized, root)) ? APP_ROOT : UNATTRIBUTED;
}
