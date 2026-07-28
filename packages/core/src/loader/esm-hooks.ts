/**
 * MODULE CUSTOMIZATION HOOKS (roadmap M5) — capwall's `resolve`/`load` pair, ON THE MAIN THREAD.
 *
 * Registered via `module.registerHooks()` from `esm-hook.ts`. **Synchronous, same realm, same
 * thread as everything else in capwall** — which is the whole of #152/#153 and the reason most of
 * the machinery this file used to carry is gone.
 *
 * ── WHY THIS IS NOT `module.register()` ANY MORE ────────────────────────────────────────────
 * `module.register()` is **Stability 0, runtime-deprecated as DEP0205 in Node 26.0.0**, with Node
 * stating it "will be removed in a future version of Node.js". On Node 26 every mediated process
 * printed a `DeprecationWarning` on the channel capwall's own `DENY` lines live on, and under
 * `--throw-deprecation` `install()` threw and the mediated application did not start at all — an
 * availability failure, which is the one thing a preload must never be (#153). `registerHooks()`
 * is Node's named replacement, it is **documented** (Stability 1.2, release candidate) where
 * `register()` is documented-and-dying, and it needs Node ≥22.15 — exactly the supported floor,
 * so there is no version gate and no second implementation of a security-critical hook (#152).
 *
 * ── WHAT WENT AWAY WITH THE LOADER THREAD ───────────────────────────────────────────────────
 * `module.register()` ran this module on Node's separate module-customization thread, which held
 * no capwall state. Everything that existed to bridge that gap is deleted rather than ported:
 *
 *  - the `MessagePort` channel and its `EsmGateSnapshot` copies (#123). The module-read gate now
 *    reads {@link liveCtx} — the same box the CJS shims read — so there is no COPY that can go
 *    stale, no `receiveMessageOnPort` drain, and no drain-on-every-invocation discipline to get
 *    right. The class of bug #62/#87 are about cannot arise here at all now, because there is
 *    nothing to keep in step.
 *  - the `initialize(data)` payload, the `transferList`, and the "the loader thread must never
 *    import a mediated builtin or it will recurse through `resolve`" constraint that shaped it.
 *  - the export-name enumeration crossing a thread boundary. It is still computed on this thread
 *    (see `esm-runtime.ts`'s `esmExportNames`), because the hook must not import a real builtin
 *    itself — that would recurse through `resolve` — but it is now handed over by a plain
 *    function call.
 *  - ~53 ms of Node's loader-thread bootstrap on every mediated process. See
 *    `scripts/bench/README.md` § Startup.
 *
 * ── TWO JOBS, UNCHANGED IN SUBSTANCE ────────────────────────────────────────────────────────
 *  1. BUILTIN MEDIATION (M5). The hook rewrites mediated builtin specifiers to a synthetic
 *     `capwall-esm:` URL and, for that URL, returns generated module source that re-exports
 *     capwall's shim members from the bridge (`esm-runtime.ts`). That source is evaluated in this
 *     realm, where the re-exported shim functions attribute the caller and evaluate policy exactly
 *     as the CJS shims do.
 *  2. THE MODULE-READ GATE (#123). `import("/home/u/.aws/x.json", { with: { type: "json" } })`
 *     returns a file's contents as a value through Node's JSON translator without ever touching
 *     capwall's `fs` shim, so the decision has to be taken at RESOLUTION time. See
 *     {@link gateModuleRead} and `loader/module-read.ts`.
 *
 * Job 1 covers BOTH `import()` (dynamic) and static `import { x } from 'node:fs'` — the load hook
 * intercepts the module graph before evaluation, so the static binding is to our shim from the
 * start (there is no "immutable binding" problem because we never swap after the fact).
 *
 * ── THE ONE GENUINELY NEW THING: THESE HOOKS ALSO SEE `require()` ───────────────────────────
 * `registerHooks()` is broader than `register()`: its `resolve` and `load` are consulted for
 * `require()` as well as `import()`, **including builtins** — measured on 22.23.1 / 24.18.0 /
 * 26.5.0, and again on 22.22.3 / 24.18.0 / 26.5.0 for this change. That is the first documented
 * API to cover the ground `Module._load` occupies, and it has one immediate consequence here that
 * is a correctness matter rather than an opportunity:
 *
 *   **the module-read gate must not decide the same load twice.** `loader/require.ts` already
 *   takes an `fs.read` decision for every CJS load of a file outside the dependency graph, at
 *   `Module.prototype.load` and with a STACK WALK for the subject — strictly better attribution
 *   than a `parentURL`, which on THIS path is derived from the `parent` record the caller handed
 *   `Module._load` (#180). Left alone, this hook would take a second, worse-attributed decision
 *   for the identical load: two `DENY` lines, two trace entries, two grants out of `observe`.
 *   {@link gateModuleRead} therefore declines every `require`-conditioned resolution — see
 *   {@link decidedByCjsGate} for why that is now one test rather than the two #152 shipped.
 *
 * ── THE SYNTHETIC URL IS AN `import`-PATH ANSWER ONLY (#183) ────────────────────────────────
 * `resolve`'s answer is not always private to Node. On the `require` path the caller can SEE it
 * (`require.resolve("fs")`) and is entitled to feed it back in (`require(require.resolve("fs"))`),
 * and on Node ≥24.18 `require.resolve` goes through this chain where on 22 it does not. Answering
 * `capwall-esm:fs` therefore broke, on ≥24.18 only:
 *
 *   require.resolve("fs")                     -> "capwall-esm:fs"      (should be "fs")
 *   Module.isBuiltin(require.resolve("fs"))   -> false                 (should be true)
 *   require(require.resolve("fs"))            -> MODULE_NOT_FOUND      (Node has no such scheme)
 *
 * which is not a security hole and is worse than one: builtin detection answers `false` for all
 * 24 mediated spellings, and every instrumentation library that keys its cache on `require.resolve`
 * (`mock-require`, `proxyquire`, `require-in-the-middle`, so `dd-trace` / `elastic-apm-node`)
 * silently mis-keys. AGENTS.md § availability is about exactly this: the fix a user reaches for is
 * to remove capwall.
 *
 * So a `require`-conditioned resolution gets NODE'S OWN URL. Nothing is given up, because nothing
 * on the `require` path was relying on it: `Module._load` returns the shim for every mediated
 * specifier before Node's resolver is reached, so a `require` for a mediated builtin does not get
 * here in the first place, and the one CJS route that could have laundered a specifier onto a
 * builtin — `require("#x")` with `"imports": {"#x": "fs"}` — is rejected by NODE with
 * `ERR_INVALID_URL_SCHEME`, with or without capwall, on 22/24/26. The fail-closed claim below is
 * unchanged and now carries the whole weight on this path: if a `require` ever does reach `load`
 * with a raw `node:<mediated>` URL, the re-mediation branch serves the shim.
 *
 * `import.meta.resolve("fs")` still answers `capwall-esm:fs`, on all three versions, and that is
 * NOT fixed here. Measured on 22.23.1 / 24.18.0 / 26.5.0: an `import.meta.resolve` reaches this
 * hook with a context byte-for-byte identical to a static `import` of the same specifier — same
 * `conditions`, same `importAttributes`, same `parentURL` — so there is no signal to branch on.
 * The only shape that would fix it is dropping the resolve-side rewrite entirely and mediating a
 * raw `node:` URL in `load`, and that trades a cosmetic deviation for a real one: the ESM registry
 * is keyed by URL and permanent, so `node:fs` would be cached as the synthetic module and a FRESH
 * import after the last `uninstall()` would keep returning it — the #152 teardown asymmetry, back,
 * on every mediated builtin. The current behaviour is pinned by `test/primitive-arity.test.ts` so
 * it cannot drift silently in either direction.
 *
 * Builtin MEDIATION is otherwise deliberately NOT restricted to the `import` path: if a `require`
 * ever arrives at `load` for a mediated builtin, serving the shim-backed synthetic module is the
 * fail-closed answer and reaching the raw builtin is not. Whether `registerHooks` could REPLACE the
 * `Module._load` patch is a separate and much larger question — see `docs/node-api-dependencies.md`
 * § The one migration that matters; it is not attempted here.
 *
 * SECURITY — why classification happens on the RESOLVED URL, not the specifier string (#59):
 * a specifier does not have to NAME a builtin to reach one. Node's subpath imports let a
 * package map any private specifier onto a bare builtin name in its own `package.json`
 * (`"imports": { "#x": "fs" }`, including conditional and `*`-pattern targets), and a
 * dependency that ships four characters of metadata then reaches the raw builtin without ever
 * writing `fs`. Matching the specifier string alone missed every such spelling, silently — the
 * bypass produced no capwall log line at all, so it was invisible to `observe` and
 * `capwall diff`. The rule is therefore: whatever Node says a specifier RESOLVES to decides
 * whether it is mediated. See `mediatedSpecifierForUrl`.
 */
import { CapabilityError } from "../errors.js";
import { isInstalled, liveCtx } from "./live-context.js";
import {
  decideEsmModuleRead,
  type EsmGateOutcome,
  type EsmGateSnapshot,
} from "./module-read.js";

const PREFIX = "capwall-esm:";

/** `Object.prototype.hasOwnProperty` bound once — never reached through a polluted prototype. */
const hasOwn = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** What {@link initialize} needs from the registering side. Both are main-thread facts now. */
export interface HookInit {
  /** file:// URL of the built `esm-runtime.js` bridge, imported by every synthetic module. */
  bridgeUrl: string;
  /** specifier → its ESM named-export identifiers (default handled separately). */
  exports: Record<string, string[]>;
}

let bridgeUrl = "";
let exportsBySpecifier: Record<string, string[]> = {};
/** Specifiers already warned about in `load`'s re-mediation path — one line each, not per import. */
const reMediationWarned = new Set<string>();

/**
 * Hand the hooks the two facts they cannot derive themselves, before they are registered.
 *
 * Both used to cross a thread boundary as `module.register()`'s `data` payload; the shape is kept
 * (rather than reaching back into `esm-runtime.ts` from here) because it keeps the ORDER explicit:
 * the export names must be enumerated while an install is active and BEFORE the hooks go live, or
 * a resolve arriving between the two would see an empty registry and mediate nothing.
 */
export function initialize(data: HookInit): void {
  bridgeUrl = data.bridgeUrl;
  exportsBySpecifier = data.exports;
}

/*
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * THE MODULE-READ GATE (issue #123), NOW WITH NOTHING BETWEEN IT AND THE POLICY
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * The decision still has to be taken at RESOLUTION time — that is what makes it a gate rather
 * than an audit — but resolution now happens on the thread that owns the policy. So the snapshot
 * is BUILT FROM {@link liveCtx} on each invocation instead of being shipped across a port and
 * refreshed, and a decision is reported by calling `liveCtx.onDecision` directly instead of
 * posting it back for the main thread to deliver a turn later.
 *
 * What that removes is not just code. The old shape had a COPY of the policy on another thread,
 * and a copy is a thing that can be stale — the failure mode #62 and #87 are both instances of.
 * `refreshSnapshot`'s synchronous port drain existed to make the window empty; there is now no
 * window, because there is no copy.
 */

/** The live policy, in the shape `decideEsmModuleRead` takes. Allocated per resolution, at
 * module-load frequency rather than per request — see `scripts/bench/README.md` § coverage. */
function currentSnapshot(): EsmGateSnapshot {
  return {
    installed: isInstalled(),
    policy: liveCtx.policy,
    mode: liveCtx.mode,
    projectRoot: liveCtx.projectRoot,
  };
}

/**
 * Is this resolution the CJS loader's? Node's own statement, and the only one either rule below
 * needs.
 *
 * `conditions` is how Node distinguishes a `require` resolution from an `import` one — the CJS
 * resolver always asks with the `require` condition and the ESM resolver never does, measured on
 * 22.22.3 / 22.23.1 / 24.18.0 / 26.5.0. TWO separate rules read it, and they are separate rules
 * about the same fact rather than one rule used twice:
 *
 *  - {@link decidedByCjsGate} — WHO decides the module-read gate for this load (#180).
 *  - {@link resolve} — WHAT URL capwall is allowed to answer with (#183). A `require` resolution's
 *    answer is a value the caller can see (`require.resolve`) and must be able to feed back into
 *    `require`, so capwall's synthetic URL has no business in it.
 */
function isCjsResolution(conditions: readonly string[]): boolean {
  return conditions.includes("require");
}

/**
 * Is this resolution the CJS loader's, i.e. one `loader/require.ts` will decide?
 *
 * ONE TEST, AND IT IS NODE'S OWN. `conditions` is how Node distinguishes a `require` resolution
 * from an `import` one — the CJS resolver always asks with the `require` condition and the ESM
 * resolver never does, measured on 22.22.3 / 24.18.0 / 26.5.0. Every such resolution that goes on
 * to read a file arrives at `Module.prototype.load`, which is where the CJS half now decides (see
 * `loader/module-read.ts` § WHICH OF THE GATES DECIDES A GIVEN LOAD), and that half has the
 * better subject: a STACK WALK, which a `createRequire()` filename cannot spoof, where this hook
 * has only `parentURL` — and on THIS path `parentURL` is derived from the `parent` record the
 * caller handed `Module._load`, which is exactly what made #180 a principal-selection bug.
 *
 * WHAT USED TO BE HERE, AND WHY IT IS GONE. `insideGatedCjsLoad() && conditions.includes(...)` —
 * a depth counter over the dynamic extent of a `Module._load` that had taken a decision. A module
 * body runs inside its own `Module._load`, so the counter was non-zero for the whole of every
 * module evaluation and the hook stood down for every nested load made from a module body, which
 * is where a supply-chain payload runs (#179). It also stood down for a load the CJS half had
 * merely RESOLVED rather than decided (#178). Both disappear with the counter: there is no state,
 * no extent, and nothing to disarm, because the CJS half can no longer fail to decide a load it
 * is handed.
 *
 * `require("./x.mjs")` is the case worth checking against this rule, because it is synchronous and
 * the ENTIRE ES subgraph loads inside that one `Module._load`. The direct resolution carries
 * `["require", …]` and is declined here — correctly, `Module.prototype.load` sees the `.mjs` file
 * and decides it. Every nested `import` inside that subgraph carries `["node", "import", …]` and
 * is decided here. Measured on 22/24/26.
 */
function decidedByCjsGate(conditions: readonly string[]): boolean {
  return isCjsResolution(conditions);
}

/**
 * Take the module-read decision for one resolution, throwing on an enforce-mode denial.
 *
 * Throwing from `resolve` — rather than from `load` — is deliberate: it is the earliest point at
 * which the target is known, and it happens BEFORE `defaultLoad` opens the file, so a denied
 * import never reads the bytes at all. Node surfaces the throw to the importer as a failed
 * import, which is what a caller already has to handle for a missing module.
 */
function gateModuleRead(context: ResolveContext, url: string): void {
  if (decidedByCjsGate(context.conditions)) return;
  const outcome: EsmGateOutcome | null = decideEsmModuleRead(
    currentSnapshot(),
    context.parentURL,
    url,
  );
  if (outcome === null) return;
  // Report through the LIVE context, exactly as a captured shim does (#87) — never through a
  // context captured when the hooks were registered.
  liveCtx.onDecision(outcome.pkg, outcome.decision);
  if (!outcome.decision.allowed) throw new CapabilityError(outcome.decision.reason, outcome.pkg);
}

/**
 * The hook signatures, written out STRUCTURALLY rather than imported from `node:module`.
 *
 * `node:module` is mediated, and `test/real-builtins.test.ts`'s source scan cannot tell an erased
 * `import type … from "node:module"` from a live one — the rule it enforces (#78: nothing in `src`
 * names a mediated builtin except the capture modules) is worth more than the convenience. `tsc`
 * still checks these against Node's real `ResolveHookSync`/`LoadHookSync` at the
 * `registerHooks({ resolve, load })` call site in `esm-hook.ts`, so a shape that drifts from
 * Node's fails the build there rather than at runtime.
 */
interface ResolveContext {
  conditions: string[];
  importAttributes: Record<string, string | undefined>;
  parentURL: string | undefined;
}
interface ResolveResult {
  url: string;
  format?: string | null | undefined;
  shortCircuit?: boolean | undefined;
  importAttributes?: Record<string, string | undefined> | undefined;
}
type NextResolve = (specifier: string, context?: Partial<ResolveContext>) => ResolveResult;

/**
 * Given a URL Node's resolution machinery produced, return the REGISTERED specifier whose
 * shim mediates it, or `null` if the URL is not a mediated builtin.
 *
 * Both spellings of every mediated builtin are registry keys (`fs` and `node:fs`, …), so the
 * direct hit covers the `node:`-prefixed URL Node always yields for a builtin; the `node:`
 * strip is belt-and-braces for a registry that only ever held the bare spelling. Nothing else
 * counts — a `file:`/`data:`/`https:` URL is never a builtin, so the check is one string
 * comparison plus at most two own-property lookups on the hot path.
 */
function mediatedSpecifierForUrl(url: string): string | null {
  if (hasOwn(exportsBySpecifier, url)) return url;
  if (url.startsWith("node:")) {
    const bare = url.slice("node:".length);
    if (hasOwn(exportsBySpecifier, bare)) return bare;
  }
  return null;
}

export function resolve(
  specifier: string,
  context: ResolveContext,
  nextResolve: NextResolve,
): ResolveResult {
  // Fast path: the specifier NAMES a mediated builtin (`import "node:fs"`). No resolution work
  // is needed and this is the overwhelmingly common case, so it stays a single lookup — the
  // `conditions` scan below is paid only by the handful of specifiers that reach it.
  if (hasOwn(exportsBySpecifier, specifier)) {
    // Encode the ORIGINAL specifier in the URL so `load` knows which shim to re-export — but
    // ONLY on the `import` path (#183). See {@link resolve}'s note on the synthetic URL.
    if (!isCjsResolution(context.conditions)) return { url: PREFIX + specifier, shortCircuit: true };
    return nextResolve(specifier, context);
  }

  // Slow path: let Node resolve, then classify on the RESULT (#59). This is the real gate —
  // subpath imports (`"imports": {"#x": "fs"}`), conditional and `*`-pattern import targets,
  // and any future spelling that lands on a builtin all pass through here, and all of them
  // produce a `node:<builtin>` URL that we mediate exactly as if it had been named directly.
  // `nextResolve` was already being called for every non-mediated specifier, so the added
  // cost is the string check above and nothing else.
  const result = nextResolve(specifier, context);
  const mediated = mediatedSpecifierForUrl(result.url);
  if (mediated !== null && !isCjsResolution(context.conditions)) {
    return { url: PREFIX + mediated, shortCircuit: true };
  }
  // Not a builtin, so it is a file (or a `data:`/`https:` target the gate ignores). This is the
  // #123 gate — see `gateModuleRead`. It runs AFTER `nextResolve` because the decision is about
  // the resolved target, never about the specifier text.
  gateModuleRead(context, result.url);
  return result;
}

interface LoadContext {
  format: string | null | undefined;
  conditions: string[];
  importAttributes: Record<string, string | undefined>;
}
interface LoadResult {
  format: string | null | undefined;
  source?: string | ArrayBuffer | NodeJS.TypedArray | undefined;
  shortCircuit?: boolean | undefined;
}
type NextLoad = (url: string, context?: Partial<LoadContext>) => LoadResult;

/** A valid, non-reserved ES identifier that can appear in `export const <name> = …`. */
const RESERVED = new Set([
  "default",
  "break", "case", "catch", "class", "const", "continue", "debugger", "delete",
  "do", "else", "export", "extends", "finally", "for", "function", "if", "import", "in",
  "instanceof", "new", "return", "super", "switch", "this", "throw", "try", "typeof", "var",
  "void", "while", "with", "yield", "let", "enum", "await", "null", "true", "false",
]);
function isExportableName(name: string): boolean {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name) && !RESERVED.has(name);
}

/**
 * Build the synthetic module source for a mediated specifier. Every interpolation is
 * `JSON.stringify`d and every export name is gated by {@link isExportableName}, so nothing
 * derived from a module's own metadata can escape a string literal or an identifier position.
 */
function synthesize(specifier: string): { format: string; source: string; shortCircuit: true } {
  const names = (exportsBySpecifier[specifier] ?? []).filter(isExportableName);
  const lines = [
    `import { getEsmShim } from ${JSON.stringify(bridgeUrl)};`,
    `const __capwall_shim = getEsmShim(${JSON.stringify(specifier)});`,
    `export default __capwall_shim;`,
    ...names.map((n) => `export const ${n} = __capwall_shim[${JSON.stringify(n)}];`),
  ];
  return { format: "module", source: lines.join("\n"), shortCircuit: true };
}

export function load(url: string, context: LoadContext, nextLoad: NextLoad): LoadResult {
  if (!url.startsWith(PREFIX)) {
    // DEFENSE IN DEPTH (#59, #61): capwall's own `resolve` never emits a bare `node:<mediated>`
    // URL, so reaching here with one means SOMETHING ELSE produced it — a resolution route we
    // did not anticipate, or another module-customization hook that short-circuited ahead of
    // us. Node runs the most recently registered hook first, so a hook registered AFTER capwall
    // is ahead of capwall's `resolve`; the load chain still descends to us, which is what makes
    // this reachable. Rather than hand back the raw builtin, re-mediate: serve the same
    // shim-backed synthetic source we would have served had our `resolve` seen it.
    //
    // WHAT CHANGED WITH `registerHooks` (#152), because it changes which attacker this catches.
    // capwall now lives in the SYNCHRONOUS chain, which Node runs entirely ahead of the
    // asynchronous `module.register()` chain. So a hostile hook registered with `register()` no
    // longer gets ahead of capwall's `resolve` at all: capwall's `resolve` runs first, calls
    // `nextResolve` (which descends into the async chain), sees the `node:<builtin>` URL that
    // chain returned and mediates it there — verified on 22/24/26. The remaining attacker this
    // branch is for is a SYNCHRONOUS hook registered after capwall's, which does run first.
    //
    // HOW FAR THIS ACTUALLY REACHES (measured, not assumed — #78). A `node:` URL already
    // resident in the ESM module cache is served from cache and the load chain is never
    // consulted at all, so this branch only exists for a specifier capwall itself has kept OUT
    // of that cache. From #74 until #78 it did the opposite: the shims captured their real
    // modules with static ESM `import realFs from "node:fs"`, every mediated builtin was cached
    // raw before the hooks were registered, and this was dead code for the whole mediated set.
    // Since #78 the capture goes through a CommonJS `require` (`src/real-builtins.cts`), which
    // populates the CJS cache and leaves the ESM cache untouched, and this branch fires for all
    // twelve mediated builtins — verified end-to-end in `test/esm.test.ts` § #78 against a hook
    // registered ahead of capwall's, including one that declares `format: "builtin"`.
    //
    // What still bounds it, honestly: this is capwall's second layer, not its first. `resolve`
    // classifying on the RESOLVED URL is what closes #59. A hostile hook that short-circuits
    // `load` as well as `resolve` never lets this run, and a host process that ESM-imported a
    // mediated builtin BEFORE capwall installed has already cached it raw — the `--import`
    // preload exists so that window is empty. The gate that actually stops #61's PoC is
    // `shims/module.ts`. See docs/threat-model.md § ESM.
    const mediated = mediatedSpecifierForUrl(url);
    if (mediated !== null) {
      // Loud, because reaching here is never normal: in a clean run capwall's own `resolve`
      // has already rewritten every mediated specifier, so `load` sees only `capwall-esm:`
      // URLs. This is capwall's only in-band signal that something else is ahead of it in the
      // hook chain — the situation the shim gate in shims/module.ts exists to prevent, which a
      // hook registered before capwall (or reached via `process.getBuiltinModule`) can still
      // create. Once per specifier so a hot import loop cannot spam the log.
      if (!reMediationWarned.has(mediated)) {
        reMediationWarned.add(mediated);
        process.stderr.write(
          `[capwall] WARN another module-customization hook resolved '${mediated}' straight to the raw builtin; ` +
            `capwall re-mediated it at load time, but it is no longer first in the hook chain\n`,
        );
      }
      return synthesize(mediated);
    }
    return nextLoad(url, context);
  }

  const specifier = url.slice(PREFIX.length);
  // Only serve `capwall-esm:` URLs whose specifier we actually registered — a dependency that
  // hand-crafts `import("capwall-esm:…")` for an unregistered specifier gets a hard error, not
  // a fabricated module. (Registered specifiers still resolve to the same guarded shim, so this
  // is defense-in-depth, not a new gate.)
  if (!hasOwn(exportsBySpecifier, specifier)) {
    throw new Error(`capwall: refusing to load unregistered ESM specifier '${specifier}'`);
  }
  return synthesize(specifier);
}
