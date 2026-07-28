/**
 * ESM module customization hooks (roadmap M5) — the LOADER-THREAD half of ESM interception.
 *
 * Registered via `module.register()` from `esm-hook.ts`. Runs on Node's separate loader thread.
 *
 * TWO JOBS, and they take opposite approaches to that thread for reasons worth reading before
 * changing either:
 *
 *  1. BUILTIN MEDIATION (M5). No policy state is needed here at all: the hook rewrites mediated
 *     builtin specifiers to a synthetic `capwall-esm:` URL and, for that URL, returns generated
 *     module source that re-exports capwall's shim members from the main-thread bridge
 *     (`esm-runtime.ts`). The synthetic source is evaluated on the MAIN thread, where the
 *     re-exported shim functions attribute the caller and evaluate policy exactly as the CJS
 *     shims do — so the decision never happens on this thread.
 *  2. THE MODULE-READ GATE (#123). This one cannot be deferred to the main thread: the decision
 *     has to be taken at RESOLUTION time, which is here, and a round trip back to main deadlocks
 *     (main blocks on hook results during synchronous module loads). So this thread holds a
 *     policy SNAPSHOT, refreshed synchronously from a `MessagePort` on every invocation. See the
 *     block comment above {@link refreshSnapshot}.
 *
 * Job 1 covers BOTH `import()` (dynamic) and static `import { x } from 'node:fs'` — the load hook
 * intercepts the module graph before evaluation, so the static binding is to our shim from the
 * start (there is no "immutable binding" problem because we never swap after the fact).
 *
 * Export names are supplied by the main thread at registration (it can enumerate the real
 * builtins without triggering this hook), so the load hook never imports the real module
 * itself — which would recurse through `resolve` and loop.
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

// `node:worker_threads` is mediated, so it comes out of the CJS capture rather than a static ESM
// import: this module IS the load hook, and caching a mediated specifier's node: URL in an ESM
// registry is precisely what left the #78 backstop dead. `test/real-builtins.test.ts`'s source
// scan enforces the rule across `src`.
import { realWorkerThreads } from "../real-builtins.cjs";
import { CapabilityError } from "../errors.js";
import { decideEsmModuleRead, type EsmGateOutcome, type EsmGateSnapshot } from "./module-read.js";

const PREFIX = "capwall-esm:";

/** `Object.prototype.hasOwnProperty` bound once — never reached through a polluted prototype. */
const hasOwn = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

interface InitData {
  /** file:// URL of the built `esm-runtime.js` bridge, imported by every synthetic module. */
  bridgeUrl: string;
  /** specifier → its ESM named-export identifiers (default handled separately). */
  exports: Record<string, string[]>;
  /**
   * Two-way channel to the main thread, for the module-read gate (#123). Main → here carries
   * policy snapshots; here → main carries decisions to record. See {@link refreshSnapshot}.
   */
  gatePort: GatePort;
  /** The policy in force at registration time; later ones arrive over `gatePort`. */
  gateSnapshot: EsmGateSnapshot;
}

let bridgeUrl = "";
let exportsBySpecifier: Record<string, string[]> = {};
/** Specifiers already warned about in `load`'s re-mediation path — one line each, not per import. */
const reMediationWarned = new Set<string>();

/*
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * THE MODULE-READ GATE ON THIS THREAD (issue #123)
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * `import("/home/u/.aws/x.json", { with: { type: "json" } })` returns a file's contents as a
 * value, through Node's JSON translator, without ever touching capwall's `fs` shim. Closing that
 * needs a policy decision at resolution time — and resolution happens HERE, on a thread that by
 * design holds no capwall state.
 *
 * WHY THE DECISION IS TAKEN ON THIS THREAD RATHER THAN DELEGATED TO THE MAIN ONE. It cannot be
 * delegated. The loader hooks are asynchronous, but the main thread BLOCKS on their result for
 * synchronous module resolution (`require(esm)`, the initial graph), so any round trip from here
 * back to main deadlocks the process the moment it happens during a blocking load. Handing the
 * hook a policy COPY and evaluating locally is the only shape that cannot deadlock.
 *
 * WHAT THAT COSTS, AND WHY IT IS NOT A SECOND IMPLEMENTATION. The copy is evaluated by the SAME
 * `evaluate()` / `packageForPath()` / `matchesGlob()` functions the main thread uses — imported,
 * not reimplemented — so there is one decision procedure, not two that can drift. What is
 * genuinely duplicated is the policy DATA, and the risk that carries is staleness, which
 * {@link refreshSnapshot} closes: `receiveMessageOnPort` drains the port SYNCHRONOUSLY, with no
 * event-loop turn, at the top of every hook invocation. `install()` posts the new snapshot
 * synchronously before it returns, so by the time any subsequent import reaches this thread the
 * message is already queued and the very next drain sees it. There is no window in which an
 * import is evaluated against a policy the main thread has already replaced.
 *
 * DECISIONS TRAVEL THE OTHER WAY over the same port, fire-and-forget. They are RECORDING, not
 * enforcement — enforcement is the throw below, which happens here and now — so the main thread
 * delivering them on its next event-loop turn is fine, and waiting for an acknowledgement would
 * reintroduce exactly the deadlock this design avoids.
 */

/**
 * The `MessagePort` type, DERIVED from the captured `node:worker_threads` rather than imported
 * from it. A `import("node:worker_threads").MessagePort` annotation would be erased at build
 * time and is harmless at runtime, but `test/real-builtins.test.ts`'s source scan cannot tell an
 * erased type reference in that form from a live one — and the rule it enforces (#78: nothing in
 * `src` names a mediated builtin except `real-builtins.cts`) is worth more than the convenience.
 */
type GatePort = Parameters<typeof realWorkerThreads.receiveMessageOnPort>[0];

/** The channel to the main thread; `null` until {@link initialize}, and on a Node without it. */
let gatePort: GatePort | null = null;

/**
 * The policy the gate evaluates against. Starts INERT (`installed: false`) so a hook that somehow
 * runs before `initialize` gates nothing rather than denying everything — the host process's own
 * imports must not become collateral damage of capwall's bootstrap.
 */
let gateSnapshot: EsmGateSnapshot = {
  installed: false,
  policy: { version: 1, mode: "enforce", default: {}, packages: {} },
  mode: "enforce",
  projectRoot: undefined,
};

export async function initialize(data: InitData): Promise<void> {
  bridgeUrl = data.bridgeUrl;
  exportsBySpecifier = data.exports;
  gatePort = data.gatePort ?? null;
  if (data.gateSnapshot) gateSnapshot = data.gateSnapshot;
}

/**
 * Adopt the newest policy snapshot the main thread has posted, synchronously.
 *
 * `receiveMessageOnPort` pops from the port's queue WITHOUT an event-loop turn, which is what
 * makes this race-free: a `postMessage` from `install()` is queued the instant it is called, so
 * the next hook invocation sees it even though the port's `"message"` event has not fired. The
 * loop drains to the END of the queue rather than taking one message, so a burst of
 * install/uninstall transitions leaves the LAST one in force, not the oldest unread one.
 */
function refreshSnapshot(): void {
  if (gatePort === null) return;
  let message = realWorkerThreads.receiveMessageOnPort(gatePort);
  while (message !== undefined) {
    gateSnapshot = message.message as EsmGateSnapshot;
    message = realWorkerThreads.receiveMessageOnPort(gatePort);
  }
}

/** Report a decision to the main thread's `onDecision` sink. Never throws, never waits. */
function reportDecision(outcome: EsmGateOutcome): void {
  if (gatePort === null) return;
  try {
    // This is a `worker_threads` MessagePort, not `window.postMessage` — there is no target
    // origin to pass, and adding one would be a TypeError.
    // eslint-disable-next-line unicorn/require-post-message-target-origin
    gatePort.postMessage(outcome);
  } catch {
    // A closed port (teardown raced with an in-flight import). The enforcement half below has
    // already happened; losing the trace line is the lesser failure and must not break the load.
  }
}

/**
 * Take the module-read decision for one resolution, throwing on an enforce-mode denial.
 *
 * Throwing from `resolve` — rather than from `load` — is deliberate: it is the earliest point at
 * which the target is known, and it happens BEFORE `defaultLoad` opens the file, so a denied
 * import never reads the bytes at all. Node surfaces the throw to the importer as a failed
 * import, which is what a caller already has to handle for a missing module.
 */
function gateModuleRead(parentURL: string | undefined, url: string): void {
  refreshSnapshot();
  const outcome = decideEsmModuleRead(gateSnapshot, parentURL, url);
  if (outcome === null) return;
  reportDecision(outcome);
  if (!outcome.decision.allowed) throw new CapabilityError(outcome.decision.reason, outcome.pkg);
}

interface ResolveContext {
  conditions: string[];
  importAttributes: Record<string, string>;
  parentURL?: string;
}
type NextResolve = (
  specifier: string,
  context: ResolveContext,
) => Promise<{ url: string; format?: string | null; shortCircuit?: boolean }>;

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

export async function resolve(
  specifier: string,
  context: ResolveContext,
  nextResolve: NextResolve,
): Promise<{ url: string; format?: string | null; shortCircuit?: boolean }> {
  // Fast path: the specifier NAMES a mediated builtin (`import "node:fs"`). No resolution work
  // is needed and this is the overwhelmingly common case, so it stays a single lookup.
  if (hasOwn(exportsBySpecifier, specifier)) {
    // Encode the ORIGINAL specifier in the URL so `load` knows which shim to re-export.
    return { url: PREFIX + specifier, shortCircuit: true };
  }

  // Slow path: let Node resolve, then classify on the RESULT (#59). This is the real gate —
  // subpath imports (`"imports": {"#x": "fs"}`), conditional and `*`-pattern import targets,
  // and any future spelling that lands on a builtin all pass through here, and all of them
  // produce a `node:<builtin>` URL that we mediate exactly as if it had been named directly.
  // `nextResolve` was already being awaited for every non-mediated specifier, so the added
  // cost is the string check above and nothing else.
  const result = await nextResolve(specifier, context);
  const mediated = mediatedSpecifierForUrl(result.url);
  if (mediated !== null) return { url: PREFIX + mediated, shortCircuit: true };
  // Not a builtin, so it is a file (or a `data:`/`https:` target the gate ignores). This is the
  // ESM half of #123 — see `gateModuleRead`. It runs AFTER `nextResolve` because the decision is
  // about the resolved target, never about the specifier text.
  gateModuleRead(context.parentURL, result.url);
  return result;
}

interface LoadContext {
  format?: string | null | undefined;
  conditions: string[];
  importAttributes: Record<string, string>;
}
type NextLoad = (
  url: string,
  context: LoadContext,
) => Promise<{ format: string; source: string | ArrayBuffer | Uint8Array; shortCircuit?: boolean }>;

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

export async function load(
  url: string,
  context: LoadContext,
  nextLoad: NextLoad,
): Promise<{ format: string; source: string; shortCircuit?: boolean } | Awaited<ReturnType<NextLoad>>> {
  if (!url.startsWith(PREFIX)) {
    // DEFENSE IN DEPTH (#59, #61): capwall's own `resolve` never emits a bare `node:<mediated>`
    // URL, so reaching here with one means SOMETHING ELSE produced it — a resolution route we
    // did not anticipate, or another module-customization hook that short-circuited ahead of
    // us (Node runs the most recently registered hook first, and the synchronous
    // `registerHooks` chain runs entirely before the asynchronous `register` chain). Rather
    // than hand back the raw builtin, re-mediate: serve the same shim-backed synthetic source
    // we would have served had our `resolve` seen it. This holds against a hostile resolve
    // short-circuit registered via BOTH `module.register()` and `module.registerHooks()` — the
    // load chain still descends to us in both cases, even though the synchronous resolve chain
    // runs first.
    //
    // HOW FAR THIS ACTUALLY REACHES (measured, not assumed — #78). A `node:` URL already
    // resident in the ESM module cache is served from cache and the load chain is never
    // consulted at all, so this branch only exists for a specifier capwall itself has kept OUT
    // of that cache. From #74 until #78 it did the opposite: the shims captured their real
    // modules with static ESM `import realFs from "node:fs"`, every mediated builtin was cached
    // raw before `module.register()` ran, and this was dead code for the whole mediated set.
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
