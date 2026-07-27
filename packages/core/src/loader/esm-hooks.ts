/**
 * ESM module customization hooks (roadmap M5) — the LOADER-THREAD half of ESM interception.
 *
 * Registered via `module.register()` from `esm-hook.ts`. Runs on Node's separate loader
 * thread, so it holds NO policy/attribution state — it only rewrites mediated builtin
 * specifiers to a synthetic `capwall-esm:` URL and, for that URL, returns generated module
 * source that re-exports capwall's shim members from the main-thread bridge (`esm-runtime.ts`).
 *
 * The synthetic source is evaluated on the MAIN thread, where the re-exported shim functions
 * attribute the caller and evaluate policy exactly as the CJS shims do. This covers BOTH
 * `import()` (dynamic) and static `import { x } from 'node:fs'` — the load hook intercepts the
 * module graph before evaluation, so the static binding is to our shim from the start (there
 * is no "immutable binding" problem because we never swap after the fact).
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

const PREFIX = "capwall-esm:";

/** `Object.prototype.hasOwnProperty` bound once — never reached through a polluted prototype. */
const hasOwn = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

interface InitData {
  /** file:// URL of the built `esm-runtime.js` bridge, imported by every synthetic module. */
  bridgeUrl: string;
  /** specifier → its ESM named-export identifiers (default handled separately). */
  exports: Record<string, string[]>;
}

let bridgeUrl = "";
let exportsBySpecifier: Record<string, string[]> = {};

export async function initialize(data: InitData): Promise<void> {
  bridgeUrl = data.bridgeUrl;
  exportsBySpecifier = data.exports;
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
    // we would have served had our `resolve` seen it. Verified to hold against a hostile
    // resolve short-circuit registered via BOTH `module.register()` and
    // `module.registerHooks()` — the load chain still descends to us in both cases.
    // Residual: a hostile hook that short-circuits `load` as well never lets us run (#61).
    const mediated = mediatedSpecifierForUrl(url);
    if (mediated !== null) return synthesize(mediated);
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
