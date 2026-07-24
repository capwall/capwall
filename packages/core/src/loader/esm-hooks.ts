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
 */

const PREFIX = "capwall-esm:";

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

export async function resolve(
  specifier: string,
  context: ResolveContext,
  nextResolve: NextResolve,
): Promise<{ url: string; format?: string | null; shortCircuit?: boolean }> {
  if (Object.prototype.hasOwnProperty.call(exportsBySpecifier, specifier)) {
    // Encode the ORIGINAL specifier in the URL so `load` knows which shim to re-export.
    return { url: PREFIX + specifier, shortCircuit: true };
  }
  return nextResolve(specifier, context);
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

export async function load(
  url: string,
  context: LoadContext,
  nextLoad: NextLoad,
): Promise<{ format: string; source: string; shortCircuit?: boolean } | Awaited<ReturnType<NextLoad>>> {
  if (!url.startsWith(PREFIX)) return nextLoad(url, context);

  const specifier = url.slice(PREFIX.length);
  // Only serve `capwall-esm:` URLs whose specifier we actually registered — a dependency that
  // hand-crafts `import("capwall-esm:…")` for an unregistered specifier gets a hard error, not
  // a fabricated module. (Registered specifiers still resolve to the same guarded shim, so this
  // is defense-in-depth, not a new gate.)
  if (!Object.prototype.hasOwnProperty.call(exportsBySpecifier, specifier)) {
    throw new Error(`capwall: refusing to load unregistered ESM specifier '${specifier}'`);
  }
  const names = (exportsBySpecifier[specifier] ?? []).filter(isExportableName);

  // Generate an ES module that pulls the shim from the main-thread bridge and re-exports it.
  const lines = [
    `import { getEsmShim } from ${JSON.stringify(bridgeUrl)};`,
    `const __capwall_shim = getEsmShim(${JSON.stringify(specifier)});`,
    `export default __capwall_shim;`,
    ...names.map((n) => `export const ${n} = __capwall_shim[${JSON.stringify(n)}];`),
  ];
  return { format: "module", source: lines.join("\n"), shortCircuit: true };
}
