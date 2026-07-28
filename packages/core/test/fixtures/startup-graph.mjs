/**
 * Ask Node what `install({ esm: true })` costs a process, prove it starts silently, and count the
 * policy validator's module graph (#152, #153, #167).
 *
 * Run in a CLEAN child by `test/esm-hook-graph.test.ts`, because both answers are properties of a
 * fresh module registry and a fresh stderr: inside the vitest worker every module here is long
 * since loaded and the process has already printed plenty.
 *
 * ORDER IS LOAD-BEARING and is why this is one child rather than three:
 *
 *  - `afterInstall` is sampled BEFORE the `module.register()` positive control, or the control
 *    contaminates the measurement it exists to validate.
 *  - `zodAfterPolicyLoad` is sampled AFTER `policy/load.js` and nothing else is imported between,
 *    so the count is that module's graph and not the ambient one. It feeds #167's budget — the
 *    guard on the MAIN thread's startup graph, which is where zod 3 -> 4 put ~58 ms with nothing
 *    in the repo noticing.
 *
 * The zod half needs a RESOLVE recorder rather than a cache inspection: zod's `import` condition
 * is an ES module, so it never lands in `require.cache` and there is no supported way to
 * enumerate the ESM registry. Since #152 that recorder is itself a `module.registerHooks()` hook,
 * synchronous and in this realm, so it keeps its log in a variable where the `module.register()`
 * version had to write a temp file and read it back.
 *
 * Prints one JSON object on stdout and, if all is well, nothing at all on stderr.
 */
import { register, registerHooks } from "node:module";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.join(HERE, "..", "..", "dist");
const url = (...p) => pathToFileURL(path.join(DIST, ...p)).href;

/**
 * The internal Node loads to run an ASYNCHRONOUS module-customization hook — i.e. to start the
 * loader thread. Read off real 22.22.3 / 24.18.0 / 26.5.0 binaries rather than from a changelog:
 * `module.register()` adds it on all three, `module.registerHooks()` adds it on none.
 *
 * ONE ENTRY, AND THE REST OF THE LIST IS DELIBERATELY ABSENT. A bare `node` also gains
 * `internal/worker`, `internal/worker/io`, `internal/worker/messaging` and `worker_threads` when
 * `register()` runs — but capwall itself loads all four unconditionally, because
 * `node:worker_threads` is a MEDIATED builtin and `src/real-builtins.cts` captures every one of
 * them eagerly (#78). Including them here would report a loader thread that is not there, on
 * every single run. `internal/modules/customization_hooks` is out for the mirror-image reason:
 * Node's own bootstrap has it resident before any user code runs.
 */
const LOADER_THREAD_INTERNALS = ["NativeModule internal/modules/esm/hooks"];

/** Every URL the resolver produced, in order. Registered BEFORE anything under test is imported. */
const resolved = [];
registerHooks({
  resolve(specifier, context, nextResolve) {
    const result = nextResolve(specifier, context);
    resolved.push(result.url);
    return result;
  },
});
const zodCount = () => resolved.filter((u) => /[\\/]zod[\\/]/.test(u)).length;

const loadedSince = (before) => {
  const added = new Set(process.moduleLoadList.slice(before));
  return LOADER_THREAD_INTERNALS.filter((m) => added.has(m));
};

const beforeInstall = process.moduleLoadList.length;
const core = await import(url("index.js"));
// A plain, already-parsed policy object rather than `loadPolicyFromObject`: nothing here is
// testing the parser, and `install()` takes the parsed document.
core.install({ version: 1, mode: "enforce", default: {}, packages: {} }, "enforce", {
  esm: true,
  env: false,
  globalEgress: false,
  projectRoot: HERE,
});
// Force the hooks to actually run at least once, so this is "capwall's ESM path works and starts
// no thread" rather than "capwall registered something".
await import("node:fs");
const afterInstall = loadedSince(beforeInstall);

// #167's floor: the policy VALIDATOR's graph, which every mediated process pays for on this
// thread because the preload always parses a policy. Imported last of the two so the count is
// its own graph.
await import(url("policy", "load.js"));
const zodAfterPolicyLoad = zodCount();

// ── the positive control, and it must come last ─────────────────────────────────────────────
// `module.register()` is what capwall used until #152. If Node ever stopped loading these to
// service it, the measurement above would report a green that means nothing.
//
// `noDeprecation` is set for exactly this call and no other. On Node 26 `register()` is DEP0205
// and would print to stderr — which is the OTHER thing this child asserts the absence of. This is
// the fixture suppressing a warning about the fixture's OWN deliberate call; nothing in `src`
// suppresses anything (docs/node-api-dependencies.md § What NOT to do).
process.noDeprecation = true;
const beforeRegister = process.moduleLoadList.length;
register("data:text/javascript,export function resolve(s,c,n){return n(s,c)}", import.meta.url);
const afterRegister = loadedSince(beforeRegister);

process.stdout.write(JSON.stringify({ afterInstall, afterRegister, zodAfterPolicyLoad }));
