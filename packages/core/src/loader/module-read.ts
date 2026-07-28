/**
 * The MODULE-LOAD READ GATE — issue #123.
 *
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * WHAT WAS WRONG
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * `fs.read` is capwall's flagship capability, and the module system was a second, completely
 * un-gated route to the same bytes. Under a deny-all `enforce` policy with zero grants — no
 * `eval`, no `vm`, no `compile`, no write — a dependency read any file on disk with **no decision
 * recorded at all**:
 *
 *     require("/home/u/.docker/config.json")          // Module._extensions['.json'] + JSON.parse
 *     import("/home/u/.docker/config.json", { with: { type: "json" } })
 *
 * `Module._load`'s patch only routed MEDIATED BUILTIN SPECIFIERS to shims; a path specifier fell
 * straight through to the real loader, and the ESM side went through Node's JSON translator
 * rather than capwall's `fs` shim. For `.js` that buys execution of code already on disk; for
 * `.json` it hands the file's contents back as a value, which is a direct exfiltration primitive
 * — and the highest-value files on a developer or CI machine are JSON (`~/.docker/config.json`,
 * `~/.config/gcloud/application_default_credentials.json`, `~/.aws/sso/cache/*.json`, service
 * account keys). Worse than the read itself: `observe` cannot record what it never sees, so a
 * generated policy confidently under-reported the package's real filesystem reach.
 *
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * THE GATE, AND WHY IT IS THIS ONE
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * The load-bearing question is not "should a module load be a capability" — it is **which module
 * loads are a FILE READ rather than a MODULE LOAD.** Loading a dependency's own files is the
 * single most common thing any program does; gating every `require` as `fs.read` would make every
 * policy grant every package its own directory, which is unusable and would train operators to
 * write wide `fs.read` globs — a net loss for a capability firewall.
 *
 * So the discriminator is the RESOLVED PATH'S RELATIONSHIP TO THE DEPENDENCY GRAPH:
 *
 *   **A module load is free when the resolved file belongs to an installed package (any
 *   `node_modules/<pkg>` tree), or when the loader is the application. Otherwise — a dependency
 *   naming a file that belongs to no package — it is an `fs.read` decision on the resolved path.**
 *
 * Each half, and what it costs:
 *
 *  - **Belongs to an installed package ⇒ free.** Every file a package owns, and every file any
 *    other installed package owns, is by construction inside somebody's `node_modules` tree — or
 *    is reached through a symlink in one, which #127's link map recovers. That makes it a cheap,
 *    exact test for "this is the dependency graph", requiring no policy grant and therefore
 *    changing no existing policy and nothing `observe` generates for an ordinary app. See
 *    {@link isDependencyGraphFile} for why it takes two forms rather than one. It is deliberately
 *    not narrowed to "the caller's OWN package": `require("mime-db")` resolves to
 *    `node_modules/mime-db/db.json`, a cross-package `.json` load through Node's package
 *    resolution, and that is the ordinary dependency graph, not a file read. See RESIDUALS below
 *    for what this concedes.
 *  - **`<app>` ⇒ free.** The application is the trust root. Every other gate in capwall treats it
 *    the same way (`shims/module.ts`'s `_compile` and loader-hook gates, `shims/env.ts`). Since
 *    #60 that is a POSITIVE identification — a real application source file on the stack — so a
 *    load capwall cannot attribute is `<unknown>` and falls through to the policy rather than
 *    being waved past.
 *
 * WHAT IS LEFT IS PRECISELY THE INTERESTING CASE: a dependency naming `/home/u/.aws/…`,
 * `<project>/package-lock.json`, `<project>/src/config.json`, `/tmp/x`. Those take an `fs.read`
 * decision on the resolved file, against the same `fs.read` globs the shim uses — the right
 * vocabulary, because it is literally the same question ("may this package read this file?") and
 * because `observe` already knows how to turn the resulting trace entries into grants.
 *
 * THE COMPATIBILITY CASE THIS DOES CHANGE, stated plainly: a test runner, bundler or framework
 * that loads the APPLICATION'S OWN files (`mocha` requiring `test/*.spec.js`, a config loader
 * requiring `<project>/app.config.js`) now needs an `fs.read` grant covering them. That is a true
 * statement about what those tools do, `capwall observe` emits the grant automatically from the
 * trace, and the observe→enforce round trip therefore still needs no hand editing.
 *
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * WHY `fs.read` AND NOT A NEW CAPABILITY
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * `native` (#49) and `compile` (#93) are BOOLEAN grants because their subject cannot usefully be
 * narrowed to a file list: a `.node` path is a platform/arch/ABI build artifact, and a `_compile`
 * filename is a per-run label. A module read has neither problem — it names a real file, the
 * policy already has a glob vocabulary for exactly that, and a package that may `require`
 * `<project>/config.json` and a package that may `readFileSync` it are making the same request.
 * A third grant kind would have been a second spelling of `fs.read` that `capwall diff` and
 * `explain` would then have to keep in step.
 *
 * `.node` IS CARVED OUT, and it is the one carve-out: an addon load is already gated as `native`
 * at `process.dlopen` (loader/native.ts), which is strictly stronger than this gate — it charges
 * BOTH the caller and the file's owner, and an addon outside the project resolves to `<unknown>`
 * for the owner subject, so it is denied unless the policy names `<unknown>`. Adding an `fs.read`
 * decision on top would charge one load twice, emit a second grant from `observe`, and change no
 * outcome. `.node` files therefore skip this gate and keep #49's.
 *
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * RESIDUALS, not papered over (see docs/threat-model.md § The module system as a read channel)
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 *  - A dependency can still `require`/`import` any file inside ANY `node_modules` tree — a
 *    sibling package's `package.json`, its shipped fixtures. That is the price of the graph
 *    exemption. It is bounded: those files are published artifacts of packages the project chose
 *    to install, not the machine's secrets, and the dependency could already `require` the
 *    package and run its code.
 *  - The gate is on the LOAD, not on the cache. A module some other principal already loaded is
 *    served from `Module._cache` / the ESM registry without reaching a loader hook, so the
 *    decision is taken once, for whoever loaded it first.
 *  - Reaching past the loader entirely — a direct `Module._extensions[".json"](m, file)` call, or
 *    `process.binding` — is the same class of escape as un-patching any shim, which capwall does
 *    not claim to stop. Since #177 the chokepoint is `Module.prototype.load`, so this residual is
 *    one level narrower than it was: `new Module(f).load(f)` IS decided now, and only the
 *    extension handler below it is out of reach.
 */
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
  APP_ROOT,
  UNATTRIBUTED,
  attributeCallerDetailed,
  packageForPath,
} from "../attribution/index.js";
import { evaluate, type Decision } from "../policy/evaluate.js";
import { attributionOptionsFor, guardAttributed, type ShimContext } from "../shims/runtime.js";
import type { Mode, Policy } from "@capwall/policy-schema";

/**
 * Root of the capwall core package tree, computed exactly as `attribution/index.ts` computes its
 * own. Files under it are capwall's own machinery — the ESM runtime bridge a synthetic module
 * imports, `real-builtins.cjs` — and must never be charged to whoever happened to trigger the
 * load. In a real install capwall lives under `node_modules/@capwall/core` and the graph
 * exemption already covers it; this is for the checkout-relative layouts (this repo's own tests,
 * a linked working copy) where it does not.
 */
const CAPWALL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Extensions this gate deliberately does not take a decision for, because another capability
 * already covers the same load — see the `.node` carve-out in the header.
 */
const GATED_BY_ANOTHER_CAPABILITY: ReadonlySet<string> = new Set([".node"]);

/** The `/`-separated absolute shape `policy/glob.ts` matches against (same as `shims/fs.ts`). */
function toPolicyPath(nativePath: string): string {
  return nativePath.split(path.sep).join("/");
}

/**
 * Is `resolvedPath` LITERALLY inside a `node_modules/<name>/` directory?
 *
 * One half of {@link isDependencyGraphFile} — see there for why the question is asked twice.
 * The scan uses the LAST `node_modules/` segment (the deepest containing package) and requires at
 * least one segment BELOW the package directory, so a loose `node_modules/x.json` is not mistaken
 * for a package's file.
 *
 * The package-name shape (`name`, or `@scope/name`) is duplicated from `attribution/index.ts`
 * rather than imported, because that module's copy is one step inside a root-relative derivation
 * this function deliberately does not perform.
 */
function isUnderNodeModules(resolvedPath: string): boolean {
  const normalized = resolvedPath.includes("\\")
    ? resolvedPath.split("\\").join("/")
    : resolvedPath;
  const marker = "/node_modules/";
  const at = normalized.lastIndexOf(marker);
  if (at === -1) return false;
  const segments = normalized.slice(at + marker.length).split("/");
  const first = segments[0];
  if (first === undefined || first === "") return false;
  // `@scope/name/…` needs three segments; `name/…` needs two. Either way the file has to be
  // BELOW the package directory, not the package directory (or a stray file) itself.
  if (first.startsWith("@")) {
    const second = segments[1];
    return second !== undefined && second !== "" && segments.length > 2;
  }
  return segments.length > 1;
}

/**
 * Does `resolvedPath` belong to an installed package — is loading it dependency-graph traversal
 * rather than a file read?
 *
 * ASKED TWO WAYS, AND THE UNION IS THE ANSWER. Neither test alone is right, and both errors were
 * found by the existing suite rather than reasoned about in advance:
 *
 *  - `packageForPath` alone MISSES nothing but ADDS a dependency on the declared project root
 *    that this question does not have. It strips `projectRoot` before scanning (so a project that
 *    itself lives inside a `node_modules` is not charged to its container — a deliberate feature
 *    for ATTRIBUTION), and since #127 it reports `<unknown>` for anything outside the root. Under
 *    a root pointed at the tree's own `node_modules` — which `test/install-option-parity.test.ts`
 *    exercises for real — an ordinary `require("some-dep")` therefore looked like a read of a file
 *    belonging to no package, and was denied.
 *  - The literal path test alone misses SYMLINKED installs. `npm i file:`, `npm link` and every
 *    workspace layout put a symlink in `node_modules`, Node resolves module paths through
 *    `realpath`, and the resolved filename then has no `node_modules` segment at all
 *    (`repo/packages/util/index.js`). That is exactly #127's finding, and its link map is what
 *    recovers the position — which lives inside `packageForPath`.
 *
 * So: literally under a `node_modules/<pkg>/`, OR resolving to a package chain once #127's link
 * map has undone the realpath. Both directions only WIDEN the exemption, and neither widens it
 * past "a file inside some installed package", which is the property the graph exemption is about.
 */
function isDependencyGraphFile(resolvedPath: string, projectRoot: string | undefined): boolean {
  if (isUnderNodeModules(resolvedPath)) return true;
  const owner = packageForPath(resolvedPath, projectRoot);
  return owner !== APP_ROOT && owner !== UNATTRIBUTED;
}

/**
 * Does loading `resolvedPath` need an `fs.read` decision at all, on the FILE's side of the
 * question? (The loader's side — is this the application? — is answered separately, because it
 * costs a stack walk on the CJS path and a URL parse on the ESM one.)
 *
 * Ordered cheapest-first: the overwhelmingly common answer is "no, it is under `node_modules`",
 * and this runs once per module the process loads.
 */
export function moduleLoadNeedsDecision(
  resolvedPath: string,
  projectRoot: string | undefined,
): boolean {
  // A bare builtin name (`Module._resolveFilename("path")` returns `"path"`), or anything else
  // that is not a filesystem location. Nothing to read.
  if (!path.isAbsolute(resolvedPath)) return false;
  if (GATED_BY_ANOTHER_CAPABILITY.has(path.extname(resolvedPath).toLowerCase())) return false;
  if (resolvedPath === CAPWALL_ROOT || resolvedPath.startsWith(CAPWALL_ROOT + path.sep)) {
    return false;
  }
  return !isDependencyGraphFile(resolvedPath, projectRoot);
}

/*
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * WHICH OF THE GATES DECIDES A GIVEN LOAD (#152, rewritten by #177/#178/#179)
 * ═════════════════════════════════════════════════════════════════════════════════════════════
 * The CJS half decides EVERY CJS load and the ESM half decides every `import`. The line between
 * them is `conditions.includes("require")`, which is Node's own statement about which loader is
 * running, and it needs no state of any kind.
 *
 * WHAT THIS REPLACED, AND WHY. The CJS half used to sit in the `Module._load` wrapper and
 * RE-RESOLVE the load from `Module._load`'s own argument list, then mark the load "decided" for
 * the dynamic extent of that call so the `registerHooks` `resolve` hook — which since #152 sees
 * `require()` too — would not decide it twice. Three CRITICAL bypasses came out of that one
 * design, and they are the same defect stated three ways: **the decision was taken from
 * arguments the caller supplies, not from the file Node opens.**
 *
 *  - #177 — `Module._load(secret, undefined, true)`. `args[2]` is `isMain`, the caller's third
 *    argument, and the CJS half skipped itself for it; `parent` was `undefined`, so the ESM half
 *    saw no importer and skipped itself too. One line, both halves waived, zero decisions.
 *  - #178 — `Module._load(spec, parent, false, bag)`. The fourth argument was classified by the
 *    fields it carried in order to reconstruct what Node would pass `_resolveFilename`. The
 *    fields are the attacker's, so the re-resolution could be steered to a decoy inside
 *    `node_modules` (graph-exempt, no decision) while Node loaded the real file — and the decoy
 *    resolution ALSO disarmed the ESM hook. A getter answered capwall and Node differently.
 *  - #179 — `insideGatedCjsLoad()` was a depth counter over a whole `Module._load`, and a module
 *    body runs inside one, so the hook stood down for every nested load while any module was
 *    evaluating. The identical call was allowed during module evaluation and denied after it.
 *
 * THE CHOKEPOINT. Node resolves a CJS load once, in `Module._load`, and then commits: it
 * constructs the module and calls **`Module.prototype.load(filename)`**, which picks the
 * extension handler and reads the file. `filename` there is Node's own resolution result — not a
 * specifier, not an argument capwall reconstructed — and every CJS route reaches it. Measured on
 * 22.22.3 / 24.18.0 / 26.5.0: `require(abs)`, `require.resolve()`-then-`require`, a direct
 * `Module._load` (with any `isMain`, any `parent`, any options bag), `require(esm)`, the process
 * entry point, and even `new Module(f).load(f)` — which never goes through `Module._load` at all,
 * so the old gate could not see it. `import()` is the one route that does NOT pass here; it is
 * the ESM half's, and there `parentURL` really is the host's record.
 *
 * So there is nothing left to coordinate. The CJS gate cannot "fail to resolve" (it is handed the
 * resolution), cannot be steered (there is no second resolution), and cannot be disarmed (there
 * is no flag). The ESM hook declines `require`-conditioned resolutions unconditionally because
 * the load it is being asked about is on its way to {@link guardCjsModuleRead} — see
 * `loader/esm-hooks.ts` § `gateModuleRead`.
 */

/**
 * Absolute paths Node ITSELF resolved as a process ROOT — the entry point, and any `--import` /
 * `--require` preload.
 *
 * WHY THIS EXISTS AT ALL. The process entry point is a file with no requiring package: the stack
 * above its load is nothing but Node's own module machinery, so {@link attributeCallerDetailed}
 * answers `<unknown>`, which since #60 is deny-by-default. Waving it through is therefore
 * necessary — and #177 is precisely what happens when the thing waved through is a CLAIM. The old
 * code believed `isMain`, the caller's own third argument to `Module._load`; the ESM half believed
 * "no `parent` was passed". Both are selectable by any caller in one line.
 *
 * WHAT IS RECORDED HERE IS NOT A CLAIM. Two independent HOST facts, neither of which any
 * in-process caller can produce, and both established before a single line of dependency code has
 * run (capwall installs from a preload):
 *
 *  1. `process.argv[1]`, snapshotted by `install()`. Node writes it from the command line during
 *     bootstrap. It is the cheap one and it is exact whenever the operator spelled the entry with
 *     its extension (`node app.js`), which is the common case.
 *  2. A ROOT RESOLUTION seen by the `resolve` hook: `parentURL === undefined` on a resolution
 *     that does NOT carry the `require` condition. That is Node resolving something for itself
 *     rather than for a module — and it is the authoritative one, because it is the fully
 *     resolved, realpath'd filename Node is about to load, so it covers `node app`, `node .`,
 *     a symlinked checkout and a `main` field. Verified on 22/24/26 that a CJS entry point is
 *     root-resolved through the hook before `Module._load` ever sees it.
 *
 * A dependency cannot reach (2): the only way it can drive a resolution with no parent is through
 * `Module._load`, and every resolution that comes from there carries the `require` condition —
 * measured on 22/24/26, and it is Node's own definition of the CJS resolver, not an accident of a
 * release. `import()` always carries the importer.
 *
 * BOUNDED so a pathological host (or a future Node that root-resolves more than it does today)
 * cannot grow it without limit; a real process records two or three entries.
 */
const hostRootTargets = new Set<string>();
const MAX_HOST_ROOT_TARGETS = 32;

/** Record one host-resolved process root. Absolute native paths only. */
export function recordHostRootTarget(nativePath: string): void {
  if (!path.isAbsolute(nativePath)) return;
  if (hostRootTargets.size >= MAX_HOST_ROOT_TARGETS) return;
  hostRootTargets.add(nativePath);
}

/** Is `nativePath` one of them? Read by {@link guardCjsModuleRead}. */
export function isHostRootTarget(nativePath: string): boolean {
  return hostRootTargets.has(nativePath);
}

/**
 * Record source (1): `process.argv[1]`, read at `install()`.
 *
 * Node writes `argv` from the command line during bootstrap and capwall installs from a preload,
 * so this is read before any dependency exists — which is the whole difference between it and
 * `isMain`. It is UNRESOLVED on purpose: `path.resolve` is a string operation, not a module
 * resolution, so nothing here consults the filesystem or Node's resolver. That makes it exact for
 * `node app.js` and silent for `node app` / `node .`, where it simply never matches and source (2)
 * answers instead. Deliberately not "fixed" by running the entry through `Module._findPath`: a
 * second resolution is what #178 was about, and this one would buy only the cases already covered.
 */
export function recordProcessEntryFromArgv(argv: readonly string[]): void {
  const entry = argv[1];
  if (typeof entry !== "string" || entry === "") return;
  recordHostRootTarget(path.resolve(entry));
}

/** Drop every recorded root. For tests only — a process has exactly one set of roots. */
export function forgetHostRootTargets(): void {
  hostRootTargets.clear();
}

/** The capability request a module read raises. Identical in shape to a `readFileSync`. */
function moduleReadRequest(resolvedPath: string): {
  kind: "fs";
  access: "read";
  path: string;
} {
  return { kind: "fs", access: "read", path: toPolicyPath(resolvedPath) };
}

/**
 * CJS half: decide whether the calling package may load `resolvedPath`. Returns normally when
 * the load may proceed; throws {@link CapabilityError} on an enforce-mode denial.
 *
 * `resolvedPath` MUST BE THE FILENAME NODE IS ABOUT TO OPEN, and the one caller — the
 * `Module.prototype.load` patch in `loader/require.ts` — is the only place that has it without
 * having reconstructed it. Handing this function a path derived from `Module._load`'s argument
 * list is what #178 was, and the note above the chokepoint discussion says why no amount of care
 * with that argument list is enough.
 *
 * The subject is the ATTRIBUTED CALLER — capwall's ordinary stack walk — and deliberately not the
 * `parent` module the loader hands us. `parent.filename` is caller-controlled: `createRequire()`
 * builds a module record whose filename is whatever string it was given, so
 * `createRequire("/proj/node_modules/granted/index.js")("./x.json")` would present itself as
 * `granted` and inherit its grants. The stack walk cannot be spoofed that way (and where it CAN
 * be defeated — an `eval` frame, a `data:` module — it answers `<unknown>`, which holds nothing).
 * Since #180 that is the subject on the `require()` side of the ESM hook as well, by the simple
 * route of that hook not deciding those loads at all.
 *
 * The walk only runs for loads that survived {@link moduleLoadNeedsDecision}, so in a normal
 * process it runs for the application's own requires and nothing else.
 */
export function guardCjsModuleRead(ctx: ShimContext, resolvedPath: string): void {
  if (!moduleLoadNeedsDecision(resolvedPath, ctx.projectRoot)) return;
  // Node loading a process ROOT — the entry point, a preload. Nobody to charge, and the entry IS
  // the application. See {@link hostRootTargets} for why this is a host fact and `isMain` was not.
  if (isHostRootTarget(resolvedPath)) return;
  const attribution = attributeCallerDetailed(attributionOptionsFor(ctx));
  if (attribution.pkg === APP_ROOT) return; // the trust root, as everywhere else
  guardAttributed(ctx, attribution, moduleReadRequest(resolvedPath));
}

/**
 * The policy state ONE ESM resolution is decided against.
 *
 * NOT A MESSAGE ANY MORE, and the previous version of this comment said it was. Under
 * `module.register()` the hook ran on Node's separate loader thread holding its own COPY of the
 * policy, which the main thread posted over a `MessagePort` whenever the live context was
 * re-pointed — hence the "every field is structured-cloneable, so the snapshot crosses the thread
 * boundary" rule that used to be stated here. #152 deleted the thread, the port and the copy (see
 * `loader/esm-hooks.ts`'s header for the full list of what went with it). Nothing is serialized,
 * nothing crosses anything, and there is no longer any constraint on what a field may hold.
 *
 * WHY THE TYPE IS KEPT, since that reason is gone. It is what makes {@link decideEsmModuleRead} a
 * PURE FUNCTION of (policy state, resolution) instead of a reader of process state.
 * `loader/esm-hooks.ts` builds one from `liveCtx` per resolution (`currentSnapshot()`) and passes
 * it in; the alternative — importing `liveCtx` here and reading it inside the decision — would
 * make the gate's answer depend on a module-level singleton and untestable without a live
 * install. The allocation is at MODULE-LOAD frequency, not per capability call, so it sits on no
 * budget in AGENTS.md § 5.
 *
 * THE ONE RULE THAT STILL APPLIES: build a snapshot per resolution and never retain one across
 * resolutions. A retained snapshot is a copy again, and a copy that can go stale is exactly the
 * #62/#87 defect this shape used to have by construction.
 */
export interface EsmGateSnapshot {
  /** False while no install is active; the gate is then inert. See {@link decideEsmModuleRead}. */
  installed: boolean;
  policy: Policy;
  mode: Mode;
  projectRoot: string | undefined;
}

/** What the ESM hook must do about one resolution, or `null` when there is nothing to decide. */
export interface EsmGateOutcome {
  pkg: string;
  decision: Decision;
}

/**
 * ESM half: decide whether the module at `importerUrl` may load `resolvedUrl`.
 *
 * **THIS IS THE `import` PATH ONLY.** `loader/esm-hooks.ts` declines every `require`-conditioned
 * resolution before calling here, and that restriction is what makes the paragraph below true —
 * see #180 for what happened while it was not.
 *
 * WHY THE IMPORTER'S URL IS THE SUBJECT HERE, when the CJS half insists on a stack walk. On the
 * `import` path `context.parentURL` is set by the HOST from the module record that actually
 * contains the `import`, and no in-process code can choose it the way it can choose a
 * `createRequire` filename. The two spellings a dependency CAN reach — a `data:` URL module and a
 * synthetic/`vm` module — are not `file:` URLs, and this function charges those to `<unknown>`
 * rather than inferring the trust root from them, which is #60's rule applied on this path.
 *
 * THAT WAS NOT TRUE OF THE `require()` PATH `registerHooks` ADDED (#180), and the claim used to be
 * stated without the qualifier — here and in `docs/threat-model.md`. There `parentURL` is derived
 * from the `parent` module record handed to `Module._load`, i.e. from an ordinary argument: a
 * dependency naming `node_modules/impostor/index.js` — a directory that need not exist — wore
 * that principal, and naming the app's own file bought the `<app>` exemption outright. The fix is
 * not a better test on `parentURL`; it is that those loads are decided by
 * {@link guardCjsModuleRead}, whose subject is a stack walk, and are not decided here at all.
 *
 * UNTIL #152 THE STACK WALK WAS ALSO IMPOSSIBLE HERE: `module.register()` ran the hook on Node's
 * loader thread, which has no JavaScript stack belonging to the importing package, so there was
 * nothing to walk even in principle. `module.registerHooks()` runs it in this realm and a walk is
 * now possible. On the `import` path it is deliberately NOT taken: `parentURL` is the stronger
 * answer there — it is the host's own record of which module contains the `import`, where a stack
 * at ESM resolution time is Node's loader machinery with the importer somewhere below it — and
 * swapping a working, unspoofable subject for a stack walk would be re-litigating #60 on the one
 * path where the host hands us the answer.
 *
 * `installed: false` makes this inert, and that is deliberate rather than an oversight. It used
 * to be load-bearing — the hook could not be unregistered, so this code outlived `uninstall()`
 * and the fail-closed `TORN_DOWN_POLICY` a captured shim falls back to would have meant "capwall
 * was uninstalled, so the host process may no longer import its own files". Since #152 the last
 * `uninstall()` really does deregister the hooks, so this is now belt-and-braces for the window
 * between them. The answer is unchanged either way, and it is the CJS answer: teardown restores,
 * it does not deny.
 */
export function decideEsmModuleRead(
  snapshot: EsmGateSnapshot,
  importerUrl: string | undefined,
  resolvedUrl: string,
): EsmGateOutcome | null {
  if (!snapshot.installed) return null;
  // A `node:`/`data:`/`https:`/`capwall-esm:` target reads no file. (Network imports are a
  // separate, currently un-mediated surface — see docs/threat-model.md.)
  if (!resolvedUrl.startsWith("file:")) return null;
  let resolvedPath: string;
  try {
    resolvedPath = fileURLToPath(resolvedUrl.split("?")[0] ?? resolvedUrl);
  } catch {
    return null; // not a convertible file: URL — Node will fail on it too
  }
  if (!moduleLoadNeedsDecision(resolvedPath, snapshot.projectRoot)) return null;

  // NO IMPORTER AT ALL. On this path — `import` conditions, the caller having been declined
  // upstream — that is Node resolving a ROOT for itself: the process entry point, or a preload.
  // There is nobody to charge and the entry IS the application, so it is free; and because this
  // is the resolved, realpath'd filename Node is about to open, it is also the authoritative
  // record of which file that is, which the CJS half needs for the same reason. See
  // {@link hostRootTargets}.
  //
  // #177 IS WHAT THIS BRANCH USED TO BE. It ran for `require`-conditioned resolutions too, where
  // `parentURL` is `undefined` because the CALLER passed `Module._load` no `parent` — a choice,
  // not a statement by the host. Those never reach here now.
  if (importerUrl === undefined) {
    recordHostRootTarget(resolvedPath);
    return null;
  }
  let pkg: string;
  if (importerUrl.startsWith("file:")) {
    try {
      pkg = packageForPath(fileURLToPath(importerUrl.split("?")[0] ?? importerUrl), snapshot.projectRoot);
    } catch {
      pkg = UNATTRIBUTED;
    }
  } else {
    // A `data:` module, a `capwall-esm:` synthetic module, anything without a filesystem
    // identity. Never the trust root — that inference is exactly what #60 closed.
    pkg = UNATTRIBUTED;
  }
  if (pkg === APP_ROOT) return null;

  const decision = evaluate(snapshot.policy, snapshot.mode, pkg, moduleReadRequest(resolvedPath));
  return { pkg, decision };
}
