/**
 * LINKED PACKAGES — recovering the install position of a dependency Node resolved through a
 * symlink (issue #127).
 *
 * ── THE PROBLEM ─────────────────────────────────────────────────────────────────────────────
 * capwall names a principal from a frame's file path: the `node_modules/<name>` segments in it,
 * in order, are the install chain (#92). Node resolves module paths through `realpath` by
 * default, so a dependency installed as a SYMLINK into `node_modules` reports a path with no
 * `node_modules` segment at all — and a path with none of them was {@link APP_ROOT}, the trust
 * root, which three gates exempt *before* the decision is recorded (`process.env` reads, `dgram`
 * sends, `module.register`/`registerHooks`) and a fourth (`Module.prototype._compile`) treats as
 * identity-granting. So a symlinked dependency read every environment variable, minted arbitrary
 * principals through `_compile`, and installed a loader hook ahead of capwall's, under a deny-all
 * `enforce` policy, with no `[capwall]` line for any of it.
 *
 * What makes that severe is that it needs no attacker action and no grant. It is the DEFAULT
 * on-disk shape of `npm i file:../x`, of `npm link`, and of every workspace tool — measured, not
 * assumed (see `test/linked-packages.test.ts`, which builds the layouts with the real package
 * managers):
 *
 *   npm i file:../x   proj/node_modules/x            -> ../../x
 *   npm link          proj/node_modules/x            -> <global>/lib/node_modules/x -> ~/x
 *   npm workspaces    repo/node_modules/@w/lib       -> ../../packages/lib
 *   pnpm workspaces   repo/packages/app/node_modules/@w/lib -> ../../../lib
 *
 * Note the last one: pnpm puts the link in the IMPORTING package's `node_modules`, not the
 * repo root's. There is therefore no directory capwall could scan at startup that is guaranteed
 * to contain the link, which is why the primary mechanism below observes resolution rather than
 * searching the tree.
 *
 * ── THE IDENTITY WE GIVE THEM, AND WHY ──────────────────────────────────────────────────────
 * A workspace member is first-party code, so "treat every linked package as untrusted" would make
 * capwall unusable in exactly the repositories most likely to adopt it. But it is also not the
 * application: it is a separate package, with its own `package.json`, reached through a
 * `node_modules` entry, and a policy author needs to be able to name it.
 *
 * So the identity is **the link source** — the `node_modules/<name>` entry that pointed here —
 * run through the ordinary install-chain derivation. `proj/node_modules/linked -> vendor/linked`
 * makes every file under `vendor/linked` answer to the principal `linked`: exactly the key an
 * operator would write, exactly what `capwall observe` / `gen-policy` now emit, and a principal
 * DISTINCT from `<app>` so none of the trust-root exemptions apply. The realpath is not the
 * identity; the position it was reached from is. That is the same rule #92 established, applied
 * to the one case where the position is not visible in the path V8 reports.
 *
 * Rewriting is ITERATIVE, so it composes with the chain: if `lib` is itself reached through
 * `app/node_modules/lib` and `lib` resolves `util` through `lib/node_modules/util`, then `util`'s
 * files rewrite to `…/lib/node_modules/util/…` and then to `…/app/node_modules/lib/node_modules/
 * util/…`, giving the principal `lib>util` rather than a bare `util` that would collect the
 * top-level install's grants.
 *
 * ── NOTHING SELF-REPORTED IS AN IDENTITY (#84), STILL ────────────────────────────────────────
 * {@link discoverPackageLink} reads a `name` out of a `package.json`, which is a string the code
 * being attributed controls. It is used ONLY as a lookup key, and the answer is accepted only if
 * `realpath(<dir>/node_modules/<name>)` really is the package directory in question. A package
 * that claims `"name": "lodash"` therefore gains nothing: either there is no
 * `node_modules/lodash` pointing at it (the probe fails and the file stays {@link UNATTRIBUTED}),
 * or there is — in which case it genuinely IS what `require("lodash")` resolves to in that tree,
 * and calling it `lodash` is the true statement. The disk is consulted; the claim is not believed.
 *
 * ── COST ────────────────────────────────────────────────────────────────────────────────────
 * Recording: one `lstat` (plus one `realpath` for an entry that IS a link) per distinct
 * `<node_modules dir, package name>` pair actually resolved, memoized in {@link probed}, on the
 * module-resolution path — startup work, not per-request. Lookup: a prefix scan of a map that
 * holds one entry per linked package (zero in an ordinary `npm ci` tree), behind attribution's
 * per-path memo. Discovery runs only for a file that would otherwise be `<unknown>`.
 *
 * ── LIFETIME ────────────────────────────────────────────────────────────────────────────────
 * The maps live for the PROCESS, not for an install. They describe the filesystem, not a policy,
 * and a module resolved under one install must keep the same identity under the next — a
 * principal that changed across an `uninstall()`/`install()` pair would be the #62/#87 defect
 * wearing a different hat. There is deliberately no reset.
 */
import { realFs } from "../real-builtins.cjs"; // never `import … from "node:fs"` — see #78

/**
 * Normalize a path for segment scanning: back-slashes become forward slashes.
 *
 * Lives here rather than in `index.ts` because both modules need it and the dependency runs this
 * way (attribution imports the link map, never the reverse). Applied UNCONDITIONALLY, not only
 * when `path.sep` is `\`: on POSIX a path such as `/proj/node_modules\lodash/x.js` contains no
 * `/node_modules/` segment, so the old scan called it application code — a separator confusion
 * resolving to the TRUST ROOT, the wrong direction to be wrong in. A real POSIX file whose name
 * genuinely contains a backslash now attributes to a dependency instead of to `<app>`; that is
 * both vanishingly rare and the conservative side of the trade.
 */
export function normalizeSeparators(p: string): string {
  return p.includes("\\") ? p.split("\\").join("/") : p;
}

/** Is `p` the directory `dir`, or something inside it? Normalized, forward-slash paths only. */
export function isUnder(p: string, dir: string): boolean {
  return p === dir || p.startsWith(dir + "/");
}

/** Strip trailing slashes so a directory has exactly one spelling. `/` itself is preserved. */
function trimTrailingSlash(dir: string): string {
  let out = dir;
  while (out.endsWith("/") && out.length > 1) out = out.slice(0, -1);
  return out;
}

/**
 * realpath'd package directory → the `node_modules/<name>` path that links to it.
 *
 * Both sides are normalized, trailing-slash-free, forward-slash paths.
 */
const linkedDirs = new Map<string, string>();

/**
 * Bumped on every change to {@link linkedDirs}.
 *
 * Attribution memoizes path → principal, and a path's answer changes the moment a link covering
 * it is recorded. In practice a link is always recorded BEFORE the linked module's code can run
 * (recording happens during its resolution), so a stale entry would need a frame from a file
 * capwall attributed before the package was ever resolved — but "in practice" is not a safety
 * argument, and clearing a memo on an event that happens a handful of times per process costs
 * nothing. See `packageForPath`.
 */
let generation = 0;

/** The current link-map generation; see {@link generation}. */
export function linkGeneration(): number {
  return generation;
}

/** How many `/node_modules/` segments a logical path carries — the tie-break key below. */
function chainDepth(p: string): number {
  return p.split("/node_modules/").length;
}

/**
 * Record that `realDir` is reachable as the `node_modules` entry `logicalDir`.
 *
 * ONE LOGICAL POSITION PER REAL DIRECTORY, CHOSEN DETERMINISTICALLY. A symlinked package can be
 * reachable through several entries at once — a monorepo where both `app` and `lib` depend on
 * `util` links `util` from two places — and V8 reports only the realpath, so capwall has to pick
 * one. Picking "whichever was resolved first" would make the principal depend on module load
 * order, i.e. on which import a refactor happens to move: a security answer that changes between
 * runs of the same program. So the shallowest chain wins, ties broken lexicographically, which
 * makes the final state a function of the SET of links observed rather than of their order.
 */
export function recordPackageLink(realDirRaw: string, logicalDirRaw: string): void {
  const realDir = trimTrailingSlash(normalizeSeparators(realDirRaw));
  const logicalDir = trimTrailingSlash(normalizeSeparators(logicalDirRaw));
  // A link that resolves to itself carries no information and would make the rewrite loop.
  if (realDir === "" || logicalDir === "" || realDir === logicalDir) return;
  const existing = linkedDirs.get(realDir);
  if (existing !== undefined) {
    const better =
      chainDepth(logicalDir) < chainDepth(existing) ||
      (chainDepth(logicalDir) === chainDepth(existing) && logicalDir < existing);
    if (!better) return;
  }
  linkedDirs.set(realDir, logicalDir);
  generation++;
}

/**
 * Hops the rewrite will follow before giving up.
 *
 * A bound rather than a visited-set because the map can genuinely contain a CYCLE — `a -> b` and
 * `b -> a` are two ordinary links a person can create with two `ln -s` commands — and an
 * unbounded walk over one would hang the process inside attribution, i.e. inside every mediated
 * call. Eight is far past any real nesting (each hop is a workspace package linking another) and
 * bailing out leaves the path partially rewritten, which the caller treats as "no `node_modules`
 * segment found" and therefore fails closed.
 */
const MAX_LINK_HOPS = 8;

/**
 * Rewrite a realpath'd file path back to the position it was REACHED from, following links
 * transitively. Returns the input unchanged when no link covers it.
 */
export function rewriteThroughLinks(normalizedPath: string): string {
  if (linkedDirs.size === 0) return normalizedPath;
  let current = normalizedPath;
  for (let hop = 0; hop < MAX_LINK_HOPS; hop++) {
    // LONGEST matching prefix: a link target nested inside another link target must win, or the
    // outer rewrite would produce a path the inner link no longer describes.
    let bestKey: string | null = null;
    for (const key of linkedDirs.keys()) {
      if (!isUnder(current, key)) continue;
      if (bestKey === null || key.length > bestKey.length) bestKey = key;
    }
    if (bestKey === null) return current;
    current = (linkedDirs.get(bestKey) as string) + current.slice(bestKey.length);
  }
  return current;
}

/* ============================================================================================
 * RECORDING — observed at resolution time (the exact route).
 * ========================================================================================== */

/** `<node_modules dir>/<package name>` pairs already probed, so a hot require path re-stats
 *  nothing. Bounded by the number of distinct packages the process actually resolves. */
const probed = new Set<string>();

/**
 * The package name a bare specifier names: `lodash`, `lodash/fp` → `lodash`;
 * `@scope/pkg/sub` → `@scope/pkg`. `null` for anything that is not a bare specifier — a relative
 * or absolute path, a URL, a `node:` builtin, a Windows drive path — because only a bare
 * specifier is resolved through `node_modules` and only those can be linked.
 */
function bareSpecifierPackage(specifier: string): string | null {
  if (specifier === "" || specifier.startsWith(".") || specifier.startsWith("/")) return null;
  if (specifier.startsWith("#") || specifier.includes(":")) return null; // imports map, node:, file:, C:
  const parts = specifier.split("/");
  const first = parts[0];
  if (first === undefined || first === "") return null;
  if (!first.startsWith("@")) return first;
  const second = parts[1];
  return second === undefined || second === "" ? null : `${first}/${second}`;
}

/** `lstat`/`realpath` without letting anything escape into Node's module resolution. */
function isSymlink(p: string): boolean {
  try {
    return realFs.lstatSync(p).isSymbolicLink();
  } catch {
    return false;
  }
}
function realpathOrNull(p: string): string | null {
  try {
    return normalizeSeparators(realFs.realpathSync(p));
  } catch {
    return null;
  }
}

/**
 * Record the link, if any, that a completed CJS resolution went through.
 *
 * Called from the `Module._findPath` patch with the arguments Node itself used, so this observes
 * the ACTUAL entry that resolved the specifier — no guessing about where a package manager might
 * have put the link, which is what makes it correct for pnpm's per-package layout as well as for
 * npm's hoisted one.
 *
 * Everything is best-effort and total: this runs inside module resolution, so a failure here must
 * degrade attribution, never break a `require`.
 */
export function recordResolvedLink(specifier: unknown, searchPaths: unknown, resolved: unknown): void {
  if (typeof specifier !== "string" || typeof resolved !== "string") return;
  if (!Array.isArray(searchPaths)) return;
  const pkgName = bareSpecifierPackage(specifier);
  if (pkgName === null) return;
  const resolvedNorm = normalizeSeparators(resolved);
  for (const dir of searchPaths as unknown[]) {
    if (typeof dir !== "string" || dir === "") continue;
    const candidate = trimTrailingSlash(normalizeSeparators(dir)) + "/" + pkgName;
    if (probed.has(candidate)) continue;
    probed.add(candidate);
    if (!isSymlink(candidate)) {
      // Not a link. If the entry exists at all, resolution stopped here and there is nothing to
      // map; if it does not, keep walking outward exactly as Node did.
      if (realpathOrNull(candidate) !== null) return;
      continue;
    }
    const real = realpathOrNull(candidate);
    // Confirm the link really is the one that produced this resolution before believing it — a
    // shadowed entry in a nearer `node_modules` must not claim a file it did not resolve.
    if (real !== null && isUnder(resolvedNorm, real)) recordPackageLink(real, candidate);
    return;
  }
}

/* ============================================================================================
 * DISCOVERY — the fallback, for a resolution capwall never observed.
 * ========================================================================================== */

/** Directory → its nearest ancestor package root (a directory holding a `package.json`), or
 *  `null`. Memoized because the walk is otherwise repeated per source file. */
const packageRootOf = new Map<string, string | null>();
/** Package roots already put through {@link discoverPackageLink}, successfully or not. */
const discovered = new Set<string>();

/** Bound on the upward walk, so a pathological path cannot turn attribution into a syscall storm. */
const MAX_ANCESTOR_WALK = 64;

/** Every ancestor of `dir`, nearest first, including `dir`. Normalized paths. */
function ancestors(dir: string): string[] {
  const out: string[] = [];
  let current = trimTrailingSlash(dir);
  for (let i = 0; i < MAX_ANCESTOR_WALK; i++) {
    out.push(current);
    const slash = current.lastIndexOf("/");
    if (slash <= 0) break;
    current = current.slice(0, slash);
  }
  return out;
}

/** The nearest ancestor of `filePath` that holds a `package.json`, or `null`. */
function nearestPackageRoot(filePath: string): string | null {
  const slash = filePath.lastIndexOf("/");
  if (slash <= 0) return null;
  const startDir = filePath.slice(0, slash);
  const chain: string[] = [];
  for (const dir of ancestors(startDir)) {
    const cached = packageRootOf.get(dir);
    if (cached !== undefined) {
      for (const seen of chain) packageRootOf.set(seen, cached);
      return cached;
    }
    chain.push(dir);
    let found = false;
    try {
      found = realFs.existsSync(dir + "/package.json");
    } catch {
      found = false;
    }
    if (found) {
      for (const seen of chain) packageRootOf.set(seen, dir);
      return dir;
    }
  }
  for (const seen of chain) packageRootOf.set(seen, null);
  return null;
}

/** The `name` a package root declares, or `null`. A HINT for where to look — never an identity;
 *  see the header. */
function declaredName(pkgRoot: string): string | null {
  try {
    const raw: unknown = JSON.parse(realFs.readFileSync(pkgRoot + "/package.json", "utf8"));
    if (typeof raw !== "object" || raw === null) return null;
    const name: unknown = (raw as Record<string, unknown>)["name"];
    return typeof name === "string" && name !== "" ? name : null;
  } catch {
    return null;
  }
}

/**
 * Best-effort: find and record the `node_modules` entry that links to the package containing
 * `filePath`. Returns `true` when something was recorded.
 *
 * WHEN THIS RUNS, and why the placement is the safety argument. Attribution calls it for exactly
 * one case: a file with no `node_modules` segment that is OUTSIDE the project root — a file whose
 * principal would otherwise be {@link UNATTRIBUTED}. So the worst outcome is that it fails and the
 * file stays deny-by-default, and the best outcome is that a fail-closed `<unknown>` becomes a
 * nameable package. It can never take `<app>` away from something that would have had it, which
 * is what keeps the trust-root sentinel a POSITIVE identification (#60) rather than a guess.
 *
 * It exists because {@link recordResolvedLink} only sees CJS resolution: `module.register()` hooks
 * run on Node's separate loader thread, so capwall's ESM `resolve` hook cannot write to this map.
 * An ESM `import "@w/lib"` of a linked package is therefore recovered here rather than observed —
 * which works whenever the link sits in a `node_modules` directory above the package itself or
 * above the project root (npm/yarn workspaces, `npm link`, `npm i file:`, and pnpm workspaces when
 * the project root is the consuming package). The residual is documented in
 * `docs/threat-model.md` § Package identity.
 */
export function discoverPackageLink(filePath: string, projectRoot: string): boolean {
  const pkgRoot = nearestPackageRoot(filePath);
  if (pkgRoot === null) return false;
  // The project's OWN package is the application, not a dependency of itself.
  if (pkgRoot === trimTrailingSlash(projectRoot)) return false;
  if (discovered.has(pkgRoot)) return false;
  discovered.add(pkgRoot);
  const name = declaredName(pkgRoot);
  if (name === null) return false;

  // Where a `node_modules/<name>` entry pointing at this package could live: above the package
  // itself (a hoisted install), or above the consumer we know about — the project root.
  const seen = new Set<string>();
  for (const dir of [...ancestors(pkgRoot), ...ancestors(trimTrailingSlash(projectRoot))]) {
    const candidate = dir + "/node_modules/" + name;
    if (seen.has(candidate)) continue;
    seen.add(candidate);
    // VERIFIED, not believed: the entry must actually resolve to this package directory.
    if (realpathOrNull(candidate) !== pkgRoot) continue;
    recordPackageLink(pkgRoot, candidate);
    return true;
  }
  return false;
}
