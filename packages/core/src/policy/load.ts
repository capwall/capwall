/**
 * Load and validate a `capabilities.json` file into a typed `Policy`.
 *
 * Parsing/validation is delegated to the Zod schema. When a `projectRoot` is supplied,
 * relative fs path globs (`./logs/**`, `logs/**`) are normalized to absolute globs against
 * it, so matching is consistent regardless of the process cwd at call time. Bare `*` and
 * already-absolute globs are stored as-is.
 *
 * Windows drive-absolute globs (`C:/…`, `C:\…`) are always treated as already-absolute and
 * reshaped to the `C:/…` form the matcher expects (glob.ts), matching what the fs shim's
 * `coercePath` (shims/fs.ts) produces for a real Windows call-time path. On an actual Windows
 * host `path.isAbsolute`/`path.sep` already recognize and reshape these correctly, so this
 * only changes behavior when `loadPolicy`/`loadPolicyFromObject` runs on a non-Windows host
 * (e.g. linting/validating a Windows-targeted policy from Linux CI): without it, a POSIX
 * `path.isAbsolute` doesn't recognize a drive letter as absolute and would wrongly resolve the
 * glob AS IF relative, against `projectRoot` — producing garbage like `/proj/C:/logs/**`.
 */
// capwall's own fs, captured through `../real-builtins.cjs` rather than a static
// `import … from "node:fs/promises"` — that import would cache the mediated specifier in the ESM
// module cache before the loader hook registers, which is what left the hook's re-mediation
// backstop dead (#78). `node:path` is not mediated and stays an ordinary import.
import { realFsPromises } from "../real-builtins.cjs";
import * as path from "node:path";
import {
  parsePolicy,
  type FsCapability,
  type IpcCapability,
  type PackagePolicy,
  type Policy,
} from "@capwall/policy-schema";
import { canonicalIpcPattern, expandIpcPlaceholders, isCanonicalNamedPipe } from "./ipc.js";

export interface LoadPolicyOptions {
  /** Absolute project root to resolve relative fs globs against. */
  projectRoot?: string;
}

/** A Windows absolute path: a drive letter followed by `\` or `/` (e.g. `C:\foo`, `C:/foo`). */
const WINDOWS_ABSOLUTE = /^[A-Za-z]:[\\/]/;

function normalizeGlob(glob: string, projectRoot: string): string {
  if (glob === "*" || glob === "**") return glob;
  if (WINDOWS_ABSOLUTE.test(glob) && !path.isAbsolute(glob)) {
    // Host `path` module doesn't recognize this as absolute (i.e. we're on a POSIX host and
    // the glob is Windows-shaped) — see the file-level doc comment. Reshape directly instead
    // of routing through the (POSIX) `path.resolve`, which doesn't understand drive letters.
    return glob.replace(/\\/g, "/");
  }
  const resolved = path.isAbsolute(glob) ? glob : path.resolve(projectRoot, glob);
  // The matcher works on `/`-separated paths.
  return resolved.split(path.sep).join("/");
}

function normalizeFs(fs: FsCapability | undefined, projectRoot: string): void {
  if (!fs) return;
  fs.read = fs.read.map((g) => normalizeGlob(g, projectRoot));
  fs.write = fs.write.map((g) => normalizeGlob(g, projectRoot));
}

/**
 * `ipc.paths` globs (#72) get the same treatment as `fs` globs — relative patterns resolved
 * against the project root, `/`-separated — after two IPC-specific steps:
 *  1. `<tmp>`/`<home>` are expanded against THIS machine, which is what makes an
 *     observe-generated grant for a socket in a temp dir portable (see policy/ipc.ts).
 *  2. Windows named pipes are canonicalized and then left alone: `\\.\pipe\x` is not relative,
 *     but `path.isAbsolute` on a POSIX host does not know that and would resolve it against the
 *     project root into nonsense — the same trap the drive-letter case in `normalizeGlob` fixes.
 */
function normalizeIpc(ipc: IpcCapability | undefined, projectRoot: string): void {
  if (!ipc) return;
  ipc.paths = ipc.paths.map((raw) => {
    const pattern = canonicalIpcPattern(expandIpcPlaceholders(raw));
    if (isCanonicalNamedPipe(pattern)) return pattern;
    return normalizeGlob(pattern, projectRoot);
  });
}

function normalizeGrant(grant: PackagePolicy, projectRoot: string): void {
  normalizeFs(grant.fs, projectRoot);
  normalizeIpc(grant.ipc, projectRoot);
}

function normalizePolicy(policy: Policy, projectRoot: string | undefined): Policy {
  if (!projectRoot) return policy;
  normalizeGrant(policy.default, projectRoot);
  for (const pkg of Object.values(policy.packages)) normalizeGrant(pkg, projectRoot);
  return policy;
}

/**
 * Read a policy file from disk and validate it against the schema.
 * Throws (ZodError or fs error) on invalid/missing input; callers surface the path.
 */
export async function loadPolicy(
  filePath: string,
  options: LoadPolicyOptions = {},
): Promise<Policy> {
  const raw = await realFsPromises.readFile(filePath, "utf8");
  const json: unknown = JSON.parse(raw);
  return normalizePolicy(parsePolicy(json), options.projectRoot);
}

/** Parse an already-in-memory value as a Policy (used by tests, the CLI, and the preload). */
export function loadPolicyFromObject(
  value: unknown,
  options: LoadPolicyOptions = {},
): Policy {
  return normalizePolicy(parsePolicy(value), options.projectRoot);
}
