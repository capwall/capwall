/**
 * Load and validate a `capabilities.json` file into a typed `Policy`.
 *
 * Parsing/validation is delegated to the Zod schema. When a `projectRoot` is supplied,
 * relative fs path globs (`./logs/**`, `logs/**`) are normalized to absolute globs against
 * it, so matching is consistent regardless of the process cwd at call time. Bare `*` and
 * already-absolute globs are stored as-is.
 */
import { readFile } from "node:fs/promises";
import * as path from "node:path";
import { parsePolicy, type FsCapability, type Policy } from "@capwall/policy-schema";

export interface LoadPolicyOptions {
  /** Absolute project root to resolve relative fs globs against. */
  projectRoot?: string;
}

function normalizeGlob(glob: string, projectRoot: string): string {
  if (glob === "*" || glob === "**") return glob;
  const resolved = path.isAbsolute(glob) ? glob : path.resolve(projectRoot, glob);
  // The matcher works on `/`-separated paths.
  return resolved.split(path.sep).join("/");
}

function normalizeFs(fs: FsCapability | undefined, projectRoot: string): void {
  if (!fs) return;
  fs.read = fs.read.map((g) => normalizeGlob(g, projectRoot));
  fs.write = fs.write.map((g) => normalizeGlob(g, projectRoot));
}

function normalizePolicy(policy: Policy, projectRoot: string | undefined): Policy {
  if (!projectRoot) return policy;
  normalizeFs(policy.default.fs, projectRoot);
  for (const pkg of Object.values(policy.packages)) normalizeFs(pkg.fs, projectRoot);
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
  const raw = await readFile(filePath, "utf8");
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
