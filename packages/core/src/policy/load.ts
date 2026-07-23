/**
 * Load and validate a `capabilities.json` file into a typed `Policy`.
 *
 * Parsing/validation is real (delegated to the Zod schema). Path-glob normalization and
 * project-root resolution are still TODO — see the marker below.
 */
import { readFile } from "node:fs/promises";
import { parsePolicy, type Policy } from "@capwall/policy-schema";

/**
 * Read a policy file from disk and validate it against the schema.
 * Throws (ZodError or fs error) on invalid/missing input; callers surface the path.
 */
export async function loadPolicy(path: string): Promise<Policy> {
  const raw = await readFile(path, "utf8");
  const json: unknown = JSON.parse(raw);
  const policy = parsePolicy(json);

  // TODO(capwall): normalize fs path globs against the project root so a package's
  // "./logs/**" is matched consistently regardless of the process cwd at call time. For
  // now globs are stored as-authored. See docs/policy-format.md and docs/architecture.md.
  return policy;
}

/** Parse an already-in-memory value as a Policy (used by tests and the CLI's gen-policy). */
export function loadPolicyFromObject(value: unknown): Policy {
  return parsePolicy(value);
}
