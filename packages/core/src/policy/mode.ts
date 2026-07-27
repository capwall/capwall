/**
 * Resolve which enforcement mode capwall runs under, from the two channels that can supply
 * one. This is the single place that answers "observe, enforce, or stay out of the way?" —
 * `preload.ts` is its only production caller, and `capwall run` exists because of rule 2.
 *
 * Precedence, highest first. It mirrors how every other capwall option already resolves: the
 * environment is the transport the CLI writes its choice into (see `packages/cli/src/run.ts`),
 * so "the CLI flag" and "the env var" are the same channel, not two.
 *
 *  1. **`CAPWALL_MODE`** — set explicitly by the operator, or by the `capwall observe` /
 *     `capwall enforce` / `capwall diff` subcommands. An explicit choice always wins.
 *  2. **the policy document's own `mode`** — used when nothing set `CAPWALL_MODE`, i.e. under
 *     `capwall run` or a bare `NODE_OPTIONS=--import @capwall/core/preload`. This is why
 *     `mode` is optional in the schema rather than defaulted: a policy that declares nothing
 *     must not be able to switch capwall on.
 *  3. **neither** → INERT. A stray `NODE_OPTIONS` left in a shell must never silently start
 *     mediating unrelated processes.
 *
 * An unrecognized `CAPWALL_MODE` is inert rather than falling through to rule 2: the caller
 * asked for something specific and misspelled it, and silently enforcing — or silently NOT
 * enforcing — on a typo is worse than doing nothing visible.
 */
import type { Mode } from "@capwall/policy-schema";

/** Which channel supplied the mode. Useful for diagnostics; not a policy input. */
export type ModeSource = "env" | "policy";

export interface ResolvedMode {
  mode: Mode;
  /** `"env"` = `CAPWALL_MODE`; `"policy"` = the policy document's `mode` field. */
  source: ModeSource;
}

/**
 * @param envMode raw `process.env.CAPWALL_MODE` (unset, empty, or anything at all).
 * @param policyMode the `mode` a loaded policy document declares, if it declares one.
 * @returns the resolved mode and where it came from, or `undefined` to stay inert.
 */
export function resolveMode(
  envMode: string | undefined,
  policyMode: Mode | undefined,
): ResolvedMode | undefined {
  if (envMode !== undefined && envMode !== "") {
    // Explicit wins — including explicitly wrong, which resolves to nothing (see above).
    if (envMode === "observe" || envMode === "enforce") return { mode: envMode, source: "env" };
    return undefined;
  }
  if (policyMode !== undefined) return { mode: policyMode, source: "policy" };
  return undefined;
}
