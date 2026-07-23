/**
 * `capwall gen-policy [--from <trace>] [-o capabilities.json]` (roadmap M2).
 *
 * Intended behavior: turn a recorded observe trace into a `capabilities.json` (or merge into
 * an existing one), grouping observed capabilities per package. Merges rather than
 * overwrites so repeated runs accumulate coverage without clobbering hand edits.
 */
export function runGenPolicy(_args: string[]): number {
  process.stdout.write(
    [
      "capwall gen-policy — not yet implemented (scaffold).",
      "",
      "Intended: synthesize/merge capabilities.json from an observe trace, one grant",
      "block per package, using @capwall/policy-schema for the output shape.",
      "See docs/roadmap.md M2 and docs/policy-format.md.",
      "",
    ].join("\n"),
  );
  // TODO(capwall): read trace, aggregate per-package capabilities, emit via policy-schema.
  return 0;
}
