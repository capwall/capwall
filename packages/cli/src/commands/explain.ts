/**
 * `capwall explain <package> <capability> [target]` (roadmap M3+).
 *
 * Intended behavior: load the current policy and report whether a given package would be
 * allowed the given capability against an optional target (path/host), plus the reason —
 * reusing @capwall/core's `evaluate`/`isGranted` so the answer matches enforcement exactly.
 */
export function runExplain(args: string[]): number {
  const [pkg, capability, targetValue] = args;
  if (!pkg || !capability) {
    process.stderr.write(
      "usage: capwall explain <package> <capability> [target]\n" +
        "  e.g. capwall explain pino fs:write ./logs/app.log\n",
    );
    return 2;
  }
  process.stdout.write(
    [
      "capwall explain — not yet implemented (scaffold).",
      "",
      `Intended: load ./capabilities.json and report whether '${pkg}' is granted`,
      `'${capability}'${targetValue ? ` for '${targetValue}'` : ""}, and why, using the`,
      "same evaluate()/isGranted() the enforcer uses. See docs/roadmap.md.",
      "",
    ].join("\n"),
  );
  // TODO(capwall): load policy, parse capability token (e.g. "fs:write"), build a
  // CapabilityRequest, call evaluate() and print the Decision.reason.
  return 0;
}
