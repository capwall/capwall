/**
 * `capwall enforce -- <cmd...>` (roadmap M3).
 *
 * Intended behavior: launch <cmd> with @capwall/core installed in `enforce` mode, loading
 * `capabilities.json`. Any capability a package uses that is not in its grant is denied
 * (deny-by-default) and throws a CapabilityError.
 */
export function runEnforce(_args: string[], target: string[]): number {
  const cmd = target.length ? target.join(" ") : "<command>";
  process.stdout.write(
    [
      "capwall enforce — not yet implemented (scaffold).",
      "",
      `Intended: run \`${cmd}\` with @capwall/core installed in ENFORCE mode,`,
      "loading ./capabilities.json and denying (throwing on) any capability not granted",
      "to the owning package. See docs/roadmap.md M3.",
      "",
    ].join("\n"),
  );
  // TODO(capwall): load policy, spawn target with a core-install preload in enforce mode,
  // surface CapabilityError violations with the attributed package + capability.
  return 0;
}
