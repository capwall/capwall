/**
 * `capwall observe -- <cmd...>` — the HEADLINE feature (roadmap M2).
 *
 * Intended behavior: launch <cmd> (typically the app entrypoint or the test suite) with
 * @capwall/core installed in `observe` mode via a preload, collect every attributed
 * capability decision, and on exit synthesize/merge a starter `capabilities.json` scoped to
 * what each package actually did. Nothing is ever blocked in observe mode — this is the
 * zero-friction on-ramp.
 */
export function runObserve(_args: string[], target: string[]): number {
  const cmd = target.length ? target.join(" ") : "<command>";
  process.stdout.write(
    [
      "capwall observe — not yet implemented (scaffold).",
      "",
      `Intended: run \`${cmd}\` with @capwall/core installed in OBSERVE mode,`,
      "record every capability each package uses (nothing blocked), then emit/merge",
      "a starter capabilities.json. See docs/roadmap.md M2.",
      "",
    ].join("\n"),
  );
  // TODO(capwall): spawn target with NODE_OPTIONS preloading a core-install shim in observe
  // mode; collect decisions via the DecisionSink; write/merge capabilities.json on exit.
  return 0;
}
