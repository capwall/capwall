/**
 * CapabilityError — thrown (enforce mode only) when a package attempts a capability it is
 * not granted. Lives in its own module so shims/loaders can import it without pulling in
 * the public entry point (which imports the loaders — a cycle otherwise).
 *
 * NOTE for catchers: the error may cross a CJS/ESM realm boundary (app code is CJS, capwall
 * is ESM), so match on `err.name === "CapabilityError"` rather than `instanceof`.
 */
export class CapabilityError extends Error {
  /** Always the literal `"CapabilityError"` — the discriminator catchers should test. */
  override readonly name = "CapabilityError";
  /**
   * @param message the denial reason, as `evaluate()` phrased it.
   * @param pkg the principal the call was attributed to — a package name, an install chain
   *     (`webpack>lodash`), or one of the `<app>` / `<unknown>` sentinels.
   */
  constructor(
    message: string,
    /** The principal denied the capability. Exposed so a catcher can report who was blocked. */
    readonly pkg: string,
  ) {
    super(message);
  }
}
