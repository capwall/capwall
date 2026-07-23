/**
 * CapabilityError — thrown (enforce mode only) when a package attempts a capability it is
 * not granted. Lives in its own module so shims/loaders can import it without pulling in
 * the public entry point (which imports the loaders — a cycle otherwise).
 *
 * NOTE for catchers: the error may cross a CJS/ESM realm boundary (app code is CJS, capwall
 * is ESM), so match on `err.name === "CapabilityError"` rather than `instanceof`.
 */
export class CapabilityError extends Error {
  override readonly name = "CapabilityError";
  constructor(
    message: string,
    readonly pkg: string,
  ) {
    super(message);
  }
}
