/**
 * OPTION-OBJECT PINNING — the shared, fail-closed rule that a caller-supplied options object is
 * never forwarded to a Node builtin verbatim.
 *
 * Extracted from `shims/net.ts` (where issues #26/#56 established it) so `shims/child_process.ts`
 * can apply the identical rule for #89 instead of growing a second, divergent implementation. A
 * divergent copy is how this class of bug propagates: `net` learned to flatten accessors, and
 * `child_process` — the one other shim that forwarded a caller object into a privileged window —
 * did not, which is exactly what #89 exploited.
 *
 * THE RULE. A shim reads each capability-relevant field off the caller's object EXACTLY ONCE, and
 * forwards a CLONE in which every own accessor has been flattened to a data property. The object
 * Node receives therefore contains no getters at all, so:
 *
 *  - Node's later internal re-reads cannot observe a value different from the one capwall guarded
 *    (the TOCTOU half — #26/#56: `net.connect`'s `path` accessor returned `undefined` on capwall's
 *    read and `/var/run/docker.sock` on Node's); and
 *  - no caller-controlled code runs during the real call (the re-entrancy half — #89: a getter on
 *    `spawnSync` options ran while the `child_process` shim had the env gate switched off
 *    process-wide, and read every value in `process.env` unrecorded).
 *
 * Both consequences follow from the SAME property — the forwarded object is inert — which is why
 * there is one helper rather than one per failure mode.
 */

/** Nothing skipped — a lossless descriptor copy (still accessor-flattening). */
export const NO_SKIPPED_KEYS: readonly string[] = [];

/**
 * Copy every OWN property of `src` onto `dst` except the keys in `skip` (which the caller pins
 * itself, from its own single read). `Reflect.ownKeys` + `defineProperty` so non-enumerable and
 * symbol-keyed fields survive — a plain enumerable-only, by-value copy silently drops those.
 *
 * SECURITY: every copied property lands on `dst` as a DATA property. An own ACCESSOR is invoked
 * EXACTLY ONCE, here, and its result frozen into a value; its descriptor is never copied. That
 * is the fail-closed half of the pinning invariant (module header): the object handed to Node
 * contains no getters at all, so Node cannot observe a value different from the one this pass
 * saw — even on a key capwall does not (yet) treat as capability-relevant. The previous version
 * copied descriptors verbatim, which is how a `path` accessor (#56) rode through live.
 *
 * A getter that THROWS propagates rather than being swallowed: capwall will not forward an
 * options object it could not pin, and Node would have thrown on the same read anyway.
 *
 * WHERE THE ACCESSOR RUNS IS THE POINT (#89). The single invocation happens HERE, on capwall's
 * own stack, BEFORE the shim enters whatever privileged state the real call needs. A getter that
 * reads `process.env` from inside this call is gated and recorded exactly like any other
 * dependency read, because no gate has been relaxed yet.
 */
export function copyOwnFieldsExcept(
  dst: Record<string, unknown>,
  src: object,
  skip: readonly string[],
): void {
  for (const key of Reflect.ownKeys(src)) {
    if (typeof key === "string" && skip.includes(key)) continue;
    const desc = Object.getOwnPropertyDescriptor(src, key);
    if (!desc) continue;
    if (desc.get !== undefined || desc.set !== undefined) {
      const value = desc.get !== undefined ? desc.get.call(src) : undefined; // the ONLY invocation
      Object.defineProperty(dst, key, {
        value,
        writable: true,
        enumerable: desc.enumerable === true,
        configurable: true,
      });
    } else {
      Object.defineProperty(dst, key, desc);
    }
  }
}

/**
 * Pin a whole options bag: a fresh object with every own field of `src` copied and every own
 * accessor flattened. Used where the shim has no per-field target keys to pin separately and
 * simply needs an inert clone (`child_process`, where any field can carry a getter and none of
 * them redirect a "destination" the way `net`'s `host`/`port` do).
 */
export function pinAllOwnFields(src: object): Record<string, unknown> {
  const pinned: Record<string, unknown> = {};
  copyOwnFieldsExcept(pinned, src, NO_SKIPPED_KEYS);
  return pinned;
}
