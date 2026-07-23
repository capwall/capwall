/**
 * Regression for fix #22: `patchRequire().uninstall()` used to only restore `Module._load`
 * when it was still EXACTLY the patched fn it installed. Two nested installs uninstalled
 * out of LIFO order (outer torn down before inner) would leak the outer layer forever —
 * the inner patch's captured `originalLoad` still pointed past the outer patch, so
 * uninstalling the outer patch (a no-op, since `_load` was no longer its own fn) left no
 * way back to the real, un-shimmed loader once the inner patch was later removed too.
 *
 * The fix threads a mutable per-install chain node (`{ load, next }`) instead of a
 * closed-over constant, so uninstalling ANY node relinks the node above it (if any)
 * straight to what the removed node was delegating to — safe regardless of removal order.
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { patchRequire } from "../src/loader/require.js";
import { loadPolicyFromObject, type Policy } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");

interface FixtureDep {
  readData(): string;
}

/** Require the fixture fresh (cache cleared) so its top-level require("fs") re-runs. */
function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

const denyAll = (): Policy =>
  loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: here });

describe("loader — nested patchRequire install/uninstall (#22)", () => {
  it("an out-of-LIFO-order uninstall does not leak the outer layer", () => {
    const outer = patchRequire(denyAll(), "enforce", { onDecision: () => {}, projectRoot: here });
    let inner: ReturnType<typeof patchRequire> | undefined;
    try {
      inner = patchRequire(denyAll(), "enforce", { onDecision: () => {}, projectRoot: here });

      // Both layers active: fs is shimmed + enforced (topmost — inner — handles the require).
      expect(() => loadFixtureFresh().readData()).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );

      // Uninstall the OUTER (first-installed) layer first — deliberately out of LIFO order.
      outer.uninstall();

      // The inner layer must still be fully active: its removal must not have leaked outer
      // (which would manifest as `_load` now bypassing enforcement) nor broken inner itself.
      expect(() => loadFixtureFresh().readData()).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );

      // Uninstalling outer a second time must stay a no-op (idempotent), not disturb inner.
      expect(() => outer.uninstall()).not.toThrow();
      expect(() => loadFixtureFresh().readData()).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    } finally {
      inner?.uninstall();
      outer.uninstall(); // idempotent safety net if an assertion above threw
    }

    // Now that BOTH layers are torn down, the loader must be fully restored: a fresh
    // require gets the real, un-shimmed fs — no leaked layer still enforcing.
    expect(loadFixtureFresh().readData()).toBe("fixture data\n");
  });

  it("uninstall is idempotent and a second call is a safe no-op", () => {
    const handle = patchRequire(denyAll(), "enforce", { onDecision: () => {}, projectRoot: here });
    handle.uninstall();
    expect(() => handle.uninstall()).not.toThrow();
    expect(loadFixtureFresh().readData()).toBe("fixture data\n");
  });

  it("normal LIFO-order nested install/uninstall still works (no regression)", () => {
    const outer = patchRequire(denyAll(), "enforce", { onDecision: () => {}, projectRoot: here });
    try {
      const inner = patchRequire(denyAll(), "enforce", { onDecision: () => {}, projectRoot: here });
      try {
        expect(() => loadFixtureFresh().readData()).toThrowError(
          expect.objectContaining({ name: "CapabilityError" }),
        );
      } finally {
        inner.uninstall();
      }
      // Outer alone still active.
      expect(() => loadFixtureFresh().readData()).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    } finally {
      outer.uninstall();
    }
    expect(loadFixtureFresh().readData()).toBe("fixture data\n");
  });

  it("a single install/uninstall (no nesting) behaves exactly as before", () => {
    const handle = patchRequire(denyAll(), "enforce", { onDecision: () => {}, projectRoot: here });
    try {
      expect(() => loadFixtureFresh().readData()).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    } finally {
      handle.uninstall();
    }
    expect(loadFixtureFresh().readData()).toBe("fixture data\n");
  });
});
