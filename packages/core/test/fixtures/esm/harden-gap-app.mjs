/**
 * THE FAIL-LOUD CHECK, exercised end to end — issue #97.
 *
 * #97 asks for the structural version of "every install option must be asserted on both paths":
 * a security option that is ACCEPTED but not APPLIED should be a startup error, not a silent
 * no-op. `install()` now verifies, after wiring everything up, that the surfaces it is mediating
 * really are frozen/pinned, and refuses to hand back a handle if any is not.
 *
 * Proving that the refusal actually fires needs a surface capwall genuinely cannot harden, and
 * the only reversible-in-theory way to create one is to pin an egress global non-configurable —
 * which is irreversible in practice, so it happens HERE, in a throwaway process, rather than in
 * the test runner's own globals.
 *
 * Sequence, one line of output per step:
 *   1. an un-hardened install, so the egress guard installs `globalThis.fetch` writable;
 *   2. un-mediated code makes that property non-configurable — capwall can no longer pin it;
 *   3. `install(…, { hardened: true })` must THROW, naming the surface;
 *   4. and must have ROLLED ITSELF BACK: the first install's grants are still the live policy,
 *      which is the property that makes a refusal safe for a host app to catch.
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { install, loadPolicyFromObject } from "../../../dist/index.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);

const loose = loadPolicyFromObject(
  {
    version: 1,
    mode: "enforce",
    packages: { "parity-cjs-dep": { fs: { read: ["./node_modules/parity-cjs-dep/**"] } } },
  },
  { projectRoot: ROOT },
);
const tight = loadPolicyFromObject({ version: 1, mode: "enforce", packages: {} }, { projectRoot: ROOT });

const first = install(loose, "enforce", { projectRoot: ROOT });
const dep = requireCjs("parity-cjs-dep");
console.log("GAP:baseline:" + dep.read());

// Step 2 — the thing capwall cannot undo. `installGlobalEgressGuard` deliberately never installs
// a non-configurable global itself (uninstall() has to be able to restore it), but anything else
// in the process may.
Object.defineProperty(globalThis, "fetch", {
  value: globalThis.fetch,
  writable: true,
  enumerable: false,
  configurable: false,
});

// Step 3 — hardened mode cannot be applied to that global any more, so the install must refuse.
try {
  install(tight, "enforce", { projectRoot: ROOT, hardened: true });
  console.log("GAP:hardened:NO_THROW");
} catch (err) {
  const msg = String(err && err.message);
  console.log("GAP:hardened:THREW:" + (msg.includes("globalThis.fetch") ? "names-fetch" : "other"));
}

// Step 4 — the refused install rolled back, so the FIRST install is still the one in force. If
// it had left its handles wired, the tighter policy would be live and this read would deny.
console.log("GAP:after-refusal:" + dep.read());

// Step 5 — teardown must not throw over the global it can no longer restore, and must still
// restore everything else. A `TypeError` escaping here would abort `install()`'s handle loop and
// leave the loader patch, the env proxy and the dlopen gate installed for the life of the
// process, which is a far worse outcome than one un-restorable global.
try {
  first.uninstall();
  console.log("GAP:teardown:ok");
} catch (err) {
  console.log("GAP:teardown:THREW:" + String(err && err.name));
}
// The env guard is one of the handles AFTER the egress guard in the teardown loop, so this is
// the assertion that the loop actually completed.
console.log("GAP:env-restored:" + (dep.readEnv("PATH") === undefined ? "no" : "yes"));
