// ESM app entry for the #62 regression: a programmatic embedder swapping policy at runtime.
//
// Unlike the other fixtures here this one does NOT run under the preload — it installs
// capwall itself, because the bug is in install/uninstall bookkeeping rather than in
// interception. It imports the BUILT core (the same dist the other ESM tests exercise) by
// relative path, so the fixture stays committed and path-independent.
//
// Each line is `SWAP:<phase>:<outcome>`. Pre-fix, every phase reported OK: the synthetic
// module captured its shim once, at first evaluation, so the first install's policy was
// pinned for the life of the process and a later, tighter install changed nothing.
import { install, loadPolicyFromObject } from "../../../dist/index.js";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const opts = { esm: true, projectRoot: ROOT, env: false };
const loose = loadPolicyFromObject(
  { version: 1, packages: { "esm-fixture-dep": { fs: { read: ["/**"], write: [] } } } },
  { projectRoot: ROOT },
);
const strict = loadPolicyFromObject({ version: 1, packages: {} }, { projectRoot: ROOT });

function attempt(readFromDep) {
  try {
    return "OK:" + readFromDep().trim();
  } catch (err) {
    return `${err && err.name}:${err && (err.pkg ?? err.message)}`;
  }
}

const first = install(loose, "enforce", opts);
const { readFromDep } = await import("esm-fixture-dep");
console.log("SWAP:loose:" + attempt(readFromDep));

// Teardown with no reinstall: the already-imported specifier must fail CLOSED, not keep
// serving the torn-down install's grants.
first.uninstall();
console.log("SWAP:uninstalled:" + attempt(readFromDep));

// A specifier NEVER IMPORTED before teardown. Since #152 the hooks are really deregistered on
// the last `uninstall()` (`module.registerHooks()` returns a `deregister()`; `module.register()`
// did not), so a FRESH import now reaches the real builtin — exactly as a fresh `require` does
// on the CJS path, which is the parity docs/threat-model.md used to have to carve out.
//
// Before #152 this threw "capwall is no longer installed" from the bridge. That was fail-closed
// but it was also a TRAP: an ESM module that throws during evaluation is cached in its errored
// state, so the specifier stayed permanently poisoned for the rest of the process — including
// for the later, legitimate install below.
const netDuringGap = await import("node:net");
const rawNet = process.getBuiltinModule("node:net");
console.log("SWAP:never-imported:" + (netDuringGap.default === rawNet ? "UNMEDIATED" : "MEDIATED"));

// Tightening must take effect on the already-imported specifier — the actual finding.
const second = install(strict, "enforce", opts);
console.log("SWAP:strict:" + attempt(readFromDep));

// …and the gap import above must not have DE-MEDIATED `node:net` for this install. It cannot:
// the raw `node:` URL went into the ESM registry, but a mediated import now resolves to a
// `capwall-esm:` URL, which is a different key and is not in it.
const netAfterReinstall = await import("node:net");
console.log(
  "SWAP:after-gap-reinstall:" + (netAfterReinstall.default === rawNet ? "UNMEDIATED" : "MEDIATED"),
);

// …and so must loosening again, so this is a live policy and not a one-way ratchet.
second.uninstall();
install(loose, "enforce", opts);
console.log("SWAP:reloose:" + attempt(readFromDep));
