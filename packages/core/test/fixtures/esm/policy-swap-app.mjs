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

// A specifier never imported before teardown keeps the explicit, visible bridge error.
try {
  await import("node:net");
  console.log("SWAP:never-imported:NO_ERROR");
} catch (err) {
  console.log("SWAP:never-imported:" + (/no longer installed/.test(String(err && err.message)) ? "FAILS_CLOSED" : "OTHER"));
}

// Tightening must take effect on the already-imported specifier — the actual finding.
const second = install(strict, "enforce", opts);
console.log("SWAP:strict:" + attempt(readFromDep));

// …and so must loosening again, so this is a live policy and not a one-way ratchet.
second.uninstall();
install(loose, "enforce", opts);
console.log("SWAP:reloose:" + attempt(readFromDep));
