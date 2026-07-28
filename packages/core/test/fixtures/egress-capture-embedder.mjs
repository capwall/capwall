/**
 * The EMBEDDER path for issue #170: `import @capwall/core`, run something, then `install()`.
 *
 * Run in a clean child by `test/global-egress-capture.test.ts` with `CAPWALL_GLOBAL_EGRESS=0`
 * in the environment AND the `globalEgress` install option left at its default — the one
 * self-contradictory configuration where the module-scope `Request.prototype.url` capture is
 * skipped and the guard is nevertheless asked for. capwall takes the capture late there, and
 * warns if it cannot prove the getter is still Node's own.
 *
 * `process.argv[2]`:
 *   `clean`       — nothing touches `Request` between capwall's module evaluation and install().
 *                   Nothing could have tampered, so capwall must take the late capture SILENTLY.
 *   `materialize` — stand in for a dependency that used `fetch`/`Request` in between, which is
 *                   what makes the late capture unprovable. capwall must warn.
 *
 * Both runs print the same two markers, so the test asserts the guard WORKS in either case
 * rather than only that a warning did or did not appear: a late capture that silently produced
 * no guard would satisfy a warning-only assertion.
 */
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const core = await import(pathToFileURL(path.join(HERE, "..", "..", "dist", "index.js")).href);

if (process.argv[2] === "materialize") {
  // Reading `globalThis.Request` is what materializes undici — the same read capwall's capture
  // performs. Any dependency that constructs a Request does this.
  void globalThis.Request;
}

// Deny-all: every `net` request is refused, so a working guard is unambiguous.
const handle = core.install({ version: 1, mode: "enforce", default: {}, packages: {} }, "enforce", {
  projectRoot: HERE,
  env: false,
});

const outcome = async (input) => {
  try {
    await fetch(input);
    return "ALLOWED";
  } catch (err) {
    return err && err.name === "CapabilityError" ? "DENIED" : `OTHER:${err && err.name}`;
  }
};

// Port 1 on loopback: nothing listens, so an un-guarded call fails with a transport error rather
// than reaching anything. `DENIED` can therefore only come from capwall.
console.log(`string-input:${await outcome("http://127.0.0.1:1/")}`);
console.log(`request-input:${await outcome(new Request("http://127.0.0.1:1/"))}`);
handle.uninstall();
