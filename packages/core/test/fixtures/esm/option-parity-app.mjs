/**
 * OPTION-PARITY PROBE — issues #97 and #90.
 *
 * Installs capwall programmatically with ONE configuration (supplied as JSON in
 * `CAPWALL_TEST_CONFIG`) and then runs an IDENTICAL set of probes through both interception
 * paths: `require("parity-cjs-dep")` and `await import("parity-esm-dep")`. The report it prints
 * is what `install-option-parity.test.ts` asserts on.
 *
 * WHY A SUBPROCESS PER CONFIGURATION, and not a loop in one process. Three of the options are
 * process-sticky by design and cannot be un-set:
 *   · `hardened` is consumed at shim BUILD time and the registries are memoized per
 *     hardened-ness, so a second install in the same process reuses whichever registry already
 *     exists for its setting rather than re-deriving it;
 *   · `esm` registers a module-customization hook, which Node cannot fully unregister;
 *   · an ESM synthetic module is evaluated once and its `const` export bindings can never be
 *     revisited (#62), so the FIRST configuration to import a specifier would decide what every
 *     later one sees.
 * A fresh process per row is the only way the rows are independent, which is the whole point of
 * a parity matrix.
 *
 * WHY THE APP INSTALLS CAPWALL ITSELF rather than running under the preload: the matrix is over
 * `InstallOptions`, and the preload only exposes the subset that has a `CAPWALL_*` spelling.
 * `hardened.test.ts` covers the env-variable channel separately.
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { install, loadPolicyFromObject } from "../../../dist/index.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const config = JSON.parse(process.env["CAPWALL_TEST_CONFIG"] ?? "{}");
const SECRET_KEY = "PARITY_PROBE_SECRET";

/**
 * Deny-by-default for both deps, so the `fs` probe reports a denial under `enforce` and an
 * allowance under `observe` — which is how `mode` becomes observable on both paths at once.
 */
const policy = loadPolicyFromObject(
  { version: 1, mode: "enforce", packages: {} },
  { projectRoot: ROOT },
);

const decisions = [];
// `downgradeAfter` is a probe directive, not an InstallOption — see below.
const { downgradeAfter, ...installOptions } = config.options ?? {};
const options = {
  projectRoot: config.projectRoot === "node_modules" ? path.join(ROOT, "node_modules") : ROOT,
  onDecision: (pkg, decision) =>
    decisions.push({ pkg, kind: decision.observed.kind, allowed: decision.allowed }),
  ...installOptions,
};

let installError = null;
let handle = null;
/**
 * #129: nest a NON-hardened install on top, BEFORE any probe requires a mediated builtin.
 *
 * The downgrade this reproduces is not about the install call — it is about what the NEXT
 * `require("node:fs")` / `import "node:net"` hands back. Both probe sets below load their
 * dependency (and therefore capture their shims) after this point, so a registry that followed
 * the newest install rather than the ratchet shows up as `frozen: false`.
 */
let downgrade = null;
try {
  handle = install(policy, config.mode ?? "enforce", options);
  if (downgradeAfter === true) {
    downgrade = install(policy, config.mode ?? "enforce", { ...options, hardened: false });
  }
} catch (err) {
  installError = String(err && err.message);
}

/** Run every probe against one dependency namespace. Identical for both paths, deliberately. */
async function probe(dep) {
  return {
    read: dep.read(),
    frozen: dep.socketPrototypeFrozen(),
    readDeep: dep.readDeep(12),
    env: dep.readEnv(SECRET_KEY) === undefined ? "hidden" : "visible",
    // Loopback, and a port nothing binds: with the guard ON this is a `CapabilityError` before
    // any socket opens, and with `globalEgress: false` it is Node's own fast `TypeError` from
    // ECONNREFUSED. A routable-but-dead address would hang instead of answering.
    fetch: await dep.fetchProbe("http://127.0.0.1:1/"),
  };
}

const report = { installError, cjs: null, esm: null, decisions: [] };

if (installError === null) {
  const requireCjs = createRequire(import.meta.url);
  report.cjs = await probe(requireCjs("parity-cjs-dep"));
  report.esm = await probe(await import("parity-esm-dep"));
  // Which principal each path's read was charged to — the `projectRoot` observable, and the
  // `attribution.maxFrames` one.
  report.decisions = decisions;
  if (downgrade !== null) downgrade.uninstall();
  handle.uninstall();
}

process.stdout.write("PARITY:" + JSON.stringify(report) + "\n");
