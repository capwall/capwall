/**
 * Ask Node what capwall's ESM hook module actually drags into a realm (#150).
 *
 * Run in a CLEAN child by `test/esm-hook-graph.test.ts`, because the answer is a property of a
 * fresh module registry: inside the vitest worker every one of these is long since loaded.
 *
 * The order below is load-bearing and is the reason this is one child rather than three:
 * `hook` must be sampled BEFORE the aggregate capture and before `policy/load.js`, so the two
 * positive controls cannot contaminate the measurement they exist to validate.
 *
 * Prints one JSON object on stdout and nothing else.
 */
import { register } from "node:module";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.join(HERE, "..", "..", "dist");
const url = (...p) => pathToFileURL(path.join(DIST, ...p)).href;

// A recorder for the ESM half of the answer. `zod` resolves to an ES module, so it never reaches
// `require.cache` and there is no way to enumerate the ESM registry — but the resolve chain sees
// every one of them. Registered BEFORE anything under test is imported.
const LOG = path.join(mkdtempSync(path.join(os.tmpdir(), "capwall-graph-")), "resolved.log");
writeFileSync(LOG, "");
register(pathToFileURL(path.join(HERE, "loader-thread-recorder.mjs")).href, {
  parentURL: import.meta.url,
  data: { log: LOG },
});

/** URLs resolved so far, as a newline-delimited read of the recorder's log. */
const resolved = () => readFileSync(LOG, "utf8").split("\n").filter(Boolean);
const zodCountAt = (urls) => urls.filter((u) => /[\\/]zod[\\/]/.test(u)).length;

/** The mediated builtins, bare-spelled as `process.moduleLoadList` reports them. */
const MEDIATED = [
  "fs",
  "fs/promises",
  "net",
  "http",
  "https",
  "tls",
  "http2",
  "dgram",
  "child_process",
  "worker_threads",
  "vm",
];

const loadedSince = (before) => {
  const added = new Set(process.moduleLoadList.slice(before));
  return MEDIATED.filter((m) => added.has(`NativeModule ${m}`));
};

const beforeHook = process.moduleLoadList.length;
await import(url("loader", "esm-hooks.js"));
const hook = loadedSince(beforeHook);
const zodAfterHook = zodCountAt(resolved());

// Positive control 1: the twelve-wide capture really does bring the rest in, so a `hook` of `[]`
// means "narrowed", not "the probe is broken".
const beforeAggregate = process.moduleLoadList.length;
await import(url("real-builtins.cjs"));
const aggregate = loadedSince(beforeAggregate);

// Positive control 2: zod is still in the product, just not on the hook's graph.
await import(url("policy", "load.js"));
const zodAfterPolicyLoad = zodCountAt(resolved());

process.stdout.write(
  JSON.stringify({ hook, aggregate, zodAfterHook, zodAfterPolicyLoad }),
);
