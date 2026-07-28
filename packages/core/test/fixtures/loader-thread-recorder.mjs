/**
 * A module-customization hook that RECORDS every URL the ESM loader resolves, one per line, into
 * the file named by `data.log`. Registered by `loader-thread-graph.mjs` (#150).
 *
 * Why a hook rather than a cache inspection: `zod`'s `import` condition is an ES module, so it
 * never lands in `require.cache` and there is no supported way to enumerate the ESM registry. The
 * resolve chain is the one place a test can watch capwall's own hook module being resolved, on
 * every Node in the support range.
 *
 * Appends synchronously, on the loader thread, so nothing is lost to an unflushed buffer when the
 * probe reads the file back.
 */
import { appendFileSync } from "node:fs";

let log = "";

export async function initialize(data) {
  log = data.log;
}

export async function resolve(specifier, context, nextResolve) {
  const result = await nextResolve(specifier, context);
  if (log !== "") {
    try {
      appendFileSync(log, `${result.url}\n`);
    } catch {
      /* the probe already failed if this file is unwritable; do not break the load */
    }
  }
  return result;
}
