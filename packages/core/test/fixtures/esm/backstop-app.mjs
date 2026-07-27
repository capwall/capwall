// ESM app entry for the #78 regression: the application registers its own loader hook — which
// capwall permits, the app being the trust root, and which is what `tsx`, `ts-node` and every
// resolver plugin legitimately do — and that hook short-circuits `raw:<builtin>` straight to the
// raw `node:` URL.
//
// Because Node runs the most recently registered hook first, capwall's `resolve` never sees those
// specifiers. Only the `load`-level backstop stands between esm-backstop-dep and the raw builtins,
// which is the whole point of the exercise: the app's hook is careless, not hostile, and capwall
// re-mediates rather than trusting it.
//
// BACKSTOP_SYNC_HOOK=1 registers the same short-circuit on the SYNCHRONOUS `registerHooks`
// chain (Node ≥22.15) instead of the asynchronous `register` one. That chain runs entirely ahead
// of the `register` chain capwall lives in, so it is the strictly stronger position — and the
// asynchronous `load` chain still descends to capwall, which is the property being asserted.
// Prints `BACKSTOP:UNSUPPORTED` where the API does not exist, rather than silently passing.
//
// A NAMESPACE import, not `import { register, registerHooks }`: `registerHooks` does not exist on
// Node 20, and a named import of a missing export is a SyntaxError at instantiation time — the
// module would not even load, on the runtime where the feature is merely absent.
import * as nodeModule from "node:module";

/** Rewrites `raw:<builtin>` straight to the raw builtin URL, declaring the format too. */
function shortCircuitToRaw(specifier, context, nextResolve) {
  if (specifier.startsWith("raw:")) {
    return { url: "node:" + specifier.slice(4), shortCircuit: true, format: "builtin" };
  }
  return nextResolve(specifier, context);
}

if (process.env.BACKSTOP_SYNC_HOOK === "1") {
  if (typeof nodeModule.registerHooks !== "function") {
    console.log("BACKSTOP:UNSUPPORTED");
    process.exit(0);
  }
  nodeModule.registerHooks({ resolve: shortCircuitToRaw });
} else {
  const source = `export const resolve = ${shortCircuitToRaw.toString()};`;
  nodeModule.register("data:text/javascript," + encodeURIComponent(source), import.meta.url);
}

const { run } = await import("esm-backstop-dep");
for (const line of await run()) console.log("BACKSTOP:" + line);
