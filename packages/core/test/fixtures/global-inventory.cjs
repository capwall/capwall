// Prints this runtime's own `globalThis` property names as JSON, plus whether
// `navigator.sendBeacon` exists. Driven by test/global-egress-inventory.test.ts (#80).
//
// A FILE rather than `node -e`: the `-e`/`-p` evaluator injects extra names onto the global
// object (the CJS wrapper bindings and a lazy alias for every builtin module), which would make
// the inventory an artifact of how the probe was launched rather than of the runtime.
const names = Object.getOwnPropertyNames(globalThis).sort();
const nav = globalThis.navigator;

// Descriptor shape of the guarded globals, reported from THIS process because the flag-only
// ones do not exist in the test runner's process at all. `configurable` is the hard
// requirement: the guard refuses to install on a global it could not restore afterwards.
const guarded = {};
for (const name of ["fetch", "WebSocket", "EventSource"]) {
  const d = Object.getOwnPropertyDescriptor(globalThis, name);
  if (d === undefined) continue;
  guarded[name] = {
    type: typeof globalThis[name],
    configurable: d.configurable === true,
    writable: d.writable === true,
  };
}

// Web Storage arrived on Node 26 (`Storage`, `localStorage`, `sessionStorage`). It was reviewed
// as INERT FOR EGRESS on the strength of its prototype carrying no transport method — report the
// prototype so the review is an assertion in the test rather than a claim in a comment. `null`
// on a Node without the class, which is the pre-26 legs of the matrix.
const storageProto =
  typeof globalThis.Storage === "function"
    ? Object.getOwnPropertyNames(globalThis.Storage.prototype).sort()
    : null;

process.stdout.write(
  JSON.stringify({
    names,
    guarded,
    storageProto,
    // `navigator.sendBeacon` is the one browser egress API this guard would have to grow if Node
    // ever adds it. Node's `navigator` currently carries only userAgent/platform/language(s)/
    // hardwareConcurrency, so this must stay false.
    hasSendBeacon: typeof nav === "object" && nav !== null && typeof nav.sendBeacon === "function",
  }),
);
