/**
 * GLOBAL EGRESS INVENTORY CANARY (#80).
 *
 * The global egress guard can only cover globals somebody knew to look for, and new global APIs
 * land in Node **minor** releases — `WebSocket` arrived unflagged in 22, `EventSource` is still
 * behind a flag, `navigator` did not exist at all in 20. "We enumerated it once" is not a
 * control. This is the control: enumerate `globalThis` on the running Node and fail when a name
 * appears that nobody has classified.
 *
 * The two lists below partition every global capwall has reviewed into **egress-bearing**
 * (guarded — see `src/shims/global-egress.ts`) and **inert** (cannot originate a network
 * request on its own). A future Node that adds anything breaks this test, and the fix is a
 * human deciding which list it belongs in. That is deliberately a little annoying: a silent
 * addition to the egress surface is exactly the failure #80 was.
 *
 * The probe runs in a CHILD PROCESS, from a file, with the experimental flags on:
 *  - a child, because vitest's own runtime installs globals of its own onto `globalThis`;
 *  - from a file rather than `node -e`, because the `-e` evaluator injects the CJS wrapper
 *    bindings and a lazy alias for every builtin module;
 *  - with the flags, so the flag-only egress classes are in the inventory on every version.
 */
import { execFile } from "node:child_process";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const PROBE = path.join(here, "fixtures", "global-inventory.cjs");

/**
 * Globals that can originate a network request, and are therefore guarded by
 * `installGlobalEgressGuard`. Adding a name here without adding a guard is a test failure in
 * `global-egress.test.ts` / `global-egress-flagged.test.ts`, not here.
 */
const GUARDED_EGRESS_GLOBALS: readonly string[] = ["fetch", "WebSocket", "EventSource"];

/**
 * Globals reviewed and found INERT for egress purposes — they carry no network capability of
 * their own. The interesting entries, since the rest are ECMAScript intrinsics:
 *
 *  - `Request` / `Response` / `Headers` / `FormData` / `Blob` / `File` — data types. A `Request`
 *    only DESCRIBES a destination; something still has to hand it to `fetch`, which is guarded.
 *  - `BroadcastChannel` / `MessageChannel` / `MessagePort` — in-process (and cross-worker)
 *    messaging, no socket.
 *  - `navigator` / `Navigator` — Node's is `userAgent`/`platform`/`language(s)`/
 *    `hardwareConcurrency` only. No `sendBeacon`; asserted separately below, because
 *    `sendBeacon` IS an egress API and would need a guard the day it appears.
 *  - `Crypto`/`SubtleCrypto`/`crypto` — local cryptography, no transport.
 *  - `URL` / `URLPattern` / `URLSearchParams` — parsing.
 *  - `process` — the door to `child_process` and the module system, both mediated elsewhere;
 *    it is not itself a network API.
 *  - `WebAssembly` — compiles bytes someone else fetched.
 */
const REVIEWED_INERT_GLOBALS: readonly string[] = [
  "AbortController", "AbortSignal", "AggregateError", "Array", "ArrayBuffer",
  "AsyncDisposableStack", "Atomics", "BigInt", "BigInt64Array", "BigUint64Array", "Blob",
  "Boolean", "BroadcastChannel", "Buffer", "ByteLengthQueuingStrategy", "CloseEvent",
  "CompressionStream", "CountQueuingStrategy", "Crypto", "CryptoKey", "CustomEvent",
  "DOMException", "DataView", "Date", "DecompressionStream", "DisposableStack", "Error",
  "EvalError", "Event", "EventTarget", "File", "FinalizationRegistry", "Float16Array",
  "Float32Array", "Float64Array", "FormData", "Function", "Headers", "Infinity", "Int16Array",
  "Int32Array", "Int8Array", "Intl", "Iterator", "JSON", "Map", "Math", "MessageChannel",
  "MessageEvent", "MessagePort", "NaN", "Navigator", "Number", "Object", "Performance",
  "PerformanceEntry", "PerformanceMark", "PerformanceMeasure", "PerformanceObserver",
  "PerformanceObserverEntryList", "PerformanceResourceTiming", "Promise", "Proxy", "RangeError",
  "ReadableByteStreamController", "ReadableStream", "ReadableStreamBYOBReader",
  "ReadableStreamBYOBRequest", "ReadableStreamDefaultController", "ReadableStreamDefaultReader",
  "ReferenceError", "Reflect", "RegExp", "Request", "Response", "Set", "SharedArrayBuffer",
  "String", "SubtleCrypto", "SuppressedError", "Symbol", "SyntaxError", "TextDecoder",
  "TextDecoderStream", "TextEncoder", "TextEncoderStream", "TransformStream",
  "TransformStreamDefaultController", "TypeError", "URIError", "URL", "URLPattern",
  "URLSearchParams", "Uint16Array", "Uint32Array", "Uint8Array", "Uint8ClampedArray", "WeakMap",
  "WeakRef", "WeakSet", "WebAssembly", "WritableStream", "WritableStreamDefaultController",
  "WritableStreamDefaultWriter", "atob", "btoa", "clearImmediate", "clearInterval",
  "clearTimeout", "console", "crypto", "decodeURI", "decodeURIComponent", "encodeURI",
  "encodeURIComponent", "escape", "eval", "global", "globalThis", "isFinite", "isNaN",
  "navigator", "parseFloat", "parseInt", "performance", "process", "queueMicrotask",
  "setImmediate", "setInterval", "setTimeout", "structuredClone", "undefined", "unescape",
];

interface Inventory {
  names: string[];
  /** Descriptor shape of each guarded global that exists, reported from the child. */
  guarded: Record<string, { type: string; configurable: boolean; writable: boolean }>;
  hasSendBeacon: boolean;
}

function probe(): Promise<Inventory> {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      ["--experimental-websocket", "--experimental-eventsource", PROBE],
      (err, stdout) => {
        if (err) return reject(err);
        resolve(JSON.parse(stdout) as Inventory);
      },
    );
  });
}

describe("#80 — the global egress surface is fully classified", () => {
  it("every global on this Node has been reviewed as egress-bearing or inert", async () => {
    const { names } = await probe();
    const reviewed = new Set([...GUARDED_EGRESS_GLOBALS, ...REVIEWED_INERT_GLOBALS]);
    const unclassified = names.filter((n) => !reviewed.has(n));
    expect(
      unclassified,
      "New global(s) on this Node. Decide for each whether it can originate a network request: " +
        "guard it in src/shims/global-egress.ts and add it to GUARDED_EGRESS_GLOBALS, or add it " +
        "to REVIEWED_INERT_GLOBALS with a one-line reason. Do not just append it to the inert " +
        "list to make the test pass.",
    ).toEqual([]);
  });

  it("navigator.sendBeacon does not exist — the day it does, it needs a guard", async () => {
    // `sendBeacon` is a fire-and-forget POST, i.e. an ideal exfiltration primitive, and it is the
    // one browser egress API plausibly heading for Node's `navigator`. There is deliberately no
    // guard code for it today (an untestable guard for a nonexistent API is how dead code rots
    // into false coverage); this assertion is what forces one to be written.
    const { hasSendBeacon } = await probe();
    expect(hasSendBeacon).toBe(false);
  });

  it("every guarded name that exists on this Node is a replaceable, restorable function", async () => {
    const { names, guarded } = await probe();
    // Every guarded name must be present under the flags — if Node ever drops or renames one,
    // the guard would silently stop covering it and nothing else would notice.
    expect(Object.keys(guarded).sort()).toEqual([...GUARDED_EGRESS_GLOBALS].sort());
    for (const name of GUARDED_EGRESS_GLOBALS) {
      expect(names).toContain(name);
      const desc = guarded[name]!;
      expect(desc.type, `globalThis.${name} must be a function to wrap`).toBe("function");
      // `configurable` is the hard requirement: the guard refuses to install on a global it
      // could not restore afterwards, so a Node that froze one of these would silently
      // un-mediate it rather than fail loudly.
      expect(desc.configurable, `globalThis.${name} must be configurable to be guardable`).toBe(true);
    }
  });
});
