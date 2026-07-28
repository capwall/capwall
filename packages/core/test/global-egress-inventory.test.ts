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
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { runNode } from "./helpers/subprocess.js";

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
 *
 * THE NODE 26 ARRIVALS, reviewed when 26 joined the matrix. This canary did its job: all six
 * appeared at once and none of them was on anyone's radar.
 *
 *  - `Temporal` — the TC39 date/time API (`Now`, `PlainDate`, `Instant`, `Duration`, …).
 *    Arithmetic on calendar values; no transport of any kind.
 *  - `ErrorEvent` — the event class `WebSocket`/`EventSource` emit on failure
 *    (`message`/`filename`/`lineno`/`colno`/`error`). A data type ABOUT a failed request, not a
 *    way to originate one; the classes that do originate are already in the guarded list.
 *  - `QuotaExceededError` — a `DOMException`-family error carrying `quota`/`requested`. An error.
 *  - `Storage` / `localStorage` / `sessionStorage` — Web Storage. The prototype is exactly
 *    `getItem`/`setItem`/`removeItem`/`clear`/`key`/`length`: a key-value store with **no network
 *    method**, so it is inert for EGRESS, which is the question this file asks.
 *
 *    It is not inert in every sense, and that is worth writing down rather than leaving implied.
 *    `localStorage` is PERSISTENT and file-backed — it materialises only when the user passes
 *    `--localstorage-file`, and Node does that file I/O internally, below the `fs` shim. So on a
 *    Node 26 process started with that flag, a dependency could read and write that one file
 *    without an `fs` grant. It is narrow (opt-in flag, one path, no path control) and it is a
 *    FILESYSTEM question, not an egress one, so it does not belong in either list here — see
 *    docs/threat-model.md § Web Storage for the writeup. `sessionStorage` is in-memory and has
 *    no such angle.
 */
const REVIEWED_INERT_GLOBALS: readonly string[] = [
  "AbortController", "AbortSignal", "AggregateError", "Array", "ArrayBuffer",
  "AsyncDisposableStack", "Atomics", "BigInt", "BigInt64Array", "BigUint64Array", "Blob",
  "Boolean", "BroadcastChannel", "Buffer", "ByteLengthQueuingStrategy", "CloseEvent",
  "CompressionStream", "CountQueuingStrategy", "Crypto", "CryptoKey", "CustomEvent",
  "DOMException", "DataView", "Date", "DecompressionStream", "DisposableStack", "Error",
  "ErrorEvent", "EvalError", "Event", "EventTarget", "File", "FinalizationRegistry",
  "Float16Array", "Float32Array", "Float64Array", "FormData", "Function", "Headers",
  "Infinity", "Int16Array", "Int32Array", "Int8Array", "Intl", "Iterator", "JSON", "Map",
  "Math", "MessageChannel", "MessageEvent", "MessagePort", "NaN", "Navigator", "Number",
  "Object", "Performance", "PerformanceEntry", "PerformanceMark", "PerformanceMeasure",
  "PerformanceObserver",
  "PerformanceObserverEntryList", "PerformanceResourceTiming", "Promise", "Proxy",
  "QuotaExceededError", "RangeError", "ReadableByteStreamController", "ReadableStream",
  "ReadableStreamBYOBReader", "ReadableStreamBYOBRequest",
  "ReadableStreamDefaultController", "ReadableStreamDefaultReader",
  "ReferenceError", "Reflect", "RegExp", "Request", "Response", "Set", "SharedArrayBuffer",
  "Storage", "String", "SubtleCrypto", "SuppressedError", "Symbol", "SyntaxError", "Temporal",
  "TextDecoder", "TextDecoderStream", "TextEncoder", "TextEncoderStream", "TransformStream",
  "TransformStreamDefaultController", "TypeError", "URIError", "URL", "URLPattern",
  "URLSearchParams", "Uint16Array", "Uint32Array", "Uint8Array", "Uint8ClampedArray", "WeakMap",
  "WeakRef", "WeakSet", "WebAssembly", "WritableStream", "WritableStreamDefaultController",
  "WritableStreamDefaultWriter", "atob", "btoa", "clearImmediate", "clearInterval",
  "clearTimeout", "console", "crypto", "decodeURI", "decodeURIComponent", "encodeURI",
  "encodeURIComponent", "escape", "eval", "global", "globalThis", "isFinite", "isNaN",
  "localStorage", "navigator", "parseFloat", "parseInt", "performance", "process",
  "queueMicrotask", "sessionStorage", "setImmediate", "setInterval", "setTimeout",
  "structuredClone", "undefined", "unescape",
];

/**
 * Web Storage (`Storage`/`localStorage`/`sessionStorage`) is Node ≥26. Read at module scope, from
 * the SAME runtime the probe child runs, so the two rows below can `skipIf` visibly rather than
 * `return` invisibly mid-body (#112).
 */
const HAS_WEB_STORAGE = typeof (globalThis as { Storage?: unknown }).Storage === "function";

interface Inventory {
  names: string[];
  /** Descriptor shape of each guarded global that exists, reported from the child. */
  guarded: Record<string, { type: string; configurable: boolean; writable: boolean }>;
  hasSendBeacon: boolean;
  /** `Storage.prototype`'s own property names, or `null` on a Node without Web Storage. */
  storageProto: string[] | null;
}

/**
 * All three cases below ask the same question of the same probe process; `runNode` runs it once
 * and shares the answer (#145), so the file costs one child rather than three.
 */
async function probe(): Promise<Inventory> {
  const r = await runNode(
    ["--experimental-websocket", "--experimental-eventsource", PROBE],
    // Sound to share: the probe reads only this Node's own globals — it has no inputs at all.
    { share: true, cwd: here },
  );
  if (r.code !== 0) throw new Error(`global-egress probe exited ${String(r.code)}: ${r.stderr}`);
  return JSON.parse(r.stdout) as Inventory;
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

  it.skipIf(!HAS_WEB_STORAGE)(
    "Web Storage carries no transport method — the reason it is classified inert (Node 26)",
    async () => {
      // `Storage`/`localStorage`/`sessionStorage` were classified INERT FOR EGRESS when Node 26
      // joined the matrix, on the strength of the prototype being a plain key-value store. Pin
      // the EXACT surface, so the classification is re-checked by machine on every run rather
      // than trusted from a comment: if a future Node grows Storage a sync/push/fetch-shaped
      // method, this fails and someone re-reviews — the same contract as `sendBeacon` above.
      //
      // Deliberately `toEqual` on the whole list rather than `not.toContain("fetch")`: the claim
      // is that we know every method it has, not that it lacks the one name we thought to name.
      const { storageProto } = await probe();
      expect(storageProto).toEqual([
        "clear", "constructor", "getItem", "key", "length", "removeItem", "setItem",
      ]);
    },
  );

  it("the probe reports Web Storage exactly as the runtime running this test has it", async () => {
    // The always-running half, so the skip above is never the whole story on a pre-26 leg: this
    // asserts the probe's view and the test runner's view of the same runtime agree, in BOTH
    // directions. On 22/24 it pins "absent, and the inventory says so"; on 26 it pins "present".
    // Without it, a probe that silently stopped reporting `storageProto` would look identical to
    // a Node without Web Storage.
    const { names, storageProto } = await probe();
    expect({ inNames: names.includes("Storage"), reported: storageProto !== null }).toEqual({
      inNames: HAS_WEB_STORAGE,
      reported: HAS_WEB_STORAGE,
    });
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
