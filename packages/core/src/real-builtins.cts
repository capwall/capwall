/**
 * THE REAL BUILTINS — the one place capwall captures an un-mediated core module, and the reason
 * exactly one file in this otherwise all-ESM package is CommonJS (issue #78).
 *
 * ── WHY THE CAPTURE MECHANISM IS A SECURITY PROPERTY, NOT PLUMBING ──────────────────────────
 * Node's ESM module cache is keyed by RESOLVED URL, and a URL already in that cache is served
 * from it without the `load` hook chain ever being consulted. capwall's `load` hook carries a
 * backstop (`loader/esm-hooks.ts`): if it is ever handed a raw `node:<mediated>` URL — meaning
 * something resolved straight to the builtin without capwall's `resolve` seeing it — it serves
 * the shim-backed synthetic source instead of the raw module.
 *
 * That backstop was DEAD CODE for as long as capwall captured its real builtins with static ESM
 * `import realFs from "node:fs"`. Those imports run before the hooks are registered, so by the
 * time the hook existed every mediated builtin was already cached raw, and the cache — not the
 * hook chain — answered. Measured, not assumed: with `node:fs` pre-cached a later resolve
 * short-circuit to `node:fs` reaches the raw builtin; without it, the backstop fires and
 * re-mediates. A CJS `require` populates the CJS cache and leaves the ESM cache untouched, so
 * routing every capture through here is what makes the second layer real.
 *
 * ── WHY CJS RATHER THAN `createRequire()` IN AN ESM MODULE ──────────────────────────────────
 * `createRequire` comes from `node:module`, which is itself mediated — its shim is what stops a
 * dependency registering a loader hook ahead of capwall's (#61). A static
 * `import { createRequire } from "node:module"` would therefore leave that one specifier cached
 * raw and the backstop latent for exactly the module the ESM perimeter is built around. In a
 * `.cjs` file `require` is ambient, so the capture needs no ESM import of anything and the
 * mediated set comes out of the cache WHOLE. It also keeps the floor where `engines` puts it —
 * reaching for `process.getBuiltinModule` instead would silently require Node ≥20.16.
 *
 * ── WHY THESE `require`s CANNOT LOOP THROUGH capwall's OWN `Module._load` PATCH ─────────────
 * A shim that captured a shim would be a stack overflow at install time, so the ordering has to
 * be structural rather than merely untested:
 *
 *   1. `Module._load` is only ever patched by `install()`, which is exported from `index.js`.
 *   2. This module sits in `index.js`'s STATIC import graph (index → loader/require → here;
 *      index → loader/live-context → shims/index → shims/fs → here), and ES module evaluation
 *      completes the whole graph before the entry module's body runs — let alone before any
 *      caller can reach an exported function.
 *   3. So every `require` below runs against the pristine `Module._load`, on every entry point
 *      (the CLI preload, a programmatic embedder, `require()`-ing the ESM build). There is no
 *      ordering in which `install()` precedes this file's evaluation.
 *
 * `test/real-builtins.test.ts` holds that shape in place from both ends: a source scan that
 * fails on any static ESM import of a mediated builtin elsewhere in `src` (and on any lazy
 * route to this module, which is what step 2 would need to be false), and an identity check
 * against `process.getBuiltinModule` after a real `install()` — so a capture that HAD been
 * routed through a shim would fail loudly rather than silently double-mediate.
 *
 * ── WHAT THIS DOES NOT CHANGE ───────────────────────────────────────────────────────────────
 * Nothing about load cost: all twelve of these were already captured eagerly at module scope,
 * just through `import` instead of `require`. Both spellings resolve to the same object
 * (`require("node:fs") === process.getBuiltinModule("node:fs")`), so no shim sees a different
 * builtin than it did before.
 *
 * ── THE ONE THING IT DOES CHANGE, STATED PLAINLY ────────────────────────────────────────────
 * These captures now travel through `Module._load`, where the ESM imports they replaced did not.
 * If a THIRD-PARTY loader patch (an APM agent, `require-in-the-middle`) is already installed when
 * capwall loads, capwall wraps whatever that patch returns rather than the raw builtin. In
 * practice such agents patch the module object in place and hand back the same object, so this is
 * invisible; where they do not, capwall's mediation sits on top of theirs, which is the correct
 * side of the sandwich to be on. It is not a fail-open either way — capwall still guards every
 * call it forwards — but it is a real ordering dependency, and capwall's own `Module._load` patch
 * is provably not part of it (see above).
 *
 * ── ADDING ONE ──────────────────────────────────────────────────────────────────────────────
 * A new mediated module needs its real capture here and its specifiers in
 * `loader/require.ts`'s `MEDIATED_MODULES`; the test above checks the two lists against each
 * other, so neither half can be added alone. The names deliberately match the local bindings the
 * shims already used, so a shim's bootstrap is one `import { realX } from "../real-builtins.cjs"`.
 */

export const realFs: typeof import("node:fs") = require("node:fs");
/**
 * The same object as `realFs.promises`, captured under its own specifier because `fs/promises`
 * is separately mediated (it is its own registry key) and `policy/load.ts` wants it directly.
 */
export const realFsPromises: typeof import("node:fs/promises") = require("node:fs/promises");
export const realNet: typeof import("node:net") = require("node:net");
export const realHttp: typeof import("node:http") = require("node:http");
export const realHttps: typeof import("node:https") = require("node:https");
export const realTls: typeof import("node:tls") = require("node:tls");
export const realHttp2: typeof import("node:http2") = require("node:http2");
export const realDgram: typeof import("node:dgram") = require("node:dgram");
export const realChildProcess: typeof import("node:child_process") = require("node:child_process");
export const realWorkerThreads: typeof import("node:worker_threads") = require("node:worker_threads");
export const realVm: typeof import("node:vm") = require("node:vm");
/**
 * Not `module` — inside a CommonJS module that name is the wrapper's own parameter. Every other
 * export here is named for the binding its consumers already used; this one cannot be.
 */
export const realModule: typeof import("node:module") = require("node:module");
