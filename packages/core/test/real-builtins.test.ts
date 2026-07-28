/**
 * THE CAPTURE RULE, ENFORCED (issue #78).
 *
 * capwall's `load` hook refuses to pass a raw `node:<mediated>` URL through and re-mediates it
 * instead — the backstop for a resolution route capwall's own `resolve` never saw. That backstop
 * is only REACHABLE for a URL that is not already in Node's ESM module cache: a cached URL is
 * served from cache and the load chain is never consulted. So the backstop's existence is
 * decided by how capwall captures its own real builtins, one line in one file at a time.
 *
 * Until #78 it captured them with static ESM `import realFs from "node:fs"`, which put every
 * mediated builtin in the cache before `module.register()` ran, and the backstop was dead code
 * for the entire mediated set. `src/real-builtins.cts` moves the capture to a CommonJS `require`,
 * which populates the CJS cache and leaves the ESM cache untouched.
 *
 * That is a one-line-per-file property, invisible in review and silent when it regresses — a
 * single re-added `import … from "node:fs"` anywhere in `src` puts `node:fs` back in the cache
 * and takes the second layer away again, with nothing failing. Hence the scans below, in the
 * shape `process-patch-sites.test.ts` established for the process-patch rule (#107):
 *
 *   1. **THE IMPORT SCAN.** No file in `packages/core/src` except `real-builtins.cts` may name a
 *      mediated builtin in an import or require position.
 *   2. **THE COVERAGE CHECK.** Every builtin `loader/require.ts` declares mediated must actually
 *      be captured in `real-builtins.cts`, so a new mediated module cannot be half-added.
 *   3. **THE ORDERING CHECK.** Nothing may reach `real-builtins.cjs` through a dynamic `import()`
 *      — the capture is correct because it happens during static module evaluation, before
 *      `install()` can possibly have patched `Module._load`, and a lazy route is what that
 *      argument needs to be false.
 *
 * Plus a runtime post-condition: after a real `install()`, what capwall captured is still the
 * genuine builtin and not one of its own shims (which is what a `require` running AFTER the
 * loader patch would have produced — a shim wrapping a shim).
 *
 * The behavioural half — the backstop firing end-to-end, for every mediated specifier, against a
 * loader hook registered ahead of capwall's — lives in `esm.test.ts` § #78.
 */
import { readdirSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { install, loadPolicyFromObject } from "../src/index.js";
import { MEDIATED_MODULES } from "../src/loader/require.js";
import * as realBuiltins from "../src/real-builtins.cjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const SRC_ROOT = path.join(here, "..", "src");

/** `process.getBuiltinModule` — Node ≥20.16 / ≥22.3, so present on every runtime in the CI
 * matrix. Read at module scope anyway, so the one test that needs it can `skipIf` visibly
 * rather than `return` invisibly if that ever stops being true (#112). */
const GET_BUILTIN_MODULE = (process as unknown as { getBuiltinModule?: (id: string) => unknown })
  .getBuiltinModule;
const CAPTURE_FILE = "real-builtins.cts";

/** The distinct builtins capwall mediates, `node:`-prefixed — `fs` and `node:fs` are one module. */
const MEDIATED_BUILTINS = [
  ...new Set(MEDIATED_MODULES.map((m) => (m.startsWith("node:") ? m : `node:${m}`))),
].sort();

/**
 * Blank comment bodies, keeping newlines so line numbers still compute.
 *
 * Not optional: the files this scans DISCUSS the imports they must not contain — `fs.ts` says in
 * a comment that the real `fs` never arrives via `import … from "node:fs"`, which is the whole
 * point of the comment. Simpler than #107's scanner, which also has to blank string bodies
 * because it looks for assignments; an import specifier IS a string literal, so here they stay.
 */
function stripComments(src: string): string {
  const keepNewlines = (m: string): string => m.replace(/[^\n]/g, " ");
  return src.replace(/\/\*[\s\S]*?\*\//g, keepNewlines).replace(/\/\/[^\n]*/g, keepNewlines);
}

function sourceFilesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sourceFilesUnder(full));
    else if (/\.[cm]?ts$/.test(entry.name)) out.push(full);
  }
  return out.sort();
}

interface Finding {
  file: string;
  line: number;
  text: string;
}

/**
 * Any module-loading reference to a mediated builtin: `from "node:fs"`, `import "fs"`,
 * `import("node:fs")`, `require("fs")`.
 *
 * TYPE positions are excluded — `typeof import("node:fs")` and `import type … from "node:fs"`
 * are erased by `tsc` and load nothing, and the shims' public signatures are written in exactly
 * those terms.
 */
function mediatedImports(file: string, source: string): Finding[] {
  const code = stripComments(source);
  const specifiers = MEDIATED_MODULES.map((m) => m.replace(/[/]/g, "\\/")).join("|");
  const quoted = String.raw`["'](?:${specifiers})["']`;
  const patterns = [
    // `import … from "fs"` / `export … from "fs"`, minus the erased `import type` form.
    new RegExp(String.raw`\bimport\s+(?!type\b)[^;\n]*?\bfrom\s*${quoted}`, "g"),
    new RegExp(String.raw`\bexport\s+(?!type\b)[^;\n]*?\bfrom\s*${quoted}`, "g"),
    // Bare side-effect import.
    new RegExp(String.raw`\bimport\s*${quoted}`, "g"),
    // Dynamic import and require, minus the erased `typeof import(…)` type query.
    new RegExp(String.raw`(?<!\btypeof\s)\bimport\s*\(\s*${quoted}`, "g"),
    new RegExp(String.raw`\brequire\s*\(\s*${quoted}`, "g"),
  ];
  const findings: Finding[] = [];
  for (const re of patterns) {
    for (const m of code.matchAll(re)) {
      const line = code.slice(0, m.index).split("\n").length;
      findings.push({ file, line, text: (source.split("\n")[line - 1] ?? "").trim() });
    }
  }
  return findings;
}

describe("#78 — every real mediated builtin is captured in src/real-builtins.cts", () => {
  it("finds no import of a mediated builtin anywhere else in packages/core/src", () => {
    const offenders: Finding[] = [];
    for (const file of sourceFilesUnder(SRC_ROOT)) {
      const rel = path.relative(SRC_ROOT, file);
      if (rel === CAPTURE_FILE) continue; // the one file allowed to load a mediated builtin
      offenders.push(...mediatedImports(rel, readFileSync(file, "utf8")));
    }
    expect(
      offenders,
      `A mediated builtin is loaded outside src/${CAPTURE_FILE}. A static ESM import puts its ` +
        `node: URL in the ESM module cache before capwall's loader hook registers, and a URL in ` +
        `that cache never consults the load chain — which silently turns the load()-level ` +
        `re-mediation backstop back into dead code for that specifier (issue #78). Import it ` +
        `from ../real-builtins.cjs instead. Offenders:\n` +
        offenders.map((o) => `  ${o.file}:${o.line}  ${o.text}`).join("\n"),
    ).toEqual([]);
  });

  it("is a scan that actually fires — the pre-#78 shape is detected", () => {
    // Worth nothing unless it catches the exact shape it forbids: every spelling that was in the
    // tree before this change, plus the two lazy ones.
    const preFix = `
      import realFs from "node:fs";
      import { readFile } from "node:fs/promises";
      import { register } from "node:module";
      import "child_process";
      const vm = await import("node:vm");
      const net = require("net");
    `;
    expect(mediatedImports("fake.ts", preFix).length).toBe(6);
  });

  it("does not fire on prose, or on a type-only reference", () => {
    // Every shim's public signature is written as `typeof import("node:fs")`, which `tsc` erases;
    // and the shims explain in comments precisely which import they must not contain.
    const benign = `
      /** The real fs never arrives via \`import realFs from "node:fs"\`. */
      // import { createRequire } from "node:module";
      import * as path from "node:path";
      import { fileURLToPath } from "node:url";
      import type { Server } from "node:http";
      export function createFsShim(): typeof import("node:fs") { return realFs; }
      const x: typeof import("node:child_process") = realChildProcess;
    `;
    expect(mediatedImports("fake.ts", benign)).toEqual([]);
  });

  it("captures every builtin loader/require.ts declares mediated", () => {
    // Half-adding a capability — a new entry in MEDIATED_MODULES whose real module still arrives
    // through an ESM import somewhere — would pass the scan above only by having no capture at
    // all, so the two checks have to be read together.
    const capture = stripComments(readFileSync(path.join(SRC_ROOT, CAPTURE_FILE), "utf8"));
    const captured = [...capture.matchAll(/\brequire\(\s*["']([^"']+)["']\s*\)/g)]
      .map((m) => m[1] ?? "")
      .sort();
    expect(
      captured,
      `src/${CAPTURE_FILE} must capture exactly the builtins loader/require.ts mediates — no ` +
        `more (an un-mediated module does not belong here) and no less (a mediated module with ` +
        `no capture has to be imported from somewhere, which puts it back in the ESM cache).`,
    ).toEqual(MEDIATED_BUILTINS);
  });

  it("is never reached lazily — the no-recursion argument depends on static evaluation", () => {
    // `require("node:fs")` inside the capture returns the REAL fs only while `Module._load` is
    // unpatched. That holds because the capture sits in `index.js`'s static import graph and ES
    // module evaluation finishes the whole graph before `install()` can be called. A dynamic
    // `import("../real-builtins.cjs")` would break exactly that argument — and the failure mode
    // is a shim capturing a shim, i.e. a stack overflow at install time.
    const offenders: Finding[] = [];
    for (const file of sourceFilesUnder(SRC_ROOT)) {
      const code = stripComments(readFileSync(file, "utf8"));
      for (const m of code.matchAll(/\bimport\s*\(\s*["'][^"']*real-builtins[^"']*["']/g)) {
        const line = code.slice(0, m.index).split("\n").length;
        offenders.push({ file: path.relative(SRC_ROOT, file), line, text: m[0] });
      }
    }
    expect(offenders, "real-builtins.cjs must be imported statically — see the header").toEqual([]);
  });
});

describe("#78 — the capture is the genuine builtin, not one of capwall's own shims", () => {
  it.skipIf(GET_BUILTIN_MODULE === undefined)("still matches process.getBuiltinModule after a real install()", () => {
    // The runtime post-condition behind the ordering argument. If the capture ever ran after
    // `Module._load` was patched, `require("node:fs")` would have handed back the fs SHIM and
    // every guarded call would be double-mediated — silently, since a shim over a shim still
    // enforces. `process.getBuiltinModule` is the one reference to the real module a mediated
    // process retains (Node ≥20.16 / ≥22.3; skipped where absent rather than guessed at).
    // `skipIf` at the `it`, not `if (…) return` in the body: this is the single strongest
    // anti-double-mediation assertion in the repo, and a silent no-op is how it would disappear
    // without anyone noticing on a runtime that dropped the API (#112).
    const getBuiltinModule = GET_BUILTIN_MODULE!;

    const captures: ReadonlyArray<readonly [string, unknown]> = [
      ["node:fs", realBuiltins.realFs],
      ["node:fs/promises", realBuiltins.realFsPromises],
      ["node:net", realBuiltins.realNet],
      ["node:http", realBuiltins.realHttp],
      ["node:https", realBuiltins.realHttps],
      ["node:tls", realBuiltins.realTls],
      ["node:http2", realBuiltins.realHttp2],
      ["node:dgram", realBuiltins.realDgram],
      ["node:child_process", realBuiltins.realChildProcess],
      ["node:worker_threads", realBuiltins.realWorkerThreads],
      ["node:vm", realBuiltins.realVm],
      ["node:module", realBuiltins.realModule],
    ];
    // Named individually so this fails if a capture is added and not checked here.
    expect(captures.map(([spec]) => spec).sort()).toEqual(MEDIATED_BUILTINS);

    const handle = install(
      loadPolicyFromObject({ version: 1, mode: "enforce", packages: {} }, { projectRoot: here }),
      "enforce",
      { projectRoot: here },
    );
    try {
      for (const [spec, captured] of captures) {
        expect(captured, `${spec} was captured as something other than the real builtin`).toBe(
          getBuiltinModule.call(process, spec),
        );
      }
    } finally {
      handle.uninstall();
    }
  });
});
