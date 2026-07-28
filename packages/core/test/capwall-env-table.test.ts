/**
 * THE `CAPWALL_*` TABLE STAYS COMPLETE (issue #139).
 *
 * The preload is configured entirely through environment variables, because a `--import` entry
 * has no other channel. `src/preload.ts`'s header documents them and ends with a claim —
 * *"That is the complete set — capwall reads no other CAPWALL_* variable"* — which is exactly
 * the kind of sentence that stops being true without anybody noticing. It has already shipped
 * false twice: `CAPWALL_ALLOW_LOADER_HOOKS` (#61, read in `shims/module.ts` rather than in the
 * preload, so it was easy to miss) and `CAPWALL_GLOBAL_EGRESS` were both live and undocumented.
 *
 * An undocumented switch is worse here than in most projects. Every one of these changes what
 * capwall mediates — `CAPWALL_ESM=0` turns off the ESM gate, `CAPWALL_ALLOW_LOADER_HOOKS=1`
 * lets a dependency register a loader hook, `CAPWALL_MODE` decides whether anything is enforced
 * at all — so a variable nobody wrote down is a documented-away security control that an
 * operator cannot audit and an attacker with environment access can find by reading the source.
 *
 * Four checks, all derived rather than listed:
 *
 *   1. every `CAPWALL_*` the source READS is in the preload's table;
 *   2. every `CAPWALL_*` the source MENTIONS AT ALL is too — a superset of (1) that catches a
 *      variable set for a child process, or named in a message, or read through a spelling the
 *      read-scan does not know;
 *   3. every variable the table names is actually read somewhere (the other direction: a table
 *      entry for a variable that no longer exists is a lie in the other direction);
 *   4. `packages/core/README.md`'s copy of the table names the same set, and its stated count
 *      matches. The README says preload.ts is the authority; this is what makes that true.
 *
 * The scan DISCOVERS the names rather than listing them, so a variable added by a concurrent
 * branch (e.g. `CAPWALL_ENV`, #125) enrolls itself — the only thing that fails is adding one
 * without documenting it.
 */
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { blankNonCode, REPO_ROOT, workspaceSources } from "./helpers/source-scan.js";

const PRELOAD = path.join(REPO_ROOT, "packages", "core", "src", "preload.ts");
const README = path.join(REPO_ROOT, "packages", "core", "README.md");

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * THE SCANS
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

const NAME = String.raw`CAPWALL_[A-Z0-9_]*[A-Z0-9]`;

/**
 * Names READ out of the environment: `process.env["X"]`, `process.env.X`, and a destructuring
 * of `process.env`.
 *
 * Comments are blanked first (a doc comment naming a variable is the documentation, not a use);
 * string bodies are NOT, because here the string body IS the name.
 */
export function envReads(source: string): string[] {
  const code = blankNonCode(source, { strings: false });
  const names = new Set<string>();
  for (const m of code.matchAll(new RegExp(String.raw`process\.env\[\s*["'\`](${NAME})`, "g"))) {
    names.add(m[1]!);
  }
  for (const m of code.matchAll(new RegExp(String.raw`process\.env\.(${NAME})`, "g"))) {
    names.add(m[1]!);
  }
  for (const m of code.matchAll(/\{([^{}]*)\}\s*=\s*process\.env\b/g)) {
    for (const n of (m[1] ?? "").matchAll(new RegExp(NAME, "g"))) names.add(n[0]);
  }
  return [...names].sort();
}

/**
 * Every `CAPWALL_*` name the code mentions at all — reads, writes into a child's environment
 * (`capwall run` sets four), names embedded in warning messages. Comments blanked, strings kept.
 *
 * Deliberately broad. `CAPWALL_ALLOW_LOADER_HOOKS` is read in `shims/module.ts`, a thousand
 * lines from the table that documents it, and the read-shaped scan above is exactly the kind of
 * thing that gets outrun by a new spelling. Anything the source says out loud must be written
 * down; over-capturing costs a doc line.
 *
 * MINUS this file's own bindings. `attribution/index.ts` and `loader/module-read.ts` each
 * declare `const CAPWALL_ROOT = …`, the directory capwall itself lives in — a SCREAMING_CASE
 * local that collides with the env-var convention and is not an environment variable at all.
 * A name that is declared here is this file's own; a name that is not came from outside.
 */
export function envMentions(source: string): string[] {
  const code = blankNonCode(source, { strings: false });
  const declared = new Set(
    [...code.matchAll(new RegExp(String.raw`\b(?:const|let|var)\s+(${NAME})\b`, "g"))].map(
      (m) => m[1]!,
    ),
  );
  const all = [...new Set([...code.matchAll(new RegExp(NAME, "g"))].map((m) => m[0]))];
  return all.filter((name) => !declared.has(name)).sort();
}

/**
 * The variables documented in `preload.ts`'s header table — a name at the start of a doc line,
 * which is the table's shape. Prose mentions inside a description ("Raise CAPWALL_MAX_FRAMES
 * if…") are indented under an entry and never start one, so they are not entries.
 */
export function documentedInPreload(source: string): string[] {
  const header = source.slice(0, source.indexOf("*/"));
  const re = new RegExp(String.raw`^\s*\*\s{2,}(${NAME})(?:\s|$)`, "gm");
  return [...new Set([...header.matchAll(re)].map((m) => m[1]!))].sort();
}

/** The variables in the README's table — one per row, in the leading cell. */
export function documentedInReadme(markdown: string): string[] {
  const re = new RegExp(String.raw`^\|\s*\`(${NAME})\`\s*\|`, "gm");
  return [...new Set([...markdown.matchAll(re)].map((m) => m[1]!))].sort();
}

const SOURCES = workspaceSources().map(({ rel, file }) => ({
  rel,
  source: readFileSync(file, "utf8"),
}));

const PRELOAD_SOURCE = readFileSync(PRELOAD, "utf8");
const README_SOURCE = readFileSync(README, "utf8");
const DOCUMENTED = documentedInPreload(PRELOAD_SOURCE);

/** `{ name → where it was seen }`, so a failure says which file to look at. */
function locate(pick: (source: string) => string[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const { rel, source } of SOURCES) {
    for (const name of pick(source)) {
      out.set(name, [...(out.get(name) ?? []), rel]);
    }
  }
  return out;
}

const READS = locate(envReads);
const MENTIONS = locate(envMentions);

const TABLE_HINT =
  `The table is the doc comment at the top of packages/core/src/preload.ts, and it is mirrored ` +
  `in packages/core/README.md § Environment variables (both, or this fails). An undocumented ` +
  `CAPWALL_* variable is a switch on capwall's own mediation that an operator cannot audit — ` +
  `#61's CAPWALL_ALLOW_LOADER_HOOKS and CAPWALL_GLOBAL_EGRESS both shipped that way.`;

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 1. THE TABLE IS COMPLETE, AND HONEST
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("#139 — every CAPWALL_* variable the code uses is documented", () => {
  it("documents every one that is READ", () => {
    const undocumented = [...READS.entries()].filter(([name]) => !DOCUMENTED.includes(name));
    expect(
      undocumented.map(([name, files]) => `${name} (read in ${files.join(", ")})`),
      `A CAPWALL_* variable is read but not documented. ${TABLE_HINT}`,
    ).toEqual([]);
  });

  it("documents every one that is MENTIONED anywhere in packages/*/src", () => {
    // Broader than the read scan on purpose: `capwall run`/`observe`/`diff` SET these on the
    // child, which is a use of the same contract from the other end.
    const undocumented = [...MENTIONS.entries()].filter(([name]) => !DOCUMENTED.includes(name));
    expect(
      undocumented.map(([name, files]) => `${name} (in ${files.join(", ")})`),
      `A CAPWALL_* variable is used but not documented. ${TABLE_HINT}`,
    ).toEqual([]);
  });

  it("names nothing that does not exist", () => {
    // The other direction. A table entry for a variable nothing reads is an instruction to
    // operators that does nothing — and it stays plausible forever, because it looks documented.
    const phantom = DOCUMENTED.filter((name) => !READS.has(name));
    expect(
      phantom,
      `The preload's table documents a CAPWALL_* variable that no source file reads. Either the ` +
        `read was removed and the row should go, or the row is a typo. ${TABLE_HINT}`,
    ).toEqual([]);
  });

  it("is non-trivially populated — the scan found the table and the reads", () => {
    // Guards against the failure mode where a regex stops matching and every check above
    // passes vacuously: two empty sets are equal.
    expect(DOCUMENTED.length).toBeGreaterThanOrEqual(9);
    expect(DOCUMENTED).toContain("CAPWALL_MODE");
    expect(DOCUMENTED).toContain("CAPWALL_ALLOW_LOADER_HOOKS"); // #61, the one read elsewhere
    expect([...READS.keys()].length).toBeGreaterThanOrEqual(9);
    expect(READS.get("CAPWALL_ALLOW_LOADER_HOOKS")).toEqual(["core/src/shims/module.ts"]);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 2. THE README'S COPY SAYS THE SAME THING
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("#139 — the README's copy of the table matches the preload's", () => {
  it("names exactly the same variables", () => {
    expect(
      documentedInReadme(README_SOURCE),
      `packages/core/README.md § Environment variables disagrees with preload.ts's header. The ` +
        `README says preload.ts is the authority when the two differ — so update the README.`,
    ).toEqual(DOCUMENTED);
  });

  it("states a count that matches", () => {
    // "That is the complete list — nine variables, and capwall reads no other CAPWALL_* one."
    const words = [
      "zero",
      "one",
      "two",
      "three",
      "four",
      "five",
      "six",
      "seven",
      "eight",
      "nine",
      "ten",
      "eleven",
      "twelve",
    ];
    const re = new RegExp(String.raw`\b(${words.join("|")})\b\*{0,2}\s+variables\b`, "gi");
    const stated = [...new Set([...README_SOURCE.matchAll(re)].map((m) => m[1]!.toLowerCase()))];
    expect(
      stated,
      `packages/core/README.md states a number of environment variables that is not the number ` +
        `of rows in the table. Documented: ${DOCUMENTED.join(", ")}`,
    ).toEqual([words[DOCUMENTED.length]]);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 3. THE META-TESTS — does the scan fire, and does it stay off prose?
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("#139 — the CAPWALL_* scan fires on a real regression", () => {
  it("sees the read shapes, including the one that is not in preload.ts", () => {
    const source = `
      const mode = process.env["CAPWALL_MODE"];
      if (process.env["CAPWALL_ALLOW_LOADER_HOOKS"] === "1") return;
      const esm = process.env.CAPWALL_ESM !== "0";
      const { CAPWALL_HARDENED } = process.env;
      const raw = process.env[\`CAPWALL_TRACE_FILE\`];
    `;
    expect(envReads(source)).toEqual([
      "CAPWALL_ALLOW_LOADER_HOOKS",
      "CAPWALL_ESM",
      "CAPWALL_HARDENED",
      "CAPWALL_MODE",
      "CAPWALL_TRACE_FILE",
    ]);
  });

  it("catches the two that really shipped undocumented", () => {
    // The regression, exactly: the reads existed, the table did not have them.
    const table = documentedInPreload(`/**
 * Configured through environment variables:
 *   CAPWALL_MODE          "observe" | "enforce"
 *   CAPWALL_POLICY_FILE   path to capabilities.json
 *
 * That is the complete set.
 */
const x = 1;`);
    expect(table).toEqual(["CAPWALL_MODE", "CAPWALL_POLICY_FILE"]);
    const reads = envReads(`
      const egress = process.env["CAPWALL_GLOBAL_EGRESS"] !== "0";
      if (process.env["CAPWALL_ALLOW_LOADER_HOOKS"] === "1") return;
    `);
    expect(reads.filter((name) => !table.includes(name))).toEqual([
      "CAPWALL_ALLOW_LOADER_HOOKS",
      "CAPWALL_GLOBAL_EGRESS",
    ]);
  });

  it("does not read the table out of prose, or a description, or a comment", () => {
    // The header's descriptions mention other variables mid-sentence, and `attribution/index.ts`
    // and the CLI discuss `CAPWALL_MAX_FRAMES` in comments. Neither is a table entry, and
    // neither is a read.
    const source = `/**
 *   CAPWALL_MODE          "observe" | "enforce" — wins over the policy's own mode. An
 *                         unrecognized CAPWALL_MODE is inert. Raise CAPWALL_MAX_FRAMES if a
 *                         deep dependency stack is involved.
 */
// process.env["CAPWALL_INVENTED"] — described, never read
const note = "raise CAPWALL_MAX_FRAMES";`;
    expect(documentedInPreload(source)).toEqual(["CAPWALL_MODE"]);
    expect(envReads(source)).toEqual([]);
    // A name inside a live string IS a mention, though — that is the point of the broad scan.
    expect(envMentions(source)).toEqual(["CAPWALL_MAX_FRAMES"]);
  });

  it("does not mistake a SCREAMING_CASE local for an environment variable", () => {
    // The real shape, found by this scan on its first run: `CAPWALL_ROOT` is the directory
    // capwall's own code lives in (`attribution/index.ts`, `loader/module-read.ts`), used to
    // skip capwall's frames during a stack walk. It is a local binding, not a switch.
    const source = `
      const CAPWALL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
      if (source.startsWith(CAPWALL_ROOT + path.sep)) continue;
    `;
    expect(envMentions(source)).toEqual([]);
    // But reading one out of the environment under the same name would still count.
    expect(envMentions(`const x = process.env["CAPWALL_ROOT"];`)).toEqual(["CAPWALL_ROOT"]);
  });

  it("reads a README table row, and not the prose around it", () => {
    const markdown = [
      "| Variable | Default | What it does |",
      "|---|---|---|",
      "| `CAPWALL_MODE` | *(unset)* | `observe` or `enforce`. |",
      "| `CAPWALL_ESM` | on | `0` disables the ESM loader hook. |",
      "",
      "That is the complete list — two variables. `CAPWALL_MODE` outranks everything.",
    ].join("\n");
    expect(documentedInReadme(markdown)).toEqual(["CAPWALL_ESM", "CAPWALL_MODE"]);
  });
});
