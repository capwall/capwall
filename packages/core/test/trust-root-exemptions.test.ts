/**
 * THE `<app>` EXEMPTION INVENTORY, ENFORCED (issue #139).
 *
 * `<app>` is the trust root, and several gates wave it through before consulting the policy.
 * How many is "several" was, until this file, a number derived from the code and maintained by
 * hand in four documents. It said **two** for three releases while three more exemptions were
 * added by later PRs; the #117/#121 docs pass corrected it to **four**, and it was **five** by
 * the time that branch merged, because #123 landed in between.
 *
 * That is not a docs-diligence problem — nobody was careless. It is a hand-maintained
 * derivation, in the document people use to reason about trust, over the one part of the system
 * where this project's bugs actually live:
 *
 *  - `<app>` being inferred rather than identified WAS issue #60: attribution fell off the end
 *    of the stack into the trust root, so a dependency with zero grants collected every
 *    exemption on this list.
 *  - `<app>` holds the identity-granting `compile` capability with no grant at all — this
 *    repo's threat model calls `compile` "a grant of every other grant", and `guardCompile`
 *    returns before the policy is consulted. It is the sharpest item in the model.
 *
 * So the point of this file is NOT the count. It is that **adding an exemption is a deliberate
 * act that fails a test until someone records it**, rather than a two-line change nobody
 * notices. Three checks, in the shape #107 established:
 *
 *   1. **THE EXEMPTION INVENTORY.** Every early return on the trust root in `packages/*​/src`
 *      must appear in {@link REVIEWED_EXEMPTIONS}, with the gate it belongs to.
 *   2. **EVERY OTHER MENTION IS RECORDED TOO.** `APP_ROOT` is compared in places that are not
 *      exemptions (`ownerOfAddon` deliberately does NOT exempt the app). Those are pinned as
 *      well, so an exemption written in a shape the classifier does not recognize still fails —
 *      it arrives as an unrecorded non-exemption rather than slipping through as nothing.
 *   3. **THE DOCUMENTS AGREE.** The four documents that carry this list state the count in
 *      words; the count derived here has to match all four.
 *
 * WHY THE SOURCE IS BLANKED FIRST. `attribution/index.ts` mentions the trust root in a dozen
 * doc comments, all of them explaining why its exemptions are dangerous — prose about the rule,
 * not the rule. `helpers/source-scan.ts` (#107's technique) blanks comments and string bodies
 * with the offsets preserved, so those cannot be counted and line numbers still work.
 */
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { blankNonCode, REPO_ROOT, workspaceSources } from "./helpers/source-scan.js";

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * THE SCAN
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

/**
 * An early return on the trust root: `if (… === APP_ROOT …) return;` / `return null;` — the
 * shape every one of today's exemptions is written in, allowing for a braced body and for extra
 * conditions (an exemption with MORE conditions is still an exemption, so matching loosely here
 * is the safe direction).
 */
const EXEMPTION = /if\s*\([^)]*\bAPP_ROOT\b[^)]*\)\s*(?:\{\s*)?return\s*(?:null|undefined)?\s*;/;

export interface TrustRootSite {
  /** Path relative to `packages/`, e.g. `core/src/shims/env.ts`. */
  file: string;
  /** Enclosing function — the identity that survives an edit above it, unlike a line number. */
  fn: string;
  line: number;
  /** Does it wave the trust root past a gate? */
  exemption: boolean;
  /** The source line, for the failure message. */
  text: string;
}

/**
 * Every place the source names the trust root, classified.
 *
 * Import/export specifiers are dropped: `import { APP_ROOT } from …` names it without doing
 * anything with it, and a scan that reported those would be a list of files rather than a list
 * of decisions.
 */
export function trustRootSites(file: string, source: string): TrustRootSite[] {
  const code = blankNonCode(source);
  const spans: [number, number][] = [];
  for (const m of code.matchAll(/\b(?:import|export)\b[^;]*?\bfrom\b[^;]*;/g)) {
    spans.push([m.index, m.index + m[0].length]);
  }
  const lines = source.split("\n");
  const found: TrustRootSite[] = [];
  for (const m of code.matchAll(/\bAPP_ROOT\b/g)) {
    const at = m.index;
    if (spans.some(([a, b]) => at >= a && at < b)) continue;
    const before = code.slice(0, at);
    const line = before.split("\n").length;
    // The nearest `function NAME` above it. Nested helpers count — `shims/env.ts`'s exemption
    // lives in `decide`, inside the proxy factory, and "which function decides" is the useful
    // identity.
    const fn = [...before.matchAll(/\bfunction\s+([A-Za-z_$][\w$]*)/g)].pop()?.[1] ?? "(top level)";
    // From the start of the enclosing statement to a little past the mention: enough to see
    // `if (…) return;` without running into the next statement.
    const stmtStart = Math.max(
      before.lastIndexOf(";"),
      before.lastIndexOf("{"),
      before.lastIndexOf("}"),
      before.lastIndexOf("\n"),
    );
    found.push({
      file,
      fn,
      line,
      exemption: EXEMPTION.test(code.slice(stmtStart + 1, at + 200)),
      text: (lines[line - 1] ?? "").trim(),
    });
  }
  return found;
}

const SOURCES = workspaceSources().map(({ rel, file }) => ({
  rel,
  source: readFileSync(file, "utf8"),
}));

const SITES: TrustRootSite[] = SOURCES.flatMap(({ rel, source }) => trustRootSites(rel, source));

/** `{ file, fn }` pairs, deduplicated and sorted — an identity that survives a line moving. */
const identities = (sites: readonly TrustRootSite[]): string[] =>
  [...new Set(sites.map((s) => `${s.file} :: ${s.fn}`))].sort();

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 1. THE EXEMPTION INVENTORY
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

/**
 * Every gate `<app>` is waved past, and where. **This is the artifact the four documents
 * describe** — `docs/threat-model.md` § Attribution outcomes, `docs/architecture.md`,
 * `docs/policy-format.md` and `packages/core/README.md` all carry this table in prose, and the
 * count check below holds them to it.
 *
 * `gate` groups SITES into the gates the documents count: the module-load read gate (#123) is
 * one gate implemented twice, once for CJS and once for ESM, because the ESM resolve hook takes
 * its subject from `parentURL` — the host's own record of which module contains the `import` —
 * rather than from a stack walk. See `loader/module-read.ts` § `decideEsmModuleRead`.
 *
 * ADDING A ROW IS ADDING AN EXEMPTION. Say in the PR why the trust root may skip that gate, and
 * update the four documents — the count is stated in words in all of them.
 */
const REVIEWED_EXEMPTIONS: ReadonlyArray<{ file: string; fn: string; gate: string }> = [
  {
    file: "core/src/shims/env.ts",
    fn: "decide",
    gate: "process.env reads",
  },
  {
    file: "core/src/shims/net.ts",
    fn: "guardDgram",
    gate: "dgram send/connect",
  },
  {
    file: "core/src/shims/module.ts",
    fn: "guardRegistration",
    gate: "loader-hook registration (#61)",
  },
  {
    file: "core/src/shims/module.ts",
    fn: "guardCompile",
    // The consequential one: `compile` is identity-granting, and `<app>` holds it for free.
    gate: "Module.prototype._compile (#93)",
  },
  {
    file: "core/src/loader/module-read.ts",
    fn: "guardCjsModuleRead",
    gate: "module-load read (#123)",
  },
  {
    file: "core/src/loader/module-read.ts",
    fn: "decideEsmModuleRead",
    gate: "module-load read (#123)",
  },
];

/** The four documents that carry the list in prose. Named in the failure messages. */
const DOCUMENTS = [
  "docs/threat-model.md",
  "docs/architecture.md",
  "docs/policy-format.md",
  "packages/core/README.md",
] as const;

const GATES = [...new Set(REVIEWED_EXEMPTIONS.map((e) => e.gate))];

const UPDATE_HINT =
  `Update REVIEWED_EXEMPTIONS in this file, and the count stated in ${DOCUMENTS.join(", ")}. ` +
  `An exemption means the trust root skips a gate entirely — say in the PR why that is safe. ` +
  `Note that '<app>' is a POSITIVE identification (#60): an unattributable call is '<unknown>' ` +
  `and gets none of this.`;

describe("#139 — the <app> exemptions are exactly the reviewed set", () => {
  it("finds no early return on the trust root that is not recorded", () => {
    const actual = identities(SITES.filter((s) => s.exemption));
    const reviewed = identities(
      REVIEWED_EXEMPTIONS.map((e) => ({ ...e, line: 0, exemption: true, text: "" })),
    );
    expect(
      actual,
      `The set of <app> exemptions changed. ${UPDATE_HINT}\nFound:\n` +
        SITES.filter((s) => s.exemption)
          .map((s) => `  ${s.file}:${s.line}  ${s.fn}  ${s.text}`)
          .join("\n"),
    ).toEqual(reviewed);
  });

  it("counts one exemption per reviewed site — no gate exempts the app twice", () => {
    // Two early returns in one function would be one identity above and two exemptions here;
    // that is a shape worth looking at rather than waving through.
    expect(SITES.filter((s) => s.exemption).length).toBe(REVIEWED_EXEMPTIONS.length);
  });

  it("pins every OTHER mention of the trust root too", () => {
    // The half that closes the classifier's blind spot. An exemption written in a shape
    // `EXEMPTION` does not match (`if (isTrustRoot(pkg)) return;`, a ternary, an early return
    // two statements down) still lands here as an unrecorded mention and fails.
    //
    // Each of these was read and is NOT an exemption:
    //  - `attribution/index.ts` (top level) — the definition, `APP_ROOT = "<app>"`.
    //  - `walkFrames` — DOWNGRADES `<app>` to `<unknown>` below an opaque frame (#60). The
    //    opposite of an exemption.
    //  - `appOrUnattributed` — decides which of the two sentinels a path is, per #127.
    //  - `isDependencyGraphFile` — `owner !== APP_ROOT && owner !== UNATTRIBUTED`, a test for
    //    "is this file owned by a dependency", not a gate.
    //  - `ownerOfAddon` — the native gate deliberately does NOT exempt `<app>`; this narrows
    //    an un-owned addon outside the project to `<unknown>` (#60's shape, by another route).
    const reviewedOther = [
      "core/src/attribution/index.ts :: (top level)",
      "core/src/attribution/index.ts :: appOrUnattributed",
      "core/src/attribution/index.ts :: walkFrames",
      "core/src/loader/module-read.ts :: isDependencyGraphFile",
      "core/src/loader/native.ts :: ownerOfAddon",
    ];
    expect(
      identities(SITES.filter((s) => !s.exemption)),
      `The source names the trust root somewhere new. If it is an exemption, record it in ` +
        `REVIEWED_EXEMPTIONS. ${UPDATE_HINT}\nFound:\n` +
        SITES.filter((s) => !s.exemption)
          .map((s) => `  ${s.file}:${s.line}  ${s.fn}  ${s.text}`)
          .join("\n"),
    ).toEqual(reviewedOther);
  });

  it("keeps the trust root spelled APP_ROOT, so the scan can see it", () => {
    // Everything above matches the IDENTIFIER. A gate that wrote `if (pkg === "<app>") return;`
    // would be invisible: string bodies are blanked before matching (they have to be — the
    // documents' own prose lives in this repo's comments). One file may hold the literal.
    const offenders = SOURCES.filter(
      ({ rel, source }) =>
        rel !== path.join("core", "src", "attribution", "index.ts") &&
        /["']<app>["']/.test(blankNonCode(source, { strings: false })),
    ).map((s) => s.rel);
    expect(
      offenders,
      `Spell the trust root as the APP_ROOT constant, not as a "<app>" literal — the exemption ` +
        `scan in this file blanks string bodies before matching, so a literal is invisible to it.`,
    ).toEqual([]);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 2. THE META-TESTS — a scan is only worth what it catches.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

describe("#139 — the exemption scan fires on code and not on prose", () => {
  it("detects a NEW exemption, in each of the shapes one would be written in", () => {
    const added = `
      import { APP_ROOT } from "../attribution/index.js";
      function guardSomethingNew(ctx: ShimContext): void {
        const pkg = attributeCaller(attributionOptionsFor(ctx));
        if (pkg === APP_ROOT) return;
        guard(ctx, pkg);
      }
      function guardAnother(ctx: ShimContext): null {
        if (attribution.pkg === APP_ROOT) return null;
        return decide(ctx);
      }
      function guardBraced(ctx: ShimContext): void {
        if (pkg === APP_ROOT && ctx.mode === "enforce") {
          return;
        }
      }
    `;
    const sites = trustRootSites("fake.ts", added);
    expect(sites.filter((s) => s.exemption).map((s) => s.fn)).toEqual([
      "guardSomethingNew",
      "guardAnother",
      "guardBraced",
    ]);
    // …and the `import` line is not one of them.
    expect(sites).toHaveLength(3);
  });

  it("does not fire on the prose that surrounds every one of these gates", () => {
    // Lifted from `attribution/index.ts`, which is where this technique earns its keep: it
    // discusses the exemptions at length and holds none of them.
    const prose = `
      /**
       * Two events used to produce the same APP_ROOT answer. That was a fail-OPEN:
       * \`<app>\` is the trust root, exempt from four gates before the decision was
       * even taken — \`if (pkg === APP_ROOT) return;\` in four different shims.
       */
      // if (pkg === APP_ROOT) return null;
      const label = "<app>";
      const message = \`attributed to \${APP_ROOT} (the trust root)\`;
    `;
    expect(trustRootSites("fake.ts", prose).filter((s) => s.exemption)).toEqual([]);
  });

  it("does not call a non-exempting comparison an exemption", () => {
    // `ownerOfAddon`'s real shape: the native gate charges the app rather than excusing it.
    const notExempt = `
      function ownerOfAddon(ctx: ShimContext, addonPath: string): string {
        const pkg = packageForPath(addonPath, ctx.projectRoot);
        if (pkg !== APP_ROOT) return pkg;
        return insideProject ? APP_ROOT : UNATTRIBUTED;
      }
    `;
    const sites = trustRootSites("fake.ts", notExempt);
    expect(sites.map((s) => s.exemption)).toEqual([false, false]);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 3. THE DOCUMENTS — the same number, in four places, or the test fails.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

const NUMBER_WORDS = [
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
] as const;

/**
 * The counts a document states about gates, e.g. `exempt from **five** gates`. Markdown emphasis
 * is allowed between the word and the noun so a document may bold either. Returns every distinct
 * claim, so a document that says two different things fails on its own.
 */
export function statedGateCounts(markdown: string): string[] {
  const re = new RegExp(String.raw`\b(${NUMBER_WORDS.join("|")})\b\*{0,2}\s+gates\b`, "gi");
  return [...new Set([...markdown.matchAll(re)].map((m) => (m[1] ?? "").toLowerCase()))];
}

describe("#139 — the four documents state the count the code produces", () => {
  const expected = NUMBER_WORDS[GATES.length];

  for (const doc of DOCUMENTS) {
    it(`${doc} says "${expected} gates"`, () => {
      const text = readFileSync(path.join(REPO_ROOT, doc), "utf8");
      expect(
        statedGateCounts(text),
        `${doc} states a different number of <app> exemptions than the code has. The gates, ` +
          `derived from REVIEWED_EXEMPTIONS:\n` +
          GATES.map((g) => `  - ${g}`).join("\n") +
          `\nThe count is prose in ${DOCUMENTS.length} documents and drifts every time an ` +
          `exemption is added — that is exactly what #139 is about, so fix the document rather ` +
          `than this test unless an exemption really was added or removed.`,
      ).toEqual([expected]);
    });
  }

  it("reads a real count out of markdown, and is not fooled by a nearby number", () => {
    expect(statedGateCounts("exempt from **five** gates: env, dgram…")).toEqual(["five"]);
    expect(statedGateCounts("exempt from — five gates, not two.")).toEqual(["five"]);
    expect(statedGateCounts("the boolean gates (`vm`, `child_process`)")).toEqual([]);
    expect(statedGateCounts("four gates here and five gates there")).toEqual(["four", "five"]);
  });
});
