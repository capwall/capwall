/**
 * THE MUTATION CATALOG STAYS HONEST — issue #112.
 *
 * `scripts/mutation-guard.mjs` answers the question #112 was opened over: *does this test still
 * pass with the mechanism it names deleted?* It does that by editing an exact anchor string out
 * of a source file and re-running only the tests that claim to cover it. That is a good check
 * and a fragile one, in one specific way: **an anchor that no longer matches makes its mutant a
 * no-op edit**, and a no-op edit is caught by nothing, forever, silently. Which is precisely the
 * class of defect the whole exercise exists to eliminate — so it would be a poor joke to leave
 * the guard itself vulnerable to it.
 *
 * This file is the cheap half that runs in the ordinary `pnpm test` (single-digit milliseconds,
 * no child processes, no mutation): every anchor still occurs EXACTLY ONCE in its file, every
 * mutation actually changes the text, every referenced source and test file exists. A refactor
 * that moves a guarded mechanism now breaks here — loudly, with the mutant's id and mechanism in
 * the message — instead of quietly retiring a mutant.
 *
 * The expensive half (`node scripts/mutation-guard.mjs`, ~2 minutes) is a manual/periodic gate
 * like `pnpm bench:gate`, because it runs vitest once per mutant plus a baseline.
 *
 * This is the same shape as the repo's other structural guards: the #107 source scan, the #109
 * patch-site inventory, the #103 option-parity matrix. Each one turns "someone has to remember"
 * into "the suite fails".
 */
import { existsSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, "..", "..", "..");
const CATALOG = path.join(REPO_ROOT, "scripts", "mutants.json");

interface Mutant {
  id: string;
  mechanism: string;
  file: string;
  anchor: string;
  mutation: string;
  tests: string[];
  needsBuild?: boolean;
  note?: string;
}

const MUTANTS: Mutant[] = (JSON.parse(readFileSync(CATALOG, "utf8")) as { mutants: Mutant[] })
  .mutants;

describe("mutation catalog (scripts/mutants.json) describes the code as it is now", () => {
  it("is non-empty and has unique ids", () => {
    expect(MUTANTS.length).toBeGreaterThan(0);
    expect(new Set(MUTANTS.map((m) => m.id)).size).toBe(MUTANTS.length);
  });

  for (const m of MUTANTS) {
    it(`${m.id} — anchor occurs exactly once in ${m.file}`, () => {
      const abs = path.join(REPO_ROOT, m.file);
      expect({ id: m.id, exists: existsSync(abs) }).toEqual({ id: m.id, exists: true });
      const source = readFileSync(abs, "utf8");
      const occurrences = source.split(m.anchor).length - 1;
      // An anchor that matches zero times makes the mutant a no-op; one that matches twice makes
      // `String.replace` edit only the first, so the mutation is partial and its verdict is not
      // trustworthy either.
      expect({ id: m.id, mechanism: m.mechanism, occurrences }).toEqual({
        id: m.id,
        mechanism: m.mechanism,
        occurrences: 1,
      });
    });

    it(`${m.id} — the mutation actually changes the source, and the tests it claims exist`, () => {
      expect(m.mutation).not.toBe(m.anchor);
      expect(m.tests.length).toBeGreaterThan(0);
      const missing = m.tests.filter((t) => !existsSync(path.join(REPO_ROOT, t)));
      expect({ id: m.id, missing }).toEqual({ id: m.id, missing: [] });
    });
  }
});
