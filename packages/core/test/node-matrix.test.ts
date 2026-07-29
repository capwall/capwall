/**
 * THE SUPPORTED-NODE MATRIX IS ONE FACT, WRITTEN DOWN FIVE TIMES (issue #197).
 *
 * `scripts/ci-local.sh` says of its own default:
 *
 *   > KEEP THIS DEFAULT AND ci.yml's `node-version:` IN SYNC — the whole claim of this script is
 *   > "a green run here is a green CI run", and a local matrix narrower than the real one quietly
 *   > stops being true.
 *
 * and `AGENTS.md` § 6 repeats it ("Three copies of that fact have to move together"). Nothing
 * checked it. That matters more here than in most repos: GitHub Actions is billing-blocked (#3),
 * so `pnpm ci:local` **is** the gate, and the failure a drifting default produces is a green
 * local run that is not a green CI run — silently, in the direction of narrower coverage. It is
 * the same defect class as #139's `<app>` exemption count and #194's patch-site enumeration: a
 * number that lives in prose in N places and moves in one of them.
 *
 * The five copies, all derived below rather than listed:
 *
 *   1. `.github/workflows/ci.yml`'s `node-version:` matrix — the definition of "a green CI run";
 *   2. `.github/workflows/release.yml`'s matrix — the same build, before publishing;
 *   3. `scripts/ci-local.sh`'s `NODE_VERSIONS` default;
 *   4. a `ci:local:<version>` shortcut in the root manifest for each leg, so no leg is the
 *      awkward one to run (26 had none until #197, and 26 is the early-warning leg);
 *   5. `engines.node` in the root manifest and all four packages, whose major must be the floor
 *      of the matrix — a floor below the matrix is a version capwall claims to support and never
 *      builds on.
 */
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { REPO_ROOT } from "./helpers/source-scan.js";

const read = (...parts: string[]): string =>
  readFileSync(path.join(REPO_ROOT, ...parts), "utf8");

/**
 * The `node-version:` MATRIX in a workflow — a bracketed list, so the single
 * `node-version: 24` on release.yml's publish job (which runs once, not per version) is not
 * mistaken for one. Every matrix in the file is returned, so a second job with a narrower one
 * fails here rather than shipping.
 */
export function workflowMatrices(yaml: string): number[][] {
  return [...yaml.matchAll(/node-version:\s*\[([^\]]*)\]/g)].map((m) =>
    (m[1] ?? "")
      .split(",")
      .map((v) => Number(v.trim()))
      .filter((v) => Number.isFinite(v)),
  );
}

/** `NODE_VERSIONS=(${CI_NODE_VERSIONS:-22 24 26})` — the default inside the `:-` expansion. */
export function ciLocalDefault(shell: string): number[] {
  const m = /NODE_VERSIONS=\(\$\{CI_NODE_VERSIONS:-([^}]*)\}\)/.exec(shell);
  return [...(m?.[1] ?? "").matchAll(/\d+/g)].map((d) => Number(d[0]));
}

/** The `ci:local:<n>` shortcuts, and the version each actually passes to the script. */
export function ciLocalShortcuts(manifest: { scripts?: Record<string, string> }): number[] {
  const out: number[] = [];
  for (const [name, cmd] of Object.entries(manifest.scripts ?? {})) {
    const key = /^ci:local:(\d+)$/.exec(name);
    if (key === null) continue;
    const arg = /ci-local\.sh\s+(\d+)\s*$/.exec(cmd);
    // A shortcut whose name and argument disagree is worse than a missing one.
    expect(arg?.[1], `${name} does not pass ${key[1]} to ci-local.sh`).toBe(key[1]);
    out.push(Number(key[1]));
  }
  return out.sort((a, b) => a - b);
}

const CI = workflowMatrices(read(".github", "workflows", "ci.yml"));
const MATRIX = CI[0] ?? [];
const HINT =
  `The supported-Node matrix is one fact in five places: .github/workflows/ci.yml, ` +
  `.github/workflows/release.yml, scripts/ci-local.sh's NODE_VERSIONS default, the ` +
  `ci:local:<version> shortcuts in the root package.json, and engines.node in the root manifest ` +
  `plus all four packages. Move all five or none (AGENTS.md § 6).`;

describe("#197 — every copy of the supported-Node matrix agrees", () => {
  it("read a real matrix out of ci.yml", () => {
    // Two empty arrays are equal; without this, a regex that stopped matching passes everything.
    expect(MATRIX.length, `no node-version: [...] matrix found in ci.yml`).toBeGreaterThanOrEqual(
      2,
    );
    expect(MATRIX).toEqual([...MATRIX].sort((a, b) => a - b));
  });

  it("ci.yml and release.yml build the same versions", () => {
    for (const m of [...CI, ...workflowMatrices(read(".github", "workflows", "release.yml"))]) {
      expect(m, HINT).toEqual(MATRIX);
    }
  });

  it("scripts/ci-local.sh defaults to that matrix", () => {
    expect(
      ciLocalDefault(read("scripts", "ci-local.sh")),
      `scripts/ci-local.sh's default matrix is not ci.yml's. A local matrix narrower than the ` +
        `real one makes "a green run here is a green CI run" false, silently. ${HINT}`,
    ).toEqual(MATRIX);
  });

  it("every leg has a one-word ci:local shortcut", () => {
    const manifest = JSON.parse(read("package.json")) as { scripts?: Record<string, string> };
    expect(
      ciLocalShortcuts(manifest),
      `A leg of the matrix has no ci:local:<version> script. 26 had none until #197 — and 26 is ` +
        `the leg AGENTS.md calls early warning, the one that caught module.register()'s DEP0205 ` +
        `and six new globals. ${HINT}`,
    ).toEqual(MATRIX);
  });

  it("engines.node's floor is the matrix's floor, in every manifest", () => {
    const manifests = [
      "package.json",
      ...["policy-schema", "core", "sbom-import", "cli"].map((p) =>
        path.join("packages", p, "package.json"),
      ),
    ];
    const floor = MATRIX[0];
    for (const rel of manifests) {
      const { engines } = JSON.parse(read(rel)) as { engines?: { node?: string } };
      const major = Number(/>=\s*(\d+)\./.exec(engines?.node ?? "")?.[1]);
      expect(major, `${rel} engines.node (${engines?.node}) is not the matrix floor. ${HINT}`).toBe(
        floor,
      );
    }
  });
});

describe("#197 — the scans fire on a real regression", () => {
  it("reads matrices, and ignores a single non-matrix node-version", () => {
    expect(
      workflowMatrices("        node-version: [22, 24, 26]\n          node-version: 24\n"),
    ).toEqual([[22, 24, 26]]);
    expect(workflowMatrices("node-version: [22,24]\nnode-version: [22, 24, 26]")).toEqual([
      [22, 24],
      [22, 24, 26],
    ]);
  });

  it("reads the shell default, and is not fooled by an override branch", () => {
    const shell = `
      if [ "$#" -gt 0 ]; then
        NODE_VERSIONS=("$@")
      else
        NODE_VERSIONS=(\${CI_NODE_VERSIONS:-22 24 26})
      fi
    `;
    expect(ciLocalDefault(shell)).toEqual([22, 24, 26]);
    expect(ciLocalDefault("NODE_VERSIONS=(${CI_NODE_VERSIONS:-22 24})")).toEqual([22, 24]);
    expect(ciLocalDefault("NODE_VERSIONS=(22 24 26)")).toEqual([]);
  });

  it("collects shortcuts by name, and rejects one that lies about its version", () => {
    expect(
      ciLocalShortcuts({
        scripts: { "ci:local": "bash scripts/ci-local.sh", "ci:local:22": "bash s/ci-local.sh 22" },
      }),
    ).toEqual([22]);
    expect(() =>
      ciLocalShortcuts({ scripts: { "ci:local:26": "bash scripts/ci-local.sh 24" } }),
    ).toThrow();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * THE OTHER PROSE COPY OF THE SAME FACT: how many manifests carry `engines`.
 *
 * #199 found `ci.yml` and `ci-local.sh` both saying "four manifests" when five carry `engines`
 * — the four packages and the private root. That is the identical defect one field over: a
 * count in prose, in three files, describing something the filesystem already knows. Asserted
 * here rather than corrected, for the same reason as everything else in this file.
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
] as const;

/** Every manifest in the workspace that declares an `engines.node` floor. */
export function manifestsWithEngines(): string[] {
  const roots = [
    "package.json",
    ...["policy-schema", "core", "sbom-import", "cli"].map((p) =>
      path.join("packages", p, "package.json"),
    ),
  ];
  return roots.filter((rel) => {
    const { engines } = JSON.parse(read(rel)) as { engines?: { node?: string } };
    return typeof engines?.node === "string";
  });
}

/**
 * Number words used to count manifests, but only where the sentence is ALSO about `engines`.
 * The window is what keeps this off "a version bump is all four manifests" — a true statement
 * about a different fact (only the four packages carry a version; the root is private).
 */
export function statedManifestCounts(text: string): string[] {
  const re = new RegExp(String.raw`\b(${NUMBER_WORDS.join("|")})\b\s+manifests?`, "gi");
  const out = new Set<string>();
  for (const m of text.matchAll(re)) {
    const window = text.slice(Math.max(0, m.index - 200), m.index + 200);
    if (/engines/i.test(window)) out.add(m[1]!.toLowerCase());
  }
  return [...out];
}

describe("#199 — every prose copy of the engines-manifest count is the real one", () => {
  const expected = NUMBER_WORDS[manifestsWithEngines().length];

  it("counted a plausible number of manifests", () => {
    expect(manifestsWithEngines().length).toBeGreaterThanOrEqual(4);
    expect(manifestsWithEngines()).toContain("package.json");
  });

  for (const rel of ["AGENTS.md", ".github/workflows/ci.yml", "scripts/ci-local.sh"]) {
    it(`${rel} says "${expected} manifests"`, () => {
      expect(
        statedManifestCounts(read(rel)),
        `${rel} states a number of manifests carrying \`engines\` that is not the number that ` +
          `do. They are: ${manifestsWithEngines().join(", ")}. The private root counts — it ` +
          `declares the floor for anyone running the repo's own scripts.`,
      ).toEqual([expected]);
    });
  }

  it("ignores a manifest count that is about something other than engines", () => {
    // AGENTS.md § 4's "a version bump is all four manifests" is true and must stay uncounted:
    // only the four PACKAGES carry a version, because the root is private.
    expect(statedManifestCounts("a version bump is all four manifests or none")).toEqual([]);
    expect(statedManifestCounts("`engines` in all five manifests (>=22.15.0)")).toEqual(["five"]);
  });
});
