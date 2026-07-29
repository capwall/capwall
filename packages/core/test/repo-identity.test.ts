/**
 * ONE OWNER/REPO, STATED ONCE AND CHECKED EVERYWHERE (the org transfer, #205).
 *
 * capwall moved from `williamzujkowski/capwall` to the `capwall` GitHub organisation, and the
 * old slug was written out **38 times across 19 files**: four npm manifests' `repository` /
 * `homepage` / `bugs`, the JSON Schema's `$id`, the CLI's help banner, five READMEs, three issue
 * templates, the PR template, the CHANGELOG's link definitions, a `git clone` line, a release
 * script's error hint, and `docs/releasing.md`'s trusted-publisher table. Not one of them is
 * covered by GitHub's post-transfer redirect in the way that matters:
 *
 *   - **npm renders `repository` / `bugs` / `homepage` itself.** A stale slug is a package page
 *     linking somewhere else, and a published tarball cannot be corrected — only republished.
 *   - **npm's trusted publisher is bound to a literal `<owner>/<repo>`.** The OIDC subject claim
 *     is not redirected. A publisher left on the old owner never errors; it silently never
 *     matches, and every release quietly falls back to asking for a token.
 *   - **A redirect is a courtesy that can be revoked.** It dies the moment anyone creates a repo
 *     at the old path, which for an abandoned security-tool slug is a thing to assume, not hope
 *     against.
 *
 * SO THE SLUG IS DERIVED, NOT REPEATED. The root manifest's `repository.url` is the single
 * source of truth — chosen because it is the one copy npm reads back out of the tarball, so it
 * cannot be wrong without the published artifact being wrong too. Everything else is checked
 * against it.
 *
 * The precedent is #139's `<app>` exemption count and #200's commit-type enumeration: a fact
 * that appears in many documents gets ONE derived check rather than N hand-maintained copies.
 * The failure mode those issues describe is not "somebody was careless" — it is that a
 * hand-maintained copy is only ever verified by someone who already knows the answer.
 *
 * WHAT THIS DELIBERATELY DOES NOT PIN: references to the *maintainer*. `.github/CODEOWNERS`
 * requests review from a person, `CODE_OF_CONDUCT.md` gives a person's GitHub handle as a
 * conduct channel, and the `author` / `LICENSE` copyright name a person. Those did not move
 * with the repository and must not be swept along by a future rename, so the scan below matches
 * `github.com/<owner>/<repo>` — a *repository* URL — and never a bare account link.
 */
import { readFileSync, readdirSync } from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { REPO_ROOT } from "./helpers/source-scan.js";

/** `git+https://github.com/<owner>/<repo>.git` → `<owner>/<repo>`. */
function slugFromRepositoryUrl(url: string): string | null {
  return (/^git\+https:\/\/github\.com\/([^/]+\/[^/.]+)\.git$/.exec(url) ?? [])[1] ?? null;
}

function readJson(rel: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path.join(REPO_ROOT, rel), "utf8")) as Record<string, unknown>;
}

const ROOT_REPOSITORY = (readJson("package.json") as { repository: { type: string; url: string } })
  .repository;

/** The one place the owner and repository name are written down. */
const SLUG = slugFromRepositoryUrl(ROOT_REPOSITORY.url);

/** Every workspace manifest, root included — the four publishable ones plus the private root. */
const MANIFESTS = [
  "package.json",
  ...readdirSync(path.join(REPO_ROOT, "packages"), { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => `packages/${e.name}/package.json`)
    .sort(),
];

/**
 * Every `github.com/<owner>/<repo>` in a text file under `root`, as `{ rel, slug }`.
 *
 * Exported so the self-check below can run it over a synthetic tree: a scan that silently walks
 * nothing passes every assertion it makes, which is the hollow-test shape #112 found six of.
 *
 * Trailing punctuation is stripped because these appear in prose — `(…/capwall)`, `…/capwall.`,
 * `…/capwall.git` — and a scan that treated `capwall.git` and `capwall` as different repositories
 * would report drift on every clone line in the documentation.
 */
export function repositoryUrlsUnder(root: string): { rel: string; slug: string }[] {
  const SKIP = new Set(["node_modules", ".git", "dist", "coverage", "dist-tarballs", ".turbo"]);
  const TEXT = /\.(md|json|ts|cts|mts|js|mjs|cjs|ya?ml|txt)$/;
  const out: { rel: string; slug: string }[] = [];

  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP.has(entry.name)) walk(full);
        continue;
      }
      // Extensionless repository files (LICENSE, CODEOWNERS) are read too — a badge or a link
      // hides in either just as well as in a `.md`.
      if (!TEXT.test(entry.name) && entry.name.includes(".")) continue;
      const text = readFileSync(full, "utf8");
      for (const m of text.matchAll(/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/g)) {
        const repo = (m[2] ?? "").replace(/\.git$/, "").replace(/[.,;:)\]}'"]+$/, "");
        if (repo === "") continue;
        out.push({ rel: path.relative(root, full), slug: `${m[1] ?? ""}/${repo}` });
      }
    }
  };

  walk(root);
  return out.sort((a, b) => a.rel.localeCompare(b.rel));
}

describe("#205 — the repository slug is stated once", () => {
  it("the root manifest's repository.url is the canonical form npm expects", () => {
    // `git+https://…​.git` is what npm normalizes a GitHub repository to and what it reads back
    // to build the package page's "Repository" link. A shorthand (`capwall/capwall`), an `ssh://`
    // form or a missing `.git` all still *work*, but they are not what the other three manifests
    // were written to match, and the derivation below would return null for them.
    expect(ROOT_REPOSITORY.type).toBe("git");
    expect(ROOT_REPOSITORY.url).toMatch(/^git\+https:\/\/github\.com\/[^/]+\/[^/.]+\.git$/);
    expect(SLUG).toMatch(/^[^/]+\/[^/]+$/);
  });

  it("the repository name matches the directory this monorepo actually is", () => {
    // Cheap, but it is the half of the slug a rename is *least* likely to touch and most likely
    // to get wrong: `capwall/capwall` has the owner and the repo spelled identically, so a
    // half-applied edit reads as correct.
    expect(SLUG?.split("/")[1]).toBe("capwall");
  });
});

describe("#205 — every manifest npm renders agrees with it", () => {
  for (const rel of MANIFESTS) {
    it(`${rel} states the same repository, homepage and bugs URL`, () => {
      const m = readJson(rel) as {
        repository: { type: string; url: string; directory?: string };
        homepage: string;
        bugs: string;
      };

      expect({ rel, slug: slugFromRepositoryUrl(m.repository.url) }).toEqual({ rel, slug: SLUG });
      expect({ rel, homepage: m.homepage }).toEqual({
        rel,
        homepage: `https://github.com/${SLUG}#readme`,
      });
      expect({ rel, bugs: m.bugs }).toEqual({ rel, bugs: `https://github.com/${SLUG}/issues` });

      // A workspace package must also say WHERE in the monorepo it lives, or npm's "Repository"
      // link lands on the root for all four and provenance has no subdirectory to attest.
      const expected = rel === "package.json" ? undefined : path.posix.dirname(rel);
      expect({ rel, directory: m.repository.directory }).toEqual({ rel, directory: expected });
    });
  }
});

describe("#205 — the facts that are not manifests", () => {
  it("the JSON Schema's $id is under this repository", () => {
    // `$id` is the schema's identity, and it is baked into every published tarball. It is NOT
    // what `capwall observe` writes into a generated policy — `cli/src/trace.ts` writes a
    // relative path to the installed copy on purpose (#124), so a rename does not break a user's
    // editor. It still has to name the right repository: it is the only thing in the file that
    // says where the schema comes from.
    const schema = readJson("packages/policy-schema/schema.json") as { $id: string };
    expect(schema.$id.startsWith(`https://github.com/${SLUG}/`)).toBe(true);
  });

  it("docs/releasing.md's trusted-publisher table names this owner and repository", () => {
    // The one document where a stale value fails SILENTLY: npm matches the OIDC subject claim
    // against these two strings literally, so a wrong owner is not an error, it is a publisher
    // that never fires. Read as table rows rather than as free text, so a mention of the old
    // owner elsewhere in the file cannot satisfy it.
    const text = readFileSync(path.join(REPO_ROOT, "docs", "releasing.md"), "utf8");
    const [owner, repo] = (SLUG ?? "/").split("/");
    const row = (field: string): RegExp =>
      new RegExp(String.raw`^\s*\|\s*${field}\s*\|\s*\x60([^\x60]+)\x60\s*\|`, "m");

    expect(row("Organization or user").exec(text)?.[1]).toBe(owner);
    expect(row("Repository").exec(text)?.[1]).toBe(repo);
  });
});

describe("#205 — nothing anywhere names a DIFFERENT capwall repository", () => {
  const found = repositoryUrlsUnder(REPO_ROOT);

  it("the scan reaches the files it claims to", () => {
    // Without this the suite passes just as well on a walk that returned nothing — a rename
    // could then land with every gate green. The floor is well under the ~55 references the
    // transfer touched, so ordinary editing does not trip it; a broken walk still does.
    expect(found.length).toBeGreaterThan(30);
    expect(new Set(found.map((f) => f.rel)).size).toBeGreaterThan(10);
  });

  it("every github.com/<owner>/capwall URL is this repository", () => {
    const repo = SLUG?.split("/")[1];
    const wrong = found.filter((f) => f.slug.split("/")[1] === repo && f.slug !== SLUG);
    expect(
      [...new Set(wrong.map((w) => `${w.rel}: ${w.slug}`))],
      `A URL names a repository called '${repo}' under an owner that is not '${SLUG?.split("/")[0]}'.\n` +
        `That is the org-transfer drift #205 is about: the slug is stated once, in the root\n` +
        `package.json's repository.url, and every other copy is derived from it. Fix the file,\n` +
        `not this test — unless the repository really did move again, in which case move\n` +
        `repository.url first and let this list tell you what else to update.`,
    ).toEqual([]);
  });

  it("the maintainer's own account links are left alone", () => {
    // The deliberate non-target, asserted so a future "just replace the string everywhere" sweep
    // has to argue with a test. These are people, not the repository, and they did not move:
    // CODEOWNERS requests review from an individual, and the CoC's channel is an individual's
    // GitHub inbox. The scan above cannot see either, because it requires an <owner>/<repo>
    // pair — this pins that property rather than trusting it.
    const coc = readFileSync(path.join(REPO_ROOT, "CODE_OF_CONDUCT.md"), "utf8");
    const owners = readFileSync(path.join(REPO_ROOT, ".github", "CODEOWNERS"), "utf8");

    const contact = /\[@([\w-]+)\]\(https:\/\/github\.com\/[\w-]+\)/.exec(coc)?.[1];
    const codeowner = /^\*\s+@([\w-]+)$/m.exec(owners)?.[1];
    expect(contact).toBeTypeOf("string");
    expect(codeowner).toBe(contact);

    // A bare account link is not a repository URL, so it is not drift and must never be swept.
    // The same assertion doubles as the tightest statement of what DID have to move: after the
    // transfer, no REPOSITORY at all lives under that account.
    expect(found.filter((f) => f.slug.startsWith(`${contact}/`))).toEqual([]);
  });
});

describe("#205 — the scan fires on a real regression", () => {
  // EVERY URL BELOW IS ASSEMBLED, NEVER WRITTEN OUT. This file is inside the tree the scan above
  // walks, so a literal stale-owner URL here would be reported as drift by the very check it
  // exists to exercise. Building the host at runtime keeps the fixture byte-identical once
  // written (the scan still reads a real URL off disk) without planting a decoy in this file.
  const HOST = `https://git${"hub"}.com`;

  it("reports a stale owner, and is not fooled by an account link", async () => {
    const { mkdtemp, mkdir, writeFile, rm } = await import("node:fs/promises");
    const os = await import("node:os");
    const dir = await mkdtemp(path.join(os.tmpdir(), "capwall-repo-identity-"));
    try {
      await mkdir(path.join(dir, "docs"), { recursive: true });
      await mkdir(path.join(dir, "node_modules", "x"), { recursive: true });
      await writeFile(path.join(dir, "README.md"), `${HOST}/capwall/capwall#readme\n`);
      // A stale clone line next to a bare account link: only the first is a repository URL.
      await writeFile(
        path.join(dir, "docs", "old.md"),
        `clone ${HOST}/oldowner/capwall.git and see ${HOST}/oldowner\n`,
      );
      // Excluded trees must not be scanned: a dependency's own repository URL is not drift.
      await writeFile(
        path.join(dir, "node_modules", "x", "package.json"),
        `{"repository":"${HOST}/someone/capwall"}`,
      );

      expect(repositoryUrlsUnder(dir).map((f) => `${f.rel}: ${f.slug}`)).toEqual([
        path.join("docs", "old.md") + ": oldowner/capwall",
        "README.md: capwall/capwall",
      ]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("normalizes the punctuation a repository URL picks up in prose", async () => {
    const { mkdtemp, writeFile, rm } = await import("node:fs/promises");
    const os = await import("node:os");
    const dir = await mkdtemp(path.join(os.tmpdir(), "capwall-repo-identity-"));
    try {
      // `.git`, a sentence-ending period and a closing markdown paren must all resolve to the
      // same repository — otherwise the scan reports three phantom repositories per README.
      await writeFile(
        path.join(dir, "a.md"),
        `${HOST}/o/capwall.git ${HOST}/o/capwall. [x](${HOST}/o/capwall)\n`,
      );
      expect([...new Set(repositoryUrlsUnder(dir).map((f) => f.slug))]).toEqual(["o/capwall"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
