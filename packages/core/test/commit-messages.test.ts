/**
 * THE COMMIT-MESSAGE GATE ACTUALLY FIRES, AND ITS TYPE LIST IS REALLY THE RELEASE CONFIG'S.
 *
 * `scripts/check-commit-messages.mjs` replaced commitlint — 68 packages of a 253-package dev
 * tree, measured from a clean resolve — with one file of Node built-ins. A replacement that is
 * merely *present* is worth nothing: the failure it exists to
 * stop — a commit release-please parses as nothing, so the change ships with no version bump and
 * no changelog line — is invisible until after a publish, which is the one thing in this
 * repository that cannot be undone. So every case here is a message that either MUST pass or MUST
 * fail, and the three that must fail are real subjects from this repository's own history
 * (`fs:`, `bench:`, `release:`), not invented ones.
 *
 * THE META-TEST IS THE POINT OF THE FILE. The validator claims it has no type list of its own —
 * that it reads `release-please-config.json`'s `changelog-sections`, so that the grammar and the
 * release pipeline cannot disagree about what `security:` or `perf:` means. A claim like that is
 * exactly the shape #112 found six hollow tests of: it passes just as well with a hardcoded array
 * that happens to match today. `describe("the type list is bound to release-please-config.json")`
 * proves it instead — it builds a throwaway tree with an INVENTED type in the config and asserts
 * the validator accepts it there and rejects it here.
 *
 * NOTHING RUNS AGAINST THIS REPOSITORY'S OWN GIT HISTORY. The range checks build a throwaway git
 * repo and commit into that, for the same reason `mutation-sentinel.test.ts` copies the tool into
 * a temp root: a test that reaches into the real working tree is a hazard, and a test pinned to
 * the real history would decay every time someone commits.
 */
import { execFileSync, spawnSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, "..", "..", "..");
const TOOL = path.join(REPO_ROOT, "scripts", "check-commit-messages.mjs");
const CONFIG = path.join(REPO_ROOT, "release-please-config.json");

const trees: string[] = [];
afterAll(() => {
  for (const dir of trees.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/**
 * Evaluate many messages in ONE child, against the copy of the tool at `tool`.
 *
 * The grammar is a pure function of (message, types), so a process per case would be ~40 spawns
 * to learn nothing extra. `node --input-type=module -e` leaves `process.argv[1]` undefined, which
 * is what the tool's entry-point guard keys on — importing it here runs no CLI.
 */
function check(messages: string[], tool: string = TOOL): { message: string; problems: string[] }[] {
  const url = JSON.stringify(pathToFileURL(tool).href);
  const program = `
    import { checkMessage, loadTypes } from ${url};
    const types = loadTypes();
    let raw = "";
    for await (const chunk of process.stdin) raw += chunk;
    process.stdout.write(JSON.stringify(JSON.parse(raw).map((m) => checkMessage(m, types))));
  `;
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", program], {
    input: JSON.stringify(messages),
    encoding: "utf8",
  });
  if (r.status !== 0) throw new Error(`harness failed (${r.status}): ${r.stderr}`);
  const results = JSON.parse(r.stdout) as string[][];
  // Paired with the input rather than indexed into: a result the harness did not return is a
  // failure, not an `undefined` that quietly satisfies an "is it empty?" assertion.
  return messages.map((message, i) => ({
    message,
    problems: results[i] ?? ["the harness returned no result for this message"],
  }));
}

/** One message, for the many cases where the pairing is not the interesting part. */
function checkOne(message: string, tool: string = TOOL): string[] {
  const [result] = check([message], tool);
  if (result === undefined) throw new Error("the harness returned nothing");
  return result.problems;
}

/** The tool's own CLI, exit code and all. */
function run(args: string[], opts: { cwd?: string; tool?: string } = {}) {
  const r = spawnSync(process.execPath, [opts.tool ?? TOOL, ...args], {
    cwd: opts.cwd ?? REPO_ROOT,
    encoding: "utf8",
  });
  return { status: r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

/** The accepted types, read the same way the tool reads them — from the config, not from here. */
const TYPES: string[] = (
  JSON.parse(readFileSync(CONFIG, "utf8")) as { "changelog-sections": { type: string }[] }
)["changelog-sections"].map((s) => s.type);

// -------------------------------------------------------------------------------------------

describe("every type release-please-config.json declares is accepted", () => {
  it("declares the types this repository actually uses", () => {
    // Not a tautology check: it fails if someone empties `changelog-sections`, which would make
    // every other assertion in this file vacuous.
    expect(TYPES).toContain("feat");
    expect(TYPES).toContain("fix");
    // `security` is this project's addition to the conventional set. It works because it is in
    // the config, which is the whole argument for reading the list from there.
    expect(TYPES).toContain("security");
    expect(TYPES.length).toBeGreaterThanOrEqual(10);
  });

  it("accepts each one bare, scoped, breaking, and scoped-and-breaking", () => {
    const messages = TYPES.flatMap((t) => [
      `${t}: a subject`,
      `${t}(core): a subject`,
      `${t}!: a subject`,
      `${t}(policy-schema)!: a subject`,
    ]);
    const rejected = check(messages).filter((r) => r.problems.length > 0);
    expect(rejected).toEqual([]);
  });

  it("accepts the shapes this repository's history is full of", () => {
    const messages = [
      // The longest subject in the history is 189 characters and names every issue it closes.
      // There is deliberately no length cap; this asserts that, rather than assuming it.
      `fix(fs): deliver deny-stream errors on handler-attach, not a fixed timer (#40); broaden fs shim test coverage (#23), and keep the safety-net timers unref'd so a hung child cannot outlive its parent (#48)`,
      "feat(core): M5 — ESM loader hook (import parity with CJS) (#47)",
      "security(core): decide the module read on the filename Node opens (#177)",
      "docs: rewrite the README around the observe→enforce journey",
      "chore(deps): bump vitest to 4.1.10",
      "refactor(core): shared shim-runtime helper + loader routing registry (#10) (#24)",
    ];
    expect(check(messages).flatMap((r) => r.problems)).toEqual([]);
  });

  it("accepts a BREAKING CHANGE footer, in both spellings the spec allows", () => {
    const messages = [
      "feat(policy): drop bare-name package keys\n\nBody text.\n\nBREAKING CHANGE: a bare \"lodash\" key now grants the top-level install only.",
      "feat(policy): drop bare-name package keys\n\nBREAKING-CHANGE: hyphenated is the other spelling the spec allows.",
      // `!` and a footer together, which is what a real breaking change usually looks like.
      "feat(policy)!: drop bare-name package keys\n\nBREAKING CHANGE: see docs/policy.md.",
    ];
    expect(check(messages).flatMap((r) => r.problems)).toEqual([]);
  });

  it("recognises `!` rather than rejecting it — the 0.x bump depends on it", () => {
    // `bump-minor-pre-major: true` is what keeps `feat!:` at 0.2.0 instead of 1.0.0. A validator
    // that rejected the marker would mean the breaking change reaches `main` without it.
    expect(checkOne("feat!: the marker parses")).toEqual([]);
  });
});

describe("rejects what release-please would silently drop", () => {
  // The three real subjects from this repository's history that parsed as nothing. Each of these
  // was a change that happened and a changelog entry that did not.
  const HISTORICAL: [string, string][] = [
    ["fs", "fs: gate the Node 22 glob family (#106), confirm latin1 byte-path decoding (#41) (#110)"],
    ["bench", "bench: add S4 performance benchmark harness (issue #14) (#35)"],
    [
      "release",
      "release: ship the sources so the maps mean something (#126); 0.1.0, lockstep, and a declared publish set (#115) (#144)",
    ],
  ];

  it("rejects the three types this history actually lost entries to", () => {
    for (const [type, message] of HISTORICAL) {
      const problems = checkOne(message).join("\n");
      expect({ type, rejected: problems !== "" }).toEqual({ type, rejected: true });
      // The message has to say what to do, not only what is wrong (#149).
      expect(problems).toContain(`'${type}' is not a type`);
      expect(problems).toContain("release-please-config.json");
    }
  });

  it("rejects a compound type and names the one to keep", () => {
    // Three of these are in the history too (`docs+cli:`, `docs+hygiene:`, `docs+hygiene+test:`).
    const problems = checkOne("docs+hygiene+test: post-registerHooks() residue (#174)");
    expect(problems.length).toBe(1);
    expect(problems.join("\n")).toContain("is a compound type");
    expect(problems.join("\n")).toContain("docs(hygiene): <subject>");
  });

  const MALFORMED: [string, string, string][] = [
    ["no type at all", "make the thing faster", "is not a conventional commit"],
    ["wrong case", "Feat(cli): add --explain", "wrong case"],
    ["no space after the colon", "feat(cli):add --explain", "exactly one space"],
    ["empty scope", "feat(): add --explain", "empty scope"],
    ["no subject", "feat(cli): ", "no subject"],
    ["empty message", "", "the message is empty"],
    ["a type that is only nearly right", "feats: add --explain", "is not a type"],
    [
      "body run into the subject",
      "feat(cli): add --explain\nIt prints the deciding rule.",
      "followed immediately by body text",
    ],
    [
      "a breaking-change footer release-please will not see",
      "feat(policy): drop bare keys\n\nBreaking change: bare keys are gone.",
      "neither a breaking-change footer nor safely not one",
    ],
    [
      "a breaking-change footer with no colon",
      "feat(policy): drop bare keys\n\nBREAKING CHANGE bare keys are gone.",
      "neither a breaking-change footer nor safely not one",
    ],
    [
      // Found by running the validator over its own commit, twice: a wrapped prose line that
      // begins with the words. Implementations disagree about leading whitespace on a note
      // keyword, so whether this moves the version is a property of the parser — and a version
      // bump must not be. Refusing it costs a reflowed paragraph.
      "an indented line that begins with the token",
      "chore(tooling): explain the rules\n\n  - the grammar covers BREAKING CHANGE: and\n" +
        "    BREAKING-CHANGE: footers, which is prose, not a footer",
      "spelled right and INDENTED",
    ],
  ];

  for (const [name, message, expected] of MALFORMED) {
    it(`rejects ${name}`, () => {
      const problems = checkOne(message);
      expect({ name, rejected: problems.length > 0 }).toEqual({ name, rejected: true });
      expect(problems.join("\n")).toContain(expected);
    });
  }
});

describe("the messages nothing generated by hand must keep passing", () => {
  // A validator that rejects any of these deadlocks a release or a merge: nobody can reword the
  // subject git wrote, and release-please regenerates its own PR title on every run.
  const GENERATED = [
    "Merge pull request #201 from williamzujkowski/chore/release-please-and-standards",
    "Merge branch 'main' into chore/zero-dep-commitlint",
    "Merge remote-tracking branch 'origin/main'",
    'Revert "feat(core): M5 — ESM loader hook (import parity with CJS) (#47)"',
    // release-please's generated release-PR title, which becomes the squash subject on `main`.
    "chore(main): release 0.2.0",
    "chore: release 0.2.0",
    // Rebase-todo markers: they are folded into another commit before the branch merges.
    "fixup! feat(cli): add --explain",
    "squash! feat(cli): add --explain",
    "Initial commit",
  ];

  for (const message of GENERATED) {
    it(`accepts ${JSON.stringify(message.slice(0, 48))}`, () => {
      expect({ message, problems: checkOne(message) }).toEqual({ message, problems: [] });
    });
  }
});

describe("the type list is bound to release-please-config.json", () => {
  /**
   * A throwaway root containing only the tool and a `release-please-config.json` whose
   * `changelog-sections` is `sections`. The tool derives its root from its own location, so this
   * is the whole of what it will read.
   */
  function treeWithTypes(types: string[]): string {
    const root = mkdtempSync(path.join(os.tmpdir(), "capwall-commitmsg-"));
    trees.push(root);
    mkdirSync(path.join(root, "scripts"), { recursive: true });
    copyFileSync(TOOL, path.join(root, "scripts", "check-commit-messages.mjs"));
    writeFileSync(
      path.join(root, "release-please-config.json"),
      JSON.stringify({ "changelog-sections": types.map((type) => ({ type, section: type })) }),
    );
    return path.join(root, "scripts", "check-commit-messages.mjs");
  }

  it("accepts a type that exists ONLY because the config declares it", () => {
    // `wibble` is not a conventional-commit type, is not in this repository's config, and is
    // nowhere in the validator. If the list were hardcoded, this fails.
    expect(checkOne("wibble: an invented type").length).toBeGreaterThan(0);

    const tool = treeWithTypes([...TYPES, "wibble"]);
    expect(checkOne("wibble: an invented type", tool)).toEqual([]);
    // …and the real types still work in that tree, i.e. the list was extended, not replaced.
    expect(checkOne("feat(core): still fine", tool)).toEqual([]);
  });

  it("rejects a type the config no longer declares", () => {
    // The other direction, which a hardcoded list would also get wrong: remove `security` from
    // the config and the grammar must lose it too, because release-please has.
    expect(checkOne("security(core): decide the module read on the filename Node opens")).toEqual(
      [],
    );

    const tool = treeWithTypes(TYPES.filter((t) => t !== "security"));
    const problems = checkOne("security(core): decide the module read", tool);
    expect(problems.length).toBe(1);
    expect(problems.join("\n")).toContain("'security' is not a type");
  });

  it("refuses to run at all if the config declares no sections", () => {
    const tool = treeWithTypes([]);
    const r = run(["--message", "feat: anything"], { tool });
    expect(r.status).toBe(1);
    expect(r.out).toContain("declares no 'changelog-sections'");
  });
});

describe("the documents that enumerate the types still enumerate all of them (#200)", () => {
  // The validator cannot drift from the release config — it reads it. Prose can, and did: the
  // CONTRIBUTING table shipped without `revert` in #201, which is the #200 failure exactly. Prose
  // cannot be bound the way code can, so it is checked instead.
  /** Each document's type enumeration, isolated so an unrelated "test" or "style" cannot pass. */
  const ENUMERATIONS: [string, string, RegExp][] = [
    // CONTRIBUTING.md § 3's table, from the header row to the blank line after it.
    ["CONTRIBUTING.md", "CONTRIBUTING.md", /\| type \| effect on the release \|[\s\S]*?\n\n/],
    // The PR template's one-line list, which is what an author actually reads before typing.
    [
      ".github/PULL_REQUEST_TEMPLATE.md",
      path.join(".github", "PULL_REQUEST_TEMPLATE.md"),
      /^ {2}Types: .*$/m,
    ],
    // CHANGELOG.md's hand-written preamble, which explains what each type does to the file.
    ["CHANGELOG.md", "CHANGELOG.md", /\*\*Which means the commit subject[\s\S]*?\n\n/],
  ];

  for (const [name, file, section] of ENUMERATIONS) {
    it(`${name} names every type in release-please-config.json`, () => {
      const text = readFileSync(path.join(REPO_ROOT, file), "utf8");
      const match = section.exec(text);
      expect({ file: name, found: match !== null }).toEqual({ file: name, found: true });

      // Word-boundary, inside the isolated section only. A type the release config declares and
      // the prose omits is the drift #200 is about: the reader plans a commit around a table that
      // is missing an option, or trusts one that no longer exists.
      const section_text = match === null ? "" : match[0];
      const missing = TYPES.filter((t) => !new RegExp(`\\b${t}\\b`).test(section_text));
      expect({ file: name, missing }).toEqual({ file: name, missing: [] });
    });
  }

  it("the PR template's list is EXACTLY the config's list, in order", () => {
    // The strongest form, available because that line is a machine-readable enumeration: not
    // "nothing is missing" but "nothing is missing and nothing is invented".
    const text = readFileSync(path.join(REPO_ROOT, ".github", "PULL_REQUEST_TEMPLATE.md"), "utf8");
    const line = /^ {2}Types: (.*)$/m.exec(text);
    expect(line?.[1]).toBeTypeOf("string");
    expect((line?.[1] ?? "").split("|").map((t) => t.trim())).toEqual(TYPES);
  });
});

/**
 * git in a throwaway repository, with the identity supplied through the environment so the run
 * never depends on — or writes — the operator's git config.
 */
function git(root: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "t",
      GIT_AUTHOR_EMAIL: "t@example.invalid",
      GIT_COMMITTER_NAME: "t",
      GIT_COMMITTER_EMAIL: "t@example.invalid",
    },
  });
}

/**
 * Whether git is on PATH at all. A GitHub runner always has it (`actions/checkout` cannot run
 * without it) and `.devcontainer/ci.Dockerfile` installs it for the same reason — but the check
 * is here rather than assumed, and it drives `skipIf` rather than an early `return`, so a run
 * without git says so in the reporter instead of reporting a pass it did not earn (#112).
 */
const HAS_GIT = spawnSync("git", ["--version"]).status === 0;

describe.skipIf(!HAS_GIT)("the CLI checks a range, and only the range", () => {
  /** A throwaway git repo with the tool inside it, so `--range` has something real to walk. */
  function repoWith(subjects: string[]): { root: string; tool: string } {
    const root = mkdtempSync(path.join(os.tmpdir(), "capwall-commitrange-"));
    trees.push(root);
    mkdirSync(path.join(root, "scripts"), { recursive: true });
    copyFileSync(TOOL, path.join(root, "scripts", "check-commit-messages.mjs"));
    copyFileSync(CONFIG, path.join(root, "release-please-config.json"));

    git(root, "init", "--quiet", "--initial-branch=main");
    git(root, "add", "-A");
    git(root, "commit", "--quiet", "--allow-empty", "-m", "chore: base");
    git(root, "tag", "base");
    for (const [i, subject] of subjects.entries()) {
      writeFileSync(path.join(root, `f${i}.txt`), `${i}\n`);
      git(root, "add", "-A");
      git(root, "commit", "--quiet", "-m", subject);
    }
    return { root, tool: path.join(root, "scripts", "check-commit-messages.mjs") };
  }

  it("passes when every commit in the range parses", () => {
    const { root, tool } = repoWith(["feat(cli): one", "fix(fs): two (#48)"]);
    const r = run(["--range", "base..HEAD"], { cwd: root, tool });
    expect({ status: r.status, out: r.out.trim() }).toEqual({
      status: 0,
      out: "commit-message check: 2 commits, all conventional",
    });
  });

  it("fails on a bad commit in the range and identifies it by sha", () => {
    const { root, tool } = repoWith(["feat(cli): one", "bench: add S4 harness (issue #14)"]);
    const r = run(["--range", "base..HEAD"], { cwd: root, tool });
    expect(r.status).toBe(1);
    expect(r.out).toContain("'bench' is not a type");
    expect(r.out).toContain("1 of 2 commits will not parse");
  });

  it("IGNORES commits outside the range — the reason CI walks base..head", () => {
    // Six commits already on `main` do not parse. A gate that walked the whole history would fail
    // every pull request on commits its author cannot fix without rewriting published history,
    // and a gate that is always red gets switched off. The bad commit here is BEFORE `base`.
    const { root, tool } = repoWith(["fs: gate the Node 22 glob family (#106)"]);
    git(root, "tag", "prbase");
    git(root, "commit", "--quiet", "--allow-empty", "-m", "feat(cli): the PR");

    expect(run(["--range", "prbase..HEAD"], { cwd: root, tool }).status).toBe(0);
    // …and the same tool, over the whole history, does see it. Without this the assertion above
    // would pass just as well against a validator that checks nothing.
    const all = run(["--all"], { cwd: root, tool });
    expect(all.status).toBe(1);
    expect(all.out).toContain("'fs' is not a type");
  });

  it("skips merge commits by parent count, not by subject", () => {
    const { root, tool } = repoWith(["feat(cli): one"]);
    git(root, "checkout", "--quiet", "-b", "side", "base");
    git(root, "commit", "--quiet", "--allow-empty", "-m", "fix(core): side");
    git(root, "checkout", "--quiet", "main");
    // A merge whose subject was hand-edited into something that is NOT conventional and does not
    // start with "Merge" — only the parent count can rescue it.
    git(root, "merge", "--quiet", "--no-ff", "-m", "brought side in", "side");

    const r = run(["--range", "base..HEAD"], { cwd: root, tool });
    expect({ status: r.status, out: r.out.trim() }).toEqual({
      status: 0,
      out: "commit-message check: 2 commits, all conventional",
    });
  });

  it("says so plainly when the range is empty rather than passing silently", () => {
    const { root, tool } = repoWith([]);
    const r = run(["--range", "base..HEAD"], { cwd: root, tool });
    expect(r.status).toBe(0);
    expect(r.out).toContain("nothing to check");
  });
});

describe("the single-message surface, which is what the PR-title job uses", () => {
  // No git here, deliberately: the pr-title job checks a string out of the event payload against
  // `release-please-config.json` and never touches a commit — which is why its workflow step has
  // no `fetch-depth` and no install.
  it("exits 0 for a good --message and 1 for a bad one", () => {
    expect(run(["--message", "feat(cli): add --explain"]).status).toBe(0);
    const bad = run(["--message", "release: ship it"]);
    expect(bad.status).toBe(1);
    expect(bad.out).toContain("'release' is not a type");
  });

  it("reads a message from stdin, which is how the PR-title job feeds it", () => {
    // `--stdin` rather than argv is what makes a title containing quotes, backticks or `$(…)`
    // data instead of a command; the workflow pipes it in and never interpolates it into `run:`.
    const r = spawnSync(process.execPath, [TOOL, "--stdin"], {
      input: "feat(cli): add --explain",
      encoding: "utf8",
      cwd: REPO_ROOT,
    });
    expect(r.status).toBe(0);
  });

  it("rejects a bad title from stdin, backticks and all", () => {
    const r = spawnSync(process.execPath, [TOOL, "--stdin"], {
      input: 'ship it `$(touch /tmp/capwall-should-not-exist)`',
      encoding: "utf8",
      cwd: REPO_ROOT,
    });
    expect(r.status).toBe(1);
    expect(`${r.stdout}${r.stderr}`).toContain("is not a conventional commit");
  });
});
