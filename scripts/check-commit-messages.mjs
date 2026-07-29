/**
 * Conventional-commit validator. THIS IS A RELEASE GATE, NOT A STYLE GATE.
 *
 * WHY IT EXISTS. release-please reads `main`'s commit subjects to decide the next version and to
 * write every line of CHANGELOG.md. A subject it cannot parse is not "untidy" — it is a change
 * that silently produces no bump and no changelog entry, and if it was the only change, a release
 * that is never proposed at all. That failure is discovered after the publish, which is the one
 * place in this repository where "discovered later" means "cannot be undone" (npm's unpublish
 * window is 72 hours and narrow inside it).
 *
 * It is not hypothetical. Run this over the history (`--all`) and it names six real subjects that
 * release-please parsed as nothing: `fs:`, `bench:`, `release:` and three compound types
 * (`docs+cli:`, `docs+hygiene:`, `docs+hygiene+test:`). Every one of them was a change that
 * happened and a changelog line that did not.
 *
 * WHY IT IS NOT commitlint. commitlint's closure is 68 packages of a 253-package dev tree — 27% —
 * to check that a string starts with a known word. MEASURED, from a clean resolve with
 * `node_modules` AND `pnpm-lock.yaml` deleted: pnpm otherwise keeps what is already installed, so
 * removing a dev dependency looks free. For a tool whose entire argument is that a dependency tree
 * is a liability you cannot see, that is a credibility cost with no technical justification — and
 * this repository already writes its own zero-dependency checks (`check-release-versions.mjs`,
 * `mutation-sentinel.mjs`, `canary.mjs`, `assert-pnpm-pack.mjs`, `check-tarball-sources.mjs`)
 * because a fitted check says more about what is wrong than a generic one does. To be clear about
 * what was NOT the reason: commitlint's transitive `argparse` is pure JavaScript and `Python-2.0`
 * is the permissive PSF licence, not the dead runtime. There was no licence problem and no
 * maintenance problem. This is weight and fit.
 *
 * THE TYPE LIST IS NOT WRITTEN DOWN HERE. It is read out of `release-please-config.json`'s
 * `changelog-sections`, because that file is what actually decides whether a type means anything.
 * A list restated in this file could drift from it, and the drift would look exactly like
 * working: a type accepted here and ignored there is precisely the silent-drop failure above.
 * Same binding principle as #200 — an enumeration that exists twice is an enumeration that is
 * wrong once. It is also why `security:`, a type this project adds to the conventional set, keeps
 * working without being special-cased anywhere: it is in the config, so it is in the grammar.
 *
 * NO HOOK, DELIBERATELY. There is no husky and no `commit-msg` hook. A local hook is opt-in per
 * clone, does not survive `--no-verify`, a fresh worktree, or a merge performed in the GitHub UI,
 * and would be a second enforcement point that can disagree with the real one. CI is the real
 * one, and `pnpm lint:commits` runs the identical script locally.
 *
 * THE PR TITLE IS THE COMMIT MESSAGE. This repository squash-merges, so the subject that reaches
 * `main` is the pull-request title, not whatever was typed into the local editor. `--message`
 * checks that string with the same grammar as `--from`/`--to` checks the branch commits — one
 * implementation, checked at the point that decides the release.
 *
 * WHAT IS DELIBERATELY NOT CHECKED, and why:
 *
 *   - SUBJECT LENGTH. Not capped, at either end. The longest subject in this history is 189
 *     characters because it names every issue the change closes, and truncating it would have
 *     meant saying less about what shipped. GitHub's 256-character pull-request title cap is the
 *     real bound, and a second tighter one here would only buy worse titles.
 *   - BODY / FOOTER LINE LENGTH. Bodies here paste measurements, tables and fenced code, none of
 *     which survives a hard wrap.
 *   - SUBJECT CASE AND TRAILING FULL STOP. Cosmetic; release-please does not care, and a
 *     case rule mis-fires on the proper nouns and identifiers these subjects are full of.
 *   - SCOPE ENUM. Scopes stay free-form. An allow-list would reject the first correctly-scoped
 *     commit for a surface that does not exist yet.
 *
 * WHAT IS CHECKED THAT commitlint's conventional config DID NOT: a near-miss spelling of the
 * breaking-change footer (see `BREAKING_OK`). Written any way but the spec's, whether it moves the
 * version is a property of the parser rather than of the commit — in both directions, since a
 * wrapped prose line beginning with those words is the easy accident. It is the same class of
 * silent mis-release as an unknown type. It caught the commit that introduced this file, twice.
 *
 * Usage:
 *   node scripts/check-commit-messages.mjs                       origin/main..HEAD (the default)
 *   node scripts/check-commit-messages.mjs --from <sha> --to <sha>
 *                                                                the CI range; either may be
 *                                                                omitted (--to defaults to HEAD)
 *   node scripts/check-commit-messages.mjs --range <rev-range>    any git range
 *   node scripts/check-commit-messages.mjs --all                  every commit reachable from
 *                                                                 HEAD (a report, not a gate)
 *   node scripts/check-commit-messages.mjs --message "feat: x"    one literal message
 *   node scripts/check-commit-messages.mjs --stdin                one message, read from stdin
 *
 * Exits 0 when everything parses, 1 when anything does not.
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CONFIG_PATH = join(ROOT, "release-please-config.json");
const CONFIG_NAME = "release-please-config.json";

// --- the type list, read from the file that gives the types meaning ------------------------

/**
 * Every type release-please is configured to understand, in the order the config declares them.
 *
 * `changelog-sections` is the whole enumeration: a type listed there maps to a changelog section
 * (`hidden: true` still means "understood", it just does not print), and a type NOT listed there
 * is a type release-please has no section for. Reading it here rather than restating it means the
 * grammar cannot accept a type the release pipeline drops, which is the only failure this script
 * is for.
 */
export function loadTypes() {
  let config;
  try {
    config = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
  } catch (err) {
    fail(
      `${CONFIG_NAME} is missing or unparseable (${err.message}).\n` +
        `    That file is where the accepted commit types come from — this script has no list of\n` +
        `    its own on purpose. Fix the config; the grammar follows it.`,
    );
  }

  const sections = config["changelog-sections"];
  if (!Array.isArray(sections) || sections.length === 0) {
    fail(
      `${CONFIG_NAME} declares no 'changelog-sections'.\n` +
        `    Without it there is no list of types that release-please understands, so there is\n` +
        `    nothing to validate against and every commit would either pass or fail vacuously.\n` +
        `    Restore the section list before relying on this gate.`,
    );
  }

  const types = [];
  for (const section of sections) {
    const type = section?.type;
    if (typeof type !== "string" || type === "") continue;
    if (!types.includes(type)) types.push(type);
  }
  if (types.length === 0) {
    fail(`${CONFIG_NAME}'s 'changelog-sections' entries carry no 'type' fields.`);
  }
  return types;
}

function fail(message) {
  process.stderr.write(`\n  commit-message check failed: ${message}\n\n`);
  process.exit(1);
}

// --- the grammar ---------------------------------------------------------------------------

/**
 * `type(scope)!: subject`, split into pieces so that each piece can be wrong in its own way and
 * be told so. A single all-or-nothing pattern can only ever say "does not match", which is the
 * least useful thing to say to someone whose commit was rejected.
 *
 * The type is captured as "everything up to the first `(`, `!` or `:`" rather than as `[a-z]+`
 * precisely so that `Feat:`, `docs+cli:` and `feat :` reach the checks below and get a sentence
 * about what they got wrong.
 */
const HEADER = /^(?<type>[^\s(!:]+)(?:\((?<scope>[^)]*)\))?(?<bang>!)?:(?<space>[ \t]*)(?<subject>.*)$/;

/**
 * Messages nothing generates by hand and no one can usefully rewrite, so validating them buys a
 * deadlock rather than a correctness property. Each is a shape git or a bot produces:
 *
 *   - `Merge …`     — git's merge subjects (`Merge branch`, `Merge pull request #12 from …`,
 *                     `Merge remote-tracking branch`, `Merge tag`). Range checks also skip any
 *                     commit with more than one parent, which catches a merge whose subject was
 *                     edited; this pattern catches the PR-title case, where there are no parents
 *                     to look at.
 *   - `Revert "…"`  — git's own `git revert` subject. The conventional `revert:` type is a
 *                     separate, also-accepted spelling; this is the one git writes for you.
 *   - `chore(main): release 0.2.0` — release-please's generated release-PR title. It happens to
 *                     be a valid conventional commit today, and it is exempted anyway: a
 *                     validator that rejects the release bot's own title deadlocks releases, and
 *                     it must not become possible for a template change upstream to do that.
 *   - `fixup!` / `squash!` / `amend!` — rebase-todo markers. They exist to be consumed by
 *                     `git rebase --autosquash` before the branch is merged; the message that
 *                     reaches `main` is the one they fold into.
 *   - `Initial commit` — GitHub's repository-creation subject. There is exactly one and it
 *                     predates any convention.
 */
const IGNORED = [
  /^Merge\b/,
  /^Revert "/,
  /^chore(\([^)]*\))?: release\b/,
  /^(fixup|squash|amend)! /,
  /^Initial commit$/,
];

/**
 * A break is declared two ways: `!` before the colon, or a footer whose token is spelled EXACTLY
 * `BREAKING CHANGE:` / `BREAKING-CHANGE:`, at column 0. conventional-commits v1.0.0 makes the
 * uppercase spelling part of the grammar ("MUST be uppercase"), not a convention.
 *
 * ANY OTHER NEAR-MISS IS REFUSED IN BOTH DIRECTIONS, and that is the point. Implementations
 * disagree about the sloppy forms: some match the token case-insensitively, tolerate leading
 * whitespace and accept a space where the colon should be, others take the spec literally. So a
 * lowercase or indented near-miss is EITHER a breaking change that release-please files as a
 * patch with no note, OR — worse, and easier to write by accident — an ordinary wrapped prose
 * line that release-please reads as a note and bumps the minor for. Which one you get depends on
 * a parser version. A version bump must not.
 *
 * The refusal costs a reflowed paragraph and buys a deterministic bump. It caught the commit that
 * introduced this file, twice.
 *
 * commitlint's conventional config has no rule for any of this. It is here because it is the same
 * class of silent mis-release as an unknown type, and it is the one a careful author is most
 * likely to hit — you only write this footer when you already know the change is breaking.
 */
const BREAKING_OK = /^BREAKING[ -]CHANGE: \S/;
const BREAKING_NEARLY = /^\s*breaking[ -]change\b/i;

/**
 * Validate one whole commit message (subject, blank line, body, footers).
 *
 * @param {string} message raw message; for a PR title this is a single line
 * @param {string[]} types accepted types, from release-please-config.json
 * @returns {string[]} zero or more problems, each already phrased as a fix
 */
export function checkMessage(message, types) {
  const lines = message.replace(/\r\n/g, "\n").split("\n");
  const header = lines[0] ?? "";

  if (header.trim() === "") {
    return [
      "the message is empty.\n" +
        `    Write '<type>(<optional scope>): <subject>' — types: ${types.join(", ")}.`,
    ];
  }
  if (IGNORED.some((pattern) => pattern.test(header))) return [];

  return [
    ...checkHeader(header, types),
    ...checkBodyLeadingBlank(lines),
    ...checkBreakingFooter(lines),
  ];
}

function checkHeader(header, types) {
  const match = HEADER.exec(header);
  if (match === null) {
    return [
      `'${header}' is not a conventional commit.\n` +
        `    Expected '<type>(<optional scope>): <subject>', for example\n` +
        `      fix(fs): unref the deny-stream safety-net timer (#48)\n` +
        `    Accepted types: ${types.join(", ")}.`,
    ];
  }

  const { type, scope, space, subject } = match.groups;
  const problems = [];

  if (!types.includes(type)) {
    problems.push(explainUnknownType(type, types));
  }
  if (scope !== undefined && scope.trim() === "") {
    problems.push(
      `'${header}' has an empty scope.\n` +
        `    Write '${type}: ${subject || "<subject>"}' with no parentheses, or name the surface:\n` +
        `    '${type}(core): …'. Scopes are free-form; the ones in use are core, cli, fs, net, env,\n` +
        `    esm, policy, attribution, loader, shims, deps, bench, tooling, docs.`,
    );
  }
  if (space !== " ") {
    problems.push(
      `'${header}' needs exactly one space after the colon.\n` +
        `    Write '${type}${scope === undefined ? "" : `(${scope})`}: ${subject}'.`,
    );
  }
  if (subject.trim() === "") {
    problems.push(
      `'${header}' has a type but no subject.\n` +
        `    The subject IS the changelog entry — release-please prints it verbatim. Say what\n` +
        `    changed, and name the issues it closes; there is no length cap.`,
    );
  }

  return problems;
}

function explainUnknownType(type, types) {
  const list = `Accepted types (from ${CONFIG_NAME}): ${types.join(", ")}.`;

  // A COMPOUND TYPE — `docs+cli:`, `docs+hygiene:`, `docs+hygiene+test:` — is the shape a real
  // change takes when it touches several surfaces at once, and it is the shape that silently lost
  // three changelog entries in this repository's own history. Conventional commits has no such
  // spelling: release-please reads the type as one word, finds `docs+cli`, and files it nowhere.
  // Recognised whenever ANY part is a real type, because the give-away parts are usually scopes
  // (`cli`) or invented words (`hygiene`) that would never be in the list.
  const parts = type.split(/[+/,&]/).filter((p) => p !== "");
  const known = parts.filter((p) => types.includes(p.toLowerCase()));
  if (parts.length > 1 && known.length > 0) {
    return (
      `'${type}' is a compound type, and there is no such thing.\n` +
      `    release-please parses the type as one word, finds no section for '${type}', and the\n` +
      `    commit produces no version bump and no changelog line — silently.\n` +
      `    Pick the ONE type that describes the change that matters ('${known[0]}') and put the\n` +
      `    rest in the scope or the body, or split the commit:\n` +
      `      ${known[0]}(${parts.find((p) => p !== known[0]) ?? "scope"}): <subject>\n` +
      `    ${list}`
    );
  }
  if (types.includes(type.toLowerCase())) {
    return (
      `'${type}' is the right type with the wrong case; write '${type.toLowerCase()}'.\n` +
        `    release-please matches the type case-sensitively.`
    );
  }

  const near = types.filter((t) => t.startsWith(type[0]?.toLowerCase() ?? ""));
  return (
    `'${type}' is not a type release-please understands, so a commit with this subject\n` +
      `    produces no version bump and no changelog entry — silently, which is why this is a\n` +
      `    gate and not a lint.\n` +
      (near.length > 0 ? `    Did you mean: ${near.join(", ")}?\n` : "") +
      `    ${list}\n` +
      `    A type that is genuinely missing is a change to ${CONFIG_NAME}'s\n` +
      `    'changelog-sections' — add it there and this script accepts it, in that order.`
  );
}

function checkBodyLeadingBlank(lines) {
  if (lines.length < 2) return [];
  if (lines[1].trim() === "") return [];
  return [
    `'${lines[0]}' is followed immediately by body text.\n` +
      `    git treats an unbroken first paragraph as ONE subject, so release-please's changelog\n` +
      `    line becomes the subject and the next line joined together. Put a blank line between\n` +
      `    the subject and the body.`,
  ];
}

function checkBreakingFooter(lines) {
  const problems = [];
  for (const line of lines.slice(1)) {
    if (BREAKING_OK.test(line)) continue;
    if (!BREAKING_NEARLY.test(line)) continue;

    // Indented but otherwise correct is its own diagnosis, and it is the AMBIGUOUS case rather
    // than the merely-wrong one: release-please's parser tolerates leading whitespace on a note
    // keyword, so a wrapped prose line that happens to begin with the token can be read as a
    // breaking-change footer and move the version. Both directions are wrong, so both are
    // refused — put a real footer at column 0, and reflow prose so no line starts with it.
    const indented = /^\s+BREAKING[ -]CHANGE: \S/.test(line);
    problems.push(
      `'${line.trim()}' is neither a breaking-change footer nor safely not one.\n` +
        (indented
          ? `    It is spelled right and INDENTED. A footer belongs at column 0; indented, whether\n` +
            `    it counts is a property of the parser, and a version bump must not be.\n`
          : `    The spec spells it 'BREAKING CHANGE: <description>' or 'BREAKING-CHANGE: <text>'\n` +
            `    — uppercase, at column 0, colon, then text. Written any other way, some parsers\n` +
            `    honour it and some ignore it.\n`) +
        `    If you MEANT a breaking change, write it exactly, or put a '!' before the colon:\n` +
        `    'feat(policy)!: …'. If this is prose, reflow the paragraph so that no line begins\n` +
        `    with the words — otherwise the release may be bumped by a sentence.`,
    );
  }
  return problems;
}

// --- git ------------------------------------------------------------------------------------

/**
 * NUL terminates each record, US separates the fields inside one. Commit messages in this
 * repository contain blank lines, tables and fenced code, so no printable delimiter is safe.
 *
 * THE FORMAT STRING SPELLS THEM `%x00` / `%x1f` RATHER THAN INTERPOLATING THE BYTES: Node
 * refuses to pass an argv entry containing a NUL to `execFileSync` ("must be a string without
 * null bytes"), so git has to be the one that writes them.
 */
const NUL = "\u0000";
const UNIT = "\u001f";
const LOG_FORMAT = "--format=%H%x1f%P%x1f%B%x00";

/**
 * Read commits in a range as {sha, parents, message}. `%B` is the raw message, so the body-blank
 * and footer checks see what git actually stored rather than a `%s`-flattened subject.
 */
function readRange(range) {
  let out;
  try {
    out = execFileSync("git", ["log", LOG_FORMAT, range], {
      cwd: ROOT,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (err) {
    fail(
      `git could not read the range '${range}' (${(err.stderr || err.message).toString().trim()}).\n` +
        `    In CI this means the checkout is shallow: a range needs both ends present, so the\n` +
        `    workflow checks out with 'fetch-depth: 0'. Locally, 'git fetch origin main' first.`,
    );
  }

  return out
    .split(NUL)
    .map((record) => record.replace(/^\n/, ""))
    .filter((record) => record.trim() !== "")
    .map((record) => {
      const [sha, parents, ...rest] = record.split(UNIT);
      return {
        sha,
        parents: parents.trim() === "" ? [] : parents.trim().split(" "),
        // git always terminates the message with a newline before our NUL; drop only that.
        message: rest.join(UNIT).replace(/\n$/, ""),
      };
    });
}

// --- entry point -----------------------------------------------------------------------------

function parseArgs(argv) {
  const args = { mode: "range", range: null, from: null, to: null, message: null };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--all") args.mode = "all";
    else if (arg === "--stdin") args.mode = "stdin";
    else if (arg === "--message") {
      args.mode = "message";
      args.message = argv[++i];
    } else if (arg === "--range") args.range = argv[++i];
    else if (arg === "--from") args.from = argv[++i];
    else if (arg === "--to") args.to = argv[++i];
    else fail(`unknown argument '${arg}'. See the header of scripts/check-commit-messages.mjs.`);
  }
  if (args.mode === "message" && typeof args.message !== "string") {
    fail(`--message needs a value: --message "feat(cli): add --explain"`);
  }
  return args;
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

function report(failures, checked, what) {
  if (failures.length > 0) {
    for (const { label, problems } of failures) {
      for (const problem of problems) {
        process.stderr.write(`\n  ${label}: ${problem}\n`);
      }
    }
    process.stderr.write(
      `\n  ${failures.length} of ${checked} ${what} will not parse.\n` +
        `  Each one is a change release-please drops from the release without saying so.\n` +
        `  Rewording a branch commit: git commit --amend, or git rebase -i <base>.\n` +
        `  Rewording a pull-request title: edit it on GitHub; the title is the squash subject.\n\n`,
    );
    process.exit(1);
  }
  process.stdout.write(`commit-message check: ${checked} ${what}, all conventional\n`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const types = loadTypes();

  if (args.mode === "message" || args.mode === "stdin") {
    const message = args.mode === "stdin" ? await readStdin() : args.message;
    const problems = checkMessage(message.trim(), types);
    report(
      problems.length > 0 ? [{ label: "message", problems }] : [],
      1,
      "message",
    );
    return;
  }

  // THE RANGE IS THE PULL REQUEST, NEVER THE HISTORY. Six commits already on `main` do not parse
  // (`--all` names them). Validating everything reachable from HEAD would fail every pull request
  // on commits its author did not write and cannot fix without rewriting published history — a
  // gate that is always red is a gate that gets switched off.
  const range =
    args.mode === "all"
      ? "HEAD"
      : (args.range ?? `${args.from ?? "origin/main"}..${args.to ?? "HEAD"}`);

  const commits = readRange(range);
  const failures = [];
  let checked = 0;
  for (const commit of commits) {
    // A merge commit's subject is generated and its parents prove it is one even if the subject
    // was edited. Nothing about it reaches the changelog under a squash-merge workflow.
    if (commit.parents.length > 1) continue;
    checked++;
    const problems = checkMessage(commit.message, types);
    if (problems.length > 0) failures.push({ label: commit.sha.slice(0, 9), problems });
  }

  if (checked === 0) {
    process.stdout.write(
      `commit-message check: no commits in '${range}' — nothing to check\n`,
    );
    return;
  }
  report(failures, checked, checked === 1 ? "commit" : "commits");
}

// Only when run as a program. `checkMessage` and `loadTypes` are exported so the grammar can be
// unit-tested without a process, the same entry-point guard `mutation-sentinel.mjs` carries.
if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
