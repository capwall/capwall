# Contributing to capwall

Thanks for looking. This file is the short version: the four things that are easy to get wrong
here and are not obvious from the tree. The long version — architecture, conventions, testing
rules, threat-model guardrails — is [`AGENTS.md`](AGENTS.md), which is written for humans as much
as for agents and is the authority whenever this file and it disagree.

**Found a security problem? Do not open an issue.** [`SECURITY.md`](SECURITY.md) has the private
channel, and — read this first — the list of documented residuals that are *not* findings.

---

## 1. `pnpm`, and only `pnpm`

```bash
corepack enable          # or: npm i -g pnpm@11
pnpm install
```

`npm install` at the repository root is **refused**, by a `preinstall` guard, with an explanation
(issue #122). This is not gatekeeping: the four packages depend on each other with pnpm's
`workspace:*` protocol, npm cannot resolve it, and a half-installed tree fails later and less
clearly than it fails now. `npm pack` inside a package is refused for the same family of reasons
(issue #116 — it would ship a tarball nobody can install).

Node **>= 22.15.0**. The floor is 22.15 rather than 22.0 because `module.registerHooks()` landed
there and capwall wants it without a version gate.

## 2. `pnpm ci:local` before you push — Actions runs too, but it runs after

**GitHub Actions now runs on every pull request** — the repo was transferred to
`capwall/capwall` and made public, which gives it unlimited standard-runner minutes, so the
billing block ([#3](https://github.com/capwall/capwall/issues/3)) no longer applies and is
closed. `ci.yml` is green on the full Node 22/24/26 matrix. That is a check on what you already
pushed, not a substitute for running the gates yourself first: a red Actions run costs a round
trip, and `ci:local` is what catches it before that.

While iterating:

```bash
pnpm build && pnpm typecheck && pnpm test && pnpm lint && pnpm bench:gate
```

Before you ask for review — this is the one that reproduces the real `ci.yml` matrix (Node 22,
24 and 26, clean install, in Docker) against your working tree, including uncommitted edits,
before Actions ever sees it:

```bash
pnpm ci:local
```

[`docs/ci-local.md`](docs/ci-local.md) explains what each gate catches and why `build` passing is
not the same as `typecheck` passing. Two things worth knowing before you run anything:

- **`pnpm canary`** (~0.5s) launches a real mediated child and asserts one granted operation is
  allowed and two ungranted ones are denied. `packages/*/dist` is gitignored, so a broken or
  half-mutated enforcement artifact is invisible to `git status` — and it is what the CLI,
  `examples/` and every reproduction actually execute. Run the canary before you trust a
  measurement or believe a bypass proof-of-concept.
- **Never run `pnpm mutation:gate` and `pnpm ci:local` at the same time.** `mutation:gate` deletes
  a security mechanism from `packages/core/src` in place and rebuilds `dist` for the duration of
  each mutant; `ci:local` tars that same working tree into its Docker context. This has corrupted
  runs more than once. It is now *enforced* — both refuse to start while a mutation stamp exists —
  but the enforcement only helps if you understand what it is protecting.
  `pnpm mutation:status` says whether a run is holding the tree; `pnpm mutation:recover` undoes an
  interrupted one.

Run `pnpm mutation:gate` (~2 min) whenever you touch a **guard, gate, pin or attribution rule**,
and add an entry to `scripts/mutants.json` when you add one. It deletes the mechanism and re-runs
only the tests that claim to cover it; anything reported `SURVIVED` is a security property nothing
actually tests.

## 3. Conventional commits are enforced, and they write the changelog

Commit messages are not cosmetic here: **release-please derives the next version and every line of
`CHANGELOG.md` from them.** A message that does not parse is a change that silently does not
appear in the release notes.

```
<type>(<optional scope>): <subject>
```

| type | effect on the release | changelog section |
|---|---|---|
| `feat` | minor (`0.1.0` → `0.2.0`) | Added |
| `fix` | patch | Fixed |
| `security` | patch | **Security** |
| `perf` | patch | Performance |
| `refactor` | patch | Changed |
| `revert` | patch | Reverted |
| `docs` `test` `build` `ci` `chore` `style` | patch | hidden |
| any of the above with `!`, or a `BREAKING CHANGE:` footer | minor while the major is `0` | ⚠ Breaking |

`security` is not part of the conventional-commit standard; this project adds it. "capwall stopped
mediating X" is a security-relevant regression for every user and has to be findable without
reading the diff.

**That table is not maintained by hand, and neither is the checker.** The accepted types are
`release-please-config.json`'s `changelog-sections`, and `scripts/check-commit-messages.mjs` reads
them from that file rather than keeping a list of its own — a type it accepted but release-please
ignored would be exactly the silent drop the check exists to stop. Adding a type is a change to
the release config; the validator follows.

**The pull-request title matters more than your local commit messages.** This repository
squash-merges, so the title becomes the subject on `main` and is the string release-please reads.
CI checks both. Check yours before pushing:

```bash
pnpm lint:commits                                                     # origin/main..HEAD
node scripts/check-commit-messages.mjs --message "feat(cli): add --explain"
node scripts/check-commit-messages.mjs --all                          # the whole history, as a report
```

That script is **zero-dependency** — Node built-ins and nothing else. It replaced commitlint,
which cost 68 packages of a 253-package dev tree (27%) to check that a string starts with a known
word; in a project whose argument is that a dependency tree is a liability you cannot see, that
was a credibility cost with no technical justification. It was not a licence or maintenance
problem, and the script's header says so explicitly so nobody re-litigates it.

There is deliberately **no git hook** — a local hook is opt-in per clone, does not survive
`--no-verify` or a merge performed in the GitHub UI, and would be a second set of rules that can
disagree with the one that decides the release. CI is the real one. Subject length is not capped;
say what changed.

Merge commits, `git revert` subjects and release-please's own generated release-PR title pass
untouched — a validator that rejects the release bot's title deadlocks releases.

**Do not hand-edit `CHANGELOG.md`.** release-please owns it. Anything you add lands above the
generated section, unattributed, and reads as a second changelog. Put the sentence in the commit
subject instead.

## 4. What "done" means

[`AGENTS.md` § 6](AGENTS.md) is the full list. The parts that get missed:

- **`pnpm build` does not type-check tests.** Run `pnpm typecheck`.
- **A security test must be able to fail.** No silent `if (…) return;` in a test body — use
  `it.skipIf(...)`, which the reporter shows. No assertion the *unguarded* code would also satisfy
  (`toMatch(/CapabilityError|TypeError/)`, `.not.toThrow()` on its own). Issue #112 found six tests
  that passed with the mechanism deleted; that is why `mutation:gate` exists.
- **Never gate on a wall-clock figure.** Gate on a ratio against a reference co-sampled in the same
  loop. A descheduled process accumulates elapsed time it did not spend running.
- **Keep [`docs/threat-model.md`](docs/threat-model.md) honest.** If you add or weaken a capability,
  it changes. Never claim formal-sandbox or isolation guarantees for capwall — it is pragmatic
  defense-in-depth, and the document's credibility is load-bearing for the whole project.
- **No new runtime dependencies** without justification in the PR description. Every dependency is
  attack surface for a supply-chain tool; the entire runtime closure of all four publishable
  packages is currently one package. Dev dependencies are fine within the three licence rules in
  [`AGENTS.md` § 5](AGENTS.md) — note that they are *three* rules of decreasing severity, not one
  blanket "permissive only".

## Pull requests

Fork or branch, then open a PR against `main`. [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md)
asks for what a reviewer needs. In short: what changed and why, which gates you ran (nobody else
can run them for you), and — if it touches enforcement — what a reader should be sceptical of.

Measurements beat assertions. This codebase's documentation is full of numbers with the method
next to them, and a PR that says "measured X on Node 22/24/26" is worth more than one that says
"should be faster".

## Releases

You do not cut them, and you do not bump a version. Merging a PR with a conventional title is the
whole of the contributor-side release process; release-please does the rest.
[`docs/releasing.md`](docs/releasing.md) is the full pipeline, with the human-only steps kept
separate at the bottom.

## Code of conduct

[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Be decent; disagree about the technical thing.
