<!--
  The PR TITLE is the commit message. This repository squash-merges, so the title becomes the
  subject on `main` and is what release-please reads to pick the next version and write
  CHANGELOG.md. It must be a conventional commit:

      feat(cli): add --explain
      fix(fs): unref the deny-stream safety-net timer (#48)
      security(core): decide the module read on the filename Node opens (#177)

  Types: security | feat | fix | perf | refactor | revert | docs | test | build | ci | chore | style
  `!` or a `BREAKING CHANGE:` footer moves the minor while the major is 0.
  Check it locally: node scripts/check-commit-messages.mjs --message "<your title>"

  DO NOT edit CHANGELOG.md. release-please generates it from these subjects.
  Security problem? Close this and read SECURITY.md — there is a private channel.
-->

## What and why

<!-- What changed, and what a reader should be sceptical of. Link the issues. -->

Closes #

## Gates run

**There is no CI ([#3](https://github.com/williamzujkowski/capwall/issues/3)) — nobody can run
these for you.** Tick what you actually ran, and say which Node versions.

- [ ] `pnpm build && pnpm typecheck && pnpm test && pnpm lint`
- [ ] `pnpm bench:gate`
- [ ] `pnpm canary` — `dist/` is gitignored, so a broken enforcement artifact is invisible to `git status`
- [ ] `pnpm ci:local` (Node 22 / 24 / 26) — the stand-in for `ci.yml`
- [ ] `pnpm lint:commits`
- [ ] `pnpm mutation:gate` — **required if this touches a guard, gate, pin or attribution rule**, and never at the same time as `ci:local`

## If this touches enforcement

- [ ] A mutant was added to `scripts/mutants.json` for any new guard/gate/pin/attribution rule
- [ ] Every new test can actually **fail** — no silent `if (…) return;`, no assertion the unguarded code would also satisfy
- [ ] `docs/threat-model.md` is still honest: what this stops, and what it does not
- [ ] No new **runtime** dependency (or: justified below)

## Measurements

<!--
  Optional, and disproportionately valuable. If this claims something is faster, safer or
  cheaper, put the numbers and the method here. "Should be" is not a measurement.
-->
