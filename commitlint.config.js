/**
 * Conventional-commit rules, enforced in CI (`.github/workflows/commit-conventions.yml`) and
 * runnable locally with `pnpm lint:commits`.
 *
 * THIS FILE IS PART OF THE RELEASE PIPELINE, not a style preference. release-please derives the
 * next version and every CHANGELOG.md line from these messages: `feat` moves the minor, `fix`
 * and `security` move the patch, `!`/`BREAKING CHANGE` moves the minor while the major is 0.
 * A commit that does not parse is a commit release-please silently drops from the changelog.
 *
 * THE PR TITLE IS THE COMMIT MESSAGE. This repository squash-merges, so the subject that reaches
 * `main` is the PR title, not whatever was typed into the local editor. The PR-title job lints it
 * with this same config — one set of rules, checked at the point that decides the release.
 *
 * NO HOOK. There is deliberately no husky/`commit-msg` hook: a local hook is opt-in per clone
 * (it does not survive `--no-verify`, a fresh worktree, or a `gh` merge), so it would be a second
 * enforcement point that disagrees with the real one. CI is the real one.
 *
 * @type {import("@commitlint/types").UserConfig}
 */
export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    // `security` is added to the conventional set on purpose. capwall's CHANGELOG has always
    // treated "capwall stopped mediating X" as a category that must be findable without reading
    // the diff, and conventional-commits has no type for it. release-please maps it to a
    // `### Security` section (release-please-config.json) and bumps the patch, so a security fix
    // can never be a release that looks like it changed nothing.
    //
    // The rest is @commitlint/config-conventional's list, restated so that adding `security` does
    // not silently drop the others — `type-enum` replaces rather than extends.
    "type-enum": [
      2,
      "always",
      [
        "security",
        "feat",
        "fix",
        "perf",
        "refactor",
        "revert",
        "docs",
        "test",
        "build",
        "ci",
        "chore",
        "style",
      ],
    ],

    // OFF, not raised. The default is 100 characters and this repository's subjects routinely run
    // past it because they name every issue the change closes — the longest in the history at the
    // time this landed is 189 characters, and truncating it would have meant saying less about
    // what shipped. GitHub caps a pull-request title at 256 characters, and since the title *is*
    // the squash subject, that cap is the real bound; a second, tighter one here would only buy
    // worse titles.
    "header-max-length": [0, "always", Infinity],

    // OFF for the same reason, one level down: commit bodies here paste measurements, tables and
    // fenced code (`Error.captureStackTrace = (h) => {...}`), none of which survive a hard wrap.
    "body-max-line-length": [0, "always", Infinity],
    "footer-max-line-length": [0, "always", Infinity],

    // Scopes stay free-form. The useful ones (`core`, `cli`, `fs`, `net`, `env`, `esm`, `policy`,
    // `attribution`, `loader`, `shims`, `deps`, `bench`, `tooling`) are conventions, and an enum
    // here would reject the first correctly-scoped commit for a surface that does not exist yet.
    "scope-enum": [0],
  },
};
