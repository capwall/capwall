/**
 * `prepack` guard: refuse to build a tarball with anything but pnpm.
 *
 * WHY THIS EXISTS. The four packages reference each other with pnpm's `workspace:*`
 * protocol. `pnpm pack` / `pnpm publish` rewrite that to a concrete version before writing
 * the tarball; `npm pack` / `npm publish` do not — they copy the manifest verbatim, so the
 * published dependency specifier reads `"@capwall/core": "workspace:*"`, which no registry
 * can resolve and every consumer's install rejects with
 * `Unsupported URL Type "workspace:"`.
 *
 * WHAT THIS GUARD TELLS THE OPERATOR TO DO NEXT, and why it is not `pnpm publish`. This message
 * used to end with `pnpm -r publish --access public`, which `docs/releasing.md` says must never
 * be used for a real release: `pnpm publish` has no `--provenance` flag and no OIDC support, so
 * it cannot do trusted publishing. Both statements were true of the tools and they told the
 * operator opposite things at the one moment they are reading a failure message. `releasing.md`
 * is the authority: PACK with pnpm, PUBLISH the tarball with npm.
 *
 * That is not a recoverable mistake. npm's unpublish window is 72 hours and narrow even
 * inside it, so a single reflexive `npm publish` from a package directory would leave three
 * permanently broken versions in the `@capwall` namespace — a bad first artifact for a
 * supply-chain security tool. The failure is silent at pack time and only shows up in
 * someone else's install, which is exactly the shape of mistake that deserves a guard
 * rather than a line in a checklist. See issue #116.
 *
 * HOW IT DECIDES. npm and pnpm both set `npm_config_user_agent` when they run a lifecycle
 * script. The check is deliberately asymmetric: it fails only when the agent positively
 * identifies as npm/yarn, and passes when the variable is absent or unrecognised. A guard
 * that blocks an unknown-but-legitimate toolchain would be worse than the bug it prevents,
 * and `pnpm pack` in CI is the path that actually matters.
 *
 * No dependencies, by design — a firewall that took a dependency to check its own package
 * manager would be arguing against itself.
 */

const agent = process.env["npm_config_user_agent"] ?? "";

// pnpm's agent string starts with `pnpm/`; npm's with `npm/`. Yarn is checked too because
// `yarn pack` has the same blind spot with the `workspace:` protocol.
const isPnpm = /(^|\s)pnpm\//.test(agent);
const isNpmOrYarn = /(^|\s)(npm|yarn)\//.test(agent);

if (isNpmOrYarn && !isPnpm) {
  const tool = /(^|\s)yarn\//.test(agent) ? "yarn" : "npm";
  process.stderr.write(
    `\n  capwall: refusing to pack with ${tool}.\n\n` +
      `  This package depends on its siblings with pnpm's \`workspace:*\` protocol.\n` +
      `  ${tool} copies that string into the tarball verbatim, producing a package that\n` +
      `  cannot be installed from a registry — and npm publishes are effectively permanent.\n\n` +
      `  Pack with pnpm:\n\n` +
      `      pnpm pack                                          # one package\n` +
      `      pnpm -r --filter './packages/*' pack               # all of them\n\n` +
      `  Then PUBLISH the tarball with npm, not with pnpm — pnpm publish has no\n` +
      `  --provenance flag and no OIDC support, so it cannot do trusted publishing:\n\n` +
      `      npm publish ./<tarball> --provenance --access public\n\n` +
      `  See docs/releasing.md (the authority for a release) and issue #116.\n\n`,
  );
  process.exit(1);
}
