/**
 * Root `preinstall` guard: refuse to install this workspace with anything but pnpm.
 *
 * WHY THIS EXISTS. The clone is the only way to get capwall today (nothing is published), so
 * the README's Quickstart is the entire first-run experience — and without this guard the
 * wrong package manager produces a failure that reads as "this project is broken":
 *
 *     $ npm install
 *     added 55 packages, and audited 56 packages in 8s
 *     found 0 vulnerabilities                       <- exit 0. Looks fine. It is not.
 *
 *     $ npm run build
 *     src/index.ts(11,19): error TS2307: Cannot find module 'zod'
 *     WARN  Local package.json exists, but node_modules missing
 *
 * The root manifest has no `workspaces` field (pnpm uses `pnpm-workspace.yaml`), so npm
 * installs the root devDependencies, links none of the four packages, and reports success.
 * The real diagnosis is the least prominent line on screen, two commands later. See #122.
 *
 * HOW IT DECIDES — the same asymmetry as `scripts/assert-pnpm-pack.mjs`, deliberately. It
 * fails only when `npm_config_user_agent` positively identifies as npm/yarn/bun, and passes
 * when the variable is absent or unrecognised. A guard that blocked an unknown-but-legitimate
 * toolchain would be worse than the bug it prevents, and `preinstall` runs on paths (Docker
 * CI, corepack, a bare `node scripts/…`) where guessing wrong is expensive.
 *
 * IT CANNOT FIRE ON A CONSUMER. `preinstall` belongs to the root manifest, which is
 * `"private": true` and never published. Someone installing `@capwall/cli` from the registry
 * never sees this file.
 *
 * No dependencies, by design — a supply-chain firewall that took a dependency to check its own
 * package manager would be arguing against itself (which is also why this is not `only-allow`).
 */

const agent = process.env["npm_config_user_agent"] ?? "";

const isPnpm = /(^|\s)pnpm\//.test(agent);
const other = /(^|\s)(npm|yarn|bun)\//.exec(agent);

if (other && !isPnpm) {
  const tool = other[2];
  process.stderr.write(
    `\n  capwall: this repository must be installed with pnpm, not ${tool}.\n\n` +
      `  It is a pnpm workspace (pnpm-workspace.yaml). The root package.json has no\n` +
      `  "workspaces" field, so ${tool} would install the root devDependencies, link none of\n` +
      `  the four packages, and exit 0 — and the build would then fail with\n` +
      `  "Cannot find module 'zod'", which is not what went wrong.\n\n` +
      `  Get the pnpm version this repo pins (see "packageManager" in package.json):\n\n` +
      `      corepack enable\n` +
      `      pnpm install\n\n` +
      `  See the Quickstart in README.md and issue #122.\n\n`,
  );
  process.exit(1);
}
