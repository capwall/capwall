/**
 * Two settings, each for a reason that is written down rather than inherited from a default.
 *
 * 1. `oxc.include` — Vite's built-in transform matches `/\.(m?ts|[jt]sx)$/`, which does not
 *    include `.cts`. `src/real-builtins.cts` and `src/real-builtins/{fs,worker_threads}.cts`
 *    are capwall's CommonJS source files (see their headers, and issue #78), and without
 *    widening the filter vitest hands them to the bundler as plain JavaScript and fails to
 *    parse the type annotations. `pnpm build` / `pnpm typecheck` are unaffected — `tsc`
 *    compiles `.cts` natively.
 *
 *    THE OPTION WAS `esbuild.include` UNTIL VITE 8, which replaced esbuild with Oxc. Renaming
 *    it is the whole of the Vite 8 migration here, but the failure mode if you miss it is
 *    nasty, so it is written down: Vite maps a legacy `esbuild.*` block onto `oxc.*` ONLY when
 *    `oxc` is unset, and Vitest always sets `oxc` defaults, so the mapping never fires. The
 *    old key is not deprecated-with-a-warning — it is inert. Measured on this suite during the
 *    vitest 4 bump: `esbuild: { include }` and NO include option at all fail identically, 37
 *    files and the same parse error, which is what "silently ignored" looks like from here.
 *    The same trap runs the other way, so if this is ever turned off it is `oxc: false`.
 *
 * 2. `testTimeout` / `hookTimeout` — a dozen suites here spawn `node --import dist/preload.js`
 *    because hardened mode, ESM caching and loader-hook registration are process-sticky. vitest's
 *    default 5000 ms was the only bound on those children, and it is a DEFAULT, not a budget:
 *    under CPU contention the suite failed with a rotating set of opaque 5000 ms timeouts
 *    (issue #145). The numbers come from `test/helpers/subprocess.ts`, which states the
 *    measurements they are derived from and enforces the tighter per-CHILD budget itself.
 */
import { defineConfig } from "vitest/config";
import { HOOK_TIMEOUT_MS, TEST_TIMEOUT_MS } from "./test/helpers/subprocess.js";

export default defineConfig({
  // Only the filter is widened; Vite already maps a `.cts` extension onto the `ts` loader.
  oxc: { include: /\.([cm]?ts|[jt]sx)$/ },
  test: {
    testTimeout: TEST_TIMEOUT_MS,
    hookTimeout: HOOK_TIMEOUT_MS,
    // Enforces the premise `testTimeout` is arithmetic on: at most two children per test.
    setupFiles: ["./test/helpers/child-budget.ts"],
  },
});
