/**
 * Two settings, each for a reason that is written down rather than inherited from a default.
 *
 * 1. `esbuild.include` — Vite's built-in esbuild transform matches `/\.(m?ts|[jt]sx)$/`, which
 *    does not include `.cts`. `src/real-builtins.cts` is capwall's one CommonJS source file (see
 *    its header, and issue #78), and without widening the filter vitest hands it to Rollup as
 *    plain JavaScript and fails to parse the type annotations. `pnpm build` / `pnpm typecheck`
 *    are unaffected — `tsc` compiles `.cts` natively.
 *
 * 2. `testTimeout` / `hookTimeout` — a dozen suites here spawn `node --import dist/preload.js`
 *    because hardened mode, ESM caching and `module.register()` are process-sticky. vitest's
 *    default 5000 ms was the only bound on those children, and it is a DEFAULT, not a budget:
 *    under CPU contention the suite failed with a rotating set of opaque 5000 ms timeouts
 *    (issue #145). The numbers come from `test/helpers/subprocess.ts`, which states the
 *    measurements they are derived from and enforces the tighter per-CHILD budget itself.
 */
import { defineConfig } from "vitest/config";
import { HOOK_TIMEOUT_MS, TEST_TIMEOUT_MS } from "./test/helpers/subprocess.js";

export default defineConfig({
  // Only the filter is widened; Vite already maps a `.cts` extension onto esbuild's `ts` loader.
  esbuild: { include: /\.([cm]?ts|[jt]sx)$/ },
  test: {
    testTimeout: TEST_TIMEOUT_MS,
    hookTimeout: HOOK_TIMEOUT_MS,
    // Enforces the premise `testTimeout` is arithmetic on: at most two children per test.
    setupFiles: ["./test/helpers/child-budget.ts"],
  },
});
