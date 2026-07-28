/**
 * Every test in this package shells out to the built CLI, so every one of them is a subprocess
 * test and vitest's default 5000 ms `testTimeout` bounded all of them. That default is not a
 * budget (issue #145): on a `docker run --cpus=2` box — the shape of a GitHub hosted runner —
 * the slowest test here already measured 2052 ms, and under CPU contention the same tests run
 * 3–4x slower still.
 *
 * The budget and the measurements behind it live in one place, `@capwall/core`'s
 * `test/helpers/subprocess.ts`; this imports it rather than restating a number that would then
 * drift. (A vitest config is not part of either package's `tsconfig.test.json`, so this
 * cross-package import is a build-tool import, not a source dependency — `packages/cli/src`
 * depends on `@capwall/core`'s published entry points only.)
 */
import { defineConfig } from "vitest/config";
import { HOOK_TIMEOUT_MS, TEST_TIMEOUT_MS } from "../core/test/helpers/subprocess.js";

export default defineConfig({
  test: {
    testTimeout: TEST_TIMEOUT_MS,
    hookTimeout: HOOK_TIMEOUT_MS,
    // Enforces the premise `testTimeout` is arithmetic on: at most two children per test.
    setupFiles: ["../core/test/helpers/child-budget.ts"],
  },
});
