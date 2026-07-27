/**
 * The ONLY reason this file exists: Vite's built-in esbuild transform matches
 * `/\.(m?ts|[jt]sx)$/`, which does not include `.cts`. `src/real-builtins.cts` is capwall's one
 * CommonJS source file (see its header, and issue #78), and without widening the filter vitest
 * hands it to Rollup as plain JavaScript and fails to parse the type annotations.
 *
 * `pnpm build` / `pnpm typecheck` are unaffected — `tsc` compiles `.cts` natively. This is a
 * test-runner gap, not a project configuration choice, so nothing else is set here.
 */
import { defineConfig } from "vitest/config";

export default defineConfig({
  // Only the filter is widened; Vite already maps a `.cts` extension onto esbuild's `ts` loader.
  esbuild: { include: /\.([cm]?ts|[jt]sx)$/ },
});
