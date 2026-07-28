/**
 * A vitest setup file that enforces the premise `testTimeout` is derived from (#145).
 *
 * `TEST_TIMEOUT_MS` is `MAX_CHILDREN_PER_TEST x CHILD_TIMEOUT_MS`. That arithmetic is only sound
 * while the first factor is true, and "no test starts more than two subprocesses" is exactly the
 * kind of claim that decays silently: someone adds a third `await runVector(…)` to an existing
 * `it`, the suite stays green on an idle laptop, and the per-test budget quietly stops covering
 * the worst case — which is how the four-child tests that lost the race under contention got
 * there in the first place.
 *
 * So it is checked rather than believed, in the same spirit as the #103 option-parity matrix and
 * the #112 mutation catalog: a test that starts a third child fails, by name, with the count.
 * Splitting it into two `it`s (or letting two of its runs share one child — identical
 * invocations already do) is the fix; raising the constant is not.
 *
 * Only children started through `helpers/subprocess.ts` are counted. A handful of suites spawn
 * `echo`-scale processes directly through `node:child_process` as part of what they are testing
 * (`child_process.test.ts`, `composition-matrix.test.ts`); those cost ~100–300 ms rather than the
 * ~500 ms a `--import dist/preload.js` child costs, and mediating them through this helper would
 * mean mediating the thing under test.
 */
import { afterEach, beforeEach } from "vitest";
import { childrenStarted, MAX_CHILDREN_PER_TEST } from "./subprocess.js";

let atTestStart = 0;

beforeEach(() => {
  atTestStart = childrenStarted();
});

afterEach((ctx) => {
  const n = childrenStarted() - atTestStart;
  if (n > MAX_CHILDREN_PER_TEST) {
    throw new Error(
      `"${ctx.task.name}" started ${n} subprocesses; the per-test budget assumes at most ` +
        `${MAX_CHILDREN_PER_TEST} (testTimeout is MAX_CHILDREN_PER_TEST x CHILD_TIMEOUT_MS). ` +
        `Split it into separate tests, or let two runs share one child by making their argv, ` +
        `cwd and env overrides identical — see test/helpers/subprocess.ts (#145).`,
    );
  }
});
