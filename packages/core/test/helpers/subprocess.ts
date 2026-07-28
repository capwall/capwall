/**
 * The one place a capwall test starts a child `node` process — and the one place the budget for
 * one is written down (issue #145).
 *
 * WHY THIS EXISTS
 *
 * A dozen suites cannot assert what they assert in-process: `CAPWALL_HARDENED` freezes
 * prototypes for the life of the process, ESM resolution is cached per process,
 * the module hooks are one registration per process, and the flag-only global egress classes need process-level
 * flags. Those suites each grew a private `runVector()` around
 * `execFile(process.execPath, ["--import=…/dist/preload.js", …])` with no timeout of its own, so
 * vitest's DEFAULT 5000 ms `testTimeout` was the only bound on them. 5000 ms was never a budget
 * — it is the number vitest ships with — and under CPU contention the suite failed with a
 * rotating cast of `Test timed out in 5000ms`, which said nothing about which child, how long it
 * really took, or whether it had even started.
 *
 * THE MEASURED BUDGET (16-core host + Docker, Node 22; numbers in the PR for #145)
 *
 * One child = `node --import dist/preload.js <fixture>`, wall clock, p90 of 15 samples:
 *
 *   | condition                                   | bare `node -e 0` | one preload child |
 *   |---------------------------------------------|------------------|-------------------|
 *   | 16-core host, load 12 (0.8x)                |            76 ms |            496 ms |
 *   | `docker run --cpus=2` (a GH hosted runner)  |            81 ms |            453 ms |
 *   | `docker run --cpus=1`                       |           110 ms |            729 ms |
 *   | 16-core host, load 36 (2.3x oversubscribed) |           185 ms |           1584 ms |
 *
 * So one child is ~0.5 s of mostly-serial startup (≈0.35 s of it loading `dist/preload.js`), and
 * core count barely moves it — CONTENTION does. Measured INSIDE a full suite run, where vitest's
 * own file parallelism piles on top, with 24 `yes` spinners on a 16-core host (load 44→68, i.e.
 * ~3–4x oversubscribed), the core suite's 142 children came out at:
 *
 *   p50 3155 ms · p90 4448 ms · p95 4857 ms · p99 5970 ms · max 6030 ms
 *
 * — which is why 5000 ms failed, and why it failed on a ROTATING set: the tests that lost were
 * whichever ones happened to be in flight when the box was busiest.
 *
 * WHAT ELSE THIS BUYS
 *
 *  - **A legible failure.** Overrunning the budget throws with the elapsed time, the argv, the
 *    cwd, the env overrides, whether the child ever started or produced output, the host's load
 *    at the time, and the tails of both streams — so a red run says what happened rather than
 *    `timed out in 5000ms`. (#142 set the precedent: fail with a number.)
 *  - **Fewer children.** A caller that passes `share: true` gets one child per distinct (argv,
 *    cwd, env) instead of one per call. Several suites deliberately assert two different things
 *    about one run — the env read and the UDP send from one laundering vector, say — and used to
 *    pay for two processes to say it. Sharing is OPT-IN, per call site, because it is only sound
 *    when the child is a pure function of its arguments: a suite that rewrites a policy file and
 *    re-runs the same command is asking a different question with the same argv, and must not
 *    get the previous answer back. Every `share: true` in the suites sits next to the reason it
 *    holds. Sharing plus splitting the two four-child tests took the core suite from 142 children
 *    to 122 for the same 1052 assertions.
 *
 * `packages/cli` uses this too — every test there shells out to the built CLI, so every one of
 * them is a subprocess test. Its `vitest.config.ts` and its tests import from here rather than
 * restating a budget that would then drift; that is why `packages/cli/tsconfig.test.json` sets
 * `rootDir` to the workspace's `packages/` (its `src` still depends on `@capwall/core`'s
 * published entry points only).
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/**
 * Wall-clock budget for ONE child `node` process: 30x what one costs on an idle or 2-core
 * machine, and 2.5x the p99 measured at 4x CPU oversubscription (see the file header). Raising
 * it is not the fix for a slow suite — removing or sharing a child is.
 */
export const CHILD_TIMEOUT_MS = 15_000;

/**
 * How many children one test may start through this helper. This is the premise
 * {@link TEST_TIMEOUT_MS} is derived from, so it is enforced rather than asserted — see
 * `child-budget.ts`, which fails any test that exceeds it and names it.
 *
 * Two, because that is what the suite needs after #145. Of the four tests that wanted three or
 * four, two were the same claim stated twice (now shared) and two were several independent
 * claims in one `it` (now several `it`s) — in every case the split reads better than the
 * original, which is usually what an over-budget test turns out to mean.
 */
export const MAX_CHILDREN_PER_TEST = 2;

/**
 * vitest's per-test backstop, for both packages: {@link MAX_CHILDREN_PER_TEST} x
 * {@link CHILD_TIMEOUT_MS}. It should never be the thing that fires — a subprocess that overruns
 * is caught by {@link CHILD_TIMEOUT_MS} first, and reports itself.
 */
export const TEST_TIMEOUT_MS = MAX_CHILDREN_PER_TEST * CHILD_TIMEOUT_MS;

/**
 * `beforeAll`/`afterAll` backstop. The heaviest hook in the repo is an `mkdtemp` plus a handful
 * of writes (single-digit ms unloaded), but a hook is not held to a tighter bound than a test.
 */
export const HOOK_TIMEOUT_MS = TEST_TIMEOUT_MS;

const here = path.dirname(fileURLToPath(import.meta.url));

/**
 * The built preload the subprocess suites run under. Resolved by path rather than
 * `require.resolve` so that merely importing this module (`vitest.config.ts` does, for the
 * timeouts) cannot throw on a tree that has not been built yet.
 */
export const PRELOAD = path.resolve(here, "..", "..", "dist", "preload.js");

/** `--import=<file url>` for {@link PRELOAD}: the flag every subprocess suite passes. */
export const PRELOAD_IMPORT_FLAG = `--import=${pathToFileURL(PRELOAD).href}`;

/**
 * `beforeAll` guard for the suites that run against the build. CI is build → test; a bare
 * `vitest run` on a fresh clone is not, and this is the message that says so.
 */
export function assertPreloadBuilt(): void {
  if (!existsSync(PRELOAD)) {
    throw new Error(`built preload not found at ${PRELOAD} — run 'pnpm build' before 'pnpm test'`);
  }
}

export interface NodeRunResult {
  /** Exit code, as `execFile` reports it. */
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
  /** Wall-clock cost of the child, in ms. Carried over when a result is shared. */
  readonly elapsedMs: number;
  /** True when this result was shared from an identical invocation earlier in this file. */
  readonly shared: boolean;
}

export interface RunNodeOptions {
  /** Working directory for the child. Required — every caller has a fixture root. */
  readonly cwd: string;
  /** Environment overrides layered over `process.env`. `undefined` unsets the key. */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Override the per-child budget. Only for a case with its own measured justification. */
  readonly timeoutMs?: number;
  /**
   * Reuse the result of an identical earlier invocation in this file instead of starting a
   * second child. Sound only when the child's output depends on nothing but (argv, cwd, env) —
   * in particular, not on a file the test rewrote between the two calls. Off by default.
   */
  readonly share?: boolean;
}

/**
 * Results available for sharing, keyed by invocation. Each test file is its own module instance
 * in its own worker, so nothing crosses file boundaries and no test can be made to depend on
 * another file's runs. Only `share: true` calls read or write this.
 */
const sharedRuns = new Map<string, Promise<NodeRunResult>>();

/** Children actually STARTED by this worker — a shared result does not count. */
let started = 0;

/** Monotonic count of children this test file has started. Read by `child-budget.ts`. */
export function childrenStarted(): number {
  return started;
}

function invocationKey(args: readonly string[], opts: RunNodeOptions): string {
  const env = Object.entries(opts.env ?? {}).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return JSON.stringify([args, opts.cwd, env, opts.timeoutMs ?? CHILD_TIMEOUT_MS]);
}

/** `load average 44.2 across 16 cpus (2.8x oversubscribed)` — the context a timeout needs. */
function hostLoad(): string {
  const cpus = os.cpus().length;
  const load = os.loadavg()[0] ?? 0;
  return `load average ${load.toFixed(1)} across ${cpus} cpus (${(load / cpus).toFixed(1)}x oversubscribed)`;
}

/** Shorten absolute paths in an argv echo so the failure message stays readable. */
function short(arg: string): string {
  if (arg.length < 60) return arg;
  const base = path.basename(arg);
  return base.length > 0 && arg.includes("/") ? `…/${base}` : arg;
}

function tail(s: string, n = 1200): string {
  if (s.trim() === "") return "(empty)";
  return s.length > n ? `…${s.slice(-n)}` : s;
}

/**
 * Run `node <args>` and resolve with its outcome, or reject with a message that says what
 * happened when it overruns {@link CHILD_TIMEOUT_MS}.
 */
export function runNode(args: readonly string[], opts: RunNodeOptions): Promise<NodeRunResult> {
  const key = invocationKey(args, opts);
  if (opts.share === true) {
    const hit = sharedRuns.get(key);
    if (hit) return hit.then((r) => ({ ...r, shared: true }));
  }

  const budget = opts.timeoutMs ?? CHILD_TIMEOUT_MS;
  const env: Record<string, string | undefined> = { ...process.env };
  for (const [k, v] of Object.entries(opts.env ?? {})) {
    if (v === undefined) delete env[k];
    else env[k] = v;
  }

  const overrides =
    Object.entries(opts.env ?? {})
      .map(([k, v]) => (v === undefined ? `-${k}` : `${k}=${v}`))
      .join(" ") || "(no overrides)";
  const invocation = [
    `  argv:  node ${args.map(short).join(" ")}`,
    `  cwd:   ${opts.cwd}`,
    `  env:   ${overrides}`,
  ].join("\n");

  started++;
  const startedAt = process.hrtime.bigint();
  const elapsed = (): number => Number(process.hrtime.bigint() - startedAt) / 1e6;
  let firstOutputMs: number | undefined;

  const promise = new Promise<NodeRunResult>((resolve, reject) => {
    const child = execFile(
      process.execPath,
      [...args],
      { cwd: opts.cwd, env, timeout: budget, killSignal: "SIGKILL" },
      (err, stdout, stderr) => {
        const ms = elapsed();
        // `execFile`'s own timeout fired: the child was killed, so `err.code` is not an exit
        // status and the streams hold whatever it managed to write.
        if (err !== null && (err as { killed?: boolean }).killed === true) {
          reject(
            new Error(
              [
                `capwall test subprocess overran its ${budget} ms budget (killed at ${ms.toFixed(0)} ms).`,
                invocation,
                `  child: ${startedText(child.pid, firstOutputMs)}`,
                `  host:  ${hostLoad()}`,
                `  stdout: ${tail(stdout)}`,
                `  stderr: ${tail(stderr)}`,
                ...(budget === CHILD_TIMEOUT_MS
                  ? [
                      "",
                      `CHILD_TIMEOUT_MS is ${CHILD_TIMEOUT_MS} ms — 30x what one of these children costs on an`,
                      "idle or 2-core machine, and 2.5x the p99 measured at 4x CPU oversubscription (see",
                      "test/helpers/subprocess.ts). Overrunning it means the child is genuinely stuck, or",
                      "this host is far past 4x load.",
                    ]
                  : [`  (this call overrode the ${CHILD_TIMEOUT_MS} ms default budget)`]),
              ].join("\n"),
            ),
          );
          return;
        }
        // A spawn failure (ENOENT, EACCES, EAGAIN) has no numeric exit code either, and is a
        // real bug rather than a budget problem — say so, with the same context.
        if (err !== null && typeof err.code !== "number") {
          reject(new Error([`capwall test subprocess failed to run: ${String(err)}`, invocation].join("\n")));
          return;
        }
        resolve({
          code: err === null ? 0 : (err.code as number),
          stdout,
          stderr,
          elapsedMs: ms,
          shared: false,
        });
      },
    );
    const note = (): void => {
      firstOutputMs ??= elapsed();
    };
    child.stdout?.on("data", note);
    child.stderr?.on("data", note);
  });

  if (opts.share === true) sharedRuns.set(key, promise);
  return promise;
}

function startedText(pid: number | undefined, firstOutputMs: number | undefined): string {
  if (pid === undefined) return "never started — no pid was assigned (spawn itself was starved)";
  if (firstOutputMs === undefined) {
    return `started (pid ${pid}) but produced no output at all before it was killed`;
  }
  return `started (pid ${pid}) and first wrote output ${firstOutputMs.toFixed(0)} ms in`;
}

/**
 * {@link runNode} with {@link PRELOAD_IMPORT_FLAG} already in front — the shape every one of the
 * process-sticky suites needs.
 */
export function runPreloaded(
  args: readonly string[],
  opts: RunNodeOptions,
): Promise<NodeRunResult> {
  return runNode([PRELOAD_IMPORT_FLAG, ...args], opts);
}
