/**
 * Regression suite for issue #89 — `child_process` x `process.env`.
 *
 * THE BUG. The child_process shim bracketed the ENTIRE real spawn call with a process-wide
 * `suspendEnvGate()`, and forwarded the caller's options object UNPINNED. Node reads that object
 * inside the window, so a getter on `options.cwd` ran with the env gate globally off: a package
 * granted `child_process` and `env: []` harvested every value in `process.env`, and the trace
 * recorded the `child_process` decision and not one env line. The window was not even scoped to
 * the spawning package — a second dependency with NO grants at all read ungated during it.
 *
 * WHAT THESE TESTS PIN, in the order the issue asks for them:
 *  1. the PoC itself — an accessor on spawn options harvests nothing, and every read it attempts
 *     is denied AND recorded;
 *  2. the process-wide half — an UNGRANTED second package (`fixture-envpeek`) reading env
 *     concurrently with a legitimate spawn is still gated. This is the more important of the two;
 *  3. every other caller-controlled hook Node invokes during a spawn, enumerated from
 *     `lib/child_process.js` rather than assumed to be only `cwd`;
 *  4. the legitimate case — ordinary `spawn`/`spawnSync`/`exec`/`execFile`/`execFileSync`/`fork`
 *     still work, and the child receives the right environment, including a custom `env`;
 *  5. the pinning invariant itself (a TOCTOU accessor cannot make Node see a second answer).
 *
 * Everything in groups 1-3 and 5 fails against `main`.
 *
 * Method: the attacker code lives in `fixtures/node_modules/fixture-dep` so attribution charges
 * it to a "dependency", and it runs through a real `install()` window so the require patch, the
 * child_process shim and the env Proxy are all wired together exactly as in production.
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { install, loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");
const PEEK = path.join(here, "fixtures", "node_modules", "fixture-envpeek");
const FORK_CHILD = path.join(here, "fixtures", "fork-child-env.cjs");

/** The #89 slice of fixture-dep (see fixtures/.../index.js for each helper). */
interface SpawnFixture {
  stealViaSpawnCwdGetter(key: string): { value: string | undefined; definedValues: number };
  stealViaSpawnCwdGetterAsOtherPackage(key: string): {
    outside: string | undefined;
    inside: string | undefined;
  };
  stealViaSpawnArbitraryGetter(key: string): string | undefined;
  stealViaEnvObjectGetter(key: string): string | undefined;
  stealViaStdioFdGetter(key: string): string | undefined;
  stealViaAbortSignalHooks(key: string): { aborted?: string; addEventListener?: string };
  stealViaArgToString(key: string): string | undefined;
  stealViaCwdUrlSubclass(key: string): string | undefined;
  stealViaChildProcessClassGetter(key: string): string | undefined;
  spawnWithFlipFloppingCwd(
    first: string,
    second: string,
  ): { cwd: string; reads: number; error: string | undefined };
  execFileSyncWithFlipFloppingArgv0(early: string, late: string): { argv0: string; reads: number };
  spawnSyncEnv(options?: Record<string, unknown>): Record<string, string>;
  spawnSyncEnvInheritExplicit(): Record<string, string>;
  execFileSyncEnv(options?: Record<string, unknown>): Record<string, string>;
  execSyncEnv(options?: Record<string, unknown>): Record<string, string>;
  execFileEnvCallbackForm(): Promise<Record<string, string>>;
  execEnvCallbackForm(): Promise<Record<string, string>>;
  execFileEnvWithOptions(options?: Record<string, unknown>): Promise<Record<string, string>>;
  forkEnv(modulePath: string, options?: Record<string, unknown>): Promise<Record<string, string>>;
  spawnSyncNoOptions(): number;
  spawnSyncOptionsAsSecondArg(): number;
  spawnSyncRejectsNullOptions(): string | null;
}

type Recorded = { pkg: string; decision: Decision };

function loadFixtureFresh(): SpawnFixture {
  for (const mod of [FIXTURE, PEEK]) {
    const resolved = requireCjs.resolve(mod);
    delete requireCjs.cache[resolved];
  }
  return requireCjs(FIXTURE) as unknown as SpawnFixture;
}

/** Run `fn` inside a real capwall window (require patch + child_process shim + env Proxy). */
function withCapwall<T>(
  policy: Policy,
  mode: "observe" | "enforce",
  fn: (dep: SpawnFixture) => T,
): { result: T; decisions: Recorded[] } {
  const decisions: Recorded[] = [];
  const handle = install(policy, mode, {
    projectRoot: here,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
  });
  try {
    return { result: fn(loadFixtureFresh()), decisions };
  } finally {
    handle.uninstall();
  }
}

/** Same, for the async helpers — the window must outlive the promise. */
async function withCapwallAsync<T>(
  policy: Policy,
  mode: "observe" | "enforce",
  fn: (dep: SpawnFixture) => Promise<T>,
): Promise<{ result: T; decisions: Recorded[] }> {
  const decisions: Recorded[] = [];
  const handle = install(policy, mode, {
    projectRoot: here,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
  });
  try {
    return { result: await fn(loadFixtureFresh()), decisions };
  } finally {
    handle.uninstall();
  }
}

/** Env-read decisions recorded against `pkg`, as `key -> allowed`. */
function envDecisions(decisions: Recorded[], pkg: string): Array<{ key: string; allowed: boolean }> {
  return decisions
    .filter((d) => d.pkg === pkg && d.decision.observed.kind === "env")
    .map((d) => ({
      key: (d.decision.observed as { kind: "env"; key: string }).key,
      allowed: d.decision.allowed,
    }));
}

const SECRET = "FIXTURE_89_SECRET";
const SECRET_VALUE = "SUPER-SECRET-89";

/**
 * `fixture-dep` may spawn and holds NO env grants — the exact shape of the issue's policy, and
 * the shape that matters: `child_process` must not silently subsume `env: ["*"]`.
 * `fixture-envpeek` is not mentioned at all, so it is denied by default.
 */
const spawnGrantedNoEnv = (): Policy =>
  loadPolicyFromObject(
    {
      version: 1,
      mode: "enforce",
      packages: { "fixture-dep": { child_process: true, env: [] } },
    },
    { projectRoot: here },
  );

beforeEach(() => {
  process.env[SECRET] = SECRET_VALUE;
});

afterEach(() => {
  // A leaked proxy would poison every later test in the file.
  expect(process.env[SECRET]).toBe(SECRET_VALUE);
  delete process.env[SECRET];
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// 1. The PoC
// ═══════════════════════════════════════════════════════════════════════════════════════════

describe("#89 — an accessor on spawn options cannot read env", () => {
  it("harvests NOTHING through a getter on options.cwd, and the attempt is recorded", () => {
    const { result, decisions } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.stealViaSpawnCwdGetter(SECRET),
    );
    // The payload: before the fix this was SECRET_VALUE and `definedValues` was ~85.
    expect(result.value).toBeUndefined();
    // Every VALUE is hidden. Key NAMES stay visible — that is the documented name-level rule in
    // shims/env.ts, not a gap this issue introduces.
    expect(result.definedValues).toBe(0);

    // The other half of #89: the reads were not merely allowed, they were INVISIBLE. Each one is
    // now a recorded denial, so `observe`/`capwall diff`/the trace can see it.
    const env = envDecisions(decisions, "fixture-dep");
    expect(env.length).toBeGreaterThan(0);
    expect(env.every((d) => !d.allowed)).toBe(true);
    expect(env.some((d) => d.key === SECRET)).toBe(true);
  });

  it("still records the child_process decision (the spawn itself is unaffected)", () => {
    const { decisions } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.stealViaSpawnCwdGetter(SECRET),
    );
    const spawns = decisions.filter((d) => d.decision.observed.kind === "child_process");
    expect(spawns).toHaveLength(1);
    expect(spawns[0]!.decision.allowed).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// 2. The process-wide half — the more important test of the two
// ═══════════════════════════════════════════════════════════════════════════════════════════

describe("#89 — one package's spawn does not un-gate env for another package", () => {
  it("an UNGRANTED second package is still denied while a granted package is inside a spawn", () => {
    const { result, decisions } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.stealViaSpawnCwdGetterAsOtherPackage(SECRET),
    );
    // Outside the spawn it was always denied; the bug was that INSIDE it succeeded.
    expect(result.outside).toBeUndefined();
    expect(result.inside).toBeUndefined();

    // And it is attributed and recorded against the RIGHT principal — the reader, not the spawner.
    const peek = envDecisions(decisions, "fixture-envpeek");
    expect(peek.length).toBeGreaterThanOrEqual(2); // one outside the spawn, one inside
    expect(peek.every((d) => d.key === SECRET && !d.allowed)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// 3. Every other caller-controlled hook Node invokes during a spawn
// ═══════════════════════════════════════════════════════════════════════════════════════════

describe("#89 — every caller-controlled hook Node runs during a spawn is gated", () => {
  // Node ends `normalizeSpawnArguments` with `{ __proto__: null, ...options }`, so an accessor on
  // ANY own enumerable key runs — not only the named `cwd`/`shell`/`argv0`/... reads.
  it("an accessor on an option key Node never names by hand", () => {
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.stealViaSpawnArbitraryGetter(SECRET),
    );
    expect(result).toBeUndefined();
  });

  it("a getter on a key of the caller's own options.env", () => {
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.stealViaEnvObjectGetter(SECRET),
    );
    expect(result).toBeUndefined();
  });

  it("a getter on an options.stdio entry's fd", () => {
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.stealViaStdioFdGetter(SECRET),
    );
    expect(result).toBeUndefined();
  });

  it("a duck-typed options.signal's aborted getter and addEventListener", () => {
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.stealViaAbortSignalHooks(SECRET),
    );
    expect(result.aborted).toBeUndefined();
    expect(result.addEventListener).toBeUndefined();
  });

  it("a toString on an element of the args array", () => {
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.stealViaArgToString(SECRET),
    );
    expect(result).toBeUndefined();
  });

  it("a URL subclass used as options.cwd", () => {
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.stealViaCwdUrlSubclass(SECRET),
    );
    expect(result).toBeUndefined();
  });

  // The low-level primitive. `lib/internal/child_process.js` reads no `process.env` at all, so
  // this path opens no authorization window whatsoever — but its options bag is still pinned.
  it("an accessor on new ChildProcess().spawn(options)", () => {
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.stealViaChildProcessClassGetter(SECRET),
    );
    expect(result).toBeUndefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// 4. The legitimate case must still work
// ═══════════════════════════════════════════════════════════════════════════════════════════

describe("#89 — a granted package's ordinary spawns still work and inherit the environment", () => {
  it("spawnSync: the child receives the real environment", () => {
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) => dep.spawnSyncEnv());
    // The child is a separate OS process outside capwall's shims — it inherits, by design
    // (this is a gate, not confinement). The point of the assertion is that the environment is
    // REAL, i.e. supplying it explicitly did not strip it.
    expect(result[SECRET]).toBe(SECRET_VALUE);
    expect(result["PATH"] ?? result["Path"]).toBeDefined();
  });

  it("spawnSync: a custom options.env is honored exactly and does not leak the parent's", () => {
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.spawnSyncEnv({ env: { CAPWALL_TEST_89: "only-this" } }),
    );
    expect(result["CAPWALL_TEST_89"]).toBe("only-this");
    expect(result[SECRET]).toBeUndefined();
  });

  it("spawnSync with an explicit `env: process.env` still inherits the whole environment", () => {
    // Regression guard for the fix's own sharp edge, not for #89: `process.env` is the read
    // PROXY, so enumerating it to build the child's env would soft-deny every key (empty child)
    // and record ~80 spurious denials. It has to be recognised as "inherit".
    const { result, decisions } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.spawnSyncEnvInheritExplicit(),
    );
    expect(result[SECRET]).toBe(SECRET_VALUE);
    expect(Object.keys(result).length).toBeGreaterThan(5);
    expect(envDecisions(decisions, "fixture-dep")).toEqual([]);
  });

  it("execFileSync: the child receives the real environment", () => {
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) => dep.execFileSyncEnv());
    expect(result[SECRET]).toBe(SECRET_VALUE);
  });

  it("execSync: the child receives the real environment", () => {
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) => dep.execSyncEnv());
    expect(result[SECRET]).toBe(SECRET_VALUE);
  });

  it("execFile in its CALLBACK form (no options slot at all)", async () => {
    const { result } = await withCapwallAsync(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.execFileEnvCallbackForm(),
    );
    expect(result[SECRET]).toBe(SECRET_VALUE);
  });

  it("exec in its CALLBACK form (no options slot at all)", async () => {
    const { result } = await withCapwallAsync(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.execEnvCallbackForm(),
    );
    expect(result[SECRET]).toBe(SECRET_VALUE);
  });

  it("execFile with BOTH an options object and a callback", async () => {
    const { result } = await withCapwallAsync(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.execFileEnvWithOptions({ env: { CAPWALL_TEST_89: "via-execFile" } }),
    );
    expect(result["CAPWALL_TEST_89"]).toBe("via-execFile");
    expect(result[SECRET]).toBeUndefined();
  });

  it("fork: the child receives the real environment", async () => {
    const { result } = await withCapwallAsync(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.forkEnv(FORK_CHILD),
    );
    expect(result[SECRET]).toBe(SECRET_VALUE);
  });

  it("fork: a custom options.env is honored", async () => {
    const { result } = await withCapwallAsync(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.forkEnv(FORK_CHILD, { env: { CAPWALL_TEST_89: "via-fork" } }),
    );
    expect(result["CAPWALL_TEST_89"]).toBe("via-fork");
    expect(result[SECRET]).toBeUndefined();
  });

  it("assembling the child's environment records NO env decisions of its own", () => {
    // Before the fix this was true only because the gate was off. Now it is true because Node
    // never enumerates `process.env`: capwall supplies `options.env` from the un-proxied object.
    // A regression here would mean every spawn spams the audit log with the whole environment.
    const { decisions } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) => dep.spawnSyncEnv());
    expect(envDecisions(decisions, "fixture-dep")).toEqual([]);
  });

  it("argument shapes Node accepts keep working, and ones it rejects still throw", () => {
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) => ({
      noOptions: dep.spawnSyncNoOptions(),
      optionsAsSecondArg: dep.spawnSyncOptionsAsSecondArg(),
      nullOptions: dep.spawnSyncRejectsNullOptions(),
    }));
    expect(result.noOptions).toBe(0);
    expect(result.optionsAsSecondArg).toBe(0);
    // `spawnSync(file, args, null)` is an ERR_INVALID_ARG_TYPE in plain Node; capwall must not
    // silently "repair" it by dropping its own options object in.
    expect(result.nullOptions).toBe("ERR_INVALID_ARG_TYPE");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// 5. The pinning invariant itself
// ═══════════════════════════════════════════════════════════════════════════════════════════

describe("#89 — the options object handed to Node contains no accessors", () => {
  // NOTE: this one passes on `main` too, and that is worth writing down rather than hiding.
  // `normalizeSpawnArguments` spreads the options into `{ __proto__: null, ...options }` before
  // reading `cwd` off the COPY, so even un-pinned the getter runs once. It is kept as the
  // invariant test — "the object Node receives has no accessors" — not as a #89 reproduction.
  it("a flip-flopping cwd getter is read ONCE, and Node acts on that first answer", () => {
    const first = path.join(here, "fixtures");
    const second = here;
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.spawnWithFlipFloppingCwd(first, second),
    );
    expect(result.reads).toBe(1); // capwall's pinning pass; Node saw a plain data property
    expect(result.error).toBeUndefined();
    expect(path.resolve(result.cwd)).toBe(path.resolve(first));
  });

  // This one DOES fail on `main`, and it is the genuine `child_process` analogue of #26/#56:
  // un-shimmed, `execFileSync` validates `options.argv0` twice and then re-reads it in the spread
  // that decides the child's actual argv[0] — so plain Node validates "innocent" and executes
  // "PWNED-argv0". Pinning collapses the five reads to one.
  it("a flip-flopping argv0 cannot validate as one value and execute as another", () => {
    const { result } = withCapwall(spawnGrantedNoEnv(), "enforce", (dep) =>
      dep.execFileSyncWithFlipFloppingArgv0("innocent", "PWNED-argv0"),
    );
    expect(result.reads).toBe(1);
    expect(result.argv0).toBe("innocent");
  });
});
