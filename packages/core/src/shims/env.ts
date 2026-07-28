/**
 * `process.env` read shim — the anti-exfiltration control (roadmap M4, issue #8).
 *
 * Unlike the module shims, `process.env` is not obtained via `require`; it is a live object.
 * We replace it with a `Proxy` whose `get` and `getOwnPropertyDescriptor` traps attribute the
 * reading package and evaluate an `{ kind: "env", key }` request. A dependency reading
 * `process.env.AWS_SECRET_ACCESS_KEY` that its policy does not grant is a violation — logged
 * in observe, soft-denied (see below) in enforce. BOTH the direct-read trap (`get`) and the
 * descriptor trap (`getOwnPropertyDescriptor`) are gated, because
 * `Object.getOwnPropertyDescriptor(process.env, k).value` would otherwise hand back the value
 * a `get` denies — a one-line exfiltration hole for an anti-exfiltration control.
 *
 * SCOPE DECISION (documented in docs/threat-model.md): reads attributed to {@link APP_ROOT}
 * pass through ungated. The app is the trust root, and the threat we model is a *dependency*
 * exfiltrating secrets, not the app reading its own environment.
 *
 * THE EXEMPTION IS NARROW SINCE #60. `<app>` now means "a real application source file was
 * found on the stack", nothing else. It used to ALSO mean "the walk found nothing" — which is
 * how a dependency running from a `data:` URL module, from `eval`, or simply via
 * `setTimeout(Object.assign, 0, stash, process.env)` (a native reader on a stack with no
 * caller frame) could read any key in the environment and never appear in a log line. Those
 * now attribute to `<unknown>` and are gated here exactly like a dependency: evaluated,
 * recorded, soft-denied when not granted.
 *
 * The blast radius of that is small but real, and it is NOT zero: reads from a path-less stack
 * attribute to `<unknown>` and are gated there. A legitimate setup that genuinely runs from
 * such frames is granted a `"<unknown>": { "env": [...] }` entry — an explicit, reviewable line
 * in `capabilities.json`, not a silent exemption.
 *
 * WHO READ IT vs WHOSE FRAME IS NEAREST (issue #119) — the rule `record` below implements.
 *
 * This guard is the ONE mediated surface Node's own code shares with dependencies. Every other
 * shim is handed out through `require`/`import`, and Node's internals do not go through the
 * loader to reach `fs` or `net` — but `process.env` is a live object replaced in place, so a
 * `node:internal/…` script reading a variable hits this proxy exactly like a dependency does.
 * Attribution then answers the only question it can: whose is the nearest frame with a package
 * identity. Node's own frames have none, so the walk skips them and charges the package that
 * happened to be underneath. Measured on a stock `express` + `pino` tree, that produced:
 *
 *   node:internal/source_map/source_map_cache  reads NODE_V8_COVERAGE while compiling a
 *     dependency that ships a `//# sourceMappingURL`  ->  charged to `type-is`, `body-parser`,
 *     `router` — three packages that do not contain the string `NODE_V8_COVERAGE`
 *   node:internal/cluster/primary  reads NODE_CLUSTER_SCHED_POLICY when `node:cluster` is first
 *     loaded  ->  charged to `express`
 *   node:internal/modules/esm/loader  reads WATCH_REPORT_DEPENDENCIES per module job, on a stack
 *     with no package frame at all  ->  charged to `<unknown>`
 *
 * Six of the twelve events in that generated policy, and five of its nine principals, described
 * Node rather than any dependency. A reviewer reading `express: env: [NODE_CLUSTER_SCHED_POLICY]`
 * concludes express reads that variable; it does not. The artifact is the product, and half of
 * it was un-reviewable — with no correct answer to "may `type-is` read NODE_V8_COVERAGE?",
 * because `type-is` never asked.
 *
 * So a read whose nearest non-capwall frame is Node's own JS is NOT RECORDED
 * (`Attribution.initiatedByNode`). It is still attributed, still evaluated, and still hidden on
 * a denial — only the audit record is dropped, exactly as for the descriptor trap above (#67).
 *
 * WHY NOT A LIST OF `NODE_*` NAMES, the obvious alternative. It is wrong in both directions.
 * It goes stale the next time Node adds a variable, and — measured on the same tree — it
 * deletes true positives: `thread-stream` reads `process.env.NODE_V8_COVERAGE` in its own
 * `index.js` (to work around nodejs/node#49344), from its own frame, and `express` reads
 * `NODE_ENV`. The stack origin separates those from the three Node-initiated reads of the SAME
 * KEY; a name list cannot, because the name is identical. The rule is about where the read came
 * from, not what it was called.
 *
 * WHAT IT COSTS, STATED PLAINLY. `observe` no longer emits grants for Node's own reads, so
 * under `enforce` they are soft-denied and Node sees those variables as unset — a `--watch` run
 * does not report dependencies through this path, `NODE_V8_COVERAGE` does not reach Node's
 * source-map cache, cluster uses its default scheduling policy. Those are Node's own
 * configuration knobs, they degrade to the unset default, and the alternative is a policy in
 * which half the lines are noise. The denial is also no longer logged, which is the same
 * bounded trade #67 made and is recorded in docs/threat-model.md § residuals.
 *
 * NOT AN EXEMPTION. `initiatedByNode` never reaches `evaluate`, and no branch here returns
 * "allowed" because of it. It could not: a dependency CAN put a `node:` frame directly above a
 * read it caused — `util.inspect(process.env)` runs in `node:internal/util/inspect` — so
 * treating Node-initiated as ungated would be a one-call laundering route around the whole
 * anti-exfiltration control. Under the rule as written that call still gets every key it is not
 * granted hidden; what it buys is silence in the trace, which is what a `for..in` already bought
 * it under #67.
 *
 * SOFT DENY: a denied env read returns `undefined` rather than throwing. The security goal
 * is to keep the *value* from the reading package (anti-exfiltration) — hiding it achieves
 * that, while throwing would crash benign dependencies that probe optional env vars at load
 * time (`process.env.NO_DEPRECATION`, `process.env.DEBUG`, …), which is common and would make
 * enforce mode unusable. The denial is still recorded via `onDecision`, so it is logged and
 * shows up in the audit trail exactly like any other violation. (Contrast fs/net/spawn,
 * where a denied *operation with side effects* throws — hiding a return value has no analog
 * there.)
 *
 * NAME-LEVEL vs VALUE-LEVEL (the rule the traps below implement):
 *
 *   - VALUE-level operations — anything that hands the dependency an actual value — go through
 *     `[[Get]]`, i.e. the `get` trap. That covers `env.K`, destructuring, `JSON.stringify(env)`,
 *     `{...env}`, `Object.entries`/`Object.values` (all of which do `[[OwnPropertyKeys]]` →
 *     `[[GetOwnProperty]]` → `[[Get]]` per key). These are GATED and RECORDED.
 *   - NAME-level operations — which reveal only that a key exists — are UNGATED and UNRECORDED:
 *     `in` (`has`), `Object.keys`, `for..in`, `Object.getOwnPropertyNames` (`ownKeys`). Names are
 *     not the secret, and hiding them would break benign feature-detection. Documented in
 *     docs/threat-model.md.
 *
 * The `getOwnPropertyDescriptor` trap straddles the two, and that is the subtlety (#67).
 * `Object.getOwnPropertyDescriptor(env, k).value` is a value read, but `Object.keys(env)` and
 * `for..in` ALSO call `[[GetOwnProperty]]` once per key — purely to read `[[Enumerable]]` — and
 * the trap cannot tell the two apart: it receives an identical `(target, key)` and an identical
 * caller stack. So the trap splits the difference along the axis that matters:
 *
 *   - it still HIDES the value for a denied key (`value: undefined`), unconditionally, because
 *     that is the security property — otherwise the descriptor is a one-line exfiltration hole
 *     around the `get` trap; but
 *   - it does NOT RECORD, because a recording there is indistinguishable from enumeration, and
 *     an enumeration recorded as "read the value of every key" is a false positive on the one
 *     capability where false positives are most expensive: it made `observe` output a property
 *     of the *machine* rather than of the package (a `for..in` recorded 83 keys, including
 *     `SSH_AUTH_SOCK` and `AWS_SECRET_ACCESS_KEY`, on the maintainer's laptop), and it printed
 *     `DENY 'debug' env:AWS_SECRET_ACCESS_KEY` for what was an enumeration. A security log that
 *     cries wolf trains operators to ignore it.
 *
 * Nothing that actually yields a value to the dependency loses its audit record: every such path
 * routes through `get`, which stays gated and recorded. What the trace gives up is the *failed*
 * `getOwnPropertyDescriptor(...).value` attempt — still blocked, just no longer logged. That is
 * a deliberate, bounded trade: the alternative discriminators (an `ownKeys`-primed "enumeration
 * epoch" heuristic; returning an accessor descriptor so only an explicit `desc.get()` records)
 * are either spoofable by the attacker they target or only catch an attacker who has adapted to
 * capwall, and a spoofable heuristic inside the anti-exfiltration control is worse than a
 * documented gap. See docs/threat-model.md § residuals.
 *
 * ENUMERATION COST — WHY THE TRAPS ARE NAMED FUNCTIONS (#133). Everything above means that one
 * `{...process.env}` is TWO gated traps per environment variable: `getOwnPropertyDescriptor`
 * (hide, do not record) and then `get` (hide and record). On an 81-key environment that is 162
 * attributions for a single JS call, and it measured **5 ms of added latency** — five times
 * capwall's entire per-intercepted-call budget, paid at startup by `dotenv`, by every config
 * loader, and by anything doing `Object.assign({}, process.env)`.
 *
 * The pair is NOT redundant and neither half was removed. The spread reads `[[Enumerable]]` from
 * the descriptor and the value from `[[Get]]`, and the descriptor trap cannot tell that spread
 * apart from a real `Object.getOwnPropertyDescriptor(env, k).value` — the #67 problem, unchanged.
 * Dropping the descriptor-trap decision would re-open the exfiltration hole; deciding once and
 * REUSING it for the `get` that follows would make the anti-exfiltration control depend on a
 * cache whose invalidation an attacker helps schedule, which is the #84 shape and is exactly what
 * this file must not contain. So both traps still decide, independently, every time.
 *
 * What changed is the price of ONE decision. Attribution's cost is dominated by how many V8
 * CallSites the capture materializes, and the reading package is almost always the frame directly
 * below the trap — so each trap hands ITSELF to `attributeCallerDetailedVia` as the point where
 * the capture starts, and a 3-frame capture answers instead of a 25-frame one. Same walk, same
 * rules, same principal; when the short capture does not reach a qualifying frame it falls back
 * to the full one. Nothing is remembered between reads. See `attribution/index.ts` for why that
 * is a cheaper computation of the same function rather than a cache, and
 * `test/attribution-fast-path.test.ts` for the attacks run against it.
 *
 * WRITES ARE NOT MEDIATED (#66). The `set` trap exists only to restore ordinary object
 * semantics, not to gate anything — see the comment on the trap itself. `has` / `deleteProperty`
 * / `defineProperty` / `ownKeys` need no trap at all: they forward to the target and already
 * match un-shimmed `process.env` exactly (verified in test/env-traps.test.ts against the real
 * object, including that a partial `Object.defineProperty` descriptor throws either way).
 *
 * `CAPWALL_*` keys (capwall's own preload plumbing) are never gated or recorded — they are
 * implementation detail, not app secrets, and gating them would pollute generated policies
 * and cause spurious mode-dependent denials (they differ between observe and enforce).
 *
 * THE SPAWN EXEMPTION IS KEY-SCOPED SINCE #89. It used to be `isEnvGateSuspended()`: a
 * process-wide boolean the child_process shim raised around the whole real spawn, which turned
 * this gate off for EVERY key and EVERY package for the duration — so a getter on a spawn
 * options object read the entire environment ungated and unrecorded, and so did an unrelated
 * dependency with no grants at all. It is now `isAuthorizedEnvKey(key)`: a fixed, audited set of
 * non-secret keys that Node's own spawn implementation reads by name, exempt only while a real
 * spawn is on the stack. See runtime.ts and shims/child_process.ts. Like `CAPWALL_*`, those keys
 * are not recorded — they are Node's plumbing, not a package's read of a secret, and recording
 * them would widen every generated policy with a key no dependency asked for.
 */
import {
  APP_ROOT,
  attributeCallerDetailedVia,
  type StackBoundary,
} from "../attribution/index.js";
import { definePropertyPatch, valueSlot } from "../lifecycle/process-patch.js";
import { evaluate, type Decision } from "../policy/evaluate.js";
import {
  attributionOptionsFor,
  isAuthorizedEnvKey,
  setUnproxiedEnv,
  type ShimContext,
} from "./runtime.js";

export interface EnvGuardHandle {
  /** Restore the original `process.env`. Best-effort: only if nobody replaced it after us. */
  uninstall(): void;
}

/** Build a read-gating Proxy over `realEnv`. Exposed for unit tests. */
export function createEnvProxy(
  realEnv: NodeJS.ProcessEnv,
  ctx: ShimContext,
): NodeJS.ProcessEnv {
  /**
   * Attribute + evaluate a single key read, WITHOUT reporting it. Returns `null` when the read
   * is exempt entirely — symbol keys, one of the few keys Node's own spawn reads while a spawn
   * is on the stack (#89), `CAPWALL_*` plumbing, and reads
   * attributed to `<app>` (application code; see header) — and otherwise the attributed
   * package plus its decision. An UNATTRIBUTABLE read is not exempt: it comes back as
   * `<unknown>` with a decision, like any dependency (#60).
   *
   * Deciding and recording are separated because the two gated traps need different halves of
   * it: `get` decides AND records, `getOwnPropertyDescriptor` decides but must not record (see
   * the #67 discussion in the header). Nothing here mutates state, so calling it without
   * reporting is safe.
   *
   * `record` is the #119 half of the same split: false when the read was INITIATED BY NODE
   * ITSELF rather than written by the attributed package (see the header). The decision is
   * still made, and the caller still hides the value on a denial — only the audit record is
   * dropped.
   *
   * `trap` is the trap function whose frame the capture should start below — see
   * {@link attributeCallerDetailedVia} and the ENUMERATION COST note in the header. It selects
   * where V8 begins materializing CallSites; it is not an identity, and it contributes nothing
   * to either the principal or the `record` flag.
   */
  function decide(
    key: string | symbol,
    trap: StackBoundary,
  ): { pkg: string; decision: Decision; record: boolean } | null {
    if (typeof key !== "string") return null;
    // #89: exempt by KEY, not by wall-clock window. Only the fixed non-secret keys Node's own
    // spawn implementation reads by name, and only while a real spawn is on the stack.
    if (isAuthorizedEnvKey(key)) return null;
    if (key.startsWith("CAPWALL_")) return null;
    // Shared frame budget with every other attribution site (#15/#58) — a shim that quietly
    // kept the default while the rest honored a raised cap would attribute the same call to a
    // different package depending on which capability it touched. `attributeCallerDetailedVia`
    // spends that budget lazily (#133); it does not change it, and it falls back to the identical
    // full walk whenever the short capture does not reach a qualifying frame.
    const attribution = attributeCallerDetailedVia(trap, attributionOptionsFor(ctx));
    const pkg = attribution.pkg;
    // App code is not gated — see header. Since #60 this is a POSITIVE identification (a real
    // application source file on the stack); an unattributable read is `<unknown>`, which
    // falls through to the policy below rather than being exempted here.
    if (pkg === APP_ROOT) return null;
    return {
      pkg,
      decision: evaluate(ctx.policy, ctx.mode, pkg, { kind: "env", key }),
      record: !attribution.initiatedByNode,
    };
  }

  /**
   * VALUE-read gate: decides, REPORTS the decision (observe log / gen-policy trace / audit
   * trail), and returns true when the caller must hide the value. Soft deny — never throws.
   *
   * The report is skipped for a read Node itself initiated (#119) — the decision, and the
   * hiding, are unchanged.
   */
  function deniedValueRead(key: string | symbol, trap: StackBoundary): boolean {
    const outcome = decide(key, trap);
    if (outcome === null) return false;
    if (outcome.record) ctx.onDecision(outcome.pkg, outcome.decision);
    return !outcome.decision.allowed;
  }

  /**
   * Same decision, deliberately NOT reported (#67). Used only by the descriptor trap, which
   * fires once per key for every `Object.keys` / `for..in` as well as for a genuine descriptor
   * read and cannot distinguish them. Hiding still happens; only the recording is dropped.
   */
  function deniedUnrecorded(key: string | symbol, trap: StackBoundary): boolean {
    const outcome = decide(key, trap);
    return outcome !== null && !outcome.decision.allowed;
  }

  /*
   * The two gated traps are NAMED FUNCTION DECLARATIONS, not method shorthands, for one reason:
   * each hands ITSELF to `attributeCallerDetailedVia` as the frame below which the capture starts
   * (#133). A method shorthand has no binding to pass. Nothing else about them changed.
   *
   * Passing the trap rather than an inner helper matters: V8 skips up to and including the
   * TOPMOST frame matching the function object, so if a decision sink re-enters `process.env`
   * the nested trap's own frame is the boundary and the sink is attributed, not the outer
   * reader. Handing it something further up would have made the outer reader the answer.
   */
  function envGet(target: NodeJS.ProcessEnv, key: string | symbol, receiver: unknown): unknown {
    if (deniedValueRead(key, envGet)) return undefined;
    return Reflect.get(target, key, receiver);
  }

  function envGetOwnPropertyDescriptor(
    target: NodeJS.ProcessEnv,
    key: string | symbol,
  ): PropertyDescriptor | undefined {
    const desc = Reflect.getOwnPropertyDescriptor(target, key);
    if (desc && deniedUnrecorded(key, envGetOwnPropertyDescriptor)) {
      return { ...desc, value: undefined };
    }
    return desc;
  }

  return new Proxy(realEnv, {
    get: envGet,
    /**
     * Restores ordinary assignment semantics; it mediates nothing (#66).
     *
     * With NO `set` trap, `proxy.K = v` falls through to the target's `[[Set]]` with
     * `receiver` = the PROXY. When the target already has the own property, the spec finishes
     * the assignment as `receiver.[[DefineOwnProperty]](K, { [[Value]]: v })` — a *partial*
     * descriptor — which reaches Node's `process.env` `defineProperty` handler and is rejected
     * with `ERR_INVALID_OBJECT_DEFINE_PROPERTY`. Absent keys take the `CreateDataProperty` path
     * instead (a complete descriptor), which is why *new* keys worked and *existing* ones threw.
     * Net effect before this trap: any dependency writing to an env var the process already had
     * crashed the host app (`debug`'s `process.env.DEBUG = namespaces` is the common trigger) —
     * a hard failure capwall itself introduced, with no security benefit.
     *
     * Forwarding with `receiver` defaulting to the target skips the `defineProperty` hop, so the
     * write lands as a plain `[[Set]]` on the real environment, exactly as un-shimmed.
     *
     * Writes are intentionally NOT gated or recorded. The policy vocabulary (`env: [key…]`)
     * expresses a READ allowlist and has no write-grant concept; gating writes under it would
     * either forbid every dependency write (a far larger blast radius than the bug being fixed)
     * or silently conflate "may read K" with "may set K". Soft deny does not compose with writes
     * either: a silently dropped write leaves the dependency believing it succeeded, and a
     * throwing write reintroduces the crash. Recording writes would be worse than useless —
     * `gen-policy` merges every observed `{kind:"env"}` into the package's READ allowlist, so an
     * observed write would silently widen read access. The residual (a dependency can set
     * `NODE_OPTIONS` / `LD_PRELOAD` / `HTTP_PROXY` to influence other code) is documented in
     * docs/threat-model.md; its payoff is realized at spawn time, and spawning is already a
     * gated capability.
     */
    set(target, key, value) {
      return Reflect.set(target, key, value);
    },
    /**
     * Closes the `Object.getOwnPropertyDescriptor(process.env, k).value` exfiltration path: a
     * denied key's descriptor reports `value: undefined`, so it can never hand back a value the
     * `get` trap denies. The property stays "present" and enumerable, matching the name-level
     * rule in the header.
     *
     * Deliberately uses the NON-recording decision (#67): this trap also fires once per key for
     * `Object.keys` / `for..in`, which read only `[[Enumerable]]`, and recording there logged
     * mere enumeration as a value read of every secret in the environment.
     */
    getOwnPropertyDescriptor: envGetOwnPropertyDescriptor,
  });
}

/*
 * EXACTLY ONE PROXY PER PROCESS, REFERENCE-COUNTED (#90, made structural by #107) — the same rule,
 * and the same reasoning, as `installCompileGate` in shims/module.ts. Not a style choice; stacking
 * BROKE this guard three separate ways, and every one of them was invisible to a single-install
 * test:
 *
 *   1. A second `installEnvGuard` captured `process.env` — which by then was the FIRST guard's
 *      proxy — and wrapped it again, so every dependency read ran the attribute→evaluate→record
 *      sequence TWICE and every decision was recorded twice in the trace.
 *   2. Worse, it then called `setUnproxiedEnv(proxy1)`. `unproxiedProcessEnv()` exists precisely
 *      so the child_process shim can build a child's environment block WITHOUT going through the
 *      read gate (#89); handed a proxy, it enumerated the gate instead, every key soft-denied to
 *      `undefined`, Node dropped the undefined values — and a GRANTED `spawn` launched its child
 *      with a completely empty environment. That is the #86 shape exactly: hardened/nested
 *      configuration breaking an ALLOWED operation, with the denied path still working fine.
 *   3. `uninstall()` restored `process.env` to whatever this install had captured, so an
 *      out-of-LIFO-order teardown left capwall's proxy on `process.env` PERMANENTLY — reading the
 *      deny-all torn-down policy for the rest of the process, in direct contradiction of
 *      `InstallHandle.uninstall`'s documented promise that a fresh access after teardown is
 *      un-mediated. `loader/require.ts` and `loader/native.ts` both keep a relink chain for that
 *      reason; this guard kept a bare save/restore.
 *
 * `definePropertyPatch` is what makes (2) structurally impossible rather than merely fixed. It
 * reads the location EXACTLY ONCE, while the patch is provably inactive, and hands that value to
 * `build` and to `onInstall` — so "the real underlying object" is not something this file has to
 * get right, it is the only value this file is ever given. There is no expression here that could
 * name a previous install's proxy.
 *
 * One proxy is not merely enough, it is what correctness requires: since #87 every guard reads
 * `liveCtx`, whose identity never changes and whose fields the install stack re-points, so a
 * single proxy already tracks whichever install is in force. The count only decides WHEN to put
 * the real object back. `index.ts` therefore hands this `liveCtx`, and the closure below captures
 * the FIRST caller's context — the same object by construction.
 */
const envPatch = definePropertyPatch<NodeJS.ProcessEnv>("process.env", {
  slot: valueSlot<NodeJS.ProcessEnv>("process.env", () => process, "env"),
  build: (ctx, realEnv) => createEnvProxy(realEnv, ctx),
  // #89: hand the un-proxied reference to the shim runtime so the child_process shim can build a
  // child's environment block WITHOUT enumerating this proxy. That enumeration — Node's
  // `options.env || { ...process.env }` — is what the old process-wide gate suspension existed to
  // let through; supplying the env explicitly deletes the need for it rather than narrowing it.
  // `realEnv` here is the value read while no proxy was installed — see (2) above.
  onInstall: (realEnv) => setUnproxiedEnv(realEnv),
  onRestore: () => setUnproxiedEnv(undefined),
});

/**
 * Replace `process.env` with the read-gating proxy. Returns a handle whose `uninstall`
 * restores the original object once the LAST install releases it (and only if `process.env` is
 * still our proxy — so we do not clobber a later replacement, mirroring the loader patch).
 */
export function installEnvGuard(ctx: ShimContext): EnvGuardHandle {
  return envPatch.install(ctx);
}
