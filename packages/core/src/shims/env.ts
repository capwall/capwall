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
 * The blast radius of that is small but real, and it is NOT zero: Node's own ESM loader reads
 * `process.env.WATCH_REPORT_DEPENDENCIES` per module job from a purely internal stack, so
 * every run under the CLI produces one unattributable env read. It soft-denies to `undefined`
 * (i.e. behaves as if the variable were unset) and is recorded, so `capwall observe` emits a
 * `"<unknown>": { "env": [...] }` grant for it automatically. That grant is the documented
 * escape hatch for any other setup that legitimately reads env from path-less frames — an
 * explicit, reviewable line in `capabilities.json`, not a silent exemption.
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
 * When the env gate is suspended (see runtime.ts `suspendEnvGate` — used by the
 * child_process shim so a spawned child inherits a real environment), all reads pass through.
 */
import { APP_ROOT, attributeCaller } from "../attribution/index.js";
import { evaluate, type Decision } from "../policy/evaluate.js";
import { attributionOptionsFor, isEnvGateSuspended, type ShimContext } from "./runtime.js";

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
   * is exempt entirely — symbol keys, a suspended gate, `CAPWALL_*` plumbing, and reads
   * attributed to `<app>` (application code; see header) — and otherwise the attributed
   * package plus its decision. An UNATTRIBUTABLE read is not exempt: it comes back as
   * `<unknown>` with a decision, like any dependency (#60).
   *
   * Deciding and recording are separated because the two gated traps need different halves of
   * it: `get` decides AND records, `getOwnPropertyDescriptor` decides but must not record (see
   * the #67 discussion in the header). Nothing here mutates state, so calling it without
   * reporting is safe.
   */
  function decide(key: string | symbol): { pkg: string; decision: Decision } | null {
    if (typeof key !== "string") return null;
    if (isEnvGateSuspended()) return null;
    if (key.startsWith("CAPWALL_")) return null;
    // Shared frame budget with every other attribution site (#15/#58) — a shim that quietly
    // kept the default while the rest honored a raised cap would attribute the same call to a
    // different package depending on which capability it touched.
    const pkg = attributeCaller(attributionOptionsFor(ctx));
    // App code is not gated — see header. Since #60 this is a POSITIVE identification (a real
    // application source file on the stack); an unattributable read is `<unknown>`, which
    // falls through to the policy below rather than being exempted here.
    if (pkg === APP_ROOT) return null;
    return { pkg, decision: evaluate(ctx.policy, ctx.mode, pkg, { kind: "env", key }) };
  }

  /**
   * VALUE-read gate: decides, REPORTS the decision (observe log / gen-policy trace / audit
   * trail), and returns true when the caller must hide the value. Soft deny — never throws.
   */
  function deniedValueRead(key: string | symbol): boolean {
    const outcome = decide(key);
    if (outcome === null) return false;
    ctx.onDecision(outcome.pkg, outcome.decision);
    return !outcome.decision.allowed;
  }

  /**
   * Same decision, deliberately NOT reported (#67). Used only by the descriptor trap, which
   * fires once per key for every `Object.keys` / `for..in` as well as for a genuine descriptor
   * read and cannot distinguish them. Hiding still happens; only the recording is dropped.
   */
  function deniedUnrecorded(key: string | symbol): boolean {
    const outcome = decide(key);
    return outcome !== null && !outcome.decision.allowed;
  }

  return new Proxy(realEnv, {
    get(target, key, receiver) {
      if (deniedValueRead(key)) return undefined;
      return Reflect.get(target, key, receiver);
    },
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
    getOwnPropertyDescriptor(target, key) {
      const desc = Reflect.getOwnPropertyDescriptor(target, key);
      if (desc && deniedUnrecorded(key)) {
        return { ...desc, value: undefined };
      }
      return desc;
    },
  });
}

/**
 * Replace `process.env` with the read-gating proxy. Returns a handle whose `uninstall`
 * restores the original object (only if `process.env` is still our proxy — so we do not
 * clobber a later replacement, mirroring the loader patch).
 */
export function installEnvGuard(ctx: ShimContext): EnvGuardHandle {
  const realEnv = process.env;
  const proxy = createEnvProxy(realEnv, ctx);
  process.env = proxy;
  return {
    uninstall() {
      if (process.env === proxy) process.env = realEnv;
    },
  };
}
