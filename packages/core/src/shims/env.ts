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
import { APP_ROOT, attributeCaller } from "../attribution/index.js";
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
   */
  function decide(key: string | symbol): { pkg: string; decision: Decision } | null {
    if (typeof key !== "string") return null;
    // #89: exempt by KEY, not by wall-clock window. Only the fixed non-secret keys Node's own
    // spawn implementation reads by name, and only while a real spawn is on the stack.
    if (isAuthorizedEnvKey(key)) return null;
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

/*
 * EXACTLY ONE PROXY PER PROCESS, REFERENCE-COUNTED (#90) — the same rule, and the same reasoning,
 * as `installCompileGate` in shims/module.ts. Not a style choice; stacking BROKE this guard three
 * separate ways, and every one of them was invisible to a single-install test:
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
 * One proxy is not merely enough, it is what correctness requires: since #87 every guard reads
 * `liveCtx`, whose identity never changes and whose fields the install stack re-points, so a
 * single proxy already tracks whichever install is in force. The count only decides WHEN to put
 * the real object back. `index.ts` therefore hands this `liveCtx`, and the closure below captures
 * the FIRST caller's context — the same object by construction.
 */
let envGuardInstalls = 0;
/** The proxy this process installed, so a repeat install can recognize its own work. */
let envGuardProxy: NodeJS.ProcessEnv | null = null;
/** The un-proxied `process.env` to put back when the last install goes. */
let envGuardReal: NodeJS.ProcessEnv | null = null;

/**
 * Replace `process.env` with the read-gating proxy. Returns a handle whose `uninstall`
 * restores the original object once the LAST install releases it (and only if `process.env` is
 * still our proxy — so we do not clobber a later replacement, mirroring the loader patch).
 */
export function installEnvGuard(ctx: ShimContext): EnvGuardHandle {
  if (envGuardProxy === null) {
    const realEnv = process.env;
    const proxy = createEnvProxy(realEnv, ctx);
    envGuardReal = realEnv;
    envGuardProxy = proxy;
    process.env = proxy;
    // #89: hand the un-proxied reference to the shim runtime so the child_process shim can build
    // a child's environment block WITHOUT enumerating this proxy. That enumeration — Node's
    // `options.env || { ...process.env }` — is what the old process-wide gate suspension existed
    // to let through; supplying the env explicitly deletes the need for it rather than narrowing
    // it. It must be the REAL object, never another guard's proxy — see (2) above.
    setUnproxiedEnv(realEnv);
  }
  envGuardInstalls++;

  let uninstalled = false;
  return {
    uninstall() {
      if (uninstalled) return; // idempotent, like every other handle
      uninstalled = true;
      if (--envGuardInstalls > 0) return; // an outer install still wants the gate
      if (envGuardReal !== null && process.env === envGuardProxy) process.env = envGuardReal;
      envGuardProxy = null;
      envGuardReal = null;
      setUnproxiedEnv(undefined);
    },
  };
}
