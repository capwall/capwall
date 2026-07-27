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
 * SCOPE DECISION (documented in docs/threat-model.md): only reads attributed to a **real
 * dependency package** are gated. Reads attributed to {@link APP_ROOT} — application code AND
 * Node-internal frames (core modules read `process.env` constantly during startup, and those
 * stacks attribute to `<app>` because internal frames are skipped) — pass through ungated.
 * Gating `<app>` would either break Node startup or force the app to enumerate every internal
 * env read, for no security gain: the app is the trust root, and the threat we model is a
 * *dependency* exfiltrating secrets, not the app reading its own environment.
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
 * Only string-key READS are mediated. Symbol keys, and the `has` / `delete` / `defineProperty`
 * / `ownKeys` traps, forward straight through so `process.env` keeps its normal semantics
 * (values coerced to strings, `in`, `for..in`). Key NAMES therefore remain enumerable to a
 * denied dependency (`Object.keys`, `in`); only VALUES are hidden — names are not the secret,
 * and hiding them would break benign feature-detection. Documented in docs/threat-model.md.
 *
 * WRITES ARE NOT MEDIATED (#66). The `set` trap below exists only to restore ordinary
 * assignment semantics — see the comment on the trap itself for why a Proxy *without* one
 * crashed the host app. `has` / `deleteProperty` / `defineProperty` / `ownKeys` need no trap at
 * all: they forward to the target and already match un-shimmed `process.env` exactly (verified
 * in test/env-traps.test.ts against the real object, including that a partial
 * `Object.defineProperty` descriptor throws either way).
 *
 * `CAPWALL_*` keys (capwall's own preload plumbing) are never gated or recorded — they are
 * implementation detail, not app secrets, and gating them would pollute generated policies
 * and cause spurious mode-dependent denials (they differ between observe and enforce).
 *
 * When the env gate is suspended (see runtime.ts `suspendEnvGate` — used by the
 * child_process shim so a spawned child inherits a real environment), all reads pass through.
 */
import { APP_ROOT, attributeCaller } from "../attribution/index.js";
import { evaluate } from "../policy/evaluate.js";
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
   * Shared gate for a single string key: returns true if the reading dependency is DENIED
   * this key (caller then hides the value). Returns false (allow) for symbol keys, suspended
   * gate, `CAPWALL_*` plumbing, `<app>`/internal reads, and granted keys. Records the
   * decision for real dependency reads.
   */
  function denied(key: string | symbol): boolean {
    if (typeof key !== "string") return false;
    if (isEnvGateSuspended()) return false;
    if (key.startsWith("CAPWALL_")) return false;
    const pkg = attributeCaller(attributionOptionsFor(ctx));
    // App code and Node internals (both attribute to <app>) are not gated — see header.
    if (pkg === APP_ROOT) return false;
    const decision = evaluate(ctx.policy, ctx.mode, pkg, { kind: "env", key });
    ctx.onDecision(pkg, decision);
    return !decision.allowed; // soft deny — caller hides the value, never throws
  }

  return new Proxy(realEnv, {
    get(target, key, receiver) {
      if (denied(key)) return undefined;
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
    // Close the Object.getOwnPropertyDescriptor(process.env, k).value exfiltration path: a
    // denied key's descriptor reports value: undefined (property still "present" and
    // enumerable, but the value is hidden — matching the get trap).
    getOwnPropertyDescriptor(target, key) {
      const desc = Reflect.getOwnPropertyDescriptor(target, key);
      if (desc && denied(key)) {
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
