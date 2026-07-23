/**
 * `process.env` read shim — the anti-exfiltration control (roadmap M4, issue #8).
 *
 * Unlike the module shims, `process.env` is not obtained via `require`; it is a live object.
 * We replace it with a `Proxy` whose `get` trap attributes the reading package and evaluates
 * an `{ kind: "env", key }` request. A dependency reading `process.env.AWS_SECRET_ACCESS_KEY`
 * that its policy does not grant is a violation — logged in observe, denied (throw) in
 * enforce.
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
 * Only string-key reads are mediated. Symbol keys, and the write / `has` / `delete` /
 * enumeration traps, forward straight through so `process.env` keeps its normal semantics
 * (values coerced to strings, assignment reaching the real environment, `in`, `for..in`).
 */
import { APP_ROOT, attributeCaller } from "../attribution/index.js";
import { evaluate } from "../policy/evaluate.js";
import type { ShimContext } from "./runtime.js";

export interface EnvGuardHandle {
  /** Restore the original `process.env`. Best-effort: only if nobody replaced it after us. */
  uninstall(): void;
}

/** Build a read-gating Proxy over `realEnv`. Exposed for unit tests. */
export function createEnvProxy(
  realEnv: NodeJS.ProcessEnv,
  ctx: ShimContext,
): NodeJS.ProcessEnv {
  return new Proxy(realEnv, {
    get(target, key, receiver) {
      if (typeof key !== "string") return Reflect.get(target, key, receiver);
      const pkg = attributeCaller(
        ctx.projectRoot !== undefined ? { projectRoot: ctx.projectRoot } : {},
      );
      // App code and Node internals (both attribute to <app>) are not gated — see header.
      if (pkg === APP_ROOT) return Reflect.get(target, key, receiver);
      const decision = evaluate(ctx.policy, ctx.mode, pkg, { kind: "env", key });
      ctx.onDecision(pkg, decision);
      // Soft deny: hide the value from an ungranted dependency, but never throw.
      if (!decision.allowed) return undefined;
      return Reflect.get(target, key, receiver);
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
