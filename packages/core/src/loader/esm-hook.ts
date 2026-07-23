/**
 * ESM loader interception (FAST-FOLLOW after the CJS path — roadmap M5).
 *
 * Approach: register a module customization hook via `module.register()` (Node ≥20.6) and
 * implement `resolve`/`load` hooks that route mediated builtins through capwall's shims.
 *
 * HARD PART (see docs/architecture.md § Risks): unlike CJS, ESM static `import` specifiers
 * are resolved before user code runs and the resulting bindings are live and immutable, so
 * the "swap the returned module object" trick used for `require` does not port directly.
 * Expect partial parity first (dynamic `import()` and redirected builtin specifiers are more
 * tractable than static named imports). CJS-first is deliberate.
 */
import type { Mode, Policy } from "@capwall/policy-schema";

export interface EsmHookHandle {
  /** Best-effort teardown; ESM hooks cannot always be fully unregistered. */
  uninstall(): void;
}

/**
 * Register the ESM loader hook.
 *
 * TODO(capwall): call module.register() pointing at a hooks module that redirects mediated
 * builtin specifiers to capwall shim modules, threading `policy`/`mode` via the register
 * `data` channel + a MessagePort. Implement in M5.
 */
export function registerEsmHook(_policy: Policy, _mode: Mode): EsmHookHandle {
  // TODO(capwall): module.register('./esm-hooks.js', { data: { policy, mode } }).
  return {
    uninstall() {
      /* TODO(capwall): best-effort unregister. */
    },
  };
}
