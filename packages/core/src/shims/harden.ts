/**
 * Opt-in HARDENED MODE (issue #17) — freeze the capability surfaces capwall hands to
 * dependencies, so a dependency cannot monkey-patch its way around mediation.
 *
 * WHY THIS IS OPT-IN. capwall's shims are ordinary mutable objects on purpose: `graceful-fs`
 * — a transitive dependency of npm, webpack, and much of the ecosystem — patches `fs`'s
 * methods at load time, and freezing the shim makes that patch throw. That breakage is the
 * price of closing the trivial un-patch, so the user pays it deliberately
 * (`install(policy, mode, { hardened: true })` / `CAPWALL_HARDENED=1`) or not at all. With
 * `hardened` off every function here is a no-op and nothing is frozen.
 *
 * WHAT IT FREEZES (only objects capwall itself CREATED):
 *  - each shim NAMESPACE object handed to a dependency (`fs`, `fs.promises`, `net`, `http`,
 *    `https`, `tls`, `http2`, `dgram`, `child_process`, `worker_threads`, `vm`) — so
 *    `fs.readFileSync = evil`, `delete fs.readFileSync`, and
 *    `Object.defineProperty(fs, "readFileSync", …)` all fail;
 *  - each guarded WRAPPER FUNCTION capwall built (so e.g. `fs.realpath.native`, a guarded
 *    wrapper hanging off another guarded wrapper, cannot be swapped out);
 *  - each guarded SUBCLASS capwall built for a capability-bearing class (`net.Socket`,
 *    `tls.TLSSocket`, `http.ClientRequest`, `http.Agent`, `dgram.Socket`,
 *    `child_process.ChildProcess`) **and its prototype** — the prototype freeze is the one
 *    that matters, because `net.Socket.prototype.connect = evil` is otherwise a one-line
 *    removal of the guard for every caller in the process.
 *
 * WHAT IT DELIBERATELY DOES **NOT** FREEZE, and why (this list is the honest half — read it
 * before assuming a surface is protected; it is mirrored in docs/threat-model.md):
 *  - **Real builtins passed through a shim namespace** (`fs.Stats`, `fs.constants`,
 *    `net.Server`, `http.globalAgent`, …). Freezing those mutates process-global objects that
 *    outlive `uninstall()` and are shared with code capwall never mediated — an SES-shaped
 *    side effect capwall explicitly does not take. They are not guard-bearing, so freezing
 *    them would buy nothing anyway.
 *  - **Construct-trap Proxy class wrappers** — `fs.ReadStream`/`WriteStream` (and the
 *    `File*Stream` aliases), `vm.Script`/`SourceTextModule`/`SyntheticModule`, and
 *    `worker_threads.Worker` are guarded by a construct-trap `Proxy` over the REAL class.
 *    `Object.freeze(proxy)` forwards `[[PreventExtensions]]` and `[[DefineOwnProperty]]` to
 *    the proxy TARGET, so freezing them would freeze the real builtin class — exactly the
 *    global side effect above. The enclosing namespace freeze still stops
 *    `fs.ReadStream = RealReadStream`, but the real class remains reachable through the proxy
 *    (`fs.ReadStream.prototype.constructor`), so these constructors are NOT hardened. Only the
 *    guarded-subclass sites above are.
 *  - **`process.env`** — the env guard is a `Proxy` over the live `process.env` object, not a
 *    capwall-created namespace; freezing it would break `process.env.X = y` for the whole
 *    process and freeze the real environment object. Replacing `process.env` wholesale
 *    remains an un-gating move hardened mode does not stop.
 *  - **Function/Object primordials.** Hardening primordials is SES's job, not capwall's.
 *
 * Hardened mode raises the cost of un-patching; it is not a sandbox. It does nothing about
 * `process.getBuiltinModule("node:fs")`, `process.binding`, native addons, or any of the other
 * raw-builtin paths listed in docs/threat-model.md — those never touch a shim object at all.
 */
import type { ShimContext } from "./runtime.js";

/** True when this install opted into hardened mode. */
export function isHardened(ctx: ShimContext): boolean {
  return ctx.hardened === true;
}

/**
 * `Object.freeze` `o` iff hardened; returns `o` either way so it can wrap an expression.
 * Only ever call this on an object capwall CREATED (a shim namespace or a guarded wrapper) —
 * see the module comment for why freezing a passed-through builtin is off the table.
 */
export function harden<T extends object>(ctx: ShimContext, o: T): T {
  if (ctx.hardened === true) Object.freeze(o);
  return o;
}

/**
 * Freeze a guarded SUBCLASS capwall built: the constructor object AND its prototype. The
 * prototype freeze closes the prototype-method replacement escape
 * (`net.Socket.prototype.connect = evil`); the constructor freeze closes tampering with the
 * `Symbol.hasInstance` override that keeps `instanceof` honest.
 *
 * Takes `unknown` and no-ops on a non-function so a caller that fell back to returning the
 * REAL class (e.g. `guardedSubclassMethod` when the method is absent on this Node) cannot
 * accidentally freeze a builtin — callers must still only pass classes capwall created.
 */
export function hardenClass(ctx: ShimContext, Cls: unknown): void {
  if (ctx.hardened !== true) return;
  if (typeof Cls !== "function") return;
  const proto: unknown = (Cls as { prototype?: unknown }).prototype;
  if (typeof proto === "object" && proto !== null) Object.freeze(proto);
  Object.freeze(Cls);
}

/**
 * Property descriptor flags for a guarded method capwall installs directly on an INSTANCE it
 * handed out (the `dgram` socket case). Freezing the whole instance is not an option — a
 * socket needs its mutable state — so the guarded own-properties are instead made
 * non-writable/non-configurable under hardened mode, which is the same escape (`socket.send =
 * evil`) closed at the only granularity available here.
 */
export function guardedPropFlags(ctx: ShimContext): { writable: boolean; configurable: boolean } {
  const mutable = ctx.hardened !== true;
  return { writable: mutable, configurable: mutable };
}
