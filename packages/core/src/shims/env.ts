/**
 * `process.env` read guard (roadmap M4) — the anti-exfiltration control.
 *
 * Unlike the other shims this does not wrap a required module: it guards property reads on
 * `process.env` so a package may only read the env keys in its allowlist. A package with
 * `"env": ["NODE_ENV"]` reading `AWS_SECRET_ACCESS_KEY` is a violation.
 *
 * HARD PART: `process.env` is a single global object shared by all packages, and reads are
 * hot. A per-read attributed Proxy is the natural mechanism but has real overhead — measure
 * against the <1ms/req target and consider fast-paths for the app itself.
 */
import type { ShimContext } from "./fs.js";

/**
 * TODO(capwall): install a Proxy around process.env whose `get` trap attributes the caller,
 * builds a { kind: "env", key } request, evaluates, and returns the value or undefined/denies
 * per mode. Preserve enumeration semantics carefully so ordinary code is unaffected.
 */
export function installEnvGuard(_ctx: ShimContext): { uninstall(): void } {
  throw new Error("capwall: env guard not yet implemented — see roadmap M4");
}
