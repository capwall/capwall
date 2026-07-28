/**
 * `capwall explain <package> <capability> [target]` (roadmap M3+).
 *
 * Loads the current policy and reports whether the given package would be allowed the given
 * capability against an optional target — using the same `evaluate()` the enforcer uses, so
 * the answer matches enforcement exactly. Exit code: 0 allowed, 1 denied, 2 usage error.
 */
import * as path from "node:path";
import { canonicalIpcPath, evaluate, loadPolicy, type CapabilityRequest } from "@capwall/core";
import { CHAIN_SEP, widenedPackageKeys, type Policy } from "@capwall/policy-schema";

const HELP = `usage: capwall explain [--policy <file>] <package> <capability> [target]

Capabilities and their targets:
  fs:read <path> | fs:write <path> | net <host:port> | ipc <socket-path> | env <KEY>
  child_process | worker_threads | vm | native [addon-path] | compile [filename]

  'native' gates whether the package may load a .node addon at all, and 'compile'
  whether it may call Module.prototype._compile with a filename outside its own
  package. Both optional targets are echoed in the answer for readability only —
  the grants are booleans, so the target does not change the verdict (see
  docs/policy-format.md).

<package> is the principal attribution reports, which for a package installed under
another package is its install chain — 'webpack>lodash', not 'lodash' (issue #92).

Examples:
  capwall explain pino fs:write ./logs/app.log
  capwall explain some-dep ipc /var/run/docker.sock
  capwall explain express net localhost:3000
  capwall explain sneaky-dep env AWS_SECRET_ACCESS_KEY
  capwall explain better-sqlite3 native
  capwall explain webpack>lodash fs:read ./package.json
  capwall explain ts-node compile
`;

function buildRequest(
  capability: string,
  target: string | undefined,
  projectRoot: string,
): CapabilityRequest | string {
  switch (capability) {
    case "fs:read":
    case "fs:write": {
      if (!target) return `capability '${capability}' requires a <path> target`;
      const abs = path.resolve(projectRoot, target).split(path.sep).join("/");
      return { kind: "fs", access: capability === "fs:read" ? "read" : "write", path: abs };
    }
    case "net": {
      const [host, portRaw] = (target ?? "").split(":");
      const port = Number(portRaw);
      if (!host || !Number.isInteger(port)) {
        return "capability 'net' requires a <host:port> target";
      }
      return { kind: "net", host, port };
    }
    case "ipc": {
      if (!target) return "capability 'ipc' requires a <socket-path> target";
      // Canonicalized the same way the shim canonicalizes an observed destination (#72), so
      // `explain` answers the question enforcement would answer: a relative path is resolved,
      // and `\\.\pipe\x` and `//./pipe/x` are the same pipe.
      return { kind: "ipc", path: canonicalIpcPath(target) };
    }
    case "env": {
      if (!target) return "capability 'env' requires a <KEY> target";
      return { kind: "env", key: target };
    }
    case "child_process":
      return { kind: "child_process" };
    case "worker_threads":
      return { kind: "worker_threads" };
    case "vm":
      return { kind: "vm" };
    case "native":
      // Target optional and NOT resolved against the project root: it is a display string,
      // not a matched target (isGranted ignores it). `<any addon>` keeps the printed reason
      // honest about that when the caller omits it.
      return { kind: "native", path: target ?? "<any addon>" };
    case "compile":
      // Same as `native`: a display string, not a matched target (isGranted ignores it).
      return { kind: "compile", filename: target ?? "<any filename>" };
    default:
      return `unknown capability '${capability}' (see capwall explain --help)`;
  }
}

/**
 * The stderr note that says WHICH ENTRY answered, and — when nothing did — which principals the
 * policy actually names (issue #118).
 *
 * `explain` takes its `<package>` argument literally, as it must: whether any code runs as that
 * principal is a runtime fact and this command does not run anything. That is fine until the
 * author's belief about the principal is the thing that is wrong, which is the common case,
 * because the name in `package.json` is not the principal for a nested install (`outer>inner`,
 * #92). Then `explain inner …` answers ALLOW about a principal that never runs, and the tool the
 * reader reached for to debug a denial has confirmed the belief that caused it. They have to
 * already know the answer to ask the question that reveals it.
 *
 * So the note is printed on EVERY answer, not only on a miss: an exact hit says which key was
 * used and that the tool cannot vouch for the key naming anything, and a miss lists the keys
 * that do exist — where a reader who typed `outer>inner` sees their own `inner` sitting in the
 * list. It goes to stderr so the ALLOW/DENY line on stdout stays the machine-readable answer,
 * and the exit code is untouched.
 */
function principalNote(policy: Policy, pkg: string, policyFile: string): string {
  const keys = Object.keys(policy.packages);
  const exact = Object.hasOwn(policy.packages, pkg);
  const widened = widenedPackageKeys(pkg).find((k) => Object.hasOwn(policy.packages, k));
  const chainHint =
    !pkg.includes(CHAIN_SEP) && !pkg.startsWith("<")
      ? ` A bare name is the TOP-LEVEL install only; a copy installed under another package is` +
        ` a different principal ('other${CHAIN_SEP}${pkg}').`
      : "";

  if (exact) {
    return (
      `[capwall] note: answered from the "${pkg}" entry in ${policyFile}. ` +
      `explain cannot know whether any code actually runs as '${pkg}' — a key that names no ` +
      `principal grants nothing, and 'capwall diff' reports those.${chainHint}\n`
    );
  }
  const source = widened === undefined ? `the "default" block` : `the "${widened}" wildcard key`;
  const known = keys.length > 0 ? keys.sort().join(", ") : "(none)";
  return (
    `[capwall] note: no "${pkg}" key in ${policyFile}; answered from ${source}.` +
    `${chainHint}\n[capwall] note: keys in this policy: ${known}\n`
  );
}

export async function runExplain(args: string[]): Promise<number> {
  let policyFile = "capabilities.json";
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-h" || arg === "--help") {
      process.stdout.write(HELP);
      return 0;
    }
    if (arg === "--policy" || arg === "-p") {
      const value = args[++i];
      if (!value) {
        process.stderr.write(`capwall explain: ${arg} requires a value\n`);
        return 2;
      }
      policyFile = value;
    } else if (arg !== undefined) {
      positional.push(arg);
    }
  }
  const [pkg, capability, target] = positional;
  if (!pkg || !capability) {
    process.stderr.write(HELP);
    return 2;
  }

  const projectRoot = process.cwd();
  const request = buildRequest(capability, target, projectRoot);
  if (typeof request === "string") {
    process.stderr.write(`capwall explain: ${request}\n`);
    return 2;
  }

  const policy = await loadPolicy(path.resolve(projectRoot, policyFile), { projectRoot });
  const decision = evaluate(policy, "enforce", pkg, request);
  process.stdout.write(`${decision.allowed ? "ALLOW" : "DENY"}: ${decision.reason}\n`);
  process.stderr.write(principalNote(policy, pkg, policyFile));
  return decision.allowed ? 0 : 1;
}
