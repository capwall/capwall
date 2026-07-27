/**
 * `capwall explain <package> <capability> [target]` (roadmap M3+).
 *
 * Loads the current policy and reports whether the given package would be allowed the given
 * capability against an optional target — using the same `evaluate()` the enforcer uses, so
 * the answer matches enforcement exactly. Exit code: 0 allowed, 1 denied, 2 usage error.
 */
import * as path from "node:path";
import { evaluate, loadPolicy, type CapabilityRequest } from "@capwall/core";

const HELP = `usage: capwall explain [--policy <file>] <package> <capability> [target]

Capabilities and their targets:
  fs:read <path> | fs:write <path> | net <host:port> | env <KEY>
  child_process | worker_threads | vm | native [addon-path]

  'native' gates whether the package may load a .node addon at all. Its optional
  [addon-path] target is echoed in the answer for readability only — the grant is a
  boolean, so the path does not change the verdict (see docs/policy-format.md).

Examples:
  capwall explain pino fs:write ./logs/app.log
  capwall explain express net localhost:3000
  capwall explain sneaky-dep env AWS_SECRET_ACCESS_KEY
  capwall explain better-sqlite3 native
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
    default:
      return `unknown capability '${capability}' (see capwall explain --help)`;
  }
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
  return decision.allowed ? 0 : 1;
}
