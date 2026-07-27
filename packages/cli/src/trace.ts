/**
 * Trace aggregation: turn the preload's JSONL decision trace into a `capabilities.json`,
 * merging into an existing policy rather than overwriting it (repeated observe runs
 * accumulate coverage without clobbering hand edits — docs/policy-format.md).
 */
import { readFile, writeFile } from "node:fs/promises";
import * as path from "node:path";
import { placeholderizeIpcPath, type CapabilityRequest } from "@capwall/core";
import { parsePolicy, type PackagePolicy, type Policy } from "@capwall/policy-schema";

export interface TraceEntry {
  pkg: string;
  req: CapabilityRequest;
}

/** Parse a JSONL trace file's contents. Unparseable lines are skipped. */
export function parseTrace(contents: string): TraceEntry[] {
  const entries: TraceEntry[] = [];
  for (const line of contents.split("\n")) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line) as TraceEntry;
      if (parsed && typeof parsed.pkg === "string" && parsed.req) entries.push(parsed);
    } catch {
      // A torn line (process killed mid-write) — skip.
    }
  }
  return entries;
}

/** Store paths under the project root as portable `./relative` globs; others as absolute. */
function relativize(absPath: string, projectRoot: string): string {
  const rel = path.relative(projectRoot, absPath);
  if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) return absPath;
  return "./" + rel.split(path.sep).join("/");
}

function sortedUnique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

/**
 * The form of an observed socket path to WRITE INTO A POLICY (#72). Generated policies have to
 * reproduce on someone else's machine — the constraint that has already bitten this project
 * three times (#27 ephemeral ports, #57 host-specific env keys, #49 native addon build paths) —
 * and a socket path is very often machine-specific.
 *
 * Three cases, most portable first:
 *  1. Under the project root → a `./relative` glob, exactly as for `fs` (`sock/api.sock`).
 *  2. Under the temp dir or the home dir → the `<tmp>`/`<home>` placeholder, which
 *     `loadPolicy` expands against the machine that loads the policy. This is what makes a
 *     socket in `/tmp` on Linux CI and `/var/folders/…` on a maintainer's mac the same grant.
 *  3. Anything else (`/var/run/app.sock`, `/./pipe/NAME`) → the literal path. Those are stable
 *     system locations; a remaining volatile component (a randomized temp directory name, a
 *     `/run/user/<uid>` segment) is left for the author to widen with `*`. capwall deliberately
 *     does not guess which segment is random: silently emitting a wider grant than what was
 *     observed is exactly the thing an operator is reviewing this file to catch.
 */
function portableIpcPath(observedPath: string, projectRoot: string): string {
  const rel = relativize(observedPath, projectRoot);
  if (rel !== observedPath) return rel;
  return placeholderizeIpcPath(observedPath);
}

/**
 * Merge observed trace entries into `existing` (or a fresh empty policy). Every capability
 * kind is handled: fs, net, ipc, env, child_process, worker_threads, vm and native. Merging is
 * ADDITIVE — a re-run appends to an existing policy rather than replacing it, which is why
 * `docs/policy-format.md` § Generating a policy tells you to observe into a scratch file when
 * you have a reviewed policy you want to keep.
 */
export function mergeTraceIntoPolicy(
  entries: TraceEntry[],
  existing: Policy | null,
  projectRoot: string,
): Policy {
  const policy: Policy =
    existing ?? parsePolicy({ version: 1, mode: "observe", default: {}, packages: {} });

  for (const { pkg, req } of entries) {
    const grant: PackagePolicy = (policy.packages[pkg] ??= {});
    switch (req.kind) {
      case "fs": {
        const fs = (grant.fs ??= { read: [], write: [] });
        const target = relativize(req.path, projectRoot);
        if (req.access === "read") fs.read.push(target);
        else fs.write.push(target);
        break;
      }
      case "net": {
        const net = (grant.net ??= { hosts: [], ports: [] });
        net.hosts.push(req.host);
        net.ports.push(req.port);
        break;
      }
      // A unix socket / named pipe, recorded per-path since #72 rather than as one `<ipc>`
      // grant covering every socket on the machine. The observed path is already canonical
      // (absolute, `/`-separated, `/./pipe/NAME` for a pipe) — see core's policy/ipc.ts.
      case "ipc": {
        const ipc = (grant.ipc ??= { paths: [] });
        ipc.paths.push(portableIpcPath(req.path, projectRoot));
        break;
      }
      case "env": {
        (grant.env ??= []).push(req.key);
        break;
      }
      case "child_process":
        grant.child_process = true;
        break;
      case "worker_threads":
        grant.worker_threads = true;
        break;
      case "vm":
        grant.vm = true;
        break;
      // The observed addon PATH is deliberately dropped here (#49). It is recorded in the
      // trace and shown by `observe`/`diff` so an operator can see which addon loaded, but it
      // is a platform/arch/ABI-specific build artifact — writing it into the policy would
      // produce a grant that stops matching on the next machine, the same non-reproducibility
      // that bit ephemeral ports (#27) and host-specific env keys (#57). The grant is the
      // boolean question: may this package load compiled code at all.
      case "native":
        grant.native = true;
        break;
    }
  }

  for (const grant of Object.values(policy.packages)) {
    if (grant.fs) {
      grant.fs.read = sortedUnique(grant.fs.read);
      grant.fs.write = sortedUnique(grant.fs.write);
    }
    if (grant.net) {
      grant.net.hosts = sortedUnique(grant.net.hosts);
      // Ports may include a hand-authored `"*"` wildcard (#27) alongside observed numbers.
      const ports = grant.net.ports;
      const nums = [...new Set(ports.filter((p): p is number => typeof p === "number"))].sort(
        (a, b) => a - b,
      );
      grant.net.ports = ports.includes("*") ? ["*", ...nums] : nums;
    }
    if (grant.ipc) grant.ipc.paths = sortedUnique(grant.ipc.paths);
    if (grant.env) grant.env = sortedUnique(grant.env);
  }
  // Deterministic package order for stable diffs.
  policy.packages = Object.fromEntries(
    Object.entries(policy.packages).sort(([a], [b]) => a.localeCompare(b)),
  );
  return policy;
}

/** Load an existing capabilities.json as-authored (no glob normalization), or null. */
export async function loadExistingPolicy(file: string): Promise<Policy | null> {
  let raw: string;
  try {
    raw = await readFile(file, "utf8");
  } catch {
    return null;
  }
  return parsePolicy(JSON.parse(raw));
}

export async function writePolicy(file: string, policy: Policy): Promise<void> {
  await writeFile(file, JSON.stringify(policy, null, 2) + "\n");
}
