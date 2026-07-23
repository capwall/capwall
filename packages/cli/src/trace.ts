/**
 * Trace aggregation: turn the preload's JSONL decision trace into a `capabilities.json`,
 * merging into an existing policy rather than overwriting it (repeated observe runs
 * accumulate coverage without clobbering hand edits — docs/policy-format.md).
 */
import { readFile, writeFile } from "node:fs/promises";
import * as path from "node:path";
import type { CapabilityRequest } from "@capwall/core";
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
 * Merge observed trace entries into `existing` (or a fresh empty policy). Only fs entries
 * are produced today (roadmap M1–M3); other kinds are ignored until their shims land in M4.
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
