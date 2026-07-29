/**
 * Trace aggregation: turn the preload's JSONL decision trace into a `capabilities.json`,
 * merging into an existing policy rather than overwriting it (repeated observe runs
 * accumulate coverage without clobbering hand edits — docs/policy-format.md).
 */
import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import * as path from "node:path";
import { placeholderizeIpcPath, type CapabilityRequest } from "@capwall/core";
import {
  parsePolicy,
  unmatchedPackageKeys,
  type PackagePolicy,
  type Policy,
} from "@capwall/policy-schema";

/** One line of the preload's JSONL trace: what a principal did, deduplicated per process. */
export interface TraceEntry {
  /** The principal — a package name, an install chain, or `<app>`/`<unknown>`. */
  pkg: string;
  /** The capability-sensitive operation it performed. */
  req: CapabilityRequest;
}

/**
 * Parse a JSONL trace file's contents. Unparseable lines are skipped.
 *
 * @param contents the whole trace file. Blank lines and any line that is not a JSON object with
 *     a string `pkg` and a `req` are dropped — including the torn last line a killed process
 *     leaves behind, which is why this is lenient rather than strict.
 * @returns the entries in file order. Never throws.
 */
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
 *
 * @param entries what a run observed, as {@link parseTrace} returns them.
 * @param existing the policy to merge into, MUTATED IN PLACE and returned; `null` starts a fresh
 *     `observe`-mode document.
 * @param projectRoot the root paths under it are rewritten relative to, so the emitted policy
 *     is portable.
 * @returns the merged policy: list-valued grants sorted and deduplicated, `packages` in name
 *     order for a stable diff.
 * @throws a ZodError only when `existing` is `null` and the fresh scaffold fails validation,
 *     which cannot happen for the literal used here.
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
      // Same reasoning as `native`: the observed filename is dropped, because the grant is the
      // boolean question "may this package name code as somebody else" and a filename list
      // would be a per-run artifact. Unlike `native`, this one is IDENTITY-GRANTING (#93) —
      // `capwall observe` will happily generate it for a transform hook that legitimately needs
      // it, and the policy-format docs say in terms that it must be reviewed before it is kept.
      case "compile":
        grant.compile = true;
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

/**
 * The one-or-more warning lines for `packages` keys that granted nothing in this run (#118),
 * or `""` when every key matched something.
 *
 * WHY THIS IS A WARNING AND NOT AN ERROR — the judgment call #118 asks for. A key that matches
 * nothing is fail-CLOSED: the grant does not apply, nothing is permitted that would not
 * otherwise be, and no denial is missed. The defect is one of trust in the artifact — the file
 * claims a grant the runtime never uses, `explain` cheerfully answers for a principal that does
 * not exist, and `diff` calls the resulting denial DRIFT, which sends the reader to look at the
 * dependency instead of at their own key. So it deserves to be said out loud, at the moment the
 * evidence exists, and it does not deserve to fail the build: a key legitimately matches nothing
 * when the dependency it names is optional, platform-specific, or simply on a code path this run
 * did not exercise. Erroring would break policies that are entirely correct. `capwall diff
 * --strict` is the opt-in for CI that wants dead keys gone.
 *
 * Rendered here rather than in each command so `observe` and `diff` say the same thing.
 *
 * @param policy the committed policy whose `packages` keys are being judged.
 * @param entries what this run observed. An EMPTY run returns `""` — it is evidence about the
 *     run, not about the file.
 * @param policyFile the path to name in the message, so a reader knows which file to edit.
 * @returns the newline-terminated warning block, or `""` when there is nothing to say. The
 *     caller decides where it goes and whether it fails the build.
 */
export function unmatchedKeyWarning(
  policy: Policy,
  entries: readonly TraceEntry[],
  policyFile: string,
): string {
  // A run that recorded nothing at all (the target crashed on line 1, or genuinely touched no
  // capability) says nothing about the policy — every key would be "unmatched", which is a
  // report about the run, not about the file. Stay quiet rather than cry wolf.
  if (entries.length === 0) return "";
  const principals = new Set(entries.map((e) => e.pkg));
  const unmatched = unmatchedPackageKeys(Object.keys(policy.packages), principals);
  if (unmatched.length === 0) return "";
  const noun = unmatched.length === 1 ? "key" : "keys";
  let out =
    `[capwall] warning: ${unmatched.length} policy ${noun} in ${policyFile} matched no ` +
    `package in this run (the grant does nothing):\n`;
  for (const { key, suggestions } of unmatched) {
    const hint =
      suggestions.length > 0
        ? ` — did you mean ${suggestions.slice(0, 3).map((s) => `"${s}"`).join(" or ")}?`
        : "";
    out += `  "${key}"${hint}\n`;
  }
  return out;
}

/**
 * Load an existing capabilities.json as-authored (no glob normalization), or null.
 *
 * Deliberately NOT `@capwall/core`'s `loadPolicy`: this policy is about to be merged and written
 * back, and absolutizing its globs first would rewrite the author's `./logs/**` into a path that
 * only works on this machine.
 *
 * @param file the policy path.
 * @returns the parsed policy, or `null` when the file does not exist or cannot be read.
 * @throws a `SyntaxError` or ZodError when the file exists but is not a valid policy — an
 *     unreadable file is `null`, a malformed one is an error the caller must surface.
 */
export async function loadExistingPolicy(file: string): Promise<Policy | null> {
  let raw: string;
  try {
    raw = await readFile(file, "utf8");
  } catch {
    return null;
  }
  return parsePolicy(JSON.parse(raw));
}

/**
 * The `$schema` pointer to write into a generated policy, or undefined (issue #124).
 *
 * A generated `capabilities.json` is the file the user is immediately told to hand-edit, and
 * editor validation/completion is worth most exactly there — the `outer>inner` package-key
 * grammar and the `*>` / `**>` wildcards are the subtleties a schema catches for free. Without
 * a `$schema` key nobody gets any of it.
 *
 * ONLY WHEN THE TARGET REALLY EXISTS. A dangling `$schema` is worse than none: most editors
 * surface an unresolvable pointer as a diagnostic on line 2 of a file capwall just wrote, which
 * would make every generated policy look broken. So this checks the path and stays silent
 * otherwise — which today means it stays silent on the from-a-clone path, where nothing is
 * installed under `node_modules/@capwall`. Revisit at first publish: a stable `https://` schema
 * URL would be better than a relative one and would work for everyone.
 */
function schemaRefFor(projectRoot: string): string | undefined {
  const rel = path.join("node_modules", "@capwall", "policy-schema", "schema.json");
  return existsSync(path.join(projectRoot, rel)) ? "./" + rel.split(path.sep).join("/") : undefined;
}

/**
 * Serialize a policy.
 *
 * `$schema` is added for a policy that has none, and written FIRST — that is where every
 * convention puts it and where a reader looks. An existing `$schema` is never rewritten: the
 * author may be pointing at a checkout, a pinned version, or a vendored copy, and silently
 * retargeting a field they set is not something a merge should do.
 *
 * @param file where to write. Overwritten wholesale — merging is {@link mergeTraceIntoPolicy}'s
 *     job and must already have happened.
 * @param policy the policy to serialize. Not mutated.
 * @param projectRoot the root to look for an installed `schema.json` under.
 * @throws a Node fs error when the write fails.
 */
export async function writePolicy(
  file: string,
  policy: Policy,
  projectRoot: string,
): Promise<void> {
  const ref = policy.$schema === undefined ? schemaRefFor(projectRoot) : undefined;
  const out = ref === undefined ? policy : { $schema: ref, ...policy };
  await writeFile(file, JSON.stringify(out, null, 2) + "\n");
}
