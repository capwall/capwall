/**
 * IPC destination canonicalization and matching (issue #72).
 *
 * Before this, EVERY unix-domain socket and Windows named pipe was the one pseudo-target
 * `<ipc>:0`, so granting a package the application socket it actually uses also granted it
 * `/var/run/docker.sock`, the systemd journal socket and an SSH agent socket. #46 and #56 made
 * that worse by routing MORE traffic through the pseudo-target (notably
 * `http.request({socketPath})`, which used to be mis-guarded as `localhost:80`). IPC is now its
 * own capability — `ipc: { paths: [...] }` — carrying the concrete socket path.
 *
 * ## Matching reuses the fs glob matcher
 *
 * `ipc.paths` entries are matched by {@link matchesGlob}, the same matcher `fs.read`/`fs.write`
 * globs go through, including the Windows drive-letter handling from #45. The semantics line up
 * exactly — these ARE filesystem paths, `/`-separated, matched lexically, with `*` confined to
 * one segment and `**` spanning segments — so a second path matcher would only be a second
 * thing to keep correct. Everything below is canonicalization FEEDING that matcher, not a
 * reimplementation of it.
 *
 * ## Windows named pipes
 *
 * A named pipe is `\\.\pipe\NAME` (equivalently `\\?\pipe\NAME`), which is not a path the fs
 * matcher can take: it is `\`-separated and its `\\.\` root collapses to an empty first segment.
 * Rather than special-case the matcher, both patterns and observed pipes are canonicalized to
 *
 *     /./pipe/NAME
 *
 * — a `/`-separated absolute path whose segments (`.`, `pipe`, NAME) survive the matcher's split
 * unchanged, so `//./pipe/myapp-*`, `\\.\pipe\myapp-*` and `/./pipe/myapp-*` are all the same
 * pattern and all match a pipe observed as `\\.\pipe\myapp-1`. A path produced by `path.resolve`
 * never contains a `.` segment, so this canonical form cannot collide with a real unix socket
 * path. The `pipe` keyword is lowercased (Win32 treats it case-insensitively); the pipe NAME is
 * matched case-sensitively, the same call the fs matcher makes for everything but the drive
 * letter — silently widening a grant to match case-varying names is a bigger mistake than a
 * spurious deny, and an author who needs it can write `*`.
 *
 * ## Machine-portable policies
 *
 * A socket path is often machine-specific — a temp dir (`/tmp` on Linux, `/var/folders/…` on
 * macOS), or something under `$HOME`. Recording the literal path would produce a policy that
 * only matches on the machine that ran `observe`, the same non-reproducibility that bit
 * ephemeral ports (#27), host-specific env keys (#57) and native addon build paths (#49). So
 * `capwall observe` emits two placeholders, expanded at policy-load time against the LOADING
 * machine:
 *
 *     <tmp>/foo.sock    ->  os.tmpdir() + "/foo.sock"
 *     <home>/.x/y.sock  ->  os.homedir() + "/.x/y.sock"
 *
 * What is deliberately NOT done: guessing which segment of `/tmp/app-a91f3/api.sock` is random.
 * capwall cannot know, and a tool that silently widened that to `/tmp/app-<star>/api.sock` would
 * be inventing authority the operator never reviewed. The concrete path is emitted and
 * `docs/policy-format.md` says to widen it by hand.
 */
import * as os from "node:os";
import * as path from "node:path";
import { matchesGlob } from "./glob.js";

/**
 * The legacy pseudo-host every IPC connect used to be gated as. Still honored in `net.hosts`
 * as an "all IPC" grant so policies written before #72 keep working — see `isGranted`.
 * The shims' copy of this string lives in `shims/net.ts` (`IPC_HOST`).
 */
export const IPC_PSEUDO_HOST = "<ipc>";

/**
 * Recorded when an IPC connect's destination cannot be determined from the call (an options
 * bag of an unexpected shape). It matches no `ipc.paths` glob except `*`/`**`, so such a call
 * needs an explicit all-IPC grant — fail closed, and visible in the trace as unknown.
 */
export const UNKNOWN_IPC_PATH = "<unknown>";

export const IPC_TMP_PLACEHOLDER = "<tmp>";
export const IPC_HOME_PLACEHOLDER = "<home>";

/** `\\.\pipe\NAME`, `\\?\pipe\NAME`, or either with `/` separators. Group 1 is NAME. */
const NAMED_PIPE = /^[\\/]{2}[.?][\\/]pipe[\\/](.*)$/i;

/** The canonical prefix every named pipe is rewritten to — see the module header. */
const PIPE_ROOT = "/./pipe/";

/** A Windows drive-absolute path (`C:\foo`, `C:/foo`) — same test as `policy/load.ts`. */
const WINDOWS_ABSOLUTE = /^[A-Za-z]:[\\/]/;

function canonicalPipe(value: string): string | undefined {
  const m = NAMED_PIPE.exec(value);
  if (!m) return undefined;
  return PIPE_ROOT + m[1]!.replace(/\\/g, "/");
}

/**
 * Canonicalize an OBSERVED IPC destination (the `path`/`socketPath` a dependency passed) into
 * the shape the matcher and the trace both use: a named pipe as `/./pipe/NAME`, anything else
 * resolved to an absolute `/`-separated path — the same treatment `shims/fs.ts` `coercePath`
 * gives an fs argument, so a relative `net.connect({ path: "./app.sock" })` records the same
 * string a policy can name.
 */
export function canonicalIpcPath(observed: string): string {
  if (observed === UNKNOWN_IPC_PATH) return observed;
  // Already canonical (this function is idempotent, and the shim canonicalizes before
  // recording). It must short-circuit: `path.resolve` would collapse the `.` segment that
  // makes `/./pipe/NAME` distinguishable from a real `/pipe/NAME` directory.
  if (observed.startsWith(PIPE_ROOT)) return observed;
  const pipe = canonicalPipe(observed);
  if (pipe !== undefined) return pipe;
  // A Windows drive-absolute path on a POSIX host: `path.isAbsolute` does not recognize it and
  // `path.resolve` would prepend the cwd, producing `/cwd/C:/…`. Reshape directly instead —
  // the identical guard `policy/load.ts` `normalizeGlob` applies for the same reason (#45).
  if (WINDOWS_ABSOLUTE.test(observed) && !path.isAbsolute(observed)) {
    return observed.replace(/\\/g, "/");
  }
  return path.resolve(observed).split(path.sep).join("/");
}

/** Is this already the canonical named-pipe form? (Such a pattern must never be resolved
 * against a project root — it is absolute in Win32 terms and `path` cannot see that.) */
export function isCanonicalNamedPipe(value: string): boolean {
  return value.startsWith(PIPE_ROOT);
}

/**
 * Canonicalize a POLICY pattern. Unlike {@link canonicalIpcPath} this does NOT resolve relative
 * patterns — `loadPolicy` does that against the project root (not the process cwd), exactly as
 * it already does for `fs` globs.
 */
export function canonicalIpcPattern(pattern: string): string {
  return canonicalPipe(pattern) ?? pattern.replace(/\\/g, "/");
}

/** Does `prefix` cover `value` at a path-segment boundary? (`/tmp` covers `/tmp/x`, not `/tmpx`.) */
function hasPathPrefix(value: string, prefix: string): boolean {
  if (prefix === "" || !value.startsWith(prefix)) return false;
  return value.length === prefix.length || value[prefix.length] === "/";
}

/**
 * Rewrite a machine-specific prefix of an absolute socket path as a placeholder, so a generated
 * policy is portable. Returns the path unchanged when no placeholder applies.
 *
 * `<tmp>` is tried before `<home>` because a `TMPDIR` under the home directory is common and the
 * temp dir is the more specific (and more volatile) of the two.
 */
export function placeholderizeIpcPath(canonicalPath: string): string {
  for (const [placeholder, dir] of [
    [IPC_TMP_PLACEHOLDER, os.tmpdir()],
    [IPC_HOME_PLACEHOLDER, os.homedir()],
  ] as const) {
    const root = dir.split(path.sep).join("/");
    if (hasPathPrefix(canonicalPath, root)) {
      return placeholder + canonicalPath.slice(root.length);
    }
  }
  return canonicalPath;
}

/** Expand `<tmp>`/`<home>` against THIS machine. Applied by `loadPolicy` before glob matching. */
export function expandIpcPlaceholders(pattern: string): string {
  for (const [placeholder, dir] of [
    [IPC_TMP_PLACEHOLDER, os.tmpdir()],
    [IPC_HOME_PLACEHOLDER, os.homedir()],
  ] as const) {
    if (pattern === placeholder || pattern.startsWith(placeholder + "/")) {
      return dir.split(path.sep).join("/") + pattern.slice(placeholder.length);
    }
  }
  return pattern;
}

/**
 * Does an `ipc.paths` entry grant `observedPath`? Both sides are canonicalized so a pattern
 * written in any accepted named-pipe spelling matches a pipe recorded in any other.
 */
export function matchesIpcPath(pattern: string, observedPath: string): boolean {
  return matchesGlob(canonicalIpcPattern(pattern), canonicalIpcPath(observedPath));
}
