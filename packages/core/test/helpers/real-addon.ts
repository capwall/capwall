/**
 * Borrow a real, loadable `.node` from the installed dependency tree — and prove it is a
 * binding for THIS machine before handing it to a test (issue #140).
 *
 * NOT a test file (no `.test.ts` suffix, so vitest's default `include` never collects it) — a
 * helper shared by `native.test.ts` and `hardened-allowed.test.ts`.
 *
 * WHY THIS EXISTS. The CI image is `node:{20,22}-bookworm-slim`: no toolchain, no network, so
 * building an addon at test time is not an option. But a gate's ALLOW path cannot be proven
 * against a file that is not an addon — `process.dlopen` throws a format error whether the gate
 * allowed the load or never ran at all, which is exactly the hole issue #112 item 5 found in
 * `hardened-allowed.test.ts`'s `native .node load: granted works` row.
 *
 * WHY THE ARCHITECTURE FILTER (#140). pnpm materializes platform-keyed native bindings (e.g.
 * `@rollup/rollup-linux-x64-gnu`, `@oxlint/binding-linux-x64-gnu`) under `node_modules/.pnpm`,
 * and those package directory names embed the platform — which is what keeps this scan cheap and
 * targeted rather than a walk of the whole store. But `pnpm install --force` materializes EVERY
 * optional binding, not just the host's, and a scan keyed on `process.platform` alone happily
 * returns `@oxlint/binding-linux-arm-gnueabihf` on an x64 host. The test then fails with
 * `wrong ELF class: ELFCLASS32`, which is not a capwall answer and reads like the gate passing.
 *
 * So a candidate has to survive two independent checks, and the file is skipped LOUDLY when
 * nothing does (see {@link REAL_ADDON_SKIP_REASON}) rather than loading the first `.node` found:
 *
 *   1. **The path names the host triple.** Tokenized, so `linux-arm64` does not match an `arm`
 *      host by substring and `x64` does not match `ia32` — the pre-#140 `includes()` test was a
 *      substring test, which is how a foreign binding got through in the first place.
 *   2. **The binary's own header agrees.** ELF / Mach-O / PE all record the machine they were
 *      built for; that is the authoritative fact, and it is 64 bytes of `read`. A format this
 *      helper cannot decode is not held against the candidate — check 1 already passed.
 *
 * Repeated `process.dlopen` of the same file into fresh `Module` objects is safe for these
 * bindings (napi-rs) — verified on Node 20 and 22 — so a caller may load the borrowed addon
 * more than once, e.g. once per hardened/plain arm of a matrix.
 */
import * as nodeFs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
/** `packages/core/test/helpers` → the monorepo root. */
const REPO_ROOT = path.resolve(HERE, "..", "..", "..", "..");

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 1. DOES THE PATH NAME THE HOST TRIPLE?
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

/**
 * Spellings of a CPU architecture, mapped onto `process.arch`. npm packages are inconsistent
 * here — napi-rs uses Node's own names, node-pre-gyp and prebuild-install trees carry `x86_64`
 * and `aarch64` from the toolchain that produced them.
 */
const ARCH_ALIASES: Readonly<Record<string, string>> = {
  x64: "x64",
  x86_64: "x64",
  amd64: "x64",
  arm64: "arm64",
  aarch64: "arm64",
  arm: "arm",
  armv7: "arm",
  armv7l: "arm",
  armhf: "arm",
  arm32: "arm",
  ia32: "ia32",
  x86: "ia32",
  i386: "ia32",
  i686: "ia32",
  ppc64: "ppc64",
  ppc64le: "ppc64",
  s390x: "s390x",
  riscv64: "riscv64",
  loong64: "loong64",
  mips64el: "mips64el",
};

/** Spellings of a platform, mapped onto `process.platform`. */
const PLATFORM_ALIASES: Readonly<Record<string, string>> = {
  linux: "linux",
  android: "android",
  darwin: "darwin",
  macos: "darwin",
  osx: "darwin",
  mac: "darwin",
  win32: "win32",
  win: "win32",
  windows: "win32",
  freebsd: "freebsd",
  openbsd: "openbsd",
  sunos: "sunos",
  aix: "aix",
};

/**
 * Path → the platform/arch words in it. Split on everything but `[A-Za-z0-9_]` so `x86_64`
 * survives as one token while `linux-x64-gnu` becomes three. TOKENS, not substrings: `arm64`
 * contains `arm`, and treating that as a match is the #140 bug in the opposite direction.
 */
function tokensOf(p: string): string[] {
  return p.toLowerCase().split(/[^a-z0-9_]+/);
}

/** Distinct values of `map` named anywhere in `p`. */
function named(p: string, map: Readonly<Record<string, string>>): Set<string> {
  const out = new Set<string>();
  for (const token of tokensOf(p)) {
    const hit = map[token];
    if (hit !== undefined) out.add(hit);
  }
  return out;
}

/**
 * Does this path name the host triple and nothing else? Requires a POSITIVE match on the host
 * arch, so a file that names no architecture at all is not accepted — "prefer a candidate
 * matching the host triple, and skip if none does" (#140). A path naming a foreign platform or
 * arch anywhere in it is rejected even if it also names the host's, because the two halves of
 * `.pnpm/@oxlint+binding-linux-arm64-gnu@1/node_modules/@oxlint/binding-linux-arm64-gnu/…` are
 * the only evidence available and disagreement means the guess is unreliable.
 */
export function matchesHostTriple(p: string): boolean {
  const arches = named(p, ARCH_ALIASES);
  const platforms = named(p, PLATFORM_ALIASES);
  if (!arches.has(process.arch) || arches.size !== 1) return false;
  if (platforms.size > 1) return false;
  return platforms.size === 0 || platforms.has(process.platform);
}

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 2. DOES THE BINARY ITSELF AGREE?
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

/** ELF `e_machine` → `process.arch`. */
const ELF_MACHINE: Readonly<Record<number, string>> = {
  0x03: "ia32",
  0x08: "mips64el",
  0x14: "ppc",
  0x15: "ppc64",
  0x16: "s390x",
  0x28: "arm",
  0x3e: "x64",
  0xb7: "arm64",
  0xf3: "riscv64",
};

/** Mach-O `cputype` → `process.arch`. */
const MACHO_CPU: Readonly<Record<number, string>> = {
  0x01000007: "x64",
  0x0100000c: "arm64",
  0x00000007: "ia32",
  0x0000000c: "arm",
};

/** PE `IMAGE_FILE_HEADER.Machine` → `process.arch`. */
const PE_MACHINE: Readonly<Record<number, string>> = {
  0x014c: "ia32",
  0x8664: "x64",
  0xaa64: "arm64",
  0x01c4: "arm",
};

/**
 * What architecture is this binary actually built for?
 *
 *  - `"host"`    — decoded, and it is this machine's.
 *  - `"foreign"` — decoded, and it is not. The `wrong ELF class` outcome, caught before load.
 *  - `"unknown"` — not decodable here (an unreadable file, a fat/universal Mach-O, a format
 *                  this helper does not know). Deliberately NOT treated as a rejection: the
 *                  name check has already passed, and a false "foreign" would silently skip
 *                  every test in the file, which is the hollow-pass failure #112 is about.
 */
export function hostBinaryVerdict(file: string): "host" | "foreign" | "unknown" {
  let head: Buffer;
  try {
    const fd = nodeFs.openSync(file, "r");
    try {
      head = Buffer.alloc(64);
      const read = nodeFs.readSync(fd, head, 0, 64, 0);
      if (read < 64) return "unknown";
    } finally {
      nodeFs.closeSync(fd);
    }
  } catch {
    return "unknown";
  }
  const verdict = (arch: string | undefined): "host" | "foreign" | "unknown" =>
    arch === undefined ? "unknown" : arch === process.arch ? "host" : "foreign";

  // ELF: 0x7f 'E' 'L' 'F', class at [4] (1 = 32-bit, 2 = 64-bit), endianness at [5],
  // e_machine at [18..19]. A 32-bit binding on a 64-bit host is `wrong ELF class`.
  if (head.readUInt32BE(0) === 0x7f454c46) {
    const little = head[5] === 1;
    const machine = little ? head.readUInt16LE(18) : head.readUInt16BE(18);
    const arch = ELF_MACHINE[machine];
    if (arch === undefined) return "unknown";
    const is64 = head[4] === 2;
    const host64 = !["ia32", "arm", "ppc"].includes(process.arch);
    return is64 === host64 ? verdict(arch) : "foreign";
  }
  // Mach-O (thin, either endianness). A fat binary (0xcafebabe) contains several slices and is
  // loadable on the host if any of them matches — not decoded here, so it stays "unknown".
  const machoMagic = head.readUInt32LE(0);
  if (machoMagic === 0xfeedface || machoMagic === 0xfeedfacf) {
    return verdict(MACHO_CPU[head.readUInt32LE(4)]);
  }
  const machoMagicBE = head.readUInt32BE(0);
  if (machoMagicBE === 0xfeedface || machoMagicBE === 0xfeedfacf) {
    return verdict(MACHO_CPU[head.readUInt32BE(4)]);
  }
  // PE/COFF: 'MZ', then the PE header offset at 0x3c. The header may sit past the 64 bytes read
  // above, so this reads the machine word only when it is within reach.
  if (head[0] === 0x4d && head[1] === 0x5a) {
    const peAt = head.readUInt32LE(0x3c);
    if (peAt + 6 > head.length) return "unknown";
    if (head.readUInt32LE(peAt) !== 0x00004550) return "unknown";
    return verdict(PE_MACHINE[head.readUInt16LE(peAt + 4)]);
  }
  return "unknown";
}

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 3. THE SCAN
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

/** Every `.node` under `dir`, breadth-bounded so an unexpected tree cannot make this expensive. */
function addonsUnder(dir: string, depth: number, budget: { left: number }): string[] {
  if (depth > 4 || budget.left <= 0) return [];
  let entries: nodeFs.Dirent[];
  try {
    entries = nodeFs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const out: string[] = [];
  // Sorted: readdir order is filesystem-dependent, and "which addon did the suite borrow"
  // should not be.
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (--budget.left <= 0) break;
    const full = path.join(dir, entry.name);
    if (entry.isFile() && entry.name.endsWith(".node")) out.push(full);
    else if (entry.isDirectory()) out.push(...addonsUnder(full, depth + 1, budget));
  }
  return out;
}

export interface AddonScan {
  /** A `.node` that is loadable on this machine, or `null`. */
  file: string | null;
  /** Human-readable "why not", empty when `file` is set. Surfaced in the skip message (#140). */
  reason: string;
  /** Every `.node` the scan saw, host and foreign alike — for the skip message and the tests. */
  seen: readonly string[];
}

export function scanForRealAddon(storeRoot?: string): AddonScan {
  const store = storeRoot ?? path.join(REPO_ROOT, "node_modules", ".pnpm");
  const triple = `${process.platform}-${process.arch}`;
  let dirs: nodeFs.Dirent[];
  try {
    dirs = nodeFs.readdirSync(store, { withFileTypes: true });
  } catch {
    return { file: null, reason: `no pnpm store at ${store}`, seen: [] };
  }
  const names = dirs
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
  // Two passes. Platform-keyed binding packages (the napi-rs convention, and what this repo
  // actually installs) are cheap and are checked first; the general walk that would find a
  // `prebuilds/linux-x64/` layout inside an ordinary package runs only if that found nothing,
  // so the common case does not pay for it.
  const conventional = names.filter((n) => named(n, PLATFORM_ALIASES).size > 0);
  const seen: string[] = [];
  for (const group of [conventional, names]) {
    const budget = { left: 3000 };
    for (const name of group) {
      for (const file of addonsUnder(path.join(store, name), 0, budget)) {
        if (!seen.includes(file)) seen.push(file);
      }
    }
    const named0 = seen.filter((f) => matchesHostTriple(path.relative(store, f)));
    const usable = named0.filter((f) => hostBinaryVerdict(f) !== "foreign");
    const best = usable.find((f) => hostBinaryVerdict(f) === "host") ?? usable[0];
    if (best !== undefined) return { file: best, reason: "", seen };
  }
  const detail =
    seen.length === 0
      ? `no .node file at all under ${path.relative(REPO_ROOT, store)}`
      : `${seen.length} .node file(s) found, none built for ${triple}: ` +
        seen.map((f) => path.relative(store, f)).join(", ");
  return {
    file: null,
    reason: `no native addon loadable on ${triple} is installed — ${detail}`,
    seen,
  };
}

/** Discovered once per test file — the scan touches the filesystem. */
const SCAN: AddonScan = scanForRealAddon();

export const REAL_ADDON: string | null = SCAN.file;

/**
 * Why there is no addon to borrow, for the skip message. A suite that skips must say WHY —
 * "0 tests, all skipped" with no reason is indistinguishable from a suite that quietly stopped
 * testing anything.
 */
export const REAL_ADDON_SKIP_REASON: string = SCAN.reason;

/** Suite title carrying the skip reason, since `describe.skipIf` has nowhere else to put it. */
export function titleWithSkipReason(title: string): string {
  return REAL_ADDON === null ? `${title} [SKIPPED: ${REAL_ADDON_SKIP_REASON}]` : title;
}

/* ═══════════════════════════════════════════════════════════════════════════════════════════
 * 4. WHY DID A LOAD FAIL?
 * ═════════════════════════════════════════════════════════════════════════════════════════ */

/**
 * The outcomes of pointing `process.dlopen` at a file, which the native tests exist to tell
 * apart. Before #140 they asserted only `name !== "CapabilityError"`, which collapses the last
 * three into one — so a foreign-architecture binding read exactly like "the gate passed and the
 * platform loader rejected the placeholder", the thing those rows claim to prove.
 *
 *  - `"gate"`   — capwall refused. A `CapabilityError`.
 *  - `"arch"`   — the file is a real addon for the wrong machine (`wrong ELF class`,
 *                 `Exec format error`, `incompatible architecture`). Never an intended outcome:
 *                 it means the borrowed binding was chosen badly (#140).
 *  - `"missing"`— there is no such file.
 *  - `"loader"` — the platform loader looked at the file and would not load it: the expected
 *                 result for the placeholder fixtures, and the proof the gate stood aside.
 */
export type LoadFailure = "gate" | "arch" | "missing" | "loader";

const ARCH_REJECTION =
  /wrong ELF class|exec format error|incompatible architecture|wrong architecture|not a valid Win32 application|ELFCLASS|no suitable image found/i;
const MISSING = /no such file|cannot find the path|ENOENT/i;

export function classifyLoadFailure(err: unknown): LoadFailure {
  const e = err as { name?: string; message?: string } | null;
  if (e?.name === "CapabilityError") return "gate";
  const message = e?.message ?? "";
  if (ARCH_REJECTION.test(message)) return "arch";
  if (MISSING.test(message)) return "missing";
  return "loader";
}
