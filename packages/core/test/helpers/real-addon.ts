/**
 * Borrow a real, loadable `.node` from the installed dependency tree.
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
 * pnpm materializes platform-keyed native bindings (e.g. `@rollup/rollup-linux-x64-gnu`,
 * `@oxlint/binding-linux-x64-gnu`) under `node_modules/.pnpm`, and those package directory
 * names embed `process.platform` — which is what keeps this scan cheap and targeted rather
 * than a walk of the whole store. Returns `null` when no such binding is installed (a
 * different package manager's layout, or a platform with no prebuilt binding), in which case
 * every dependent test must skip LOUDLY rather than pretend to pass.
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

export function findRealAddon(): string | null {
  const store = path.join(REPO_ROOT, "node_modules", ".pnpm");
  let budget = 3000;
  const walk = (dir: string, depth: number): string | null => {
    if (depth > 4 || budget <= 0) return null;
    let entries: nodeFs.Dirent[];
    try {
      entries = nodeFs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return null;
    }
    for (const entry of entries) {
      if (--budget <= 0) return null;
      const full = path.join(dir, entry.name);
      if (entry.isFile() && entry.name.endsWith(".node")) return full;
      if (entry.isDirectory()) {
        const hit = walk(full, depth + 1);
        if (hit) return hit;
      }
    }
    return null;
  };
  let candidates: nodeFs.Dirent[];
  try {
    candidates = nodeFs.readdirSync(store, { withFileTypes: true });
  } catch {
    return null;
  }
  for (const entry of candidates) {
    if (!entry.isDirectory() || !entry.name.includes(process.platform)) continue;
    const hit = walk(path.join(store, entry.name), 0);
    if (hit) return hit;
  }
  return null;
}

/** Discovered once per test file — the scan touches the filesystem. */
export const REAL_ADDON: string | null = findRealAddon();
