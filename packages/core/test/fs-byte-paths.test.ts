/**
 * Byte (`Uint8Array`) path arguments — the decode strategy and the shapes it has to cover
 * (issues #41, #19, #108).
 *
 * A POSIX path is BYTES; a policy glob is a JS STRING. capwall bridges them by decoding the byte
 * path with **`latin1`**, and #41 asked whether that is the right default or whether `utf8`
 * (which matches a policy author's intent for a real non-ASCII filename) is. This file PINS the
 * answer rather than leaving it to whichever decode a future edit happens to reach for:
 *
 *  - `latin1` is a BIJECTION over byte sequences, so the string that was matched against policy
 *    determines the bytes that reach the real `fs` uniquely. "The author believes a path is
 *    denied but it matches" is therefore unreachable, not merely unlikely.
 *  - `utf8` is not: every invalid subsequence collapses to U+FFFD, so many distinct byte paths
 *    share one string. Granting the path an `observe` run recorded would grant all of them, and
 *    the audit trail could not say which file was read. That is what #19 fixed.
 *  - The residual cost is a FALSE-DENY: a valid non-ASCII UTF-8 path supplied as bytes does not
 *    match a UTF-8-authored glob. Fail-closed, loud, and asserted below so it stays a known
 *    trade rather than a surprise.
 *
 * Every case runs through `fixture-dep` so the read attributes to a package rather than to
 * `<app>`, and each is expressed as raw byte VALUES so the test does not depend on any encoding
 * of its own source file.
 */
import { createRequire } from "node:module";
import * as nodeFs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { install, loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");
const SCRATCH = path.join(here, "fixtures", "scratch-bytes");

interface FixtureDep {
  readFileSyncBufferPath(bytes: number[]): string;
  readFileSyncUint8ArrayPath(bytes: number[]): string;
  readFileSyncUint8ArrayViewPath(bytes: number[], padding: number): string;
  readFileSyncMutatedBytePath(checked: number[], swapped: number[]): string;
  /** An ordinary STRING path, for the complement of the false-deny case. */
  statSync(target: string): { size: number };
}

function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

const readGrant = (read: string[]): Policy =>
  loadPolicyFromObject(
    { version: 1, mode: "enforce", packages: { "fixture-dep": { fs: { read, write: [] } } } },
    { projectRoot: here },
  );

type Recorded = { pkg: string; decision: Decision };

function withCapwall<T>(
  policy: Policy,
  mode: "observe" | "enforce",
  fn: (dep: FixtureDep) => T,
): { result: T; decisions: Recorded[] } {
  const decisions: Recorded[] = [];
  const handle = install(policy, mode, {
    projectRoot: here,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
  });
  try {
    return { result: fn(loadFixtureFresh()), decisions };
  } finally {
    handle.uninstall();
  }
}

/** The path capwall recorded for the one decision this call produced. */
function recordedPath(decisions: Recorded[]): string {
  expect(decisions).toHaveLength(1);
  return (decisions[0]!.decision.observed as { path: string }).path;
}

/** `path.join(SCRATCH, name)` as raw bytes, with `name` given byte-wise so a test can name a
 * file whose name is not valid UTF-8 at all. */
function scratchPathBytes(nameBytes: number[]): number[] {
  return [...Buffer.from(SCRATCH + path.sep), ...nameBytes];
}

/** ASCII "plain.txt". */
const PLAIN = [...Buffer.from("plain.txt", "ascii")];
/** "café.txt" as valid UTF-8 — the case a policy author writes as `café.txt` in JSON. */
const CAFE_UTF8 = [0x63, 0x61, 0x66, 0xc3, 0xa9, 0x2e, 0x74, 0x78, 0x74];
/** "x<0xFF>.txt" — 0xFF is not valid UTF-8 anywhere, but is a perfectly legal POSIX filename
 * byte. This is the file a `utf8` decode could not name without losing information. */
const INVALID_UTF8 = [0x78, 0xff, 0x2e, 0x74, 0x78, 0x74];
/** ASCII "swapd.txt" — deliberately the same byte length as `plain.txt`, so the TOCTOU test can
 * overwrite one name with the other in place. */
const SWAPPED = [...Buffer.from("swapd.txt", "ascii")];

beforeEach(() => {
  nodeFs.mkdirSync(SCRATCH, { recursive: true });
  nodeFs.writeFileSync(Buffer.from(scratchPathBytes(SWAPPED)), "SWAPPED");
  for (const name of [PLAIN, CAFE_UTF8, INVALID_UTF8]) {
    nodeFs.writeFileSync(Buffer.from(scratchPathBytes(name)), "contents-of-" + name.length);
  }
});
afterEach(() => {
  nodeFs.rmSync(SCRATCH, { recursive: true, force: true });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// The full `Uint8Array` surface (#108). Node's `validatePath` accepts `isUint8Array(path)`, not
// `Buffer.isBuffer` — capwall tested the latter, so a plain `Uint8Array` path was an UN-GATED,
// unlogged read under a deny-all enforce policy. Every byte-carrying shape Node accepts is
// exercised here, so the two predicates cannot drift apart again.
// ═══════════════════════════════════════════════════════════════════════════════════════════
const byteShapes: Array<{ name: string; run: (dep: FixtureDep, bytes: number[]) => string }> = [
  { name: "Buffer", run: (dep, b) => dep.readFileSyncBufferPath(b) },
  { name: "plain Uint8Array", run: (dep, b) => dep.readFileSyncUint8ArrayPath(b) },
  { name: "Uint8Array view at a non-zero byteOffset", run: (dep, b) => dep.readFileSyncUint8ArrayViewPath(b, 7) },
];

describe.each(byteShapes)("byte path — $name (#108)", ({ run }) => {
  it("is gated: denied by default, on the decoded path", () => {
    const { decisions } = withCapwall(readGrant([]), "enforce", (dep) => {
      expect(() => run(dep, scratchPathBytes(PLAIN))).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expect(decisions[0]!.decision.allowed).toBe(false);
    expect(recordedPath(decisions)).toBe(path.join(SCRATCH, "plain.txt"));
  });

  it("reads normally when granted", () => {
    const { result, decisions } = withCapwall(readGrant(["./fixtures/scratch-bytes/**"]), "enforce", (dep) =>
      run(dep, scratchPathBytes(PLAIN)),
    );
    expect(result).toBe("contents-of-9");
    expect(decisions[0]!.decision.allowed).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// The decode itself (#41 / #19).
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("byte path — latin1 is byte-exact (#19, confirmed under #41)", () => {
  it("a path whose bytes are not valid UTF-8 is decoded losslessly and read", () => {
    // Under a `utf8` decode 0xFF collapses to U+FFFD, so the string capwall checked would not be
    // the bytes it forwarded — the audit-fidelity gap #19 closed. Under latin1 it round-trips.
    const { result, decisions } = withCapwall(readGrant(["./fixtures/scratch-bytes/**"]), "enforce", (dep) =>
      dep.readFileSyncBufferPath(scratchPathBytes(INVALID_UTF8)),
    );
    expect(result).toBe("contents-of-6");
    expect(decisions[0]!.decision.allowed).toBe(true);
    // The recorded path is the byte-for-byte decoding: 0xFF → U+00FF, and NOT U+FFFD.
    const recorded = recordedPath(decisions);
    expect(recorded).toBe(path.join(SCRATCH, "xÿ.txt"));
    expect(recorded).not.toContain("�");
    // The bijection, stated as an assertion: re-encoding the recorded string as latin1 gives
    // back exactly the bytes the call named. That is the property that makes a false-ALLOW
    // unreachable — no second byte sequence shares this string.
    expect([...Buffer.from(recorded, "latin1")]).toEqual(scratchPathBytes(INVALID_UTF8));
  });

  it("two byte paths that a utf8 decode would ALIAS stay distinct decisions", () => {
    // `x<0xFF>.txt` and `x<0xFE>.txt` both decode to `x<U+FFFD>.txt` under utf8, so a grant for
    // one would be a grant for the other. Under latin1 they are different strings, and a grant
    // naming one denies the other.
    const other = [0x78, 0xfe, 0x2e, 0x74, 0x78, 0x74];
    nodeFs.writeFileSync(Buffer.from(scratchPathBytes(other)), "other");
    const grant = readGrant(["./fixtures/scratch-bytes/xÿ.txt"]);
    const granted = withCapwall(grant, "enforce", (dep) =>
      dep.readFileSyncBufferPath(scratchPathBytes(INVALID_UTF8)),
    );
    expect(granted.result).toBe("contents-of-6");
    withCapwall(grant, "enforce", (dep) => {
      expect(() => dep.readFileSyncBufferPath(scratchPathBytes(other))).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
  });

  it("THE KNOWN COST: a valid non-ASCII UTF-8 path given as bytes false-denies", () => {
    // A policy author writing `café.txt` produces U+00E9; the byte path carries C3 A9, which
    // latin1-decodes to `cafÃ©.txt`. They do not match. This is fail-CLOSED — the read is
    // refused, never silently allowed — and it is the whole cost of the decision recorded in
    // this file's header. Asserted so a future change to `utf8` cannot land quietly.
    const grant = readGrant(["./fixtures/scratch-bytes/café.txt"]);
    const { decisions } = withCapwall(grant, "enforce", (dep) => {
      expect(() => dep.readFileSyncBufferPath(scratchPathBytes(CAFE_UTF8))).toThrowError(
        expect.objectContaining({ name: "CapabilityError" }),
      );
    });
    expect(recordedPath(decisions)).toBe(path.join(SCRATCH, "cafÃ©.txt"));
  });

  it("the same file named with an ordinary STRING path matches the same grant", () => {
    // The complement of the case above: the common spelling is unaffected, which is why the
    // mismatch stays confined to byte paths instead of being normalized away globally. (The
    // byte-space alternative #41 raises would fix the false-deny by making BOTH sides bytes —
    // and would turn this recorded path into `cafÃ©.txt` in every trace and generated policy.)
    const grant = readGrant(["./fixtures/scratch-bytes/café.txt"]);
    const { decisions } = withCapwall(grant, "enforce", (dep) =>
      dep.statSync(path.join(SCRATCH, "café.txt")),
    );
    expect(decisions[0]!.decision.allowed).toBe(true);
    expect(recordedPath(decisions)).toBe(path.join(SCRATCH, "café.txt"));
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Byte paths are PINNED, on the same rule as a URL argument (#26/#56/#99).
// ═══════════════════════════════════════════════════════════════════════════════════════════
describe("byte path — the checked bytes are the forwarded bytes (#41)", () => {
  it("mutating the array after the decision does not change which file Node opens", () => {
    // Node's `readFileSync` runs `getOptions(options)` — which reads `options.encoding` —
    // BEFORE it opens the path, so a getter there executes after capwall has decided. In plain
    // Node the rewrite lands and the second path is opened (measured); capwall forwards its own
    // copy of the bytes it checked, so the guarded path is the one that is read.
    // Both files exist and both are inside the grant, so the ONLY thing under test is which one
    // Node opened — not whether the second was denied. On `main` this test reads "SWAPPED".
    const { result, decisions } = withCapwall(
      readGrant(["./fixtures/scratch-bytes/**"]),
      "enforce",
      (dep) => dep.readFileSyncMutatedBytePath(scratchPathBytes(PLAIN), scratchPathBytes(SWAPPED)),
    );
    expect(recordedPath(decisions)).toBe(path.join(SCRATCH, "plain.txt"));
    expect(result).toBe("contents-of-9"); // plain.txt, i.e. what was guarded — not "SWAPPED"
  });
});
