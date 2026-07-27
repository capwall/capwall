/**
 * @capwall/policy-schema
 *
 * The single source of truth for the `capabilities.json` shape: a Zod schema plus the
 * TypeScript types inferred from it. `@capwall/core` re-exports these; the CLI validates
 * user-supplied policy files against `PolicySchema`.
 *
 * Keep this in sync with `schema.json` (the machine-readable JSON Schema) and with
 * `docs/policy-format.md`. See docs/policy-format.md for the authoritative field docs.
 */
import { z } from "zod";

/** File read/write capability: path globs resolved relative to the project root. */
export const FsCapabilitySchema = z
  .object({
    read: z.array(z.string()).default([]),
    write: z.array(z.string()).default([]),
  })
  .strict();

/**
 * Network egress capability. `hosts` entries match by EXACT string equality or the single
 * literal `"*"` (any host) — there are no partial globs, so `"*.internal"` does not match
 * `api.internal`. `ports` are numeric, or the literal `"*"` for any port (#27).
 */
export const NetCapabilitySchema = z
  .object({
    hosts: z.array(z.string()).default([]),
    ports: z
      .array(z.union([z.number().int().nonnegative(), z.literal("*")]))
      .default([]),
  })
  .strict();

/**
 * Per-package capability grant. Every field is optional; an omitted capability means the
 * package is NOT granted it. Boolean gates (`child_process`, `worker_threads`, `vm`,
 * `native`) gate whether the capability may be used at all — they do NOT confine what a
 * spawned subprocess / worker / vm context / native addon then does (see
 * docs/threat-model.md).
 */
export const PackagePolicySchema = z
  .object({
    fs: FsCapabilitySchema.optional(),
    net: NetCapabilitySchema.optional(),
    child_process: z.boolean().optional(),
    worker_threads: z.boolean().optional(),
    /** Allowlist of `process.env` keys this package may read. `["*"]` allows all. */
    env: z.array(z.string()).optional(),
    vm: z.boolean().optional(),
    /**
     * Gate: may this package load a native (`.node`) addon? (roadmap S2, issue #49)
     *
     * Deliberately a BOOLEAN and not a path list, unlike `fs`. An addon's on-disk path is a
     * build artifact — `build/Release/x.node` for a locally compiled package,
     * `prebuilds/<platform>-<arch>/<name>.node` (or an ABI-keyed name) for a prebuilt one —
     * so a grant naming a concrete path is correct on the machine that ran `observe` and
     * wrong on every other platform/arch/Node-ABI combination. That is precisely the
     * non-reproducible-policy trap that bit ephemeral `net` ports (#27) and host-specific
     * `env` keys (#57). A path list would also buy no real containment: a package that ships
     * `build/Release/a.node` can ship `b.node` too, so restricting WHICH file inside a
     * package may load only constrains a party that was never adversarial. The security
     * question worth answering — and the only one capwall can answer — is "may this package
     * bring arbitrary compiled code into the process at all".
     *
     * **Gating, not confinement.** Once an addon is loaded it has raw libc and capwall sees
     * nothing it does. See docs/threat-model.md § Native addons.
     */
    native: z.boolean().optional(),
  })
  .strict();

/** Top-level policy document (the shape of `capabilities.json`). */
export const PolicySchema = z
  .object({
    $schema: z.string().optional(),
    version: z.literal(1),
    /**
     * Enforcement mode this document declares. Deliberately OPTIONAL rather than defaulted:
     * "declared observe" and "declares nothing" are different states, and only the former may
     * switch capwall on. Consulted only when nothing set `CAPWALL_MODE` — see
     * `resolveMode()` in @capwall/core and docs/policy-format.md § Enforcement mode.
     */
    mode: z.enum(["observe", "enforce"]).optional(),
    /** Applied to any package with no explicit entry in `packages`. */
    default: PackagePolicySchema.default({}),
    packages: z.record(z.string(), PackagePolicySchema).default({}),
  })
  .strict();

export type FsCapability = z.infer<typeof FsCapabilitySchema>;
export type NetCapability = z.infer<typeof NetCapabilitySchema>;
export type PackagePolicy = z.infer<typeof PackagePolicySchema>;
export type Policy = z.infer<typeof PolicySchema>;

/** Enforcement mode. `observe` logs violations; `enforce` denies-by-default and throws. */
export type Mode = "observe" | "enforce";

/** The capability kinds capwall mediates. */
export type CapabilityKind =
  | "fs"
  | "net"
  | "child_process"
  | "worker_threads"
  | "env"
  | "vm"
  | "native";

/**
 * Parse and validate an unknown value as a Policy. Throws a ZodError on invalid input.
 * The CLI/loader should surface these errors with the offending path.
 */
export function parsePolicy(input: unknown): Policy {
  return PolicySchema.parse(input);
}
