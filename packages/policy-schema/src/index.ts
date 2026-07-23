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

/** Network egress capability: allowed hosts (glob `*` supported) and numeric ports. */
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
 * package is NOT granted it. Boolean gates (`child_process`, `worker_threads`, `vm`) gate
 * whether the capability may be used at all — they do NOT confine what a spawned
 * subprocess / worker / vm context then does (see docs/threat-model.md).
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
  })
  .strict();

/** Top-level policy document (the shape of `capabilities.json`). */
export const PolicySchema = z
  .object({
    $schema: z.string().optional(),
    version: z.literal(1),
    mode: z.enum(["observe", "enforce"]).default("observe"),
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
  | "vm";

/**
 * Parse and validate an unknown value as a Policy. Throws a ZodError on invalid input.
 * The CLI/loader should surface these errors with the offending path.
 */
export function parsePolicy(input: unknown): Policy {
  return PolicySchema.parse(input);
}
