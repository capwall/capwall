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
import { validateHostPattern } from "./host.js";
import { validatePackageKey } from "./package-key.js";

/** File read/write capability: path globs resolved relative to the project root. */
export const FsCapabilitySchema = z
  .object({
    read: z.array(z.string()).default([]),
    write: z.array(z.string()).default([]),
  })
  .strict();

/**
 * Network egress capability.
 *
 * `hosts` entries are either an EXACT hostname, the single literal `"*"` (any host), or a
 * wildcard pattern — `"*.internal"` (one label) / `"**.internal"` (one or more). `*` never
 * crosses a dot and a wildcard never matches an IP literal. `./host.ts` owns the grammar and
 * `docs/policy-format.md` § net documents it; a MALFORMED pattern is rejected here, at
 * policy-load time, rather than silently matching nothing (issue #83).
 *
 * `ports` are numeric, or the literal `"*"` for any port (#27).
 */
export const NetCapabilitySchema = z
  .object({
    hosts: z.array(z.string()).superRefine((hosts, ctx) => {
      for (let i = 0; i < hosts.length; i++) {
        const problem = validateHostPattern(hosts[i]!);
        if (problem !== null) ctx.addIssue({ code: z.ZodIssueCode.custom, message: problem, path: [i] });
      }
    }).default([]),
    ports: z
      .array(z.union([z.number().int().nonnegative(), z.literal("*")]))
      .default([]),
  })
  .strict();

/**
 * IPC capability: unix-domain sockets and Windows named pipes (issue #72).
 *
 * `paths` are globs matched by the SAME matcher `fs` grants use (see
 * `@capwall/core` `policy/ipc.ts` for the canonicalization that feeds it, including named
 * pipes and the `<tmp>`/`<home>` placeholders that keep a generated policy portable).
 *
 * A grant is required per socket. The legacy shape — `net: { hosts: ["<ipc>"], ports: [0] }` —
 * still works and still means EVERY socket and pipe; it is kept for policies written before
 * #72 and is documented as the coarse form. Prefer `ipc.paths`.
 */
export const IpcCapabilitySchema = z
  .object({
    paths: z
      .array(
        z
          .string()
          // An empty pattern can never match anything; saying so at load time is the whole
          // point of #83's root-cause finding applied here.
          .min(1, "ipc path pattern must not be empty"),
      )
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
    /** Unix sockets / Windows named pipes this package may connect to (#72). */
    ipc: IpcCapabilitySchema.optional(),
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
    /**
     * Gate: may this package call `Module.prototype._compile(source, filename)` directly, with
     * a filename that is not its own? (issue #93)
     *
     * **This is an IDENTITY-GRANTING capability — the strongest thing in this schema.** V8
     * reports the caller-chosen `filename` as `getFileName()` on every frame of the compiled
     * code, and capwall names packages from frame file names, so a package holding `compile`
     * can execute code as ANY principal in the policy, including `<app>`. Granting it is
     * granting every other grant in the file. Treat it the way you would treat handing out a
     * signing key, and prefer to scope it to the one build/instrumentation tool that needs it.
     *
     * It exists because refusing outright would break the dominant legitimate use of
     * `_compile`: the `require.extensions` transform hook, which is how `ts-node`, `tsx`,
     * `@babel/register`, `@swc/register`, `pirates` (and thus `nyc`/`istanbul`) and
     * `require-in-the-middle` (and thus `dd-trace`, `elastic-apm-node`) all work. Each of those
     * compiles ANOTHER package's or the application's file by design, which is indistinguishable
     * on its face from the attack.
     *
     * Not needed for: Node's own loading of any module (capwall recognizes its loader frames), a
     * package compiling source under its OWN name (a template engine, `require-from-string`), or
     * the application itself, which is the trust root.
     */
    compile: z.boolean().optional(),
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
    /**
     * Per-principal grants. A key is an install chain as attribution reports it — `lodash` for
     * the top-level install, `webpack>lodash` for the copy nested under `webpack` (#92) — one of
     * the sentinels `<app>`/`<unknown>`, or a wildcard (`*>lodash`, `**>lodash`).
     *
     * Keys are VALIDATED, for the reason #83 exists: a wildcard that silently matches nothing is
     * worse than one that is refused. `"*"` on its own, `"evil>*"` and `"lod*"` are all load-time
     * errors that say what to write instead. See `./package-key.ts` for the grammar.
     */
    packages: z
      .record(z.string(), PackagePolicySchema)
      .superRefine((packages, ctx) => {
        for (const key of Object.keys(packages)) {
          const problem = validatePackageKey(key);
          if (problem !== null) ctx.addIssue({ code: z.ZodIssueCode.custom, message: problem, path: [key] });
        }
      })
      .default({}),
  })
  .strict();

export type FsCapability = z.infer<typeof FsCapabilitySchema>;
export type NetCapability = z.infer<typeof NetCapabilitySchema>;
export type IpcCapability = z.infer<typeof IpcCapabilitySchema>;
export type PackagePolicy = z.infer<typeof PackagePolicySchema>;
export type Policy = z.infer<typeof PolicySchema>;

// The `net.hosts` grammar. Validation (above) and matching (@capwall/core's evaluator) come
// from the same module on purpose — #83 was the two disagreeing. See ./host.ts.
export { ANY_HOST, isIpLiteral, matchesHostPattern, validateHostPattern } from "./host.js";
export { CHAIN_SEP, validatePackageKey, widenedPackageKeys } from "./package-key.js";

/** Enforcement mode. `observe` logs violations; `enforce` denies-by-default and throws. */
export type Mode = "observe" | "enforce";

/** The capability kinds capwall mediates. */
export type CapabilityKind =
  | "fs"
  | "net"
  | "ipc"
  | "child_process"
  | "worker_threads"
  | "env"
  | "vm"
  | "native"
  | "compile";

/**
 * Parse and validate an unknown value as a Policy. Throws a ZodError on invalid input.
 * The CLI/loader should surface these errors with the offending path.
 */
export function parsePolicy(input: unknown): Policy {
  return PolicySchema.parse(input);
}
