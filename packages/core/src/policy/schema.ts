/**
 * Re-export the policy types from the single source of truth, @capwall/policy-schema, so
 * the rest of core imports policy types from one place. Do not redeclare the shape here.
 */
export {
  PolicySchema,
  PackagePolicySchema,
  parsePolicy,
} from "@capwall/policy-schema";

export type {
  Policy,
  PackagePolicy,
  FsCapability,
  NetCapability,
  Mode,
  CapabilityKind,
} from "@capwall/policy-schema";
