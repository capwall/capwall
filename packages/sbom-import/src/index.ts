/**
 * @capwall/sbom-import — STRETCH (post-MVP, roadmap S1). STUB ONLY.
 *
 * Turn a CycloneDX SBOM (later, a CBOM) into a starter capwall policy. Do not implement
 * until the MVP is complete. See README.md and docs/roadmap.md § S1.
 */
import type { Policy } from "@capwall/policy-schema";

/** Minimal shape of the CycloneDX input we will consume (to be fleshed out in S1). */
export interface CycloneDxBom {
  bomFormat?: string;
  specVersion?: string;
  components?: Array<{ name?: string; purl?: string }>;
  [key: string]: unknown;
}

/**
 * Convert a CycloneDX BOM into a starter capabilities.json policy.
 *
 * TODO(capwall): implement in S1 — one deny-by-default package entry per component, seeded
 * from any capability metadata in the BOM, emitted via @capwall/policy-schema. Users tighten
 * the result before enforcing.
 */
export function sbomToPolicy(_bom: CycloneDxBom): Policy {
  throw new Error(
    "capwall: @capwall/sbom-import is a post-MVP stub — see docs/roadmap.md S1",
  );
}
