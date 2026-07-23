# @capwall/sbom-import (STRETCH — post-MVP)

**Not part of the MVP.** This package will import a CycloneDX SBOM (and eventually a CBOM)
and produce a starter capwall `capabilities.json`, in the spirit of NodeShield's
"security-enhanced SBOM" input. It is a stub today; do not build it until the MVP
(roadmap M1–M5) is done.

## Intended behavior

- Parse a CycloneDX BOM (JSON) → the set of packages and any capability/permission metadata
  carried in `properties` / evidence.
- Emit a `capabilities.json` skeleton (one entry per component) via `@capwall/policy-schema`,
  which the user then tightens — the same review-then-enforce loop as the trace path.
- Stay compatible with NodeShield's SBOM-driven policy notion (see the CCS 2025 paper,
  DOI 10.1145/3719027.3765136) so existing security-enhanced SBOMs can seed a capwall policy.

See [`../../docs/roadmap.md`](../../docs/roadmap.md) § S1.
