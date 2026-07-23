/**
 * @capwall/sbom-import (roadmap S1)
 *
 * Turn a CycloneDX JSON SBOM into a starter capwall `capabilities.json`. The mapping is
 * deliberately dumb and safe: one `packages[name]` entry per component, seeded from any
 * capwall CBOM annotations found on that component (see "CBOM annotation convention"
 * below), or an **empty grant `{}`** — i.e. nothing — when no annotations are present.
 * `{}` under deny-by-default `enforce` mode means "this package gets nothing until a human
 * tightens the policy", which is the same safe-default posture as the rest of capwall (see
 * docs/policy-format.md and AGENTS.md § 1).
 *
 * ## Input handling
 *
 * The input is untrusted (an SBOM may be attacker-influenced, e.g. checked into a
 * compromised repo, or simply malformed/hand-edited). We validate shape defensively with
 * plain `typeof`/`Array.isArray` checks — no schema library, no new runtime dependency
 * (CycloneDX JSON is just JSON; see AGENTS.md § 5 on dependency hygiene). A malformed
 * top-level document or a bad individual component is *skipped with a warning*, never
 * thrown — one bad `components[]` entry must not abort the whole import.
 *
 * ## CBOM annotation convention
 *
 * CycloneDX components may carry an arbitrary `properties: [{ name, value }]` array (this
 * is a standard CycloneDX extensibility point, not a capwall invention). We read
 * `capwall:*`-prefixed properties off that array as a lightweight "CBOM" (capability
 * bill-of-materials) convention:
 *
 * | property name            | value format                          | maps to               |
 * |---------------------------|---------------------------------------|------------------------|
 * | `capwall:fs:read`         | comma-separated globs                 | `fs.read`              |
 * | `capwall:fs:write`        | comma-separated globs                 | `fs.write`             |
 * | `capwall:net:hosts`       | comma-separated hostnames/globs       | `net.hosts`            |
 * | `capwall:net:ports`       | comma-separated integers              | `net.ports`            |
 * | `capwall:child_process`   | `"true"` / `"false"`                  | `child_process`        |
 * | `capwall:worker_threads`  | `"true"` / `"false"`                  | `worker_threads`       |
 * | `capwall:vm`              | `"true"` / `"false"`                  | `vm`                   |
 * | `capwall:env`             | comma-separated env key names, or `*` | `env`                  |
 *
 * A property may be repeated (e.g. two separate `capwall:fs:read` entries) — values from
 * repeated properties are concatenated. Values are comma-separated so a single property
 * can also carry a list (`"./views/**,./public/**"`). Unknown `capwall:*` property names
 * and non-`capwall:` properties are ignored, not errors. This is a first-cut convention
 * scoped to what `PackagePolicy` can express; it deliberately does not attempt to parse
 * the (much heavier, still-evolving) OWASP CycloneDX ML/CBOM `evidence` block — a future
 * iteration can add that as an additional source without changing this one.
 *
 * If a component has no recognized `capwall:*` properties, it gets `{}` — empty, safe,
 * user-tightened.
 */
import {
  type PackagePolicy,
  type Policy,
  parsePolicy,
} from "@capwall/policy-schema";

/** A single CycloneDX `properties[]` entry (name/value pair). */
export interface CycloneDxProperty {
  name?: string;
  value?: string;
}

/** The subset of a CycloneDX `components[]` entry we care about. Untrusted input. */
export interface CycloneDxComponent {
  type?: string;
  name?: string;
  version?: string;
  purl?: string;
  "bom-ref"?: string;
  properties?: CycloneDxProperty[];
  [key: string]: unknown;
}

/** Minimal shape of the CycloneDX document we consume. Untrusted input. */
export interface CycloneDxBom {
  bomFormat?: string;
  specVersion?: string;
  components?: unknown[];
  [key: string]: unknown;
}

/**
 * A component parsed out of a CycloneDX BOM, plus the capability grant (possibly empty)
 * derived from its `capwall:*` CBOM properties.
 */
export interface Component {
  name: string;
  version?: string;
  purl?: string;
  bomRef?: string;
  grant: PackagePolicy;
}

export interface SbomToPolicyOptions {
  /** Enforcement mode to stamp onto the emitted policy. Default: "observe" (safe on-ramp). */
  mode?: "observe" | "enforce";
  /**
   * Mutated in place: malformed-input warnings are pushed here (top-level shape issues and
   * per-component skip reasons). Never thrown for a single bad component.
   */
  warnings?: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

function parseBoolean(value: string): boolean | undefined {
  const normalized = value.trim().toLowerCase();
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  return undefined;
}

/**
 * Fold a component's `capwall:*` properties into a PackagePolicy grant. Unrecognized
 * property names, malformed values, and a missing/malformed `properties` array are all
 * ignored (collected as warnings when `componentLabel` + `warnings` are supplied) rather
 * than thrown — one bad annotation must not block the rest of the grant.
 */
function grantFromProperties(
  properties: unknown,
  componentLabel: string,
  warnings: string[],
): PackagePolicy {
  const grant: PackagePolicy = {};
  if (properties === undefined) {
    return grant;
  }
  if (!Array.isArray(properties)) {
    warnings.push(
      `${componentLabel}: "properties" is not an array — ignoring capability annotations`,
    );
    return grant;
  }

  const fsRead: string[] = [];
  const fsWrite: string[] = [];
  const netHosts: string[] = [];
  const netPorts: number[] = [];
  const envKeys: string[] = [];
  let sawFs = false;
  let sawNet = false;
  let sawEnv = false;

  for (const raw of properties) {
    if (!isRecord(raw)) {
      warnings.push(`${componentLabel}: skipping non-object property entry`);
      continue;
    }
    const name = raw["name"];
    const value = raw["value"];
    if (typeof name !== "string" || typeof value !== "string") {
      continue; // not a capwall-shaped property; not an error, just not ours
    }
    if (!name.startsWith("capwall:")) {
      continue;
    }

    switch (name) {
      case "capwall:fs:read":
        fsRead.push(...splitList(value));
        sawFs = true;
        break;
      case "capwall:fs:write":
        fsWrite.push(...splitList(value));
        sawFs = true;
        break;
      case "capwall:net:hosts":
        netHosts.push(...splitList(value));
        sawNet = true;
        break;
      case "capwall:net:ports": {
        sawNet = true;
        for (const portStr of splitList(value)) {
          // Require a pure non-negative integer string (rejects floats "80.5", hex "0x50",
          // negatives, trailing garbage "80x" — parseInt would silently truncate those).
          if (!/^\d+$/.test(portStr)) {
            warnings.push(
              `${componentLabel}: ignoring non-numeric capwall:net:ports value "${portStr}"`,
            );
            continue;
          }
          const port = Number(portStr);
          if (port > 65535) {
            warnings.push(
              `${componentLabel}: ignoring out-of-range capwall:net:ports value "${portStr}" (>65535)`,
            );
            continue;
          }
          netPorts.push(port);
        }
        break;
      }
      case "capwall:child_process": {
        const parsed = parseBoolean(value);
        if (parsed === undefined) {
          warnings.push(
            `${componentLabel}: ignoring non-boolean capwall:child_process value "${value}"`,
          );
        } else {
          grant.child_process = parsed;
        }
        break;
      }
      case "capwall:worker_threads": {
        const parsed = parseBoolean(value);
        if (parsed === undefined) {
          warnings.push(
            `${componentLabel}: ignoring non-boolean capwall:worker_threads value "${value}"`,
          );
        } else {
          grant.worker_threads = parsed;
        }
        break;
      }
      case "capwall:vm": {
        const parsed = parseBoolean(value);
        if (parsed === undefined) {
          warnings.push(
            `${componentLabel}: ignoring non-boolean capwall:vm value "${value}"`,
          );
        } else {
          grant.vm = parsed;
        }
        break;
      }
      case "capwall:env":
        envKeys.push(...splitList(value));
        sawEnv = true;
        break;
      default:
        warnings.push(`${componentLabel}: ignoring unrecognized property "${name}"`);
        break;
    }
  }

  if (sawFs) {
    grant.fs = { read: fsRead, write: fsWrite };
  }
  if (sawNet) {
    grant.net = { hosts: netHosts, ports: netPorts };
    if (netHosts.includes("*")) {
      warnings.push(`${componentLabel}: WILDCARD net host "*" seeded from SBOM — review before enforce`);
    }
  }
  if (sawEnv) {
    grant.env = envKeys;
    if (envKeys.includes("*")) {
      warnings.push(`${componentLabel}: WILDCARD env "*" seeded from SBOM — review before enforce`);
    }
  }
  return grant;
}

/**
 * Parse a CycloneDX JSON document into the components we can act on. Defensive by design:
 * a malformed top-level document yields an empty array (+ a warning); a malformed
 * individual component entry is skipped (+ a warning) rather than aborting the whole
 * parse. Never throws on malformed input.
 */
export function parseCycloneDx(json: unknown, warnings: string[] = []): Component[] {
  if (!isRecord(json)) {
    warnings.push("SBOM root is not a JSON object — no components imported");
    return [];
  }

  const componentsRaw = json["components"];
  if (componentsRaw === undefined) {
    warnings.push('SBOM has no "components" array — nothing to import');
    return [];
  }
  if (!Array.isArray(componentsRaw)) {
    warnings.push('SBOM "components" is not an array — nothing to import');
    return [];
  }

  const results: Component[] = [];
  componentsRaw.forEach((raw, index) => {
    const label = `components[${index}]`;
    if (!isRecord(raw)) {
      warnings.push(`${label}: not an object — skipped`);
      return;
    }
    const name = raw["name"];
    if (typeof name !== "string" || name.trim().length === 0) {
      warnings.push(`${label}: missing/invalid "name" — skipped`);
      return;
    }

    const component: Component = {
      name,
      grant: grantFromProperties(raw["properties"], `${label} ("${name}")`, warnings),
    };

    const version = raw["version"];
    if (typeof version === "string" && version.length > 0) {
      component.version = version;
    }
    const purl = raw["purl"];
    if (typeof purl === "string" && purl.length > 0) {
      component.purl = purl;
    }
    const bomRef = raw["bom-ref"];
    if (typeof bomRef === "string" && bomRef.length > 0) {
      component.bomRef = bomRef;
    }

    results.push(component);
  });

  return results;
}

/**
 * Convert a CycloneDX SBOM (JSON, untrusted) into a starter capwall policy: one
 * `packages[name]` entry per component, seeded from any `capwall:*` CBOM annotations
 * present, or `{}` (deny-by-default scaffold) otherwise. Package ordering is sorted for
 * stable diffs. Always emitted through `parsePolicy()` so the result is guaranteed
 * schema-valid. Never throws on malformed SBOM input — collects warnings instead (see
 * `opts.warnings`); throws only if `parsePolicy` itself rejects the assembled document,
 * which should not happen for well-formed component names.
 */
export function sbomToPolicy(sbom: unknown, opts: SbomToPolicyOptions = {}): Policy {
  const warnings = opts.warnings ?? [];
  const components = parseCycloneDx(sbom, warnings);

  // Later components with a duplicate name win (last one wins), but ordering of the
  // final packages map is sorted regardless — see below. Null-prototype maps so a component
  // literally named `__proto__` becomes an OWN key instead of hitting the prototype setter
  // (which would silently drop it) — untrusted SBOM input must not lose entries.
  const packages: Record<string, PackagePolicy> = Object.create(null);
  for (const component of components) {
    // `__proto__` cannot round-trip as a policy key (parsePolicy's object construction drops
    // it), so skip it explicitly with a warning rather than silently losing the entry.
    // `constructor`/`prototype` are ordinary own keys and pass through fine.
    if (component.name === "__proto__") {
      warnings.push(`component named "__proto__" cannot be a policy key — skipping`);
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(packages, component.name)) {
      warnings.push(`duplicate component name "${component.name}" — later entry wins`);
    }
    packages[component.name] = component.grant;
  }

  const sortedPackages: Record<string, PackagePolicy> = Object.create(null);
  for (const [name, grant] of Object.entries(packages).sort(([a], [b]) =>
    a.localeCompare(b),
  )) {
    sortedPackages[name] = grant;
  }

  return parsePolicy({
    version: 1,
    mode: opts.mode ?? "observe",
    default: {},
    packages: sortedPackages,
  });
}
