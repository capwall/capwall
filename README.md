# capwall

**A runtime, per-package capability firewall for Node.js.** Defense-in-depth against
supply-chain malware — declare what each dependency is *allowed to do* (files, network,
subprocesses, env, …), then enforce it at runtime.

> Status: **fs vertical slice working (roadmap M1–M3).** The observe → policy → enforce loop
> is live end-to-end for the `fs` capability on the CJS path: `capwall observe` emits a
> starter policy from a real run, and `capwall enforce` denies-by-default with attributed
> errors. The other shims (`net`, `child_process`, `worker_threads`, `env`, `vm`) and ESM
> are not yet mediated — see [`docs/roadmap.md`](./docs/roadmap.md) (M4/M5) and the honest
> scope note in [`docs/threat-model.md`](./docs/threat-model.md).

---

## Why capwall exists

Modern supply-chain malware does not stop at install time. Worms like **Shai-Hulud**
(Nov 2025) and **Glassworm** (2026) run malicious code at **both** the lifecycle-script
phase *and* the application-runtime phase. Install-time gates (lockfile pinning,
`--ignore-scripts`, socket/scanner tooling) never see the runtime phase, where the
interesting damage — credential exfiltration, wallet theft, lateral movement — actually
happens.

capwall closes that gap. It sits inside the running process and mediates the
capability-sensitive surface (`fs`, `net`/`http(s)`, `child_process`, `worker_threads`,
`process.env`, `vm`) **per owning package**. A logging library that suddenly opens a
socket to an unknown host, or a color-string helper that reads `process.env`, is a policy
violation — logged in `observe` mode, denied in `enforce` mode.

### The GO rationale

The idea is proven. The KTH-LangSec **NodeShield** research prototype (CCS 2025,
["Runtime Enforcement of Security-Enhanced SBOMs for Node.js"](https://doi.org/10.1145/3719027.3765136),
Cornelissen & Balliu) demonstrated per-package capability enforcement via
module-load/resource interception that is **non-SES, out-of-band, "vanilla Node
compatible", and <1ms/req**. But NodeShield is a dead single-commit prototype with no DX.

capwall takes that core mechanism and makes it *usable*:

- **No SES tax.** [LavaMoat](https://github.com/LavaMoat/LavaMoat) (MetaMask) is the mature
  OSS analog, but it is SES-based: hardened primordials break some packages, ESM and
  native-addon coverage is uneven, and it shines in the browser-bundler path. capwall
  intercepts at the module-load (`require`/`import`) and syscall-surface boundary instead
  of hardening every primordial — trading some isolation strength for near-zero adoption
  friction.
- **Per-package granularity.** Node's built-in [`--permission`](https://nodejs.org/api/permissions.html)
  model is **process-global**, not per-package. capwall's whole point is that *express*
  and *some-transitive-dep-you've-never-heard-of* get different capability sets in the same
  process.
- **Trace-to-policy DX (the headline feature).** Run your app or test suite once in
  `observe` mode → capwall auto-emits a starter per-package `capabilities.json` → you review
  and tighten it → flip to `enforce`. This trace→policy loop is underdeveloped everywhere
  and is capwall's reason to exist.

---

## Landscape

| Tool | Boundary / mechanism | Granularity | Runtime enforcement | SES / primordial tax | Primary turf |
|---|---|---|---|---|---|
| **capwall** | module-load + core-API shims (non-SES, out-of-band) | **per-package** | **yes** (observe → enforce) | **no** | runtime confinement of deps in Node services |
| **LavaMoat** | SES compartments, hardened primordials | per-package | yes | **yes** | browser/bundler builds, MetaMask |
| **Node `--permission`** | process-level flag (fs/net/child_process/worker) | **process-global** | yes | no | coarse whole-process lockdown |
| **Socket Firewall / socket.dev** | install-time + registry signals, network broker | per-package (install) | mostly install-time | no | blocking known-bad installs/publishes |
| **guarddog (Datadog)** | static/heuristic package scanner | per-package (scan) | **no** | no | CI detection of malicious packages |

capwall is complementary to the scanners: they try to *detect* a bad package before it
lands; capwall assumes one got through and *contains what it can do at runtime*.

---

## MVP scope (build order)

1. **Module-load interception** — patch CJS `require`/loader; ESM via `module.register`
   loader hooks. Attribute every capability-sensitive call to the **owning package** via
   call-stack / module path.
2. **Declarative per-package capability policy** — `capabilities.json` mapping each package
   to allowed `fs` (read/write path globs), `net` (hosts/ports), `child_process`,
   `worker_threads`, `env` (key allowlist), `vm`. Compact, a handful of entries per dep.
3. **Two modes: `observe` and `enforce`** — observe logs violations without blocking (the
   on-ramp); enforce denies-by-default and throws.
4. **Auto-policy generation from a trace run** — `capwall observe` runs the target's
   entrypoint/test suite, records observed capabilities, and emits a starter
   `capabilities.json`. **Headline feature.**
5. **Capability shims for the core surface** — `node:fs`, `node:net`/`node:http(s)`,
   `node:child_process`, `node:worker_threads`, `process.env`, `node:vm`.

**Stretch (post-MVP, not yet built):** SBOM/CBOM import (CycloneDX → policy,
NodeShield-compatible) in `packages/sbom-import`; full ESM parity; native-addon
attribution; a CI observed-vs-declared diff report.

---

## Quickstart (the observe → enforce loop)

> Working today for the `fs` capability (CJS). The `net`/`env`/`child_process` parts of the
> flow land with roadmap M4.

```bash
# 1. Install capwall in your project
pnpm add -D @capwall/cli

# 2. OBSERVE: run your app or test suite; capwall records what each package actually does
#    and writes a starter policy. Nothing is blocked in this mode.
capwall observe -- node ./src/server.js
#   → wrote capabilities.json (12 packages, 41 observed capabilities)

# 3. Review & tighten capabilities.json by hand. Remove anything a dep shouldn't need.

# 4. ENFORCE: run for real. Anything not in the policy is denied by default and throws.
capwall enforce -- node ./src/server.js

# Explain why a given call was allowed/denied:
capwall explain pino fs:write ./logs/app.log
```

See [`examples/express-app`](./examples/express-app) for a full observe→enforce walkthrough
and [`examples/malicious-dep-demo`](./examples/malicious-dep-demo) for a fixture dependency
that capwall blocks in `enforce` mode.

---

## Honest scope note (read this)

capwall is **pragmatic defense-in-depth, not a formal sandbox.** Without SES's frozen
primordials, a *determined in-process attacker* (prototype pollution, shared mutable
primordials, fd/symlink escapes, un-patching the shims, `node:sqlite`/`vm`/`eval`, native
`.node` addons, spawned-subprocess internals) can defeat it. Its job is to stop
**opportunistic, worm-style supply-chain malware** — the Shai-Hulud / Glassworm class that
runs at application-runtime and does not go out of its way to break out of a capability
shim.

Native addons and subprocesses can be **gated** (whether they run) but not **confined**
(what they do once running). Full details and comparison to the SES and Node-permission
threat models are in [`docs/threat-model.md`](./docs/threat-model.md) — read it before
relying on capwall for anything.

---

## Repository layout

```
packages/core            @capwall/core          interception engine + policy evaluator
packages/cli             @capwall/cli           capwall observe|enforce|gen-policy|explain
packages/policy-schema   @capwall/policy-schema  capabilities.json schema + TS types
packages/sbom-import     @capwall/sbom-import    STRETCH: CycloneDX/CBOM → policy
examples/express-app                             observe→enforce walkthrough fixture
examples/malicious-dep-demo                      inert "malicious" dep capwall blocks
docs/                                            threat-model, architecture, policy-format, roadmap
```

## License

[MIT](./LICENSE) © 2026 William Zujkowski.

capwall deliberately avoids non-compete / source-available (e.g. PolyForm) code so it stays
freely adoptable. See [`AGENTS.md`](./AGENTS.md) § Conventions.
