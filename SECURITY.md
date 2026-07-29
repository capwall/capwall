# Security policy

capwall is a security tool, so this file has to do two jobs: give you a private way to report a
bypass, and tell you **before you spend a weekend on it** which bypasses are already documented
residuals rather than findings. Both matter. A public issue describing a working bypass is a
zero-day with a README, and a report of something [`docs/threat-model.md`](docs/threat-model.md)
already spends four pages on is work nobody needed to do.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a security problem.**

Use GitHub's private vulnerability reporting: the **Security** tab of this repository →
**Report a vulnerability**. It creates a private advisory only you and the maintainer can see,
gives you a place to attach a proof of concept, and turns into a published advisory with a CVE
if the report holds up.

If that form is not available to you, open a public issue that says only *"security report,
please open a private channel"* — no details, no reproduction — and wait to be contacted.

What to expect:

| | |
|---|---|
| Acknowledgement | within 7 days |
| First assessment (in scope / documented residual / not a bug) | within 14 days |
| Fix or a public statement of why there will not be one | best effort, and you will be told which |

This is a single-maintainer project with no funding and, at the time of writing, **no CI**
(GitHub Actions is billing-blocked — issue #3). Those timelines are honest intentions, not an
SLA. There is no bug bounty.

Coordinated disclosure is the default: please give the fix a chance to ship before publishing.
If you want credit in the advisory and the changelog, say so; if you want to stay anonymous,
say that instead.

## What versions are supported

Nothing has been published to npm yet. When it is, only the **latest** `0.x` release will
receive fixes — `0.y.z` means the surface may still move, and there is no installed base to
maintain a branch for. See [`docs/releasing.md`](docs/releasing.md).

## What is in scope

A report is in scope if it shows capwall making a **wrong decision about a principal**, or making
**no decision at all** where it claims to make one. Concretely:

- **A bypass of a gate that `docs/threat-model.md` § What capwall stops says is enforced** — a
  dependency reading a file, opening a socket, spawning a process, reading an `env` key, loading a
  native addon or using `vm` under a policy that does not grant it, in `enforce` mode.
- **Attribution confusion** — a call charged to the wrong package, so that one dependency spends
  another's grant, or so the `observe` trace and `capwall diff` name the wrong culprit.
- **A silent allow.** capwall's audit trail is half the product. An operation that succeeds with
  *no* `ALLOW` and *no* `DENY` recorded is a finding even when the operation itself was
  permissible, because it means something is invisible to `observe` and to drift detection.
- **Enforcement that does not survive the lifecycle** — a gate that is live after `install()` but
  not after `install(); uninstall(); install(tighter)`, or that a teardown leaves half-relinked.
- **A defect in the release pipeline itself**: anything that would let a tarball published from
  this repository contain code that is not in the repository, or that would move a published
  artifact's provenance away from its trusted publisher.
- **A dependency of a published package** with a known advisory. Today that closure is exactly one
  package (`zod`); `pnpm --filter '@capwall/*' licenses list --prod` prints it.

`CAPWALL_HARDENED=1` is in scope on its own terms: a bypass that hardened mode *claims* to close
and does not is a finding, and the threat model is explicit about which bullets hardened mode
does and does not cover.

## What is out of scope, and why that list is long

**Read [`docs/threat-model.md`](docs/threat-model.md) § What capwall does NOT stop before
reporting.** capwall is pragmatic defense-in-depth, not a sandbox, and it says so everywhere. It
does not harden JavaScript primordials — that is SES's job — so a **determined, capwall-aware
in-process attacker** can defeat it, and the document works through exactly how.

The cheapest escape in the whole document is one line, and it is written down:

```js
Error.captureStackTrace = (h) => {
  h.stack = [{ isEval: () => false, getFileName: () => "node:internal/modules/cjs/loader" }];
};
```

Every capwall decision is a decision about a principal, and the principal comes from V8 stack
machinery any code in the process can replace. That escape is self-restoring, leaves no artifact,
and hardened mode does not touch it. It is documented, reproduced against a deny-all policy, and
**not a vulnerability report** — it is the stated bound of the tool.

Also out of scope:

- Un-patching or replacing a shim from inside the process, prototype pollution, and the rest of
  the shared-mutable-primordials class.
- Anything reachable only from code that is already **granted** the capability it uses.
- Install-time (lifecycle-script) execution. capwall mediates the **runtime** phase; the repo runs
  no dependency install scripts at all, and `pnpm-workspace.yaml` explains why.
- Native code that escapes JavaScript entirely once a `.node` addon load has been *granted* —
  gating the load is the whole of that control, and `docs/threat-model.md` § Native `.node` addons
  says so.
- Denial of service against a process that has already chosen to run capwall.
- Findings in the `examples/malicious-dep-demo` fixture. It is a test fixture that calls
  `console.log`; it is supposed to look like malware.
- Advisories in **devDependencies**. They are never installed by a consumer — the published
  tarballs are `dist/`, `src/`, `LICENSE`, `README.md` and `package.json`, with no bundled
  `node_modules`.

If you are not sure which side of the line a finding falls on, **report it privately anyway**.
Being wrong in that direction costs a maintainer ten minutes; being wrong in the other direction
publishes a working bypass.

## The residual-risk statement, in one paragraph

Deploying capwall in `enforce` mode meaningfully raises the cost of opportunistic supply-chain
malware and gives you a per-package audit trail. It does **not** provide a security boundary
against a determined, capwall-aware in-process attacker. Treat it as one layer alongside
dependency review, lockfile pinning, least-privilege process/OS sandboxing (containers, seccomp)
and secret hygiene.
