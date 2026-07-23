# example: malicious-dep-demo

> **Inert fixture.** `node_modules/sneaky-dep` (vendored and committed, so capwall's
> attribution sees it as a real dependency) simulates a compromised dependency of the
> Shai-Hulud / Glassworm class — one that runs its payload at **application runtime**, not
> just at install. It performs **no real exfiltration and no real network egress**: the
> env-read and socket "actions" are `console.log("would … (INERT)")`, and its one real
> capability use is an fs read of its own bundled `fake-secret.txt` placeholder. The demo
> shows capwall **blocking the attempt**, not the attack itself. Do not add real payloads
> here (see AGENTS.md § 8).

## What it demonstrates

`sneaky-dep` "wants" to read a credentials file — a capability a helper library has no
business using. The committed `capabilities.json` grants it **nothing** (deny-by-default):

| Mode | Result |
|---|---|
| `capwall observe -- node src/index.js` | the read is **logged and allowed** (on-ramp); exit 0 |
| `capwall enforce -- node src/index.js` | the read is **denied (CapabilityError)** before any effect; exit 1 |

That observe→enforce difference on this fixture is capwall's core value: it contains an
opportunistic supply-chain payload at the runtime phase that install-time gates never see.

## Run

```bash
# from this directory (pnpm install at the repo root first, then pnpm build)
node ../../packages/cli/dist/index.js observe -o /tmp/demo-policy.json -- node src/index.js
#   → "[capwall] observe: recorded fs:read …/sneaky-dep/fake-secret.txt for 'sneaky-dep'"
#   → /tmp/demo-policy.json now lists exactly what sneaky-dep tried. You review it, decide
#     a helper has no business reading credential files, and grant it nothing.

node ../../packages/cli/dist/index.js enforce -- node src/index.js
#   → "[demo] BLOCKED by capwall: enforce: DENY 'sneaky-dep' fs:read … (deny-by-default)"
#   → exit code 1
```

(The observe run above writes its starter policy to `/tmp` so it does not overwrite the
committed deny-everything `capabilities.json` this demo enforces against.)
