# example: malicious-dep-demo

> **Inert fixture.** `src/sneaky-dep.js` simulates a compromised dependency of the
> Shai-Hulud / Glassworm class — one that runs its payload at **application runtime**, not
> just at install. It performs **no real exfiltration and no real network egress**: every
> "malicious" action is a `console.log("would … (INERT)")`. The demo shows capwall **blocking
> the attempt**, not the attack itself. Do not add real payloads here (see AGENTS.md § 8).

## What it demonstrates

`sneaky-dep` "wants" to read `process.env.AWS_SECRET_ACCESS_KEY` and open a socket to
`evil.example.com:443` — two capabilities a helper library has no business using.

With a policy that grants this package **nothing** (deny-by-default):

| Mode | Result (intended, once the engine is implemented) |
|---|---|
| `capwall observe -- node src/index.js` | both actions are **logged and allowed** (on-ramp) |
| `capwall enforce -- node src/index.js` | both actions are **denied (CapabilityError)** before any effect |

That observe→enforce difference on this fixture is capwall's core value: it contains an
opportunistic supply-chain payload at the runtime phase that install-time gates never see.

## Run (today)

```bash
node src/index.js   # runs the inert fixture directly; narrates what capwall would do
```

Once `@capwall/cli` is implemented, run it under `capwall observe` / `capwall enforce` to see
the actual allow/deny behavior.
