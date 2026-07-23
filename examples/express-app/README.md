# example: express-app

> **Fixture, not production code.** A minimal Express server used to demonstrate the capwall
> observe→enforce loop. It exercises two real capabilities so capwall has something to see:
> serving on a port (`net` — not yet mediated, roadmap M4) and appending to
> `./logs/requests.log` (`fs:write` — mediated today).

## Walkthrough

```bash
pnpm install && pnpm build        # from the repo root, then cd examples/express-app

# 1. OBSERVE — nothing is blocked; capwall records what express + this app do and
#    emits/merges a starter capabilities.json.
node ../../packages/cli/dist/index.js observe -- node src/server.js
curl localhost:3000/              # exercise routes so they get observed
curl localhost:3000/log
# Ctrl-C the server → capwall writes/merges capabilities.json before exiting.

# 2. REVIEW — open capabilities.json and tighten it (drop anything a package
#    shouldn't need). A committed one, generated exactly this way, is in this directory.

# 3. ENFORCE — run for real; any fs use outside the policy is denied and throws.
node ../../packages/cli/dist/index.js enforce -- node src/server.js
curl localhost:3000/log           # → "logged" — the granted write goes through
```

If you delete the `./logs/requests.log` write grant from `capabilities.json` and hit `/log`
under enforce, capwall denies the write (deny-by-default) and the route 500s with a
`CapabilityError`. That is the mechanism the malicious-dep-demo leans on.
