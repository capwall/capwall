# example: express-app

> **Fixture, not production code.** A minimal Express server used to demonstrate the capwall
> observe→enforce loop. It exercises two real capabilities so capwall has something to see:
> serving on a port (`net`) and appending to `./logs/requests.log` (`fs:write`).

## Walkthrough (intended UX — CLI is scaffolded)

```bash
pnpm install                      # from the repo root

# 1. OBSERVE — nothing is blocked; capwall records what express + this app do and
#    emits/merges a starter capabilities.json.
capwall observe -- node src/server.js
curl localhost:3000/              # exercise routes so they get observed
curl localhost:3000/log
#    → capabilities.json now has entries for express and this app.

# 2. REVIEW — open capabilities.json and tighten it (narrow "*" hosts, drop anything
#    a package shouldn't need).

# 3. ENFORCE — run for real; anything outside the policy is denied and throws.
capwall enforce -- node src/server.js
```

If you delete the `fs:write ./logs/**` grant and hit `/log` under enforce, capwall should
deny the write (deny-by-default). That is the mechanism the malicious-dep-demo leans on.
