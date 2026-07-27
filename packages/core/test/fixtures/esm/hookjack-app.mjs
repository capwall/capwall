// ESM app entry for the #61 regression: lets esm-hookjack-dep try to register a loader hook
// ahead of capwall's, then reports what an innocent third package's `import … "node:fs"` got.
import { run } from "esm-hookjack-dep";
for (const line of await run()) console.log("HOOKJACK:" + line);
