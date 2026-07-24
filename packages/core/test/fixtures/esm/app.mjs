// ESM app entry: imports the ESM dependency and reports whether its fs use was allowed or
// blocked. Run with capwall preloaded via `node --import <preload> app.mjs`.
import { readFromDep } from "esm-fixture-dep";
try {
  const data = readFromDep();
  console.log("READ_OK:" + data.trim());
} catch (err) {
  if (err && err.name === "CapabilityError") {
    console.log("BLOCKED:" + err.pkg);
    process.exitCode = 1;
  } else {
    throw err;
  }
}
