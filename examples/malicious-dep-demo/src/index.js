// Demo runner: loads the inert "malicious" dependency and narrates what capwall does.
//
//   capwall observe -- node src/index.js   → sneaky-dep's fs read is LOGGED, allowed; exit 0
//   capwall enforce -- node src/index.js   → it is DENIED (CapabilityError) before any
//                                            effect; this runner reports BLOCKED and exits 1
//
// The committed ./capabilities.json grants 'sneaky-dep' NOTHING (deny-by-default) — enforce
// mode is what stops an opportunistic supply-chain payload at the runtime phase.
// A FAKE secret, so the env anti-exfiltration control has something inert to hide. This is
// set by the app (<app>), which the env shim does NOT gate; the dependency reading it IS.
process.env.AWS_SECRET_ACCESS_KEY = "FAKE-not-a-real-secret-fixture-value";

const pretendToBeHelpful = require("sneaky-dep");

console.log("== capwall malicious-dep-demo (inert fixture) ==\n");

try {
  const result = pretendToBeHelpful();
  console.log(`\nsneaky-dep returned: ${result}`);
  console.log("Nothing was blocked (raw node, or capwall observe mode).");
  console.log("No real secrets were read and no network connections were made — this is a fixture.");
} catch (err) {
  // CapabilityError crosses the CJS/ESM boundary, so match by name, not instanceof.
  if (err && err.name === "CapabilityError") {
    console.log(`\n[demo] BLOCKED by capwall: ${err.message}`);
    process.exitCode = 1;
  } else {
    throw err;
  }
}
