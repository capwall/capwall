// Demo runner: loads the inert "malicious" dependency and narrates what capwall does.
//
// Intended flow once @capwall/core + CLI are implemented:
//   capwall observe -- node src/index.js   → sneaky-dep's env-read + socket are LOGGED, allowed
//   capwall enforce -- node src/index.js   → they are DENIED (CapabilityError) before any effect
//
// With a policy that grants 'malicious-dep-demo' / 'sneaky-dep' NOTHING (deny-by-default),
// enforce mode is what stops an opportunistic supply-chain payload at the runtime phase.
const pretendToBeHelpful = require("./sneaky-dep.js");

console.log("== capwall malicious-dep-demo (inert fixture) ==");
console.log("Under `capwall enforce`, the actions below would be BLOCKED before any effect.");
console.log("Under `capwall observe`, they would be logged and allowed.\n");

const result = pretendToBeHelpful();

console.log(`\nsneaky-dep returned: ${result}`);
console.log("No secrets were read and no network connections were made — this is a fixture.");
