// Fixture entrypoint for the package-identity round-trip (#92 / #93). Kept out of `main.js`
// so the existing fs/native round-trip tests keep observing exactly what they observed before.
//
//   nested   — a genuinely nested install reads its own file. Its principal is the install
//              chain `trace-dep>nested-dep`, so gen-policy must emit that key and enforce
//              must match it.
//   compile  — trace-dep compiles source under ANOTHER package's filename, the `compile`
//              capability (#93). Recorded by observe, granted by gen-policy, allowed by
//              enforce under the generated policy — the documented escape hatch for the
//              `require.extensions` transform tools that need it.
const dep = require("trace-dep");

console.log("nested:", dep.readNested().trim());
console.log("compile:", dep.compileAsNested());
