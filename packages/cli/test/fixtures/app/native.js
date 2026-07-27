// Fixture entrypoint for the native-addon capability round-trip (#49).
//
// The load ALWAYS fails — the fixture `.node` is a placeholder, not a real addon — so what
// this prints is the error's NAME, which is exactly the signal under test: `CapabilityError`
// means capwall's gate denied the load, anything else means the gate allowed it through to
// the platform loader. Printing rather than throwing keeps the exit code out of the
// assertion, so the test reads one unambiguous line either way.
const dep = require("trace-dep");
try {
  dep.loadAddon();
  console.log("native: loaded");
} catch (err) {
  console.log("native:", err.name);
}
