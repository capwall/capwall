// Fixture entrypoint for the net host-glob round-trip (#83).
//
// `api.internal` deliberately does not resolve: capwall decides before any DNS lookup, so
// "CapabilityError" (denied) vs "allowed-through" (the guard passed it to the OS, which then
// failed to resolve it) is an unambiguous signal that needs no network.
const dep = require("trace-dep");

dep.connectHost("api.internal", 9999).then((outcome) => {
  console.log("net:", outcome);
  return outcome;
});
