// Fixture app for the FLAGGED global egress classes (#80). Run under the capwall preload with
// `--experimental-websocket --experimental-eventsource`, so `WebSocket` and `EventSource` exist
// on every supported Node — on Node 20 both are flag-only, so an in-process vitest run would
// silently skip them there and the CI matrix's older half would prove nothing.
//
// argv[2]/argv[3] are two DISTINCT `host:port` pairs on loopback that nothing is listening on:
// the ALLOW path then fails at the transport instead of at capwall, which is exactly what
// distinguishes "the guard let it through" from "the guard denied it" without needing a real
// WebSocket/SSE server. Two ports rather than one because the preload deduplicates identical
// decisions per process, so a shared port would collapse the two classes into a single trace
// line and the observe assertion could not tell whether both were recorded.
const dep = require("fixture-dep");

const wsTarget = process.argv[2];
const esTarget = process.argv[3];

function label(err, prefix) {
  return err && err.name === "CapabilityError" ? `${prefix}:BLOCKED` : `${prefix}:ALLOWED`;
}

async function main() {
  try {
    await dep.openWebSocket(`ws://${wsTarget}/`);
    console.log("WS:ALLOWED"); // opened for real (not expected against a closed port)
  } catch (err) {
    console.log(label(err, "WS"));
  }

  try {
    dep.openEventSource(`http://${esTarget}/`);
    console.log("ES:ALLOWED"); // constructed without a capability error
  } catch (err) {
    console.log(label(err, "ES"));
  }
}

main().then(
  () => process.exit(0),
  (err) => {
    console.log("FATAL:" + (err && err.message));
    process.exit(1);
  },
);
