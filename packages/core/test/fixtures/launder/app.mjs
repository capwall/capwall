// App entry for the attribution-laundering fixture (issue #60).
//
// `node app.mjs <vector>` runs one laundering vector from `launder-dep` and prints
// `env=<value|undefined>` and `udp=<SENT|BLOCKED:pkg|ERR:…>` lines. The `app-*` vectors run
// the same two operations from THIS file — application code, the trust root — so the tests
// can prove ordinary app behavior is unchanged.
import { createSocket } from "node:dgram";
import { run, runDirect } from "launder-dep";

const SECRET = "LAUNDER_FIXTURE_SECRET";
const PORT = 9;
const HOST = "127.0.0.1";
const vector = process.argv[2];

function appOperations() {
  console.log(`env=${process.env[SECRET] ?? "undefined"}`);
  const s = createSocket("udp4");
  return new Promise((resolve) => {
    try {
      s.send(Buffer.from("x"), PORT, HOST, (err) => {
        console.log(`udp=${err ? "ERR:" + err.message : "SENT"}`);
        s.close();
        resolve();
      });
    } catch (err) {
      console.log(
        `udp=${err && err.name === "CapabilityError" ? "BLOCKED:" + err.pkg : "THREW:" + err.message}`,
      );
      s.close();
      resolve();
    }
  });
}

if (vector === "app-direct") {
  await appOperations();
} else if (vector === "app-detached") {
  // App code, but reached through a timer: still app code, and still no opaque frame between
  // the app and the capability call, so this must keep attributing to `<app>`.
  await new Promise((resolve) => setTimeout(() => void appOperations().then(resolve), 0));
} else if (vector === "dep-direct") {
  runDirect();
} else {
  await run(vector);
}
console.log("done");
