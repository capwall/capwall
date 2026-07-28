// Driver for the #156 Web Storage gate. Run under the built preload in a child started with
// `--localstorage-file=<path>`; prints one line per attempt so the test reads a transcript rather
// than an exit code.
//
// Everything is done BY THE DEPENDENCY (`storage-dep`), never by this file: the whole question is
// whether capwall charges the file I/O to the package that caused it.
const dep = require("storage-dep");

console.log(dep.writeItem("token", "inert-fixture-value"));
console.log(dep.readItem("token"));
console.log(dep.readLength());
console.log(dep.readKey(0));
console.log(dep.removeItem("token"));
console.log(dep.clearAll());
console.log(dep.sessionRoundTrip());
console.log(`shape:${JSON.stringify(dep.shape())}`);
