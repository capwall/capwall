// Fixture entrypoint for the IPC capability round-trip (#72).
//
// The app (the trust root) binds a unix socket inside the project root; the DEPENDENCY connects
// to it, so the connect is attributed to `trace-dep` and gated as `ipc <path>`. Binding is not
// gated (capwall mediates who a package may reach, not that it may serve), so the server side
// needs no grant. On Windows a path under the project root is not a valid socket name, so this
// entrypoint is POSIX-only — the named-pipe spelling is covered by unit tests instead.
const net = require("net");
const path = require("path");
const dep = require("trace-dep");

const sockPath = path.join(__dirname, "api.sock");
const server = net.createServer((c) => c.end());
server.listen(sockPath, () => {
  dep
    .connectIpc(sockPath)
    .then((outcome) => {
      console.log("ipc:", outcome);
      server.close();
      return outcome;
    })
    .catch((err) => {
      console.log("ipc:", err.name);
      server.close();
    });
});
