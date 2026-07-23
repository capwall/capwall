/**
 * `net` capability shim (also covers `http`/`https`, which build on `net`). Roadmap M4.
 *
 * Wraps outbound connection creation (`net.connect`/`Socket.connect`, and by extension
 * `http(s).request`/`get`) and, per owning package, allows only the host/port pairs in the
 * package's `net` grant. Deny-by-default in enforce mode.
 */
import type { ShimContext } from "./fs.js";

/**
 * TODO(capwall): wrap net.connect / Socket.prototype.connect (and http/https request paths)
 * to build a { kind: "net", host, port } request, attribute + evaluate, then forward or
 * deny. Resolve host from the connect options (string host, or lookup for hostnames).
 */
export function createNetShim(_ctx: ShimContext): typeof import("node:net") {
  throw new Error("capwall: net shim not yet implemented — see roadmap M4");
}
