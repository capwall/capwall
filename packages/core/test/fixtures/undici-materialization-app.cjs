// Fixture for issue #170: report whether capwall's install MATERIALIZED undici.
//
// `internal/deps/undici/undici` enters `process.moduleLoadList` at the instant anything reads
// `globalThis.Request`, and not before — merely reading `globalThis.fetch` does not do it
// (measured on 22.22.3 / 24.18.0 / 26.5.0). capwall reads `globalThis.Request` for exactly one
// reason: to capture the real `Request.prototype.url` getter for the global egress guard. So
// this line is a machine-checkable, machine-independent stand-in for "did the mediated process
// pay the ~21 ms undici materialization?" — where a wall-clock assertion would be forbidden
// (AGENTS.md § 7) and would not survive a busy CI box anyway.
//
// This file must not touch `fetch`, `Request`, `Response`, `Headers` or `FormData`.
const materialized = process.moduleLoadList.some((m) =>
  typeof m === "string" && m.endsWith("internal/deps/undici/undici"),
);
console.log(`undici-materialized:${materialized}`);
