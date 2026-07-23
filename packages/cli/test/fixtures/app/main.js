// Fixture entrypoint: exercises the capability the policy SHOULD end up granting.
const dep = require("trace-dep");
console.log("main:", dep.readData().trim());
