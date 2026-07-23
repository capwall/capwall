// Fixture entrypoint: exercises a capability NOT covered by a policy generated from
// main.js — enforce mode must deny it (deny-by-default).
const dep = require("trace-dep");
console.log("extra:", dep.readOther().trim());
