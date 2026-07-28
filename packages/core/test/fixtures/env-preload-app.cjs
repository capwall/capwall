// Fixture app for the CAPWALL_ENV preload channel (#125). Run under the capwall preload with a
// deny-all `enforce` policy: `fixture-dep` holds no `env` grant, so with the guard ON the read is
// hidden (a denied env read is a SOFT deny — it returns `undefined`), and with `CAPWALL_ENV=0`
// `process.env` is never proxied at all and the value comes straight back.
//
// The probe reads through the DEPENDENCY rather than here, because `<app>` is exempt from the env
// gate either way and would report the value under both settings — proving nothing.
const dep = require("fixture-dep");

console.log("ENV:" + String(dep.readEnv(process.argv[2])));
