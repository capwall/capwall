// #15 env-var path fixture. Run under the capwall preload (NODE_OPTIONS=--import <preload>)
// so CAPWALL_MAX_FRAMES is exercised end-to-end, exactly as the CLI runs a target app.
//
// The app itself is trivial: it asks fixture-dep to read its own data file through a chain of
// `argv[2]` wrapper frames. Whether capwall charges that read to 'fixture-dep' (correct) or
// falls back to '<app>' (mis-attributed, because the walk ran out of frames) depends ONLY on
// the configured frame budget — which is the point of the test.
const dep = require("fixture-dep");

const depth = Number(process.argv[2] ?? 60);
process.stdout.write(`READ_OK:${dep.readDataViaDeepStack(depth).trim()}\n`);
