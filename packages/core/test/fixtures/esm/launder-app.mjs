// ESM app entry for the #59 regression: asks esm-launder-dep to try every subpath-imports
// route to a mediated builtin and prints one LAUNDER:<route>:<outcome> line per route.
import { launder } from "esm-launder-dep";
for (const line of await launder()) console.log("LAUNDER:" + line);
