// Fork target for the #89 tests: prints the environment it was launched with, so the parent can
// assert that a `fork` still inherits (or overrides) the environment correctly.
process.stdout.write(JSON.stringify(process.env));
