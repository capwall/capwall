/**
 * Unit tests for attribution: path→package resolution (the building block) and the stack
 * walk's three outcomes — a dependency, the application, or unattributable (issue #60).
 */
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { APP_ROOT, UNATTRIBUTED, attributeCaller, packageForPath } from "../src/attribution/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));

describe("packageForPath", () => {
  it("resolves a plain node_modules path", () => {
    expect(packageForPath("/proj/node_modules/express/lib/router.js")).toBe("express");
  });

  it("resolves a scoped package", () => {
    expect(packageForPath("/proj/node_modules/@scope/pkg/dist/i.js")).toBe("@scope/pkg");
  });

  it("uses the LAST node_modules segment (pnpm layout, nested deps)", () => {
    expect(
      packageForPath(
        "/proj/node_modules/.pnpm/express@4.19.2/node_modules/express/lib/a.js",
      ),
    ).toBe("express");
    expect(
      packageForPath("/proj/node_modules/a/node_modules/b/index.js"),
    ).toBe("b");
  });

  it("attributes non-dependency paths to the app root", () => {
    expect(packageForPath("/proj/src/server.js")).toBe(APP_ROOT);
  });
});

describe("attributeCaller — the three outcomes (#60)", () => {
  it("keeps the app sentinel distinct from the unattributable sentinel", () => {
    // The whole bug was that these were one value. If they ever converge again, the `<app>`
    // exemptions in the env shim and the dgram guard swallow every attribution failure.
    expect(UNATTRIBUTED).not.toBe(APP_ROOT);
  });

  it("attributes ordinary application code to <app>", () => {
    // This test file is a real source file outside any node_modules — a POSITIVE app frame.
    expect(attributeCaller({ projectRoot: here })).toBe(APP_ROOT);
  });

  it("attributes a call with no caller frame at all to <unknown>, not <app>", async () => {
    // A native function invoked straight from a timer: every frame is a Node internal. The
    // walk used to fall off the end and return `<app>`, handing the trust root's exemptions
    // to code with no identity.
    const pkg = await new Promise<string>((resolve) => {
      setTimeout(
        () => resolve(attributeCaller({ projectRoot: here })),
        0,
      );
    });
    // The arrow above is still a frame in THIS file, so it attributes to the app. What must
    // not happen is the reverse: an empty stack claiming to be the app. Assert the empty case
    // directly by walking with a budget too small to reach any real frame.
    expect(pkg).toBe(APP_ROOT);
    expect(attributeCaller({ projectRoot: here, maxFrames: 1 })).toBe(UNATTRIBUTED);
  });

  it("never infers <app> through an eval frame (#84)", () => {
    // `eval` frames carry no file name, and since #84 the origin V8 reports for them is not
    // consulted at all — it is partly attacker-controlled (see below). An eval frame is
    // therefore opaque, and `<app>`, the trust root, may not be claimed through opaque code.
    const evaluate = eval; // indirect eval — global scope, same origin reporting
    expect(evaluate(ATTRIBUTE_CALL)).toBe(UNATTRIBUTED);
  });

  it("never infers <app> through a new Function frame either (#84)", () => {
    expect(new Function(`return ${ATTRIBUTE_CALL}`)()).toBe(UNATTRIBUTED);
  });

  it("attributes code with an attacker-supplied sourceURL to <unknown>", () => {
    // `//# sourceURL=` REPLACES V8's eval origin with an arbitrary string, so evaled code
    // could otherwise name any package it liked — including one with broad grants.
    const evaluate = eval;
    const pkg = evaluate(
      `${ATTRIBUTE_CALL}\n//# sourceURL=/proj/node_modules/lodash/index.js`,
    ) as string;
    expect(pkg).toBe(UNATTRIBUTED);
  });

  it("cannot be made to name a package by a NESTED eval + sourceURL (#84)", () => {
    // The #84 forgery, at unit level. A single `sourceURL` cannot forge V8's `eval at …` form,
    // because a `sourceURL` may not contain whitespace — that much was always true. But for a
    // NESTED eval V8 synthesizes the `eval at <fn> (…)` wrapper itself, wrapped around the
    // OUTER script's name, and the outer script's name is exactly what its `sourceURL` set.
    // Appending `:1:1` (still no whitespace) completes the shape, and the result is
    // indistinguishable from a genuine depth-1 origin:
    //
    //   getEvalOrigin() === "eval at <anonymous> (/proj/node_modules/lodash/index.js:1:1)"
    //
    // The forged path need not exist — attribution never touches the disk.
    const evaluate = eval;
    const forged = "/proj/node_modules/lodash/index.js";
    const pkg = evaluate(
      `eval(${JSON.stringify(ATTRIBUTE_CALL)})\n//# sourceURL=${forged}:1:1`,
    ) as string;
    expect(pkg).not.toBe("lodash");
    expect(pkg).toBe(UNATTRIBUTED);
  });

  it("cannot be made to name a package at any nesting depth (#84)", () => {
    // There is no depth at which the innermost group stops being attacker-chosen, so no
    // "reject more than one `eval at`" or "take the outermost match" parse recovers this.
    const evaluate = eval;
    const forged = "/proj/node_modules/lodash/deep.js";
    const inner = `eval(${JSON.stringify(ATTRIBUTE_CALL)})`;
    const pkg = evaluate(
      `eval(${JSON.stringify(inner)})\n//# sourceURL=${forged}:1:1`,
    ) as string;
    expect(pkg).not.toBe("lodash");
    expect(pkg).toBe(UNATTRIBUTED);
  });

  it("cannot be made to name <app> by a nested eval naming a non-node_modules path (#84)", () => {
    // The variant that needs no granted package in the policy at all: any path outside
    // `node_modules` resolves to `<app>`, the trust root, whose env reads are exempted before
    // the decision is recorded.
    const evaluate = eval;
    const pkg = evaluate(
      `eval(${JSON.stringify(ATTRIBUTE_CALL)})\n//# sourceURL=${path.join(here, "app.js")}:1:1`,
    ) as string;
    expect(pkg).toBe(UNATTRIBUTED);
  });

  it("never lets a data: URL module inherit the app sentinel", async () => {
    const src = `export const pkg = ${ATTRIBUTE_CALL};`;
    // Detach first, so the importing frame in this file is not on the stack when the data:
    // module body runs — the issue's PoC shape.
    const mod = await new Promise<{ pkg: string }>((resolve, reject) => {
      setTimeout(() => {
        import("data:text/javascript," + encodeURIComponent(src)).then(
          (m) => resolve(m as { pkg: string }),
          reject,
        );
      }, 0);
    });
    // In a plain Node process this is `<unknown>` — see the subprocess cases in
    // `attribution-laundering.test.ts`, which run the real PoC. Under vitest the dynamic
    // import is routed through vite-node, so a REAL dependency frame sits below the data:
    // module and is charged instead, which is the other half of the rule: a positively
    // identified package still wins, only `<app>` may not be inferred through opaque code.
    expect(mod.pkg).not.toBe(APP_ROOT);
  });
});

/**
 * `attributeCaller` itself is exposed on `globalThis` — NOT a wrapper defined in this file.
 * A wrapper would put an app frame between the compiled code and the walk, which is exactly
 * what the walk is supposed to find, and the cases would prove nothing. Calling the real
 * function directly reproduces the shipped shape: the only frames above the opaque one belong
 * to capwall, and capwall skips its own.
 */
(globalThis as Record<string, unknown>)["__capwallAttribute"] = attributeCaller;
const ATTRIBUTE_CALL = `globalThis.__capwallAttribute({ projectRoot: ${JSON.stringify(here)} })`;
