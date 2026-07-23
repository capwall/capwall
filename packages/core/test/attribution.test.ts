/** Unit tests for path→package resolution (the attribution building block). */
import { describe, expect, it } from "vitest";
import { APP_ROOT, packageForPath } from "../src/attribution/index.js";

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
