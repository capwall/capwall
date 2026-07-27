/**
 * IPC path grants (issue #72) — canonicalization, the matching table (unix sockets AND Windows
 * named pipes), the `<tmp>`/`<home>` portability placeholders, and the backward-compatibility
 * contract for the pre-#72 `net: { hosts: ["<ipc>"], ports: [0] }` shape.
 *
 * The point of the issue: before this, `<ipc>:0` was ONE pseudo-target for every unix socket
 * and named pipe on the machine, so granting a package the socket it actually uses also granted
 * it the Docker socket. The first block below is the test that says that is no longer true.
 */
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import type { PackagePolicy } from "@capwall/policy-schema";
import { isGranted } from "../src/policy/evaluate.js";
import { loadPolicyFromObject } from "../src/policy/load.js";
import {
  canonicalIpcPath,
  expandIpcPlaceholders,
  matchesIpcPath,
  placeholderizeIpcPath,
  UNKNOWN_IPC_PATH,
} from "../src/policy/ipc.js";

function grants(grant: PackagePolicy, socketPath: string): boolean {
  return isGranted(grant, { kind: "ipc", path: socketPath });
}

/** os.tmpdir()/os.homedir() in the `/`-separated shape the matcher and the trace use. */
function slashed(dir: string): string {
  return dir.split(path.sep).join("/");
}

describe("the point of #72: one socket grant is not every socket grant", () => {
  const grant: PackagePolicy = { ipc: { paths: ["/var/run/myapp/api.sock"] } };

  it("grants the socket it names", () => {
    expect(grants(grant, "/var/run/myapp/api.sock")).toBe(true);
  });

  it("does NOT grant the Docker socket, the journal socket, or an SSH agent socket", () => {
    for (const other of [
      "/var/run/docker.sock",
      "/run/systemd/journal/socket",
      "/tmp/ssh-XXXX/agent.1234",
      "/var/run/myapp/admin.sock",
    ]) {
      expect(grants(grant, other)).toBe(false);
    }
  });
});

describe("ipc.paths — the matching table", () => {
  // [pattern, observed socket path, expected]
  const table: Array<[string, string, boolean]> = [
    // Exact and single-segment `*`, from the fs glob matcher (deliberately reused).
    ["/var/run/app.sock", "/var/run/app.sock", true],
    ["/var/run/app.sock", "/var/run/other.sock", false],
    ["/var/run/*.sock", "/var/run/app.sock", true],
    ["/var/run/*.sock", "/var/run/app.socket", false],
    ["/var/run/*.sock", "/var/run/nested/app.sock", false], // `*` never crosses a `/`
    ["/var/run/**", "/var/run/nested/app.sock", true],
    ["/var/run/**", "/var/run", true], // `dir/**` covers the dir itself, as for fs
    ["/var/run/app-*/api.sock", "/var/run/app-a91f3/api.sock", true],
    ["*", "/var/run/docker.sock", true], // the all-paths grant, same as fs
    ["**", "/var/run/docker.sock", true],

    // Windows named pipes. Every accepted spelling of a pattern matches every accepted
    // spelling of an observed pipe, because both sides canonicalize to `/./pipe/NAME`.
    ["\\\\.\\pipe\\myapp", "\\\\.\\pipe\\myapp", true],
    ["\\\\.\\pipe\\myapp-*", "\\\\.\\pipe\\myapp-1", true],
    ["//./pipe/myapp-*", "\\\\.\\pipe\\myapp-1", true],
    ["/./pipe/myapp-*", "\\\\.\\pipe\\myapp-1", true],
    ["\\\\.\\pipe\\myapp-*", "\\\\?\\pipe\\myapp-1", true], // `\\?\` is the same namespace
    ["\\\\.\\PIPE\\myapp", "\\\\.\\pipe\\myapp", true], // the `pipe` keyword is case-insensitive
    ["\\\\.\\pipe\\myapp-*", "\\\\.\\pipe\\other-1", false],
    // The pipe NAME is case-SENSITIVE, matching the fs matcher's call for everything but a
    // drive letter: a spurious deny is a smaller mistake than a silently widened grant.
    ["\\\\.\\pipe\\MyApp", "\\\\.\\pipe\\myapp", false],
    // A pipe is not a unix socket and vice versa.
    ["/var/run/myapp", "\\\\.\\pipe\\myapp", false],
    ["\\\\.\\pipe\\myapp", "/var/run/myapp", false],

    // Windows drive-letter paths still work (the #45 handling, inherited from the fs matcher).
    ["C:/app/**", "C:/app/run/api.sock", true],
    ["c:/app/**", "C:/app/run/api.sock", true], // drive letter is case-insensitive
    ["C:/app/**", "D:/app/run/api.sock", false],

    // `<unknown>` — an IPC connect whose destination the call's shape hid. Only an all-paths
    // grant (or the legacy `<ipc>` net grant, tested below) covers it.
    ["**", UNKNOWN_IPC_PATH, true],
    ["/var/run/**", UNKNOWN_IPC_PATH, false],
  ];

  for (const [pattern, socketPath, expected] of table) {
    it(`'${pattern}' ${expected ? "grants" : "does not grant"} '${socketPath}'`, () => {
      expect(matchesIpcPath(pattern, socketPath)).toBe(expected);
    });
  }
});

describe("canonicalIpcPath", () => {
  it("resolves a relative socket path to absolute, as the fs shim does for an fs argument", () => {
    expect(canonicalIpcPath("./api.sock")).toBe(
      path.resolve("./api.sock").split(path.sep).join("/"),
    );
  });

  it("is idempotent — a named pipe canonicalized twice is unchanged", () => {
    const once = canonicalIpcPath("\\\\.\\pipe\\myapp");
    expect(once).toBe("/./pipe/myapp");
    expect(canonicalIpcPath(once)).toBe(once);
  });

  it("leaves the `<unknown>` sentinel alone", () => {
    expect(canonicalIpcPath(UNKNOWN_IPC_PATH)).toBe(UNKNOWN_IPC_PATH);
  });
});

describe("machine portability: <tmp> and <home> placeholders", () => {
  it("rewrites a temp-dir socket and expands it back", () => {
    const observed = slashed(os.tmpdir()) + "/capwall-test/api.sock";
    expect(placeholderizeIpcPath(observed)).toBe("<tmp>/capwall-test/api.sock");
    expect(expandIpcPlaceholders("<tmp>/capwall-test/api.sock")).toBe(observed);
  });

  it("rewrites a home-dir socket and expands it back", () => {
    const observed = slashed(os.homedir()) + "/.myapp/api.sock";
    // A TMPDIR inside $HOME would make `<tmp>` win; skip the assertion in that case rather
    // than encode one machine's layout.
    if (!observed.startsWith(slashed(os.tmpdir()) + "/")) {
      expect(placeholderizeIpcPath(observed)).toBe("<home>/.myapp/api.sock");
    }
    expect(expandIpcPlaceholders("<home>/.myapp/api.sock")).toBe(observed);
  });

  it("only matches at a path-segment boundary", () => {
    expect(placeholderizeIpcPath(slashed(os.tmpdir()) + "-decoy/api.sock")).toBe(
      slashed(os.tmpdir()) + "-decoy/api.sock",
    );
  });

  it("leaves a stable system path alone — those are already portable", () => {
    expect(placeholderizeIpcPath("/var/run/docker.sock")).toBe("/var/run/docker.sock");
  });

  it("a <tmp> grant loaded on this machine matches a socket observed on this machine", () => {
    const policy = loadPolicyFromObject(
      { version: 1, packages: { dep: { ipc: { paths: ["<tmp>/svc/*.sock"] } } } },
      { projectRoot: "/proj" },
    );
    const observed = canonicalIpcPath(path.join(os.tmpdir(), "svc", "api.sock"));
    expect(isGranted(policy.packages["dep"]!, { kind: "ipc", path: observed })).toBe(true);
  });
});

describe("loadPolicy normalization of ipc.paths", () => {
  it("resolves a relative pattern against the project root, like an fs glob", () => {
    const policy = loadPolicyFromObject(
      { version: 1, packages: { dep: { ipc: { paths: ["./run/api.sock"] } } } },
      { projectRoot: "/proj" },
    );
    expect(policy.packages["dep"]!.ipc!.paths).toEqual(["/proj/run/api.sock"]);
  });

  it("does NOT resolve a named pipe against the project root", () => {
    // A POSIX `path.isAbsolute` does not recognize `\\.\pipe\x` as absolute, so without the
    // named-pipe branch this would become `/proj/\\.\pipe\x` — the same trap #45 fixed for
    // Windows drive letters.
    const policy = loadPolicyFromObject(
      { version: 1, packages: { dep: { ipc: { paths: ["\\\\.\\pipe\\myapp"] } } } },
      { projectRoot: "/proj" },
    );
    expect(policy.packages["dep"]!.ipc!.paths).toEqual(["/./pipe/myapp"]);
  });

  it("normalizes the `default` grant too", () => {
    const policy = loadPolicyFromObject(
      { version: 1, default: { ipc: { paths: ["./run/api.sock"] } } },
      { projectRoot: "/proj" },
    );
    expect(policy.default.ipc!.paths).toEqual(["/proj/run/api.sock"]);
  });
});

describe("BACKWARD COMPATIBILITY: the pre-#72 `<ipc>` net grant", () => {
  it("`net: { hosts: [\"<ipc>\"], ports: [0] }` still means EVERY socket and pipe", () => {
    const legacy: PackagePolicy = { net: { hosts: ["<ipc>"], ports: [0] } };
    for (const p of ["/var/run/docker.sock", "/tmp/app.sock", "/./pipe/myapp", UNKNOWN_IPC_PATH]) {
      expect(grants(legacy, p)).toBe(true);
    }
  });

  it("a `hosts: [\"*\"] / ports: [\"*\"]` grant covers IPC, as it did before", () => {
    expect(grants({ net: { hosts: ["*"], ports: ["*"] } }, "/var/run/docker.sock")).toBe(true);
  });

  it("a `<ipc>` host on a NON-zero port does not grant IPC — unchanged from before #72", () => {
    expect(grants({ net: { hosts: ["<ipc>"], ports: [443] } }, "/var/run/docker.sock")).toBe(false);
  });

  it("a NEW host wildcard cannot acquire IPC authority as a side effect", () => {
    // The legacy test is written with literal comparisons for exactly this reason: `*.internal`
    // must not become an all-IPC grant just because #83 taught `hosts` to glob.
    expect(grants({ net: { hosts: ["*.internal"], ports: [0] } }, "/var/run/docker.sock")).toBe(false);
    expect(grants({ net: { hosts: ["**.internal"], ports: [0] } }, "/var/run/docker.sock")).toBe(false);
  });

  it("no net grant and no ipc grant is a denial", () => {
    expect(grants({}, "/var/run/docker.sock")).toBe(false);
    expect(grants({ net: { hosts: ["api.example.com"], ports: [443] } }, "/var/run/docker.sock")).toBe(false);
  });

  it("the narrow and legacy forms compose: either one granting is enough", () => {
    const both: PackagePolicy = {
      ipc: { paths: ["/var/run/myapp/api.sock"] },
      net: { hosts: ["api.example.com"], ports: [443] },
    };
    expect(grants(both, "/var/run/myapp/api.sock")).toBe(true);
    expect(grants(both, "/var/run/docker.sock")).toBe(false);
    expect(isGranted(both, { kind: "net", host: "api.example.com", port: 443 })).toBe(true);
  });
});
