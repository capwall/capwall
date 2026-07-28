/**
 * The `dgram` guard matrix — issue #86.
 *
 * #86 was the project's first confirmed case of two separately-reviewed merges breaking each
 * other, and it survived review because no test crossed the two axes. #17 (hardened mode) pins
 * the guarded `send`/`connect` properties capwall installs on a socket; #60's auto-bind replay
 * fix needed to control what Node's internal `this.send` read yields for the duration of one
 * authorized call, and did it by REDEFINING that pinned property — so under
 * `CAPWALL_HARDENED=1` every ALLOWED `dgram.createSocket().send()` threw
 * `TypeError: Cannot redefine property: send`. Fail-closed, but it made UDP unusable in the one
 * mode users enable to get MORE safety, with no capwall log line to explain it.
 *
 * So this file runs the whole cross product deliberately:
 *
 *   { createSocket(), new dgram.Socket() } x { hardened, not } x { granted, denied }
 *                                          x { bound, unbound }
 *
 * plus the properties each of the two fixes established, which must both survive:
 *  - #17: `socket.send = evil` / `Object.defineProperty(socket, "send", …)` cannot strip the
 *    guard off a socket capwall handed out (and CAN, with hardened off — graceful-fs parity);
 *  - #60: an already-authorized send is forwarded without re-entering the guard, while a send
 *    laundered through a detached timer — whose stack is byte-identical to that replay — is
 *    still denied. The laundering half runs end-to-end in `attribution-laundering.test.ts`
 *    (it needs real timer detachment and an uncatchable throw); what is asserted HERE is that
 *    the authorization capwall carries for the replay cannot be turned into an unauthorized
 *    send, which is the security question the #86 fix has to answer.
 *
 * Every socket is created from inside `fixture-dep` so attribution charges a dependency: the
 * dgram gate exempts `<app>`, so a test-file-owned socket would prove nothing.
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { install, loadPolicyFromObject, type Decision, type Policy } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const requireCjs = createRequire(import.meta.url);
const FIXTURE = path.join(here, "fixtures", "node_modules", "fixture-dep");

/** The REAL dgram, resolved outside any install window — used for the receiving socket, which
 * must not be mediated (and belongs to the test, not to a dependency). */
const REAL_DGRAM = requireCjs("node:dgram") as typeof import("node:dgram");

type Flavor = "factory" | "class";
type Target = { host: string; port: number };

interface FixtureDep {
  udpSend(
    flavor: Flavor,
    host: string,
    port: number,
    bindFirst: boolean,
    cb: (err: unknown) => void,
  ): unknown;
  udpSendStringPort(flavor: Flavor, host: string, port: number): unknown;
  udpSendWithOffset(flavor: Flavor, host: string, port: number): unknown;
  udpConnect(flavor: Flavor, host: string, port: number, cb: (err: unknown) => void): unknown;
  patchUdpSocketSend(flavor: Flavor, replacement: unknown): unknown;
  patchUdpSocketSendStrict(flavor: Flavor, replacement: unknown): string;
  redefineUdpSocketSend(flavor: Flavor, replacement: unknown): string;
  stealUdpSendDuringAuthorizedSend(
    flavor: Flavor,
    allowed: Target,
    denied: Target,
    cb: (stolenType: string, outcome: string) => void,
  ): unknown;
  replayStolenUdpSendOnOtherSocket(
    flavor: Flavor,
    allowed: Target,
    cb: (outcome: string) => void,
  ): void;
  replayStolenUdpSendRepeatedly(
    flavor: Flavor,
    allowed: Target,
    times: number,
    cb: (stolenType: string, outcomes: string[]) => void,
  ): void;
}

function loadFixtureFresh(): FixtureDep {
  const resolved = requireCjs.resolve(FIXTURE);
  delete requireCjs.cache[resolved];
  return requireCjs(FIXTURE) as FixtureDep;
}

type Recorded = { pkg: string; decision: Decision };

/** Run `fn` inside an install window, hardened on or off, collecting every decision. The window
 * stays open for the whole (possibly async) body: Node's auto-bind replay fires a tick later,
 * and closing the window early would hide exactly the interaction under test. */
async function withCapwall<T>(
  policy: Policy,
  hardened: boolean,
  fn: (dep: FixtureDep) => T | Promise<T>,
): Promise<{ result: T; decisions: Recorded[] }> {
  const decisions: Recorded[] = [];
  const handle = install(policy, "enforce", {
    projectRoot: here,
    hardened,
    onDecision: (pkg, decision) => decisions.push({ pkg, decision }),
  });
  try {
    return { result: await fn(loadFixtureFresh()), decisions };
  } finally {
    handle.uninstall();
  }
}

const HOST = "127.0.0.1";
let receiver: import("node:dgram").Socket;
/** Granted in the policy below. */
let allowedPort = 0;
/** Never granted — a second real port so a "denied" send would go somewhere real if it leaked. */
let deniedPort = 0;
let received: Buffer[] = [];

beforeAll(async () => {
  receiver = REAL_DGRAM.createSocket("udp4");
  receiver.on("message", (msg) => received.push(msg));
  await new Promise<void>((resolve) => receiver.bind(0, HOST, resolve));
  allowedPort = receiver.address().port;
  // Any port that is not the granted one. Nothing listens there; the assertion is the policy
  // decision, not delivery.
  deniedPort = allowedPort === 65535 ? 65534 : allowedPort + 1;
});

afterAll(() => {
  receiver.close();
});

/** Grants fixture-dep exactly one UDP destination: 127.0.0.1:<receiver>. */
function grantReceiver(): Policy {
  return loadPolicyFromObject(
    {
      version: 1,
      mode: "enforce",
      packages: { "fixture-dep": { net: { hosts: [HOST], ports: [allowedPort] } } },
    },
    { projectRoot: here },
  );
}

const denyAll = (): Policy =>
  loadPolicyFromObject({ version: 1, mode: "enforce" }, { projectRoot: here });

/** Wait until `received` has at least one datagram, or time out. Delivery is the load-bearing
 * assertion for the ALLOWED cases — "did not throw" would also be true if capwall silently
 * dropped the packet. */
async function awaitDatagram(timeoutMs = 1000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (received.length === 0 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 5));
  }
  return received.length > 0;
}

const FLAVORS: Flavor[] = ["factory", "class"];
const HARDENED = [false, true];
const BOUND = [false, true];

describe("#86 — an ALLOWED dgram send works in every corner of the matrix", () => {
  for (const flavor of FLAVORS) {
    for (const hardened of HARDENED) {
      for (const bindFirst of BOUND) {
        const label = `${flavor}, hardened=${hardened}, ${bindFirst ? "bound" : "unbound"}`;
        it(`delivers the datagram (${label})`, async () => {
          received = [];
          const { result, decisions } = await withCapwall(grantReceiver(), hardened, (dep) => {
            return new Promise<unknown>((resolve) => {
              dep.udpSend(flavor, HOST, allowedPort, bindFirst, resolve);
            });
          });
          // The regression: this used to be `TypeError: Cannot redefine property: send`, thrown
          // out of capwall's own bookkeeping AFTER the policy allowed the send.
          expect(result).toBeFalsy();
          expect(await awaitDatagram()).toBe(true);
          // Exactly one decision, and it allowed: the auto-bind replay must NOT re-enter the
          // guard and produce a second (denied, `<unknown>`) decision.
          const netDecisions = decisions.filter((d) => d.decision.observed.kind === "net");
          expect(netDecisions).toHaveLength(1);
          expect(netDecisions[0]?.pkg).toBe("fixture-dep");
          expect(netDecisions[0]?.decision.allowed).toBe(true);
        });
      }
    }
  }
});

describe("#86 — a DENIED dgram send is denied in every corner of the matrix", () => {
  for (const flavor of FLAVORS) {
    for (const hardened of HARDENED) {
      it(`denies an unbound send (${flavor}, hardened=${hardened})`, async () => {
        const { decisions } = await withCapwall(denyAll(), hardened, (dep) => {
          expect(() => dep.udpSend(flavor, HOST, deniedPort, false, () => {})).toThrowError(
            expect.objectContaining({ name: "CapabilityError" }),
          );
        });
        expect(decisions.some((d) => d.pkg === "fixture-dep" && !d.decision.allowed)).toBe(true);
      });

      it(`denies a bound send (${flavor}, hardened=${hardened})`, async () => {
        const { result } = await withCapwall(denyAll(), hardened, (dep) => {
          return new Promise<unknown>((resolve) => {
            dep.udpSend(flavor, HOST, deniedPort, true, resolve);
          });
        });
        expect(result).toMatchObject({ name: "CapabilityError" });
      });
    }
  }
});

describe("#86 — the destination is derived the way Node derives it", () => {
  for (const flavor of FLAVORS) {
    for (const hardened of HARDENED) {
      // Node's `validatePort` accepts a numeric STRING, so `send(buf, "1234", host)` is a real
      // datagram to port 1234. A type-based "last number argument is the port" derivation saw
      // no number, concluded there was no destination, and skipped the guard entirely — silent,
      // unlogged UDP egress under a deny-all policy.
      it(`guards a string port (${flavor}, hardened=${hardened})`, async () => {
        const { decisions } = await withCapwall(denyAll(), hardened, (dep) => {
          expect(() => dep.udpSendStringPort(flavor, HOST, deniedPort)).toThrowError(
            expect.objectContaining({ name: "CapabilityError" }),
          );
        });
        expect(
          decisions.some(
            (d) =>
              !d.decision.allowed &&
              d.decision.observed.kind === "net" &&
              d.decision.observed.port === deniedPort,
          ),
        ).toBe(true);
      });

      it(`guards the 6-argument offset/length form (${flavor}, hardened=${hardened})`, async () => {
        const { decisions } = await withCapwall(denyAll(), hardened, (dep) => {
          expect(() => dep.udpSendWithOffset(flavor, HOST, deniedPort)).toThrowError(
            expect.objectContaining({ name: "CapabilityError" }),
          );
        });
        expect(
          decisions.some(
            (d) =>
              !d.decision.allowed &&
              d.decision.observed.kind === "net" &&
              d.decision.observed.port === deniedPort,
          ),
        ).toBe(true);
      });

      it(`allows the same string port when granted (${flavor}, hardened=${hardened})`, async () => {
        const { decisions } = await withCapwall(grantReceiver(), hardened, (dep) => {
          expect(() => dep.udpSendStringPort(flavor, HOST, allowedPort)).not.toThrow();
        });
        expect(decisions.some((d) => d.decision.allowed)).toBe(true);
      });
    }
  }
});

describe("#86 — connect() on an unbound socket", () => {
  // Node defers `connect` behind the same auto-bind, but queues its INTERNAL `_connect`, not
  // `this.connect`, so the guard is not re-entered. This pins that: if a future Node queued the
  // public method instead, the granted case below would die with an uncatchable CapabilityError
  // from inside Node's 'listening' flush — the shape of the DoS #60 fixed for `send`.
  for (const flavor of FLAVORS) {
    for (const hardened of HARDENED) {
      it(`a granted unbound connect completes (${flavor}, hardened=${hardened})`, async () => {
        await withCapwall(grantReceiver(), hardened, (dep) => {
          return new Promise<void>((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error("connect never completed")), 2000);
            dep.udpConnect(flavor, HOST, allowedPort, () => {
              clearTimeout(timer);
              resolve();
            });
          });
        });
      });

      it(`a denied unbound connect throws (${flavor}, hardened=${hardened})`, async () => {
        await withCapwall(denyAll(), hardened, (dep) => {
          expect(() => dep.udpConnect(flavor, HOST, deniedPort, () => {})).toThrowError(
            expect.objectContaining({ name: "CapabilityError" }),
          );
        });
      });
    }
  }
});

describe("#17 — hardened mode still pins the guard onto the socket", () => {
  for (const flavor of FLAVORS) {
    it(`a sloppy 'socket.send = evil' no-ops under hardened (${flavor})`, async () => {
      const evil = (): string => "PATCHED";
      const { result } = await withCapwall(denyAll(), true, (dep) =>
        dep.patchUdpSocketSend(flavor, evil),
      );
      expect(result).not.toBe(evil);
      expect(typeof result).toBe("function");
    });

    it(`the same write under 'use strict' throws under hardened (${flavor})`, async () => {
      const { result } = await withCapwall(denyAll(), true, (dep) =>
        dep.patchUdpSocketSendStrict(flavor, () => "PATCHED"),
      );
      expect(result).toBe("TypeError");
    });

    it(`the same write LANDS with hardened off — graceful-fs parity (${flavor})`, async () => {
      const evil = (): string => "PATCHED";
      const { result } = await withCapwall(denyAll(), false, (dep) =>
        dep.patchUdpSocketSend(flavor, evil),
      );
      expect(result).toBe(evil);
    });
  }

  it("Object.defineProperty over the guarded send throws on a createSocket() socket", async () => {
    const { result } = await withCapwall(denyAll(), true, (dep) =>
      dep.redefineUdpSocketSend("factory", () => "PATCHED"),
    );
    expect(result).toBe("TypeError");
  });

  it("…and succeeds on a `new dgram.Socket()` instance — a documented residual, not a fix", async () => {
    // The guard for the class flavor lives on the guarded SUBCLASS's (frozen) prototype, and an
    // own property on an unfrozen instance shadows a frozen prototype property no matter what.
    // Closing this would mean freezing the socket, which a socket cannot survive. Asserted so
    // the asymmetry is a recorded decision rather than an untested assumption — see
    // docs/threat-model.md § Hardened mode.
    const { result } = await withCapwall(denyAll(), true, (dep) =>
      dep.redefineUdpSocketSend("class", () => "PATCHED"),
    );
    expect(result).toBe("redefined");
  });
});

describe("#86 — attacking the authorization the replay fix carries", () => {
  // THE security question the fix has to answer: the replay is authorized by state, so can a
  // dependency manufacture that state and get an UNAUTHORIZED send forwarded?
  //
  // The state is reachable at exactly one moment — Node reads `this.send` from inside its own
  // send in order to queue the auto-bind replay — and a dependency CAN run code there, via an
  // accessor on an element of a buffer list argument (`fixBufferList` reads `list[i]`). These
  // cases do exactly that and then try to spend what they stole.
  for (const flavor of FLAVORS) {
    for (const hardened of HARDENED) {
      it(`a stolen authorization cannot reach another destination (${flavor}, hardened=${hardened})`, async () => {
        const { result } = await withCapwall(grantReceiver(), hardened, (dep) => {
          return new Promise<{ stolenType: string; outcome: string }>((resolve) => {
            dep.stealUdpSendDuringAuthorizedSend(
              flavor,
              { host: HOST, port: allowedPort },
              { host: HOST, port: deniedPort },
              (stolenType, outcome) => resolve({ stolenType, outcome }),
            );
          });
        });
        // The steal itself succeeds — that is the point. What it yields is not power.
        expect(result.stolenType).toBe("function");
        // Before the fix the same steal yielded the REAL, unguarded `send` (it was installed as
        // an own property of the socket for the duration of the call) and this said "sent".
        expect(result.outcome).toBe("CapabilityError");
      });

      it(`a stolen authorization cannot be moved to another socket (${flavor}, hardened=${hardened})`, async () => {
        const { result, decisions } = await withCapwall(grantReceiver(), hardened, (dep) => {
          return new Promise<string>((resolve) => {
            dep.replayStolenUdpSendOnOtherSocket(
              flavor,
              { host: HOST, port: allowedPort },
              resolve,
            );
          });
        });
        // The destination is granted, so "did it send?" cannot distinguish the two paths. The
        // DECISION COUNT can: an authorization spent on the wrong socket must fall back to the
        // guard, which records. Two sends → two decisions. A socket-portable authorization
        // would forward the second one silently and leave exactly one.
        expect(result).toBe("sent");
        expect(decisions.filter((d) => d.decision.observed.kind === "net")).toHaveLength(2);
      });

      it(`a stolen authorization is SINGLE-USE (${flavor}, hardened=${hardened})`, async () => {
        /*
         * FOUND BY `scripts/mutation-guard.mjs` (#112). Deleting the `spent` guard from
         * `mintDgramReplayToken` left `dgram.test.ts` and `net.test.ts` fully green: the two
         * cases above vary the DESTINATION and the SOCKET, and both fall back to the guard for
         * reasons that have nothing to do with `spent`. Nothing anywhere spent a valid token
         * twice, so "one use" was asserted by the comment and by nothing else.
         *
         * What a re-spendable token buys an attacker: an un-gated `send` to that socket and
         * destination that lives as long as the reference does — including across an
         * `install()` that tightened the policy — and, because it never reaches the guard, one
         * that is absent from the audit trail.
         *
         * The destination is granted, so "did it send?" cannot tell the two apart. The DECISION
         * COUNT can: 1 for the original send, plus one per use that correctly fell back to the
         * guard. 3 uses ⇒ 1 + 2 = 3 decisions; a re-spendable token records exactly 1.
         */
        const USES = 3;
        const { result, decisions } = await withCapwall(grantReceiver(), hardened, (dep) => {
          return new Promise<{ stolenType: string; outcomes: string[] }>((resolve) => {
            dep.replayStolenUdpSendRepeatedly(
              flavor,
              { host: HOST, port: allowedPort },
              USES,
              (stolenType, outcomes) => resolve({ stolenType, outcomes }),
            );
          });
        });
        expect(result.stolenType).toBe("function"); // the steal itself still succeeds
        expect(result.outcomes).toEqual(["sent", "sent", "sent"]); // all granted, none throws
        expect(decisions.filter((d) => d.decision.observed.kind === "net")).toHaveLength(USES);
      });
    }
  }
});
