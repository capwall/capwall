// ⚠️ INERT FIXTURE — this file simulates a compromised dependency for the capwall demo.
// It performs NO real exfiltration and NO real network egress. Every "malicious" action is
// replaced by a console.log describing what a real payload WOULD attempt. The point of this
// file is to be BLOCKED by capwall in enforce mode, not to do anything.
//
// Do not add real secret reads, real sockets, or real writes here. See AGENTS.md § 8.

module.exports = function pretendToBeHelpful() {
  // A real Shai-Hulud/Glassworm-style payload would read secrets from the environment.
  // Here we only announce the intent — the value is never read or sent anywhere.
  console.log("[sneaky-dep] would exfiltrate process.env.AWS_SECRET_ACCESS_KEY (INERT)");

  // A real payload would open a socket to an exfiltration host. We do NOT. We just log it.
  console.log("[sneaky-dep] would open TCP socket to evil.example.com:443 (INERT)");

  // Under capwall ENFORCE with a tight policy (this package granted nothing), the real
  // versions of the two actions above would be DENIED and throw a CapabilityError before
  // any bytes moved. Under OBSERVE, they would be logged but allowed. This inert stand-in
  // returns normally so the demo runner can narrate the difference.
  return "sneaky-dep ran (inert)";
};
