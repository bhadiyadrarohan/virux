# Virux Threat Model

Scope: the whole MacBook and its local/external assets, plus Virux itself as
a security control that must not become a liability. Method: asset/ adversary
/ threat / mitigation, with severity and confidence kept distinct.

## Assets

- Host OS integrity and system processes.
- User data: personal files, photos, documents, credentials, Keychain.
- External drives when connected.
- Virux itself: sensor, daemon, extension, quarantine store, telemetry store,
  signature update channel, admin controls.
- User trust: a false "protected" state is itself a harm.

## Adversaries and capabilities

- A1 Commodity macOS malware (info-stealers such as AMOS/Atomic Stealer,
  adware, persistence droppers). User-level, frequently unsigned or ad-hoc
  signed, script-driven.
- A2 Ransomware / destructive wiper. Aggressive, time-critical behavior.
- A3 Targeted human operator with root or admin. May attempt to disable Virux.
- A4 Supply-chain / update-channel attacker.
- A5 Accidental harm: legitimate software, dev tools, and system updates that
  resemble malicious behavior (the dominant practical risk is false positives).

## Threats, mitigations, residual risk

T1 **EDR tampering / self-protection bypass** (A3). An attacker tries to
  unload the extension, kill the daemon, or edit the store.
  Mitigations: code signing + hardened runtime, protected helper, TCC/approval
  gating, integrity checks on the store and binaries, audit of pause/disable.
  Residual: a root attacker can eventually win; Virux aims to make it loud and
  auditable, not impossible.

T2 **Event flood / backpressure causing silent gaps** (A1, A5). Dropped events
  while the UI shows "protected".
  Mitigations: bounded queues, backpressure metrics, explicit health state,
  "events not flowing" banner, coverage-gap documentation.
  Residual: some loss under extreme load; must be visible, never hidden.

T3 **Sandbox VM escape** (A2). Malware in the guest escapes to the host.
  Mitigations: Virtualization.framework hardware isolation, no home share, no
  clipboard/device passthrough, constrained networking, verified guest image,
  reset between samples, strict timeouts.
  Residual: non-zero; treated as residual risk and documented. Never run
  untrusted samples on the host to "test" the defense.

T4 **IPC spoofing / privilege escalation** (A3, A4). A rogue process talks to
  the daemon or impersonates the worker.
  Mitigations: XPC code-signing requirement + audit-token check; Unix socket
  peer-credential check; least-privilege daemon; narrow privileged surface.

T5 **Signature/update channel attack** (A4). Malicious or downgraded
  signatures pushed to Virux.
  Mitigations: Ed25519-signed bundles, verify-before-apply, rollback and
  last-known-good, update-failure alerts, no unsigned hot path.
  Residual: signing-key compromise; mitigate with key hygiene and offline key.

T6 **False positives breaking system processes** (A5). Virux quarantines or
  kills a legitimate component.
  Mitigations: observe-only first, measured FP baseline, allowlists scoped by
  signing identity/hash, staged enforcement, admin override, safe defaults,
  guard against accidental mass quarantine.
  Residual: irreducible; managed by staging and reversibility.

T7 **Resource-exhaustion DoS against the host** (A1, A5). Aggressive hashing or
  a runaway scan degrades the user's machine.
  Mitigations: CPU/RAM budgets, adaptive throttling, defer low-risk work under
  pressure, never disable critical protection silently.

T8 **Privacy leakage** (design risk). Personal files or full samples leave the
  machine.
  Mitigations: local-only analysis, hash-only optional enrichment with explicit
  permission and a terms check, no automatic upload, offline-safe.

T9 **Unhealthy agent misrepresented as protected** (product-integrity risk).
  Mitigations: explicit health reporting, last-event timestamps, offline and
  full-disk states surfaced, acceptance tests that assert health accuracy.

## Design consequences

- Enforcement is staged; observe-only is the default until a measured baseline
  exists (D006).
- Severity is kept separate from confidence; a clean sandbox run is not proof
  of safety.
- Every enforcement action is auditable; destructive and release actions need
  administrator authentication.
- Coverage gaps (startup timing, entitlements not yet granted, sandbox gating)
  are documented, not hidden.
