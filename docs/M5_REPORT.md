# M5 Report - Response and Quarantine (no-entitlement subset)

Date: 2026-10-08. Status: **complete for the subset that does not need the
Endpoint Security entitlement.** Two capabilities remain deferred and are named
below.

## What was built

New `ViruxRespond` module:

- **`QuarantineStore`** - moves a file into a protected directory (mode 0700),
  **clears its execute bits** so it can no longer be launched from its original
  path, records metadata (original path, SHA-256, size, original POSIX perms,
  reason, detection id, signing identity), and writes a sidecar JSON so the
  record survives DB loss. Nothing is ever deleted automatically.
- **`AuditLog`** - append-only trail of every action and refusal (`quarantine`,
  `restore`, `delete`, `terminate`, `refuse-allowlisted`, `refuse-rate-limit`,
  `authorize-denied`, `observe`).
- **`AdminGate`** - `SecurityAdminGate` uses Authorization Services (the macOS
  administrator prompt) and **fails closed**; `MockAdminGate` is a test double.
  Restore and delete both require it.
- **`ProcessTerminator`** - SIGTERM then SIGKILL, refusing pid <= 1.
- **`ResponseEngine`** - maps severity to action and applies safety rails:
  system-path + trusted-team allowlist, and an anti-mass-quarantine rate limit.
- Store: new `quarantine` and `audit` tables.
- CLI: `virux quarantine`, `quarantine-add`, `quarantine-restore`,
  `quarantine-delete`, `audit`.

## Severity to action

| Severity | Action |
|---|---|
| none / low | log only |
| medium | log only (observe) |
| high | quarantine |
| critical | quarantine + terminate the process |

Everything is allowlisted against system paths and trusted signers, rate
limited, and audited. Confidence is tracked separately and does not by itself
trigger containment.

## Test results (this machine, 2026-10-08)

- Unit: `QuarantineTests` (moves file, strips exec bit, sidecar written,
  restore requires admin and returns the file verbatim with original perms,
  delete requires admin, cannot restore twice, missing file throws),
  `ResponseEngineTests` (severity mapping, high -> quarantine,
  critical -> quarantine + terminate, system path skipped, trusted team
  skipped, anti-mass rate limit), `TerminatorTests` (terminates a real
  `/bin/sleep`, refuses pid 1 and 0).
- End to end (`scripts/verify-m5.sh`, benign fixture only): quarantine moves
  the file, original path gone, exec bits cleared, sidecar present, CLI list
  and audit show the action.

## Honest limitations

- **Execution denial is deferred.** There is no inline kernel block; quarantine
  prevents future execution by relocating the file and removing its execute
  bits. The real "deny the next launch" path needs ES AUTH events and the
  Apple entitlement.
- **Network containment is deferred.** ES is not a firewall; real network
  blocking needs a Network Extension content filter (separate, self-service
  entitlement). Not built in M5.
- **Termination privileges.** Terminating your own processes works today.
  Reliably killing another user's process needs the daemon running as root,
  which arrives with the privileged-helper work at M5 hardening.
- **`SecurityAdminGate`** presents the OS admin prompt; in a non-GUI context it
  fails closed (denies). Verified behaviourally in tests via the mock gate.
- Quarantine of a *running* binary relocates the file but does not stop the
  already-running process; pair with termination for active threats.

## Next

- M6 (forensics + UI): searchable history, incident reports, process trees,
  quarantine center in the dashboard.
- Deferred with external dependencies: ES AUTH blocking (Apple entitlement),
  network containment (Network Extension).