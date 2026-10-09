# Virux

Local-first Endpoint Detection and Response (EDR) for macOS.
Personal, non-commercial project. Working name: Virux.

Virux protects the whole MacBook and its local/external assets. It runs
independently of Hermes. Hermes is the development assistant, not a runtime
dependency.

## Status

Milestone status: **M0, M1, M3, M6, M7 complete**; **M5 complete within its
no-Apple-entitlement scope**; **M4 partial** (static analysis works, guest
detonation is disk-gated); **M2 blocked** on Apple's Endpoint Security
entitlement (request submitted, under review).

79 automated tests pass. No privileged component has been installed, and no
malware is used anywhere: every test runs on benign fixtures in a temp
directory. See `docs/M7_REPORT.md` for the current milestone.

## Read this first

- `docs/M0_FEASIBILITY.md` - what this machine can and cannot do, hard blockers.
- `docs/ENTITLEMENTS.md` - the exact Apple approvals and entitlements required.
- `docs/ARCHITECTURE.md` - component design and data flow.
- `docs/THREAT_MODEL.md` - assets, adversaries, mitigations.
- `docs/MILESTONE_PLAN.md` - M0 to M8 with acceptance tests.
- `REQUIREMENTS.md` - living requirements.
- `DECISIONS.md` - living decision log.

## Non-negotiable principles (summary)

Lightweight agent, event-driven local telemetry, no automatic permanent
deletion, admin authentication to pause/disable, privacy by default (local
hashing, no automatic upload of personal files), honest health reporting,
never misrepresent an unhealthy agent as protected. Full text in
`REQUIREMENTS.md`.

## Truthfulness rule

Virux reports what actually runs and what actually fails. It never claims
parity with CrowdStrike Falcon Pro, and never presents simulated detections
as real protection.
