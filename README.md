# Virux

Local-first Endpoint Detection and Response (EDR) for macOS.
Personal, non-commercial project. Working name: Virux (V-I-R-U-X).

Virux protects the whole MacBook and its local/external assets. It runs
independently of Hermes. Hermes is the development assistant, not a runtime
dependency.

## Status

Milestone: **M0 complete (discovery and feasibility)**.
No protection is active. No privileged component, sensor, or response
capability has been installed or run. Everything below is a plan plus a
read-only audit of this machine.

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
