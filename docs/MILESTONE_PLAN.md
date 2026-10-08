# Virux Milestone Plan

Build and verify one milestone at a time. A milestone is complete only when
its tests pass and its limitations are documented. Milestones marked GATED
cannot be promised until the named blocker clears.

## M0 - Discovery and feasibility (DONE 2026-10-08)
Deliverables: machine audit, component feasibility verdicts, entitlement
matrix, blockers/risks, architecture, threat model, milestone plan, living
REQUIREMENTS.md and DECISIONS.md. No privileged action taken.
Gate to leave M0: user confirms project location and approves the M1 start,
and the ES entitlement request is filed.

## M1 - Foundation (DONE 2026-10-08)
Delivered: Swift package (ViruxCore, ViruxIPC, ViruxSensor), `viruxd` agent
skeleton, `virux` CLI, `ViruxMenuBar` shell, Python worker over a
peer-checked Unix socket, SQLite store with retention, eslogger/replay/synth
sources, 12 unit tests + 7 integration checks, benchmark harness. Measured
0.78% routine CPU and 8 MB RSS on the synthetic source. See `M1_REPORT.md`.
Limitations: no real sensor (ES entitlement pending), daemon not installed,
menu-bar app not bundled, no detection/response.
Exit tests: build clean; daemon starts and writes events; UI shows live
counts; idle CPU/RAM measured and reported. PASSED.

## M2 - Endpoint telemetry (GATED on ES entitlement)
- Native ES client: exec/fork/exit, file open/close, code-signing identity,
  mount, persistence changes, network metadata where exposed.
- Efficient filters, bounded queues, backpressure metrics, accurate health.
- Replace the eslogger bridge with the real sensor behind the same interface.
Exit tests: coverage vs eslogger; overhead measured; backpressure handled;
unhealthy states surfaced correctly.

## M3 - Detection (starts in parallel with M2 where possible)
- SHA-256 hashing + reputation cache.
- Local signatures + configurable rules + behavioral sequences.
- Severity/confidence model; explainable evidence records.
- Observe-only false-positive baseline on this machine.
- Optional VirusTotal hash-only enrichment, gated on a documented terms check.
Exit tests: detections on safe fixtures; FP baseline recorded; explainability
review.

## M4 - Automated sandbox (GATED on disk + RAM)
- Disposable macOS guest, one run at a time, 2 vCPU / ~3 GB (benchmark, revise).
- Queued sample analysis, evidence capture, reset between samples.
- Strict resource gating; never force-launch under pressure; failure handling.
- Safe test corpus only (EICAR + benign simulators). Never live malware on host.
Exit tests: isolation verified (no host effects); reset verified; resource
gates verified; sandbox peak memory measured.

## M5 - Response (GATED on ES for AUTH-based denial)
- Quarantine with metadata + audit trail; admin-gated restore/delete.
- High/critical containment (terminate, isolate).
- Network containment via Network Extension content filter.
- Safe system-process exclusions; audit logs; anti-mass-quarantine guard.
Exit tests: system processes unaffected; quarantine reversible; every action
audited.

## M6 - Forensics and UI
- Searchable history, incident reports, process trees, relationship graphs,
  quarantine center, startup/persistence alerts without duplicate noise.
Exit tests: investigation flow on a seeded incident; UI responsiveness under
load.

## M7 - Ransomware and external-drive coverage
- Safe simulated ransomware behaviors on benign test data.
- External-drive on-connect lightweight checks + event-driven prioritization.
Exit tests: containment on simulation; no heavy full-volume scan; drive
monitoring accuracy.

## M8 - Hardening and performance
- Fault injection (crash, full disk, VM failure, offline).
- Security tests (tamper resistance, IPC validation, update signing).
- Detection accuracy + FP review; CPU/RAM/energy/disk measurements; startup
  latency; release packaging + notarization.
Exit tests: all budgets met or transparently revised; release artifact signed
and notarized.

## Continuous acceptance tests (every milestone)
Idle/routine CPU, agent resident memory, sandbox peak memory, battery/energy,
disk growth, detection latency, UI responsiveness, boot/login startup
coverage, false-positive rate, precision/recall on safe curated cases,
quarantine correctness, failure recovery, absence of host effects from
sandbox tests. Harmless fixtures only (EICAR, benign simulators).

## Future (not now)
NAS/Time Machine backup + recovery integration, dedicated Mac mini malware
lab, optional cloud intelligence, commercial deployment, Windows/Linux ports.
