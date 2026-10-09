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

## M4 - Automated sandbox (PARTIAL, 2026-10-08; guest gated on disk)
Delivered and tested: `ViruxSandbox` module - `MachOAnalyzer` static inspection
(thin + fat Mach-O, signing, encryption, dylibs, strings, entropy),
`ResourceGate` + `SystemResourceProbe` (RAM/disk/concurrency gating),
`SandboxCoordinator` (static-first, reset between runs), `SandboxBackend`
protocol with an honest `VirtualizationBackend` stub and a test-only mock, and
`virux analyze FILE`. 42 tests pass. See `M4_REPORT.md`.
NOT done: no guest provisioned, no sample executed anywhere, no guest agent or
virtio-socket channel, no real evidence capture. `VirtualizationBackend`
reports "no guest provisioned" rather than faking analysis.
Exit tests: isolation and reset verified against the mock; resource gates
verified (real host defers: ~2.6 GB free < 4 GB). Real-guest isolation and
sandbox peak memory remain unmeasured.
Blockers: disk (~63 GB free) and RAM (~2.6 GB free) - see `M4_SANDBOX_OPTIONS.md`.

## M5 - Response (PARTIAL, 2026-10-08; no-entitlement subset done)
Delivered and tested: `ViruxRespond` module - `QuarantineStore` (move + clear
exec bits + metadata + sidecar), `AuditLog`, `AdminGate` (Authorization
Services, fails closed), `ProcessTerminator`, `ResponseEngine` (severity to
action, system/trusted allowlist, anti-mass rate limit). Store `quarantine` +
`audit` tables. CLI: `quarantine`, `quarantine-add`, `quarantine-restore`,
`quarantine-delete`, `audit`. See `M5_REPORT.md`.
DEFERRED: ES AUTH execution denial (Apple entitlement); network containment
(Network Extension content filter, separate self-service entitlement).
DEFERRED to hardening: root-privileged termination of other users' processes.
Exit tests: quarantine/restore/delete semantics, exec-bit stripping, admin gating,
allowlist, rate limit, real process termination. PASSED.
Remaining: real-ES containment validation once the entitlement is granted.

## M6 - Forensics and UI (DONE 2026-10-08)
Delivered and tested: `ViruxForensics` module - searchable history
(`EventQuery`/`DetectionQuery`), process-tree reconstruction + ancestry, ASCII
tree renderer, SVG relationship graph, incident report builder (markdown with
evidence/chain/tree/containment/recommendations/residual risk), and autostart
persistence monitoring with security-relevant, deduplicated alerts. CLI:
`find`, `report`, `tree`, `persistence`. Dashboard rewritten as a tabbed UI
(Overview / Detections with report view / Quarantine / Timeline). 65 tests
pass; `verify-m6.sh` 12/12. See `M6_REPORT.md`.
NOT done: `.app` bundle/notarization (M8); SVG graph not yet embedded in the UI;
persistence heuristics do not verify signer of the referenced binary; no
Notification Center delivery yet.
Exit tests: investigation flow on fixture data, search filters, report content,
tree/ancestry, persistence scan on the real machine. PASSED.

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
