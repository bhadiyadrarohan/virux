# Virux REQUIREMENTS (living document)

Last updated: 2026-10-08 (M0). Status tags: [M#] milestone, [BLOCKED] waiting
on external approval, [DEFERRED] future phase, [RISK] known feasibility risk.

## 1. Product goal

Protect the entire MacBook and its local/external assets. Personal,
non-commercial. Benchmark capability and usability goals against professional
EDR (e.g. CrowdStrike Falcon Pro), especially strong process evidence and low
resource consumption. Never claim parity without independent evidence.

## 2. Target environment (measured, see M0_FEASIBILITY)

- Apple M1 Pro, 8 performance + 2 efficiency cores, 16 GB unified RAM.
- macOS 27.0 (build 26A428).
- Xcode 27.0, Swift 6.4, Python 3.12 (system).
- Frequent concurrent Xcode, Hermes, Codex workloads.

## 3. Operating principles (non-negotiable)

- R1 Lightweight background agent. Targets (not guarantees): <1% CPU idle,
  <2% CPU routine monitoring, 100-150 MB typical memory, ~200 MB aspirational
  ceiling. Measure real workloads and revise transparently. No continuous LLM
  calls, no continuous heavy UI rendering.
- R2 Event-driven detection, compact local telemetry, searchable history.
  Initial 90-day retention goal, subject to measured disk usage,
  user-adjustable.
- R3 Security-critical detection and containment take priority over deferred
  low-risk analysis. Under pressure, defer low-priority sandbox work and
  throttle background work. Never silently disable critical protection.
- R4 Start protection early in supported startup, independently of the
  dashboard. Do not promise monitoring before macOS permits the extension or
  daemon to run. Document coverage gaps.
- R5 Menu-bar icon: letter V (graphic to be supplied) plus green/yellow/red
  status dot. Click opens dashboard. Protection continues when UI closes.
- R6 Minimalist, graphics-rich dashboard. Process trees, file/network graphs,
  and investigation views render only when an incident is opened.
- R7 No automatic permanent deletion. Delete and restore require user
  approval. Critical containment may be automatic. Admin authentication
  required to pause/disable protection. Keep a documented safe
  recovery/uninstall path.
- R8 Privacy by default. Local analysis and local file hashes. No automatic
  upload of personal files or full samples to outside services.
- R9 Distinguish confidence from severity. Preserve explainable evidence.
  A negative sandbox result is not proof of safety.
- R10 Build an accurate, measurable product, not a visually impressive
  prototype with ineffective defenses.

## 4. Components

- A. Swift endpoint sensor / system extension + privileged service [M2] [BLOCKED: ES entitlement]
- B. Detection and correlation engine (hashing, reputation cache, signatures,
  rules, behavior, risk scoring, dedup, allowlists, evidence) [M3]
- C. Python analysis worker (isolated, on-demand, over authenticated
  least-privilege IPC) [M1]
- D. Sandbox coordinator (disposable macOS VM via Virtualization.framework)
  [M4] [RISK: disk + RAM]
- E. Response / quarantine (restrict, terminate, isolate, block network) [M5]
- F. Forensic store and dashboard [M6]

## 5. Detection pipeline

Observe -> local hash -> local signature/reputation cache -> optional
VirusTotal hash-only enrichment (only if current API terms permit; never
upload content without explicit permission; rate-limit, cache, offline-safe,
non-blocking) -> behavioral rules -> correlate severity+confidence ->
route by severity/confidence -> contain or quarantine with full report ->
allow/restore decisions evidence-based and reversible.

## 6. Severity and response

- LOW: record, monitor, no disruptive action.
- MEDIUM: queue sandbox when feasible, proportionate temporary restriction
  only if justified, reassess.
- HIGH: automatic quarantine/containment, report, notify.
- CRITICAL: active ransomware/destructive behavior. Immediate supported
  containment (terminate / block network), preserve evidence, urgent notify.
  No auto-delete.
- Severity (impact) is distinct from confidence (certainty of detection).

## 7. Resource-aware sandbox policy

- Local sandbox mandatory in first functional release. Dedicated Mac mini lab
  [DEFERRED].
- Initial VM experiment: 2 vCPU, ~3 GB guest RAM, one run at a time,
  60-120 s default window (provisional; benchmark and revise).
- Require at least 4 GB free host RAM before normal launch. Measure actual
  macOS memory pressure. Never force launch if it risks host stability.
- Pressure policy: defer low-risk; for medium risk attempt promptly, and if
  the VM cannot start, prefer temporary execution restriction for unfamiliar
  untrusted apps where technically supported (bounded timeout, clear
  notification, admin override). Do not blindly allow execution because RAM
  is scarce. For high/critical, contain immediately and defer VM analysis.
- Quarantine and sandbox are separate. Quarantine prevents host execution;
  sandbox runs a COPY in isolation. Never auto-release a quarantined item
  because sandbox findings are negative.
- Default no direct internet. Disposable guests reset between samples.

## 8. Ransomware and external drives

- Watch rapid encryption/rename, abnormal writes, destructive ops,
  backup/snapshot tampering.
- Protect newly connected USB drives with lightweight on-connect checks and
  event-driven prioritization. No heavy full-volume scan by default.
- Record potentially affected files; reconstruct history from telemetry.
- Future recovery workflow: contain -> scope -> locate verified clean backup
  -> propose restore -> restore on approval -> validate. No backup exists
  today. Do not promise rollback or guaranteed APFS snapshot recovery.

## 9. Dashboard and reporting

- Main: protection state, last detection/signature update, active incidents,
  quarantined count, recent detections, sandbox queue, resource usage.
- Incident: reason, severity, confidence, evidence, process tree, file/network
  graph, timeline, sandbox findings, impacted assets, residual risk,
  recommended actions.
- Quarantine center: full history, search/filter, hash/signature, detection
  time, status, report, admin-authenticated restore/delete.
- Startup monitoring: track launch agents, launch daemons, login items,
  other persistence. Alert only when security-relevant; avoid duplicate macOS
  notifications.

## 10. Signatures and updates

- Own compact local signature/behavior pipeline. No dependence on a
  heavyweight always-on third-party AV.
- Optionally consume trustworthy open formats after verifying licensing.
  External open-source may be selectively reused, not required as a
  heavyweight agent.
- Signed verifiable differential updates proposed every 6 hours; urgent
  updates; rollback; last-known-good; update-failure alerts. Validate the
  security and operational feasibility of this cadence. [RISK: cadence]
- Reputation cache avoids repeat queries for unchanged files; re-evaluate on
  change or new suspicious behavior.

## 11. Security, privilege, failure safety

- Least privilege, secure IPC, code signing, notarization where relevant,
  hardened runtime, restricted storage permissions, authenticated admin
  overrides.
- Resist unauthorized disabling/tampering, but keep an explicit auditable
  admin pause, recovery, and uninstall path.
- Do not disable SIP, Gatekeeper, XProtect, or other native safeguards.
- Handle extension crash, event backpressure, full disk, VM failure, offline
  operation visibly. Never misrepresent an unhealthy agent as protected.
- Audit all enforcement and user actions. Safe defaults. Prevent accidental
  mass quarantine.

## 12. Out of scope now

NAS/Time Machine backup integration, dedicated Mac mini malware lab,
optional cloud intelligence, commercial deployment, Windows/Linux ports.
