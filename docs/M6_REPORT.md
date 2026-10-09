# M6 Report - Forensics and UI

Date: 2026-10-08. Status: **complete** for the no-entitlement scope.

## What was built

New `ViruxForensics` module:

- **Searchable history** (`EventStore.searchEvents` / `searchDetections`, with
  `EventQuery` / `DetectionQuery`): filter by time range, kind, minimum
  severity, file hash, path substring, executable substring, source, and event
  ids; detections by severity, status, title, and linked evidence id.
- **Process tree reconstruction** (`ProcessTreeBuilder`): rebuilds parent/child
  links from pid/ppid in telemetry, with a cycle guard, plus
  `ancestry(of:)` for a single pid and an ASCII renderer.
- **Incident reports** (`ReportBuilder`): assembles a plain-English, evidence
  backed markdown report: why it was flagged, the process chain, the process
  tree, the evidence table, potentially impacted files, hashes, containment
  state, recommended next actions, and residual risk.
- **Relationship graph** (`GraphRenderer.processTreeSVG`): a standalone SVG of
  the process tree, with unsigned processes outlined in amber and XML-escaped
  labels.
- **Startup / persistence monitoring** (`PersistenceMonitor`): scans Launch
  Agents, Launch Daemons and Startup Items, parses each plist (Label,
  ProgramArguments, RunAtLoad), hashes the file, flags entries that reference
  writable locations or invoke network/shell tools, diffs snapshots, and emits
  alerts **only** for security-relevant changes, **deduplicated** so the user is
  not spammed.

CLI: `virux find`, `virux report`, `virux tree`, `virux persistence` (plus the
existing `status`, `tail`, `detections`, `analyze`, `quarantine*`, `audit`, `hash`, `stats`).

Dashboard (`ViruxMenuBar`): now a real tabbed UI reading the store -
**Overview** (health, counts, host resources, sandbox gate, persistence scan),
**Detections** (colour-coded list; click a row for the full incident report),
**Quarantine** (records with status, hash, reason), **Timeline** (recent
events, unsigned executions highlighted).

## Verified results (this machine, 2026-10-08)

- Unit tests: SearchTests, ProcessTreeTests, ReportTests, GraphTests,
  PersistenceTests all pass (65 test cases total across the project).
- `virux find --path LaunchDaemons` -> returns the persistence event.
- `virux report 3` -> complete report: process chain
  `Safari -> bash -> /tmp/evil (UNSIGNED)`, process tree, evidence table,
  impacted file, recommendations.
- `virux tree --since 48h` -> renders the tree; `--pid 200` resolves ancestry
  to pid 100.
- `virux persistence` -> scans 30 autostart entries on this real machine.
- Dashboard launches headless with the V icon (`logoLoaded=true`).
- `scripts/verify-m6.sh`: **12 passed, 0 failed**.

## Bugs found and fixed during M6

1. **Process tree refused to link to launchd.** The builder treated `ppid == 1`
   as a root boundary, so every process launched by launchd became a spurious
   root and the tree fragmented. Now it links to any parent present in the
   telemetry (including pid 1).
2. **Report focused on the wrong process.** It used the first evidence event;
   it now focuses on the highest-severity (then most recent) evidence event, so
   the chain shows the interesting child, not the benign parent.
3. **Public API gaps**: the persistence value types needed public initialisers.

## Limitations (honest)

- The dashboard runs as a bare SwiftPM executable; a proper `.app` bundle
  (LSUIElement, Info.plist, notarization) is the M8 packaging step. It is not a
  distributable app yet.
- The SVG graph renderer is implemented and unit-tested but is not yet surfaced
  in the dashboard (it is written to be embedded next).
- Persistence "suspicious" detection is a heuristic over plist arguments
  (`/tmp`, `Downloads`, `curl`, `osascript`, `base64`, `bash -c`); it does not
  yet verify code signing of the referenced binary.
- Process trees are only as complete as the retained telemetry; a parent's exec
  can fall outside the retention window.
- No alert delivery to macOS Notification Center yet (alerts are computed and
  shown in the UI/CLI; wiring them to a notification is a small follow-up).

## Next

- M7: ransomware and external-drive coverage (safe simulated behaviours only).
- Deferred with external dependencies: ES AUTH blocking (Apple entitlement),
  network containment (Network Extension), real sandbox guest (disk).