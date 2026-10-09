# M7 Report - Ransomware and external-drive coverage

Status: **complete** (2026-10-08).
Tests: **79 passing, 0 failures** (M7 added 14). Harness: `scripts/verify-m7.sh`, **22/22**.
No malware was used or needed. Every test runs on benign fixtures in a temp directory.

## Objective

Detect and validate containment of destructive (ransomware-like) behaviour, and
give newly connected external drives a light, bounded on-connect check rather
than a heavy full-volume scan.

## What was built

New module `ViruxCoverage` plus three new detection rules and four CLI commands.

| Piece | File | What it does |
|---|---|---|
| Canary files | `Sources/ViruxCoverage/Canary.swift` | Plants decoy files, hashes them, and reports intact / changed / missing. Persisted manifest. |
| Volume enumeration | `Sources/ViruxCoverage/Volumes.swift` | Lists mounted volumes via `FileManager` resource values (removable / internal / capacity). |
| On-connect scanner | `Sources/ViruxCoverage/Volumes.swift` | Bounded walk (depth 2, 4000 entries, 5 s) that flags Windows autorun, `.lnk`/`.url` shortcuts, root-level payloads, and hidden executables. |
| Volume watcher | `Sources/ViruxCoverage/Volumes.swift` | `diff(previous:current:)` yields added and removed volumes. |
| Impact summary | `Sources/ViruxCoverage/Impact.swift` | Groups affected files by directory and extension from telemetry. |
| Safe simulator | `Sources/ViruxCoverage/Simulator.swift` | Renames benign fixtures to `.locked` and overwrites them with random bytes, then runs the real rules and the real quarantine path. |
| Rules | `Sources/ViruxDetect/RuleEngine.swift` | R-006 backup/snapshot tampering, R-007 canary touched, R-008 mass modification burst. |
| CLI | `Sources/virux/main.swift` | `canary plant\|check\|list`, `volumes [PATH]`, `impact`, `sim-ransomware`. |
| Daemon wiring | `Sources/viruxd/main.swift` | Loads the canary manifest at start so R-007 fires on live telemetry. |

## Detection rules added

| Rule | Trigger | Severity | Confidence |
|---|---|---|---|
| R-006 | open/rename/unlink under a backup or snapshot marker (`Backups.backupdb`, `com.apple.TimeMachine`, `.sparsebundle`, `/.backup/`, `.bak`) | high | medium |
| R-007 | open/rename/unlink on a canary (decoy) file | critical | high |
| R-008 | 40+ distinct files touched (open/close/rename) inside a 10 s window | high | medium |

R-007 is the near-zero-false-positive anchor: nothing legitimate has a reason to
modify a decoy file, so a touch is treated as active destructive behaviour.

## Evidence from real runs

Safe simulation (60 benign fixtures, temp workspace only):

```
  fixtures:  60   simulated renames: 60
  detections:
    [critical] R-005 Mass file rename burst
    [high] R-008 Mass file modification burst
    [critical] R-007 Canary (decoy) file touched
  contained: canary quarantined -> .../quarantine/<uuid>-virux_canary_backup.dat (#1)
```

Canary lifecycle: `canary check` exits 0 when intact and exits 2 with `CHANGED`
after the file is overwritten, `MISSING` after deletion.

Live daemon path (real eslogger event shape, replay source): the daemon reports
`3 canary file(s) under watch` and records a `[critical/high] Canary (decoy)
file touched` detection.

Volumes on this machine: `/  [internal]  free 62.1 GB / 460.4 GB`.

On-connect scan of a prepared removable-style directory: flagged `autorun.inf`,
a root-level `setup.command`, and a hidden executable, within the entry budget.

## Bugs found and fixed during M7

1. **Canary matching was exact-string.** A path with a redundant slash (a very
   common telemetry variance) or the `/private` alias did not match. Fixed with
   cheap normalisation plus a `/private`-prefixed variant, precomputed once.
2. **Parser ignored a top-level file path.** Real eslogger nests the path
   (`event.rename.destination`); a producer emitting it at the top level was
   silently dropped. Added a defensive fallback.
3. Two harness bugs (a reversed helper and an option placed before the
   subcommand) - these were test-script defects, not product defects.

## Safety properties

- The simulator refuses any workspace outside the system temp directory. The
  guard is enforced in code and covered by a test.
- Benign fixtures and random bytes only; no live malware is used anywhere.
- Containment goes through the real quarantine engine, so the normal audit and
  authorisation path applies.

## Limitations (honest)

- Canary integrity checking is on demand (`virux canary check`) plus the
  event-driven R-007 path in the daemon. There is no scheduled integrity sweep.
- Canary matching is string-based. A symlinked or hardlinked alias pointing at a
  canary is not matched. Documented residual risk.
- R-006 is a path heuristic over backup markers, not a verified query of
  Time Machine or APFS snapshot state.
- R-008 cannot distinguish a read from a write: Endpoint Security event flags
  are required to know intent, and that needs the M2 entitlement.
- The on-connect scan is bounded by design (depth 2, 4000 entries, 5 s). It is
  not a full-volume scan and does not hash file contents.
- `VolumeWatcher.diff` is implemented and tested but not yet polled by a live
  daemon loop; wiring mount notifications is a small follow-up.
- There is still no recovery workflow. With no backup infrastructure on this
  machine, M7 can contain but cannot restore.

## Next

M8 - hardening and performance: fault injection, security tests, measured
budgets, packaging and notarisation.
