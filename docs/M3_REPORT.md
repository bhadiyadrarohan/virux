# M3 Report - Detection Engine (observe-only)

Date: 2026-10-08. Status: **complete** for the observe-only scope. Nothing is
enforced; findings are recorded with evidence.

## What was built

New `ViruxDetect` module:

- **`RuleEngine`** - deterministic behavioural rules, each returning severity
  (impact) and confidence (certainty) separately:
  - R-001 unsigned executable launched from a non-system path (low/low)
  - R-002 unsigned executable from `/tmp`, `/var/tmp`, or `Downloads` (medium/medium)
  - R-003 a host app (browser, document viewer) spawned a shell (medium/medium)
  - R-004 write/rename into an autostart location (medium/medium)
  - R-005 mass rename burst, ransomware-like churn (critical/medium)
  - Per-rule cooldown (default 30 s) deduplicates repeat fires.
- **`SignatureBundle` / `SignatureSigner`** - versioned signature payloads
  signed with Ed25519 (CryptoKit). Verify-before-apply; tampered or wrongly
  signed bundles are rejected.
- **`DetectionPipeline`** - hashes executed images (bounded, cached), checks the
  local signature and reputation cache, runs the rules, and persists an
  explainable `Detection` with evidence event ids.
- Store: new `detections` and `reputation_cache` tables.
- CLI: `virux detections`, and detection counts in `virux status`.
- Daemon: `viruxd` now runs the pipeline in observe-only mode (`--detect` on by
  default, `--no-detect` to disable).

## How to run

```
cd ~/Projects/Virux
swift build
.build/debug/viruxd --db /tmp/virux.db \
  --source replay:tests/fixtures/detection-scenario.jsonl --seconds 3
.build/debug/virux detections --db /tmp/virux.db
bash scripts/verify-m3.sh
```

## Test results

- Unit tests: SignatureTests 4, RuleEngineTests 7, PipelineTests 3 (all pass).
- Scenario fixture (29 events): exactly 4 detections, deduplicated -
  1 critical (mass rename), 3 medium (host-app shell, unsigned from temp,
  persistence write).

## Limitations (honest)

- Observe-only: no quarantine, no termination, no blocking.
- The rule set is a first pass; the false-positive baseline on real traffic has
  not been measured yet (that needs the ES sensor or the eslogger bridge on live
  events).
- Hashing is limited to executed images and capped (256 MB) for cost.
- The 90-day retention default is not yet validated against real disk growth.
- No VirusTotal or other enrichment (gated on a documented terms check, D010).