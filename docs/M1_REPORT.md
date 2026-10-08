# M1 Report - Foundation

Date: 2026-10-08. Status: **complete**. Telemetry capture only; no detection,
no response, no privileged component. All checks run with harmless data.

## What was built

Swift Package Manager workspace at `~/Projects/Virux`:

- `ViruxCore` - models (SecurityEvent, ProcessRef, Severity, Confidence,
  Detection), SHA-256 hashing (streaming), SQLite event store (WAL, indexed,
  purge/retention), retention policy.
- `ViruxIPC` - length-prefixed framing, worker request/response messages,
  peer-credentials struct, health record (shared by daemon, CLI, UI).
- `ViruxSensor` - `EventSource` protocol plus three sources: `EsloggerAdapter`
  (Apple's pre-entitled ES CLI, the M1 bridge), `ReplayAdapter` (JSONL fixture
  replay), `SynthAdapter` (synthetic, for tests/benchmarks), and a defensive
  `EsloggerParser`.
- `viruxd` - background agent skeleton (run manually, NOT installed as a
  launchd daemon yet). Consumes a source, writes to the store, publishes a
  health record, applies retention.
- `virux` - CLI: `status`, `tail`, `stats`, `hash`.
- `ViruxMenuBar` - AppKit + SwiftUI menu-bar placeholder: "V" with a
  green/yellow/red dot; click opens a dashboard shell that reads the store.
- `worker/virux_worker.py` - Python analysis worker skeleton over a
  peer-credential-checked Unix socket (`getpeereid`). Honest "inconclusive"
  verdict placeholder.
- `tests/fixtures/sample-eslogger.jsonl` - safe replay fixture.
- `scripts/verify-m1.sh` - full end-to-end verification.
- `scripts/bench.sh` - CPU/RAM benchmark.

## How to build and run

```
cd ~/Projects/Virux
swift build
swift test
bash scripts/verify-m1.sh

# agent on synthetic data (no privileges)
.build/debug/viruxd --source synth --seconds 10
# CLI
.build/debug/virux status
.build/debug/virux tail -n 20
# menu bar (dev; not a bundled app yet)
.build/debug/ViruxMenuBar

# real Endpoint Security telemetry (requires root + Full Disk Access)
sudo .build/debug/viruxd --source eslogger --events exec,open,close
```

## Test results (this machine, 2026-10-08)

- `swift build`: clean, no warnings.
- Unit tests: **12 passing** (ViruxCoreTests 7: hashing vectors, store
  insert/query/ordering/purge, retention; ViruxSensorTests 5: eslogger parse
  exec/open/unknown/malformed, synth emission).
- Integration (`verify-m1.sh`): **7 passed, 0 failed**. Includes fixture replay
  storing exactly 6 rows and 2 exec events, CLI status/hash, worker self-test
  and IPC ping round-trip, headless menu-bar launch.

## Measured resources (synthetic source, ~2 events/s)

- Average routine CPU: **0.78%**
- Peak resident memory: **8 MB**
- 21 events stored over 10 s; store size measured in KB.

These meet the M1 targets (<2% routine CPU, 100-150 MB typical). They are NOT
representative of real Endpoint Security load; re-measure at M2.

## Limitations (honest)

- No real sensor yet: it needs the Endpoint Security entitlement (Apple).
  The eslogger bridge is a prototype, not a product sensor.
- `viruxd` is not a launchd daemon and has no privileged surface. Not installed.
- The menu-bar app is a bare SwiftPM executable, not a bundled/notarized app
  (needs an Info.plist with LSUIElement and a project; M6 packaging).
- Detection, correlation, quarantine, and sandbox are not implemented.
- The Python worker returns an explicit "inconclusive" verdict by design; it
  performs no real analysis yet.
- Retention enforcement is a 5-minute timer with a 90-day default; not yet
  validated against real disk growth.

## Next milestone

M2 (endpoint telemetry) is gated on the ES entitlement. In the meantime, M3
detection scaffolding can begin against the eslogger bridge and the replay
fixture. See `docs/APPLE_ES_REQUEST.md` for the critical-path action.