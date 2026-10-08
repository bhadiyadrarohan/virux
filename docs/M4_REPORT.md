# M4 Report - Sandbox (static-first, disk-gated VM)

Date: 2026-10-08. Status: **partial** - the orchestration, resource gate, and
static analysis are complete and tested; real guest detonation is **not**
implemented and is blocked on disk. This report states exactly what runs.

## What was built

New `ViruxSandbox` module:

- **`MachOAnalyzer`** - static, no-execution inspection of a candidate file:
  Mach-O detection (thin + fat/universal, both endiannesses), architecture,
  file type, `LC_CODE_SIGNATURE` presence, encryption load command, linked
  dylibs, embedded-string scan for high-signal tokens, and Shannon entropy.
  Produces a verdict of clean / inconclusive / suspicious with explicit reasons.
  A clean static verdict is NOT proof of safety.
- **`ResourceGate` + `SystemResourceProbe`** - refuses to start a VM unless the
  host has enough free RAM (default 4 GB), enough free disk (default 8 GB), and
  fewer than the max concurrent runs (default 1). Never force-launches.
- **`SandboxBackend` protocol** with:
  - `VirtualizationBackend` - the real Apple Virtualization.framework backend.
    It is a **stub**: it reports "no guest provisioned" honestly rather than
    pretending to analyse. Provisioning needs a guest image and disk headroom
    this Mac does not have.
  - `MockSandboxBackend` - a **test double only**, clearly labelled, never used
    in production.
- **`SandboxCoordinator`** - static-first orchestration: always runs static
  analysis; escalates to the VM only when the static verdict is not clean AND
  the resource gate allows; one run at a time; resets the guest between runs.
- **`virux analyze FILE`** CLI command - prints static findings, the host
  resource snapshot, and the gate decision.

## How to run

```
cd ~/Projects/Virux
swift build
virux analyze /bin/ls
virux analyze /path/to/suspicious-binary
bash scripts/verify-m4.sh
```

## Test results (this machine, 2026-10-08)

- `swift build`: clean.
- Unit tests: all suites pass (Core, Sensor, Detect, Sandbox).
- Real binary: `/bin/ls` -> Mach-O **fat/universal**, archs `x86_64, arm64`
  (deduped), `MH_EXECUTE`, **signed**, entropy 2.87, verdict **clean**.
- Suspicious fixture (unsigned Mach-O with `/bin/sh`):
  verdict **suspicious**, reasons: no code signature, suspicious strings.
- Non-Mach-O text file: verdict **inconclusive** ("not a Mach-O binary").
- Gate: with ~2.6 GB free memory the coordinator **defers** the VM run
  ("free memory 2.60 GB < 4.00 GB required") instead of launching.

## Bugs found and fixed during M4 (the tests earned their keep)

1. **Fat/universal binaries are big-endian.** I first read the fat header
   little-endian and missed `/bin/ls` entirely. Fixed with a big-endian reader
   and both `FAT_MAGIC` (32-bit) and `FAT_MAGIC_64` (64-bit) handling.
2. **String scanner never flushed a run that ended at EOF** (the whole point
   when a sample's interesting string is the last thing in the file).
3. **False positive: bare `http://` / `https://`.** Present in nearly every
   binary; removed from the pattern set in favour of high-signal tokens.
4. **Duplicate architectures and dylibs** across fat slices; now deduped.

## What is NOT done (honest)

- No macOS guest is provisioned and **no sample has been executed anywhere**.
  `VirtualizationBackend.prepare()` fails with "no guest provisioned".
- No guest agent, no virtio-socket command channel, no VirtioFS sample
  injection, no snapshot/reset implementation.
- No evidence capture from a real guest (the coordinator's evidence shape
  exists and is exercised by the mock, but is not fed by a real VM).
- No safe test corpus beyond the fixtures used in tests.

## Blockers

- **Disk: ~63 GB free.** A macOS guest base image plus clones wants more than
  that comfortably (see `M4_SANDBOX_OPTIONS.md`).
- **RAM: only ~2.6 GB free** on this machine at test time, well below the 4 GB
  gate, so the gate correctly defers in practice today. This is the gate
  working, not a bug.

## Next

- M5 (response/quarantine) needs no VM and is not gated on disk.
- M4's real backend can be completed once a guest image fits (free space or an
  external SSD), reusing the coordinator, gate, and evidence types as-is.