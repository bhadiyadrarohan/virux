# Virux DECISIONS (living decision log)

Format: ID | Date | Decision | Rationale | Status

## D001 | 2026-10-08 | Project root at ~/Projects/Virux
Keeps Virux alongside the user's other local projects and inside the normal
backup/working area. Not under any Hermes profile tree. Status: proposed,
awaiting user confirmation.

## D002 | 2026-10-08 | Swift-first, Python only for offline analysis/tests
Mandated by the build prompt and by Apple platform realities (ES, system
extensions, Virtualization are Swift/ObjC APIs). Python must never be a
privileged always-on bottleneck. Status: adopted.

## D003 | 2026-10-08 | Use Apple's eslogger as the M1 telemetry bridge
The Endpoint Security entitlement is a restricted entitlement that requires
Apple approval and will not be available immediately. eslogger ships with
macOS, is pre-entitled for ES, and emits JSON NOTIFY events. Using it lets the
detection/correlation engine (component B), store, and UI be built and proven
before the entitlement arrives. It is a prototype bridge, not a product
sensor. Status: adopted (subject to Full Disk Access for the responsible
process).

## D004 | 2026-10-08 | Sandbox = Virtualization.framework macOS guest (arm64)
Only supported lightweight-virtualisation path on Apple Silicon. macOS guests
are permitted for personal, non-commercial use, max two concurrent, enforced
by the framework. No host home-folder share, no clipboard/device passthrough,
no direct internet by default, snapshot/reset between samples. Status:
adopted pending disk/RAM resolution (see D005).

## D005 | 2026-10-08 | Sandbox is BLOCKED until disk and RAM are resolved
A macOS VM bundle needs roughly 40-80 GB; the Data volume has ~63 GB free.
Host swap is already near full under current workloads. M4 cannot be promised
until the user frees space or attaches an external SSD, and until memory
headroom is measured under realistic load. Status: open blocker.

## D006 | 2026-10-08 | Enforcement starts in observe-only mode
Per R7 and the staged-enforcement requirement, Virux will not enable automatic
quarantine until a measured false-positive baseline exists on this machine.
Status: adopted.

## D007 | 2026-10-08 | Network blocking via Network Extension, not ES
Endpoint Security is not a general network firewall. Network containment needs
a content-filter / filter-data-provider Network Extension, which carries its
own (self-service) entitlement and its own system extension. Status: adopted
for M5 design.

## D008 | 2026-10-08 | IPC = XPC where supported, else protected Unix socket
Swift sensor/daemon and the Python worker communicate over an authenticated,
least-privilege channel: XPC Mach service with code-signing + audit-token
validation for native clients, and a Unix-domain socket with peer-credential
checking for the Python worker. Status: adopted.

## D009 | 2026-10-08 | No auto-delete, no auto-restore of quarantined items
Aligns with R7. All destructive or release actions require
administrator-authenticated approval and are audited. Status: adopted.

## D010 | 2026-10-08 | Verify VirusTotal terms before any enrichment
Free quota does not equal authorisation for this use. Enrichment is optional,
hash-only, non-blocking, and gated on a documented terms check. Status: open,
to verify at M3.

## D011 | 2026-10-08 | M1 built as a plain SwiftPM package, not an Xcode project
Fastest path to compiling, testable code without privileged components. The
menu-bar app runs as a bare SwiftPM executable in M1; a bundled/notarized app
comes at M6 packaging. Status: adopted.

## D012 | 2026-10-08 | M1 telemetry transport is the eslogger bridge behind EventSource
The daemon consumes a single `EventSource`. eslogger, replay, and synth all
implement it, so swapping in a real ESSensor at M2 changes no other component.
Status: adopted (D003 follow-on).

## D013 | 2026-10-08 | Sandbox direction: static-first plus slim macOS guest with CoW clones
User chose a lighter sandbox. Mach-O detonation still requires a macOS guest,
so reduce cost instead of removing it: minimal base image, APFS copy-on-write
clones per run, static analysis before escalation. Details in
`docs/M4_SANDBOX_OPTIONS.md`. Status: adopted pending disk headroom.

## D014 | 2026-10-08 | Health record is a first-class, shared artifact
`Health` (in ViruxIPC) is written by the daemon and read by the CLI and UI so
an unhealthy or stale agent is always visible. Supports R3 and threat T2/T9.
Status: adopted.

## D015 | 2026-10-08 | Apple Developer Program paid; ES request is the next action
Membership paid by the user. Next concrete steps: (1) file the ES entitlement
request, (2) create a Developer ID Application certificate. Until ES is
granted, development continues on the eslogger bridge and M3 detection.
Status: DONE (see D016).

## D016 | 2026-10-08 | ES entitlement request submitted
Request ID kept in local, gitignored notes (not in this public repo). Filed as
https://github.com/bhadiyadrarohan/virux . Apple reviews manually. Developer ID
cert deferred to M8 packaging (a Development profile suffices for local ES
testing). Meanwhile M3 detection proceeds with no Apple dependency.
Status: awaiting Apple.

## D017 | 2026-10-08 | M4 ships static-first orchestration; the VM backend stays an honest stub
Build the resource gate, coordinator, evidence types, and static Mach-O
analysis now (no disk, no RAM, no guest needed). The `VirtualizationBackend`
reports "no guest provisioned" instead of pretending to detonate. This keeps
the codebase truthful and makes the real backend a drop-in once a guest image
fits. Status: adopted.

## D018 | 2026-10-08 | Untrusted samples are never executed on the host
Static analysis runs on the host; any execution happens only inside a
disposable VM. No sample has been executed anywhere yet in this project, and
tests use hand-crafted fixtures, not live malware. Status: adopted (safety).

## D019 | 2026-10-08 | Detection/scoring lessons from M4
Fat/universal binaries store their header big-endian (read it as such); string
scans must flush a run ending at EOF; broad tokens like bare `http://` are
false-positive magnets and must not be used alone. Status: adopted.

## D020 | 2026-10-08 | M5 quarantine prevents execution by relocation, not by a kernel block
Without the ES entitlement there is no inline execution denial. Quarantine MOVES
the file into a 0700 store and clears its execute bits, which stops future
launches from the original path. This is honest containment; the inline AUTH
block is explicitly deferred. Status: adopted.

## D021 | 2026-10-08 | Admin authorisation uses Authorization Services and fails closed
Restore and delete require the OS administrator prompt (`SecurityAdminGate`).
If it cannot prompt (headless/non-GUI) it denies. Tests use `MockAdminGate`.
Status: adopted.

## D022 | 2026-10-08 | Safe-defaults for automatic response
Automatic response is allowlisted against system paths and trusted team IDs,
rate limited (anti-mass-quarantine), and fully audited including refusals.
Confidence does not by itself trigger containment; severity drives the action.
Status: adopted.
