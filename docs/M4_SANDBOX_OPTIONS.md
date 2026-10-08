# M4 Sandbox - Lighter Approach Options

You chose "explore a lighter sandbox approach (no full macOS guest)". This note
records the honest tradeoffs before any M4 build. No approach here executes
untrusted code on the host.

## The hard constraint

macOS malware is a Mach-O binary. To actually detonate it you must run it
inside an environment that can execute Mach-O, which on Apple silicon means a
**macOS guest** (there is no other supported path). A Linux guest cannot run
Mach-O, so it cannot fulfil the macOS detonation requirement by itself.

So "no full macOS guest" cannot mean "no macOS guest at all" if detonation of
Mach-O is a requirement. It can mean "a much smaller, cheaper macOS guest".

## Options

### A. Slimmed macOS guest + copy-on-write clones (recommended direction)
- One shared base macOS guest image, kept minimal (no Xcode, no App Store
  apps, no data). Base install is roughly 15-25 GB on disk.
- Each analysis run boots a **copy-on-write APFS clone** of the base, so
  per-run disk cost is only what the sample writes, not a full duplicate.
- Data disk is sparse. Reset = discard the clone; the base is never touched.
- Guest: 2 vCPU, 2-3 GB RAM, one run at a time, 60-120 s window.
- Realistic total footprint: base (~20 GB) + sparse working clones. Still needs
  the disk question resolved, but far less than a full 40-80 GB per-VM design.
- Automation: virtio socket (`VZVirtioSocketDevice`) + a small guest agent,
  VirtioFS only for injecting the sample copy. No home share, no clipboard.

### B. Separate Mac mini as the lab host (deferred)
Keeps the VM off this MacBook entirely. Already listed as Future in the plan.

### C. Static-first, detonate only when needed
- M3 already computes hashes and signatures. Add static extraction (Mach-O
  header, entitlements, embedded strings, linked libraries) with no execution.
- Escalate to the VM (option A) only for medium/high items where a static
  verdict is inconclusive. This reduces how often the sandbox must run, which
  is the real resource lever.
- Honest caveat: a clean static result is not proof of safety, exactly as a
  clean sandbox run is not.

### D. arm64 Linux micro-VM (limited, not a macOS substitute)
- Tiny and fast (a few hundred MB), useful for Linux-file samples and for
  testing the orchestration/vsock plumbing cheaply.
- Cannot detonate Mach-O. Do not present it as macOS detonation.

## Recommendation

Adopt **C (static-first) + A (slim macOS guest with CoW clones)**. Build the
sandbox orchestration and vsock plumbing using option D as a cheap harness,
then point it at the slim macOS guest once disk headroom is confirmed. Keep
the resource gates (>=4 GB free host RAM, never force-launch) and the
"quarantine and sandbox are separate" rule.

## Still an open blocker

Disk: ~63 GB free today. Even the slim path wants the user to free space or
attach an external SSD before M4 is attempted. Nothing here removes that
requirement; it only reduces how much is needed.