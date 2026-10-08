# M0 - Discovery and Feasibility

Date: 2026-10-08. All findings below come from read-only inspection of this
machine. No privileged component was installed, no security setting changed,
no sample executed.

## 1. Machine audit (measured)

| Item | Value | Note |
|---|---|---|
| Model / SoC | Apple M1 Pro | 8 performance + 2 efficiency cores |
| RAM | 16 GB unified | `hw.memsize` = 16.0 GB |
| OS | macOS 27.0 (26A428) | very new; ES surface to be re-verified |
| SIP | **enabled** | must stay enabled |
| Xcode | 27.0 (27A266a) | |
| Swift | 6.4 (swiftlang-6.4.0.34.1) | |
| Python | 3.12.7 system | Hermes also ships 3.14 |
| Data volume | 460 GB total, **63 GB free** | 85% used |
| Swap | 17.7 GB used of 18.4 GB | **host already under memory pressure** |
| Load average | 2.66 / 1.98 / 1.85 | 10 logical cores |
| Rosetta | **not installed** | relevant to x86 sample detonation |
| External drives | none connected | matches the prompt's assumption |
| Codessign identities | 1x "Apple Development" (team Z3NP36C65D, UID 7RXM93A66V, "rohan bhadiyadra") | **no Developer ID cert** |
| Provisioning profiles | 1 present (S&R project) | **none carrying ES capability** |
| System extensions | Tailscale network extension only (team W5364U7YZB) | no Virux extension |
| Developer mode for extensions | unavailable (requires SIP off on macOS 15+) | so the provisioning-profile path is required |

Frameworks confirmed present: EndpointSecurity, NetworkExtension,
Virtualization, and PrivilegedHelperTools install location.

## 2. Capability verdicts

### 2.1 Endpoint Security sensor (component A) - FEASIBLE, GATED
- ES is the correct mechanism for process/file/persistence/network-metadata
  telemetry. It is a C API, macOS 10.15+.
- Requires the restricted entitlement `com.apple.developer.endpoint-security.client`,
  granted only via Apple's System Extension entitlement request form. It also
  requires Full Disk Access (TCC) for the responsible process.
- Shipping requires a provisioning profile carrying the ES capability, which
  only exists after Apple grants the entitlement.
- **Verdict: build the pipeline now against `eslogger` (see 2.2); the native
  sensor is blocked until Apple grants the entitlement.**

### 2.2 eslogger bridge - AVAILABLE NOW
- `/usr/bin/eslogger` present. Apple's own, pre-entitled ES client. Emits JSON
  NOTIFY events (exec, fork, exit, open, close, iokit_open, and more).
- Must run as superuser; the responsible terminal needs Full Disk Access.
- It is a learning/investigation tool, **not** a production agent (Apple's own
  positioning). Use it to prove components B/F and the UI before the real
  sensor exists.

### 2.3 Automated sandbox (component D) - FEASIBLE, RESOURCE-BLOCKED
- Virtualization framework on Apple Silicon runs macOS guests (arm64) and
  Linux guests. macOS guests are permitted for personal, non-commercial use,
  max two concurrent, framework-enforced.
- Headless automation is proven: virtio socket (`VZVirtioSocketDevice`) +
  a small guest agent, plus VirtioFS for controlled file injection.
- Rosetta 2 is available inside macOS guests to run x86_64 apps, so x86
  samples are theoretically detonable, but Rosetta is not installed on the
  host and adds setup cost. Most current macOS malware is arm64/universal.
- **Blocked in practice by disk (~63 GB free vs ~40-80 GB bundle) and by host
  memory pressure (swap near full). See section 4.**

### 2.4 Response / quarantine (component E) - PARTIALLY FEASIBLE
- File isolation + audit trail: fully feasible (move to a protected store,
  record metadata, admin-gated restore/delete).
- Process termination: feasible for processes the privileged daemon can signal.
- Execution denial of new processes: possible with ES AUTH events *once the
  entitlement exists*; not available via eslogger.
- Network containment: needs a Network Extension content filter (separate
  self-service entitlement + separate system extension). ES alone is not a
  firewall. Budget extra time for this.

### 2.5 Signature delivery - FEASIBLE
- Ed25519-signed update bundles, differential, rollback to last-known-good,
  verify-then-apply, all local. No hard external dependency. The 6-hour
  cadence is a policy choice; feasibility is fine, value depends on signature
  sources (decide at M3).

## 3. Entitlement and approval matrix

| Capability | Entitlement | Grant path | Needed by |
|---|---|---|---|
| ES telemetry/control | com.apple.developer.endpoint-security.client | Apple request form, manual review | M2 |
| System extension install (host app) | com.apple.developer.system-extension.install | standard capability | M2 |
| VM sandbox | com.apple.security.virtualization | self-service (Xcode capability) | M4 |
| Network filter/containment | com.apple.developer.networking.networkextension (content-filter-provider) | self-service capability | M5 |
| Privileged helper (SMJobBless) | none extra; Developer ID signing | local | M1/M5 |
| Notarization | Developer ID Application cert + notarytool | Apple Developer Program | M8 |

Note: the ES entitlement is the single hard external dependency. Everything
else is available with a paid Apple Developer Program membership
(team Z3NP36C65D already exists).

## 4. Known blockers and risks (honest)

- **B1 (hard, external): ES entitlement not present.** No profile locally
  carries ES. Must be requested and approved by Apple. Reported lead times
  range from days to about a month. Mitigation: eslogger bridge (D003).
- **B2 (deferred, local): no Developer ID Application certificate.** Needed to
  sign/notarize for distribution to other machines, so it blocks M8 packaging,
  not M1/M2. Local testing uses a Development provisioning profile with the
  existing Apple Development cert (team Z3NP36C65D, valid to Sep 2027). Create
  the Developer ID cert when packaging begins.
- **B3 (hard, resource): disk.** ~63 GB free cannot safely host a macOS VM
  bundle plus a reset snapshot plus the telemetry store. Mitigation: free
  space, or attach an external SSD, or shrink the guest (must be re-measured).
  **M4 is gated on this.**
- **B4 (medium, resource): host memory.** Swap is already near full under
  normal concurrent use. A 3 GB guest plus VM overhead will frequently fail
  the "4 GB free" gate. Mitigation: adaptive gating, measure real pressure
  under load, consider 2 GB guest, never force-launch.
- **B5 (medium, platform): macOS 27 is very new.** ES event availability,
  system-extension approvals, and framework behavior should be re-verified
  against macOS 27 specifically before M2. Sample code deployment target is
  macOS 27, so this is a supported target, but assumptions must be tested.
- **B6 (medium, platform): Rosetta is slated for removal in macOS 28.** x86_64
  sample detonation may age out. Prefer arm64 fixtures; treat x86 support as
  best-effort.
- **B7 (design): two system extensions total.** ES sensor (M2) and network
  filter (M5). Both need user approval at install. Plan the UX and the
  install/uninstall flow together.
- **B8 (design): false positives on system processes.** R7/R8 and the prompt
  require staged enforcement; enforce observe-only first with a measured
  baseline. Non-negotiable.

## 5. Minimum viable M1 (what can proceed today without any approval)

1. Swift package skeleton: ViruxCore, ViruxIPC, ViruxSensor (stub), ViruxApp.
2. Python worker skeleton over a Unix-domain socket with peer-credential
   checks.
3. Local SQLite (or GRDB) telemetry store with retention scaffolding.
4. menu-bar "V" placeholder + dashboard shell (state, counts, resource panel).
5. eslogger-based telemetry adapter that pipes JSON events into the store.
6. Unit tests + a benchmark harness for CPU/RAM/idle measurement.
7. REQUIREMENTS.md and DECISIONS.md kept current.

None of the above needs the ES entitlement, a privileged helper, or any
security-setting change.
