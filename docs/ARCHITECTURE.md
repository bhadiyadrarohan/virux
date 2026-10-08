# Virux Architecture

Typical request/event flow, all local. No mandatory cloud dependency.

```
                         +--------------------------------------------+
                         |                macOS host                  |
                         |                                            |
   Gestalt events        |   +----------------+   XPC (Mach svc)      |
   (ES NOTIFY / AUTH) ---+-->|  ViruxSensor   |<----------------+      |
                         |   |  (system ext,  |                 |      |
                         |   |   M2, BLOCKED) |                 |      |
                         |   +-------+--------+                 |      |
                         |           | compact events           |      |
                         |           v                          |      |
                         |   +----------------+   protected     |      |
                         |   |  ViruxDaemon   |   Unix socket   |      |
                         |   | (privileged,   |<--------------+ |      |
                         |   |  launchd)      |               | |      |
                         |   +--+----+--------+               | |      |
                         |      |    |                        | |      |
                         |      |    +--> detection engine --+ |      |
                         |      |         (B: hash, sig,      |      |
                         |      |          rules, score)      |      |
                         |      |                             |      |
                         |      |                    +--------+----+ |
                         |      |                    | Python      | |
                         |      |                    | worker (C)  | |
                         |      |                    | on-demand   | |
                         |      |                    +-------------+ |
                         |      v                                    |
                         |   +----------------+     +---------------+ |
                         |   | Forensics store|     | Response /    | |
                         |   | (F: SQLite)    |     | quarantine(E) | |
                         |   +--------+-------+     +-------+-------+ |
                         |            |                     |         |
                         |            v                     v         |
                         |   +----------------------------------------+|
                         |   |  ViruxApp (SwiftUI menu-bar + dash)   ||
                         |   |  reads store; renders on demand       ||
                         |   +----------------------------------------+|
                         |                                            |
                         |   +----------------------------------------+|
                         |   |  Sandbox (D: Virtualization.framework) ||
                         |   |  disposable macOS guest, vsock agent   ||
                         |   +----------------------------------------+|
                         +--------------------------------------------+
```

## Components

A. **ViruxSensor** (Swift system extension, M2). ES client: exec/fork/exit,
   file open/close, code-signing identity, mount, persistence changes,
   network metadata where exposed. Bounded queues, backpressure signaling,
   safe degrade. Sends compact events over XPC to the daemon. BLOCKED on the
   ES entitlement; M1 uses an eslogger adapter in its place.

B. **Detection and correlation engine** (in ViruxDaemon, M3). SHA-256 hashing,
   local reputation cache, signature matching, configurable rules, behavioral
   sequences, risk scoring, dedup, allowlists scoped by signing identity/hash,
   evidence retention.

C. **Python worker** (M1). Isolated, on-demand enrichment and report assembly.
   Talks to the daemon over an authenticated least-privilege channel
   (Unix-domain socket with peer-credential check, or XPC). Never privileged,
   never always-on.

D. **Sandbox coordinator** (Swift, M4). Disposable macOS guest via
   Virtualization.framework. No host home share, no clipboard/device
   passthrough, NAT default-off or constrained, verified guest image,
   snapshot/reset between samples, strict timeouts, evidence capture. Runs a
   COPY, never the host file. Gated on disk/RAM (see M0 blockers).

E. **Response / quarantine** (M5). Isolate files with metadata + audit trail,
   terminate confirmed critical processes where safe, block malicious network
   activity via a Network Extension content filter. Narrow scope, reversible
   where possible, tested against system processes.

F. **Forensic store and dashboard** (M6). Durable local event DB with
   retention, tamper-evident logging where practical, case histories, process
   tree / relationship graph / timeline, quarantine center, plain-English
   reports backed by evidence.

## IPC design

- Native clients (app, extensions, helpers): XPC Mach service. Validate
  caller by code-signing requirement + audit token; reject anything not signed
  by the Virux team identity.
- Python worker: Unix-domain socket in a daemon-owned directory (0700), verify
  peer credentials (uid/gid/pid) and a per-session token. No network sockets.
- Least privilege: the privileged daemon performs only privileged actions;
  the sensor is passive; the UI is unprivileged and reads the store read-only.

## Data and storage

- Telemetry: SQLite (WAL). Tables: events, processes, files, network,
  detections, quarantine, audit, signatures, reputation_cache, settings.
- Retention: initial 90-day goal for events, configurable; quarantine and
  audit kept longer (bounded by disk-usage guard).
- Hashing: SHA-256 on access, computed locally, cached by inode+mtime+size.
- Reputation cache: keyed by hash; invalidated on file change.

## Startup and lifecycle

- Privileged daemon + system extension start early (launchd, extension
  activation). Dashboard is independent and may be closed at any time.
- Health is reported explicitly: sensor connected, events flowing, last-event
  timestamp, backlog, update freshness. Unhealthy state is shown, never masked.

## Proposed on-disk project structure

```
~/Projects/Virux/
  README.md  REQUIREMENTS.md  DECISIONS.md
  docs/            ARCHITECTURE.md THREAT_MODEL.md M0_FEASIBILITY.md
                   ENTITLEMENTS.md MILESTONE_PLAN.md diagrams/
  apps/ViruxApp/           SwiftUI menu-bar app + dashboard (Xcode project, M1)
  packages/
    ViruxCore/             SPM: models, hashing, store, rules (M1)
    ViruxIPC/              SPM: XPC / socket protocol, shared Codable (M1)
    ViruxSensorKit/        SPM: ES client (M2)
    ViruxResponse/         SPM: quarantine + containment (M5)
  services/
    ViruxDaemon/           privileged launchd daemon (M1 skeleton)
    ViruxWorker/           Python analysis worker (M1)
  sandbox/ViruxSandbox/    Virtualization coordinator + guest agent (M4)
  tools/eslogger-adapter/  M1 telemetry bridge
  tests/fixtures/          EICAR, benign behavior simulators
  scripts/                 build, sign, install helpers
```

## Dependency notes

- System: EndpointSecurity, NetworkExtension, Virtualization, Security,
  CryptoKit, SQLite3 (or GRDB), ServiceManagement (SMJobBless/SMAppService).
- No heavyweight third-party AV. Open formats reused only after license check.
