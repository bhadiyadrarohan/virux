import Foundation
import ViruxCore
import ViruxSensor
import ViruxIPC
import ViruxSandbox
import ViruxRespond
import ViruxForensics

// virux: command-line companion for the Virux agent. Reads the store and the
// daemon health record. No privileged action.

func defaultDBPath() -> String {
    let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    return base.appendingPathComponent("Virux/events.db").path
}

func quarantineDir(forDB dbPath: String) -> String {
    ((dbPath as NSString).deletingLastPathComponent as NSString).appendingPathComponent("Quarantine")
}

/// Accepts an ISO-8601 timestamp or a relative age like 30m / 2h / 3d.
func parseSince(_ s: String) -> Date? {
    let iso = ISO8601DateFormatter()
    if let d = iso.date(from: s) { return d }
    let unit = s.last.map(String.init) ?? ""
    let num = String(s.dropLast())
    guard let n = Double(num) else { return nil }
    let mult: Double
    switch unit {
    case "s": mult = 1
    case "m": mult = 60
    case "h": mult = 3600
    case "d": mult = 86400
    default: return nil
    }
    return Date().addingTimeInterval(-n * mult)
}

func human(_ bytes: Int64) -> String {
    let units = ["B", "KB", "MB", "GB"]
    var value = Double(bytes)
    var idx = 0
    while value >= 1024 && idx < units.count - 1 { value /= 1024; idx += 1 }
    return String(format: "%.1f %@", value, units[idx])
}

func fmt(_ date: Date?) -> String {
    guard let date else { return "never" }
    let f = DateFormatter()
    f.dateFormat = "yyyy-MM-dd HH:mm:ss"
    return f.string(from: date)
}

let usage = """
virux - Virux CLI (M1)

USAGE:
  virux status [--db PATH]     Show agent health and store summary
  virux tail   [--db PATH] [-n N]   Show most recent events
  virux detections [--db PATH] [-n N]   Show recent detections
  virux analyze FILE           Static analysis + sandbox gate for a file
  virux quarantine             List quarantined files
  virux quarantine-add FILE REASON   Move a file to quarantine (user initiated)
  virux quarantine-restore ID  Restore a file (requires admin authorization)
  virux quarantine-delete ID   Permanently delete (requires admin authorization)
  virux audit [-n N]           Show the audit trail
  virux find [--kind K] [--min-severity S] [--path P] [--hash H] [--since T] [-n N]
                               Search event history
  virux report DETECTION_ID    Full incident report (markdown)
  virux tree [--pid P] [--since T]   Process tree or ancestry
  virux persistence            Scan autostart locations for suspicious entries
  virux stats  [--db PATH]     Show counts by kind and disk usage
  virux hash   FILE...         Print SHA-256 for files
  virux --help

Default database: \(defaultDBPath())
"""

var argv = Array(CommandLine.arguments.dropFirst())
guard let command = argv.first else { print(usage); exit(0) }
argv.removeFirst()

var dbPath = defaultDBPath()
var limit = 20
var files: [String] = []
var kindFilter: String?
var minSeverity: Severity?
var pathFilter: String?
var hashFilter: String?
var exeFilter: String?
var sinceStr: String?
var pidArg: Int32?
var j = 0
while j < argv.count {
    switch argv[j] {
    case "--db": j += 1; if j < argv.count { dbPath = argv[j] }
    case "-n", "--limit": j += 1; if j < argv.count { limit = Int(argv[j]) ?? 20 }
    case "--kind": j += 1; if j < argv.count { kindFilter = argv[j] }
    case "--min-severity": j += 1; if j < argv.count { minSeverity = Severity(rawValue: argv[j].lowercased()) }
    case "--path": j += 1; if j < argv.count { pathFilter = argv[j] }
    case "--hash": j += 1; if j < argv.count { hashFilter = argv[j] }
    case "--exe": j += 1; if j < argv.count { exeFilter = argv[j] }
    case "--since": j += 1; if j < argv.count { sinceStr = argv[j] }
    case "--pid": j += 1; if j < argv.count { pidArg = Int32(argv[j]) }
    default: files.append(argv[j])
    }
    j += 1
}

switch command {
case "status":
    let healthPath = Health.defaultPath(dbPath: dbPath)
    print("Virux status")
    print("  db:       \(dbPath)")
    if let h = Health.load(from: healthPath) {
        print("  state:    \(h.state)\(h.isFresh() ? " (events live)" : " (STALE: no recent events)")")
        print("  source:   \(h.source)")
        print("  started:  \(fmt(h.startedAt))")
        print("  updated:  \(fmt(h.updatedAt))")
        print("  last evt: \(fmt(h.lastEventAt))")
        print("  received: \(h.eventsReceived)  stored: \(h.eventsStored)  errors: \(h.insertErrors)")
        print("  rows:     \(h.rowCount)   db size: \(human(h.dbSizeBytes))")
        if let d = h.detections {
            print("  detectns: \(d)\(h.lastDetectionTitle.map { "  last: \($0)" } ?? "")")
        }
        if let e = h.lastError { print("  last err: \(e)") }
        for n in h.notes { print("  note:     \(n)") }
    } else {
        print("  state:    unknown (no health record; is viruxd running?)")
    }

case "tail":
    do {
        let store = try EventStore(path: dbPath)
        let rows = store.recent(limit: limit)
        if rows.isEmpty { print("(no events)") }
        for e in rows.reversed() {
            let exe = e.process.executablePath.map { ($0 as NSString).lastPathComponent } ?? "?"
            let file = e.filePath.map { " -> \($0)" } ?? ""
            print("[\(fmt(e.timestamp))] #\(e.id ?? 0) \(e.kind.rawValue) pid=\(e.process.pid) \(exe)\(file)")
        }
    } catch { print("error: \(error)"); exit(1) }

case "detections":
    do {
        let store = try EventStore(path: dbPath)
        let rows = store.recentDetections(limit: limit)
        if rows.isEmpty { print("(no detections)") }
        for d in rows.reversed() {
            print("[\(fmt(d.timestamp))] #\(d.id ?? 0) [\(d.severity.rawValue)/\(d.confidence.rawValue)] \(d.title)")
            print("    \(d.reason)")
        }
    } catch { print("error: \(error)"); exit(1) }

case "analyze":
    guard let file = files.first else { print("usage: virux analyze FILE"); exit(1) }
    let findings: MachOFindings
    do { findings = try MachOAnalyzer.analyze(path: file) }
    catch { print("error: \(error)"); exit(1) }
    print("Virux static analysis")
    print("  file:      \(findings.path)")
    if let h = Hashing.sha256(ofFileAt: file) { print("  sha256:    \(h)") }
    print("  size:      \(findings.sizeBytes) bytes")
    print("  mach-o:    \(findings.isMachO ? "yes" : "no")\(findings.isFat ? " (fat/universal)" : "")")
    print("  arch:      \(findings.architectures.isEmpty ? "-" : findings.architectures.joined(separator: ", "))")
    print("  type:      \(findings.fileType ?? "-")")
    print("  signed:    \(findings.hasCodeSignature ? "yes" : "no")")
    print("  encrypted: \(findings.isEncrypted ? "yes" : "no")")
    print(String(format: "  entropy:   %.2f", findings.entropy))
    if !findings.linkedLibraries.isEmpty {
        print("  libs:      \(findings.linkedLibraries.prefix(6).joined(separator: ", "))")
    }
    if !findings.suspiciousStrings.isEmpty {
        print("  strings:   \(findings.suspiciousStrings.joined(separator: ", "))")
    }
    print("  verdict:   \(findings.verdict.rawValue)")
    for r in findings.reasons { print("    - \(r)") }
    let probe = SystemResourceProbe().sample()
    print(String(format: "  host:      free mem %.2f GB, free disk %.2f GB", probe.freeMemoryGB, probe.freeDiskGB))
    switch ResourceGate().decide(resources: probe, activeRuns: 0) {
    case .allow: print("  sandbox:   VM run would be allowed")
    case .deferred(let reason): print("  sandbox:   deferred (\(reason))")
    }

case "quarantine":
    do {
        let store = try EventStore(path: dbPath)
        let qs = try QuarantineStore(directory: quarantineDir(forDB: dbPath), store: store)
        let rows = qs.list()
        if rows.isEmpty { print("(quarantine empty)") }
        for q in rows {
            print("#\(q.id ?? 0) [\(q.status.rawValue)] \(q.originalPath)")
            print("    sha256: \(q.sha256 ?? "?")")
            print("    reason: \(q.reason)")
        }
    } catch { print("error: \(error)"); exit(1) }

case "quarantine-add":
    guard files.count >= 2 else { print("usage: virux quarantine-add FILE REASON"); exit(1) }
    let target = files[0]
    let reason = files.dropFirst().joined(separator: " ")
    do {
        let store = try EventStore(path: dbPath)
        let qs = try QuarantineStore(directory: quarantineDir(forDB: dbPath), store: store)
        let rec = try qs.quarantine(filePath: target, reason: reason, actor: "user")
        print("quarantined #\(rec.id ?? 0): \(rec.originalPath)")
        print("  -> \(rec.quarantinePath)")
        print("  sha256: \(rec.sha256 ?? "?")  exec bit cleared")
    } catch { print("error: \(error)"); exit(1) }

case "quarantine-restore", "quarantine-delete":
    guard let idStr = files.first, let id = Int64(idStr) else { print("usage: virux \(command) ID"); exit(1) }
    do {
        let store = try EventStore(path: dbPath)
        let qs = try QuarantineStore(directory: quarantineDir(forDB: dbPath), store: store)
        let gate = SecurityAdminGate()
        if command == "quarantine-restore" {
            let rec = try qs.restore(id: id, gate: gate)
            print("restored #\(rec.id ?? 0) to \(rec.originalPath)")
        } else {
            let rec = try qs.delete(id: id, gate: gate)
            print("deleted #\(rec.id ?? 0) (was \(rec.originalPath))")
        }
    } catch { print("error: \(error)"); exit(1) }

case "audit":
    do {
        let store = try EventStore(path: dbPath)
        let rows = store.recentAudit(limit: limit)
        if rows.isEmpty { print("(no audit entries)") }
        for a in rows.reversed() {
            print("[\(fmt(a.timestamp))] \(a.ok ? "ok " : "ERR") \(a.action) (\(a.actor))\(a.target.map { " \($0)" } ?? "")\(a.detail.map { " :: \($0)" } ?? "")")
        }
    } catch { print("error: \(error)"); exit(1) }

case "find":
    do {
        let store = try EventStore(path: dbPath)
        var q = EventQuery(limit: limit)
        if let k = kindFilter {
            q.kinds = Set(k.split(separator: ",").compactMap { EventKind(rawValue: String($0)) })
        }
        q.minSeverity = minSeverity
        q.pathContains = pathFilter
        q.fileHash = hashFilter
        q.exeContains = exeFilter
        if let s = sinceStr { q.since = parseSince(s) }
        let rows = store.searchEvents(q)
        if rows.isEmpty { print("(no matching events)") }
        for e in rows {
            let exe = e.process.executablePath.map { ($0 as NSString).lastPathComponent } ?? "?"
            var line = "[\(fmt(e.timestamp))] #\(e.id ?? 0) \(e.kind.rawValue) pid=\(e.process.pid) \(exe)"
            if let f = e.filePath { line += " -> \(f)" }
            if let h = e.fileHash { line += " (\(h.prefix(12))…)" }
            print(line)
        }
    } catch { print("error: \(error)"); exit(1) }

case "report":
    guard let idStr = files.first, let id = Int64(idStr) else { print("usage: virux report DETECTION_ID"); exit(1) }
    do {
        let store = try EventStore(path: dbPath)
        guard let det = store.searchDetections(DetectionQuery(limit: 5000)).first(where: { $0.id == id }) else {
            print("no detection #\(id)"); exit(1)
        }
        let qs = try QuarantineStore(directory: quarantineDir(forDB: dbPath), store: store)
        print(ReportBuilder.build(detection: det, store: store, quarantineStore: qs).markdown())
    } catch { print("error: \(error)"); exit(1) }

case "tree":
    do {
        let store = try EventStore(path: dbPath)
        let since = sinceStr.flatMap(parseSince) ?? Date().addingTimeInterval(-3600)
        let events = store.searchEvents(EventQuery(since: since, limit: 5000))
        if let p = pidArg {
            let chain = ProcessTreeBuilder.ancestry(of: p, from: events)
            if chain.isEmpty { print("(no ancestry recorded for pid \(p))") }
            for (i, r) in chain.enumerated() {
                print(String(repeating: "  ", count: i) + "- \(r.executablePath ?? "(unknown)") [pid \(r.pid)]")
            }
        } else {
            let tree = ProcessTreeRenderer.ascii(ProcessTreeBuilder.build(from: events))
            print(tree.isEmpty ? "(no process activity in window)" : tree)
        }
    } catch { print("error: \(error)"); exit(1) }

case "persistence":
    let monitor = PersistenceMonitor()
    let snap = monitor.scan()
    print("autostart entries: \(snap.items.count)")
    for it in snap.items {
        let flag = it.suspicious ? "   SUSPICIOUS: \(it.reasons.joined(separator: "; "))" : ""
        let name = it.label ?? (it.path as NSString).lastPathComponent
        print("  [\(it.kind)] \(name)\(flag)")
    }
    let suspicious = snap.items.filter { $0.suspicious }.map { PersistenceChange(kind: .added, item: $0) }
    for a in monitor.alerts(for: suspicious) { print("  alert [\(a.severity.rawValue)] \(a.message)") }

case "stats":
    do {
        let store = try EventStore(path: dbPath)
        print("rows: \(store.count())   size: \(human(store.dbSizeBytes()))")
        for (k, c) in store.countByKind() { print("  \(k): \(c)") }
    } catch { print("error: \(error)"); exit(1) }

case "hash":
    guard !files.isEmpty else { print("usage: virux hash FILE..."); exit(1) }
    for f in files {
        if let h = Hashing.sha256(ofFileAt: f) {
            print("\(h)  \(f)")
        } else {
            print("ERROR       \(f)")
        }
    }

case "-h", "--help":
    print(usage)

default:
    print(usage); exit(1)
}