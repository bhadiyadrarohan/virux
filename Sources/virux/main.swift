import Foundation
import ViruxCore
import ViruxSensor
import ViruxIPC

// virux: command-line companion for the Virux agent. Reads the store and the
// daemon health record. No privileged action.

func defaultDBPath() -> String {
    let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    return base.appendingPathComponent("Virux/events.db").path
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
var j = 0
while j < argv.count {
    switch argv[j] {
    case "--db": j += 1; if j < argv.count { dbPath = argv[j] }
    case "-n", "--limit": j += 1; if j < argv.count { limit = Int(argv[j]) ?? 20 }
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