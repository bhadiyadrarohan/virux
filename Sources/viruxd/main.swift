import Foundation
import Darwin
import ViruxCore
import ViruxSensor
import ViruxIPC
import ViruxDetect
import ViruxCoverage

// viruxd: the Virux background agent skeleton (M1). It consumes telemetry from
// an EventSource, stores it in the local SQLite store, and publishes a health
// record. It performs NO privileged action and runs NO response capability yet.
// Not installed as a launchd daemon in M1; run it manually.

var gStop = false
signal(SIGINT) { _ in gStop = true }
signal(SIGTERM) { _ in gStop = true }

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(("viruxd: " + message + "\n").data(using: .utf8)!)
    exit(1)
}

func defaultDBPath() -> String {
    let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    return base.appendingPathComponent("Virux/events.db").path
}

let usage = """
viruxd - Virux background agent skeleton (M1)

USAGE:
  viruxd [--db PATH] [--source synth|eslogger|replay:FILE]
         [--events exec,fork,exit,open,close] [--seconds N] [--purge-days N]

NOTES:
  --source eslogger requires root and Full Disk Access for the responsible process.
  --source synth and replay:FILE need no privileges (use for tests/benchmarks).
Default database: \(defaultDBPath())
"""

var dbPath = defaultDBPath()
var source = "synth"
var eventTypes = ["exec", "fork", "exit", "open", "close"]
var seconds: Double? = nil
var purgeDays = 90
var detect = true

var args = Array(CommandLine.arguments.dropFirst())
var i = 0
while i < args.count {
    switch args[i] {
    case "--db":
        i += 1; if i < args.count { dbPath = args[i] }
    case "--source":
        i += 1; if i < args.count { source = args[i] }
    case "--events":
        i += 1; if i < args.count { eventTypes = args[i].split(separator: ",").map(String.init) }
    case "--seconds":
        i += 1; if i < args.count { seconds = Double(args[i]) }
    case "--purge-days":
        i += 1; if i < args.count { purgeDays = Int(args[i]) ?? 90 }
    case "--detect":
        detect = true
    case "--no-detect":
        detect = false
    case "-h", "--help":
        print(usage); exit(0)
    default:
        break
    }
    i += 1
}

let store: EventStore
do {
    store = try EventStore(path: dbPath)
} catch {
    fail("cannot open store at \(dbPath): \(error)")
}

let healthPath = Health.defaultPath(dbPath: dbPath)
let startedAt = Date()

// M7: load decoy (canary) files so a touch fires rule R-007 on live telemetry.
let canaryManifest = ((dbPath as NSString).deletingLastPathComponent as NSString)
    .appendingPathComponent("canaries.json")
let canaries = CanaryManager(manifestPath: canaryManifest)
let pipeline = DetectionPipeline(store: store,
                                 engine: RuleEngine(config: RuleEngine.Config(canaryPaths: canaries.paths)),
                                 hashExecImages: true)
if !canaries.paths.isEmpty {
    FileHandle.standardError.write(Data("viruxd: \(canaries.paths.count) canary file(s) under watch\n".utf8))
}

final class Counters {
    let lock = NSLock()
    var received = 0
    var stored = 0
    var errors = 0
    var detections = 0
    var lastEventAt: Date?
    var lastError: String?
    var lastDetectionTitle: String?
}
let counters = Counters()

let src: EventSource
if source == "synth" {
    src = SynthAdapter()
} else if source == "eslogger" {
    src = EsloggerAdapter(eventTypes: eventTypes)
} else if source.hasPrefix("replay:") {
    src = ReplayAdapter(filePath: String(source.dropFirst("replay:".count)))
} else {
    fail("unknown source '\(source)'")
}

func publishHealth(state: String, notes: [String] = []) {
    counters.lock.lock()
    let h = Health(
        state: state,
        source: src.name,
        startedAt: startedAt,
        updatedAt: Date(),
        lastEventAt: counters.lastEventAt,
        eventsReceived: counters.received,
        eventsStored: counters.stored,
        insertErrors: counters.errors,
        lastError: counters.lastError,
        dbPath: dbPath,
        dbSizeBytes: store.dbSizeBytes(),
        rowCount: store.count(),
        notes: notes,
        detections: counters.detections,
        lastDetectionTitle: counters.lastDetectionTitle
    )
    counters.lock.unlock()
    try? h.write(to: healthPath)
}

let notes = [
    "M3 observe-only: detections are recorded, nothing is enforced.",
    "source=\(src.name)"
]

src.start(onEvent: { event in
    counters.lock.lock()
    counters.received += 1
    counters.lastEventAt = event.timestamp
    counters.lock.unlock()
    do {
        var stored = event
        stored.id = try store.insert(event)
        counters.lock.lock(); counters.stored += 1; counters.lock.unlock()
        if detect, let det = pipeline.process(stored) {
            counters.lock.lock()
            counters.detections += 1
            counters.lastDetectionTitle = det.title
            counters.lock.unlock()
        }
    } catch {
        counters.lock.lock()
        counters.errors += 1
        counters.lastError = "\(error)"
        counters.lock.unlock()
    }
}, onError: { message in
    counters.lock.lock()
    counters.lastError = message
    counters.lock.unlock()
})

publishHealth(state: "observe-only", notes: notes)

let policy = RetentionPolicy(eventRetentionDays: purgeDays)
var lastPurge = Date.distantPast

while !gStop {
    if let s = seconds, Date().timeIntervalSince(startedAt) >= s { break }
    if Date().timeIntervalSince(lastPurge) > 300 {
        _ = try? store.purge(olderThanDays: policy.eventRetentionDays)
        lastPurge = Date()
    }
    publishHealth(state: "observe-only", notes: notes)
    Thread.sleep(forTimeInterval: 1.0)
}

src.stop()
publishHealth(state: "stopped", notes: notes + ["shut down cleanly"])
print("viruxd: stopped. db=\(dbPath) rows=\(store.count()) detections=\(store.countDetections())")