import Foundation
import ViruxCore
import ViruxDetect
import ViruxRespond

/// A safe, self-contained validation of the ransomware response path. It works
/// ONLY inside a caller-supplied workspace directory, on freshly created benign
/// fixtures. It never touches user data and never encrypts anything real: it
/// renames fixtures to ".locked" and overwrites them with random bytes, then
/// feeds the resulting telemetry through the real detection rules and the real
/// quarantine path.
public struct RansomwareSimulationResult: Sendable {
    public var workspace: String
    public var fixturesCreated: Int
    public var filesRenamed: Int
    public var canaryPath: String
    public var detections: [(ruleID: String, title: String, severity: Severity)]
    public var canaryStatusConfirmed: Bool
    public var quarantinedPath: String?
    public var quarantineID: Int64?
    public var summary: String
}

public enum RansomwareSimulator {

    public enum SimulationError: Error, CustomStringConvertible {
        case workspaceNotIsolated(String)
        public var description: String {
            switch self { case .workspaceNotIsolated(let p): return "refusing to run: workspace \(p) is not inside a temp directory" }
        }
    }

    /// - Parameter workspace: must be inside the system temp directory. This is
    ///   enforced so a bug can never rename or overwrite real files.
    public static func run(workspace: String,
                           fileCount: Int = 60,
                           store: EventStore) throws -> RansomwareSimulationResult {
        let tmp = (NSTemporaryDirectory() as NSString).standardizingPath
        let ws = (workspace as NSString).standardizingPath
        guard ws.hasPrefix(tmp) else { throw SimulationError.workspaceNotIsolated(workspace) }

        let fm = FileManager.default
        let fixturesDir = (ws as NSString).appendingPathComponent("fixtures")
        try? fm.removeItem(atPath: ws)
        try fm.createDirectory(atPath: fixturesDir, withIntermediateDirectories: true)

        // 1. benign fixtures + a canary
        var paths: [String] = []
        for i in 0..<fileCount {
            let p = (fixturesDir as NSString).appendingPathComponent("document\(i).txt")
            try Data("benign content \(i)\n".utf8).write(to: URL(fileURLWithPath: p))
            paths.append(p)
        }
        let canary = (fixturesDir as NSString).appendingPathComponent("virux_canary_backup.dat")
        try Data("VIRUX CANARY (decoy)\n".utf8).write(to: URL(fileURLWithPath: canary))

        // 2. simulated "encryption": rename to .locked and overwrite with random bytes
        let engine = RuleEngine(config: RuleEngine.Config(
            massRenameThreshold: 20,
            canaryPaths: [canary],
            massModifyThreshold: 40))
        let pid: Int32 = 4242
        var matches: [(Int64, RuleMatch)] = []
        var renamed = 0

        func record(_ kind: EventKind, _ path: String, hashing: Bool) {
            let ev = SecurityEvent(kind: kind,
                                   process: ProcessRef(pid: pid, ppid: 1, executablePath: "/tmp/virux-sim"),
                                   filePath: path,
                                   fileHash: hashing ? Hashing.sha256(ofFileAt: path) : nil,
                                   severity: .none, confidence: .low, source: "simulation")
            if let id = try? store.insert(ev) {
                var stored = ev; stored.id = id
                if let m = engine.evaluate(stored) { matches.append((id, m)) }
            }
        }

        for p in paths {
            record(.open, p, hashing: false)
            let locked = p + ".locked"
            try? fm.moveItem(atPath: p, toPath: locked)
            var rnd = Data(count: 512)
            rnd.withUnsafeMutableBytes { raw in
                let p = raw.bindMemory(to: UInt8.self)
                for i in 0..<p.count { p[i] = UInt8.random(in: 0...255) }
            }
            try? rnd.write(to: URL(fileURLWithPath: locked))
            record(.rename, locked, hashing: false)
            renamed += 1
        }
        // the canary is a favourite target
        record(.rename, canary, hashing: false)

        // 3. deduplicate detections by rule
        var seenRules = Set<String>()
        var detections: [(String, String, Severity)] = []
        for (_, m) in matches where !seenRules.contains(m.ruleID) {
            seenRules.insert(m.ruleID)
            detections.append((m.ruleID, m.title, m.severity))
            _ = try? store.insertDetection(Detection(timestamp: Date(), title: m.title, reason: m.reason,
                                                     severity: m.severity, confidence: m.confidence,
                                                     evidenceEventIDs: [], status: .observed))
        }

        // 4. containment: quarantine through the real engine
        let qstore = try QuarantineStore(directory: (ws as NSString).appendingPathComponent("quarantine"),
                                         store: store)
        let engineResp = ResponseEngine(quarantineStore: qstore,
                                        terminator: MockProcessTerminator(), audit: qstore.audit)
        var quarantinedPath: String?
        var quarantineID: Int64?
        let canaryStillThere = fm.fileExists(atPath: canary)
        if canaryStillThere {
            let outcome = engineResp.apply(action: .quarantineAndTerminate, filePath: canary, pid: pid,
                                           severity: .critical, reason: "simulated ransomware touched a canary file")
            if case .quarantinedAndTerminated(let rec, _) = outcome {
                quarantinedPath = rec.quarantinePath; quarantineID = rec.id
            } else if case .quarantined(let rec) = outcome {
                quarantinedPath = rec.quarantinePath; quarantineID = rec.id
            }
        }

        let ruleIDs = detections.map { $0.0 }.sorted()
        let summary = "simulated \(renamed) renames on \(fileCount) benign fixtures; "
            + "rules fired: \(ruleIDs.isEmpty ? "none" : ruleIDs.joined(separator: ", ")); "
            + "canary quarantined: \(quarantinedPath != nil ? "yes" : "no")"

        return RansomwareSimulationResult(
            workspace: ws, fixturesCreated: fileCount, filesRenamed: renamed, canaryPath: canary,
            detections: detections, canaryStatusConfirmed: quarantinedPath != nil,
 quarantinedPath: quarantinedPath, quarantineID: quarantineID, summary: summary)
 }
 }
