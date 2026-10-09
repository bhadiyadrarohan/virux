import XCTest
import Foundation
@testable import ViruxCore
@testable import ViruxDetect
@testable import ViruxRespond
@testable import ViruxCoverage

final class CoverageTests: XCTestCase {

    private func tempDir() -> String {
        let d = (NSTemporaryDirectory() as NSString).appendingPathComponent("virux-m7-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true)
        return d
    }

    // MARK: - Canaries

    func testCanaryPlantAndCheckIntact() throws {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(atPath: dir) }
        let cm = CanaryManager(manifestPath: dir + "/canaries.json")
        let planted = try cm.plant(inDirectory: dir)
        XCTAssertEqual(planted.count, CanaryManager.defaultNames.count)
        XCTAssertTrue(cm.check().allSatisfy { $0.status == .intact })
    }

    func testCanaryDetectsModification() throws {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(atPath: dir) }
        let cm = CanaryManager(manifestPath: dir + "/canaries.json")
        let planted = try cm.plant(inDirectory: dir)
        try Data("changed".utf8).write(to: URL(fileURLWithPath: planted[0].path))
        let findings = cm.check()
        let f = findings.first { $0.canary.path == planted[0].path }
        guard case .modified = f?.status else { return XCTFail("expected modified, got \(String(describing: f?.status))") }
    }

    func testCanaryDetectsDeletion() throws {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(atPath: dir) }
        let cm = CanaryManager(manifestPath: dir + "/canaries.json")
        let planted = try cm.plant(inDirectory: dir)
        try FileManager.default.removeItem(atPath: planted[1].path)
        let f = cm.check().first { $0.canary.path == planted[1].path }
        XCTAssertEqual(f?.status, .missing)
    }

    func testCanaryManifestPersists() throws {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/canaries.json"
        let cm = CanaryManager(manifestPath: path)
        _ = try cm.plant(inDirectory: dir)
        let reloaded = CanaryManager(manifestPath: path)
        XCTAssertEqual(reloaded.canaries.count, cm.canaries.count)
        XCTAssertTrue(reloaded.check().allSatisfy { $0.status == .intact })
    }

    // MARK: - Rules R-006 / R-007 / R-008

    func testBackupTamperingRuleFires() {
        let engine = RuleEngine()
        let e = SecurityEvent(kind: .open,
                              process: ProcessRef(pid: 9, ppid: 1, executablePath: "/tmp/x"),
                              filePath: "/Volumes/Backup/Backups.backupdb/Mac/2026/file", fileHash: nil,
                              severity: .none, confidence: .low, source: "test")
        let m = engine.evaluate(e)
        XCTAssertEqual(m?.ruleID, "R-006")
        XCTAssertEqual(m?.severity, .high)
    }

    func testCanaryRuleFiresAsCritical() {
        let canary = "/Users/x/Documents/virux_canary_backup.dat"
        let engine = RuleEngine(config: RuleEngine.Config(canaryPaths: [canary]))
        let e = SecurityEvent(kind: .rename,
                              process: ProcessRef(pid: 9, ppid: 1, executablePath: "/tmp/x"),
                              filePath: canary, fileHash: nil,
                              severity: .none, confidence: .low, source: "test")
        let m = engine.evaluate(e)
        XCTAssertEqual(m?.ruleID, "R-007")
        XCTAssertEqual(m?.severity, .critical)
    }

    func testCanaryRuleMatchesPathVariants() {
        let canary = "/Users/x/Documents/virux_canary_backup.dat"
        let variants = ["/Users/x/Documents//virux_canary_backup.dat",
                        "/Users/x/Documents/virux_canary_backup.dat/",
                        "/private/Users/x/Documents/virux_canary_backup.dat"]
        for variant in variants {
            let engine = RuleEngine(config: RuleEngine.Config(ruleCooldown: 0, canaryPaths: [canary]))
            let e = SecurityEvent(kind: .rename,
                                  process: ProcessRef(pid: 9, ppid: 1, executablePath: "/tmp/x"),
                                  filePath: variant, fileHash: nil,
                                  severity: .none, confidence: .low, source: "test")
            XCTAssertEqual(engine.evaluate(e)?.ruleID, "R-007", "variant \(variant) should match")
        }
    }

    func testMassModificationRuleFires() {
        let engine = RuleEngine(config: RuleEngine.Config(massRenameThreshold: 1000, massModifyThreshold: 10))
        var last: RuleMatch?
        for i in 0..<10 {
            let e = SecurityEvent(kind: .open,
                                  process: ProcessRef(pid: 7, ppid: 1, executablePath: "/tmp/x"),
                                  filePath: "/tmp/data/file\(i).txt", fileHash: nil,
                                  severity: .none, confidence: .low, source: "test")
            if let m = engine.evaluate(e) { last = m }
        }
        XCTAssertEqual(last?.ruleID, "R-008")
    }

    // MARK: - Volumes

    func testVolumeWatcherDiff() {
        let a = VolumeInfo(path: "/Volumes/A", name: "A", isRemovable: true, isInternal: false, totalBytes: 1, freeBytes: 1)
        let b = VolumeInfo(path: "/Volumes/B", name: "B", isRemovable: true, isInternal: false, totalBytes: 1, freeBytes: 1)
        let d = VolumeWatcher.diff(previous: [a], current: [b])
        XCTAssertEqual(d.added.map { $0.path }, ["/Volumes/B"])
        XCTAssertEqual(d.removed.map { $0.path }, ["/Volumes/A"])
    }

    func testOnConnectScannerFlagsSuspiciousArtifacts() throws {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(atPath: dir) }
        let fm = FileManager.default
        try Data("x".utf8).write(to: URL(fileURLWithPath: dir + "/autorun.inf"))
        try Data("x".utf8).write(to: URL(fileURLWithPath: dir + "/shortcut.lnk"))
        try Data("x".utf8).write(to: URL(fileURLWithPath: dir + "/payload.command"))
        try Data("x".utf8).write(to: URL(fileURLWithPath: dir + "/.DS_Store"))  // benign
        try Data("x".utf8).write(to: URL(fileURLWithPath: dir + "/notes.txt"))  // benign

        let vol = VolumeInfo(path: dir, name: "TEST", isRemovable: true, isInternal: false,
                             totalBytes: 0, freeBytes: 0)
        let report = OnConnectScanner().scan(volume: vol)
        let kinds = Set(report.artifacts.map { $0.kind })
        XCTAssertTrue(kinds.contains("autorun"))
        XCTAssertTrue(kinds.contains("windows-shortcut"))
        XCTAssertTrue(kinds.contains("executable-payload"))
        XCTAssertFalse(report.artifacts.contains { $0.path.hasSuffix(".DS_Store") },
                       ".DS_Store must not be flagged")
        XCTAssertEqual(report.suspiciousArtifacts.count, report.artifacts.count)
    }

    func testOnConnectScannerRespectsTimeAndEntryBudget() throws {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(atPath: dir) }
        for i in 0..<50 { try Data("x".utf8).write(to: URL(fileURLWithPath: dir + "/f\(i).txt")) }
        var cfg = OnConnectScanner.Config(); cfg.maxEntries = 5; cfg.maxSeconds = 0.05
        let vol = VolumeInfo(path: dir, name: "T", isRemovable: true, isInternal: false, totalBytes: 0, freeBytes: 0)
        let report = OnConnectScanner(config: cfg).scan(volume: vol)
        XCTAssertLessThanOrEqual(report.entriesSeen, 6)
        XCTAssertTrue(report.truncated)
    }

    // MARK: - Impact

    func testImpactTrackerGroupsFiles() {
        func ev(_ p: String) -> SecurityEvent {
            SecurityEvent(kind: .open, process: ProcessRef(pid: 1, ppid: 1, executablePath: "/tmp/x"),
                          filePath: p, fileHash: nil, severity: .none, confidence: .low, source: "test")
        }
        let events = [ev("/data/a.txt"), ev("/data/b.txt"), ev("/other/c.pdf"), ev("/data/a.txt")]
        let s = ImpactTracker.summarize(events: events)
        XCTAssertEqual(s.totalAffected, 3)  // de-duplicated
        XCTAssertEqual(s.byDirectory.first?.0, "/data")
        XCTAssertEqual(s.byDirectory.first?.1, 2)
        XCTAssertTrue(s.byExtension.contains { $0.0 == "txt" && $0.1 == 2 })
    }

    // MARK: - End-to-end safe ransomware simulation

    func testRansomwareSimulationDetectsAndContains() throws {
        let ws = (NSTemporaryDirectory() as NSString).appendingPathComponent("virux-sim-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(atPath: ws) }
        let dbDir = tempDir(); defer { try? FileManager.default.removeItem(atPath: dbDir) }
        let store = try EventStore(path: dbDir + "/events.db")

        let res = try RansomwareSimulator.run(workspace: ws, fileCount: 60, store: store)
        let rules = Set(res.detections.map { $0.ruleID })
        XCTAssertTrue(rules.contains("R-005"), "mass rename must fire; got \(rules)")
        XCTAssertTrue(rules.contains("R-007"), "canary touch must fire; got \(rules)")
        XCTAssertTrue(rules.contains("R-008"), "mass modification must fire; got \(rules)")
        XCTAssertNotNil(res.quarantinedPath, "canary should be quarantined")
        XCTAssertTrue(FileManager.default.fileExists(atPath: ws), "workspace still exists")
        // the quarantined file is inside the workspace's quarantine store
        XCTAssertTrue(res.quarantinedPath!.hasPrefix(ws))
    }

    func testSimulatorRefusesNonTemporaryWorkspace() throws {
        let dbDir = tempDir(); defer { try? FileManager.default.removeItem(atPath: dbDir) }
        let store = try EventStore(path: dbDir + "/events.db")
        XCTAssertThrowsError(try RansomwareSimulator.run(workspace: "/Users/rohanbhadiyadra/Documents/not-temp",
                                                         fileCount: 2, store: store))
    }
}
