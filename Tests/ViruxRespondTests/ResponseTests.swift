import XCTest
import Foundation
import Darwin
@testable import ViruxRespond
import ViruxCore

final class QuarantineTests: XCTestCase {
    var tmp: String!
    var store: EventStore!
    var qstore: QuarantineStore!
    var allowGate: MockAdminGate!
    var denyGate: MockAdminGate!

    override func setUpWithError() throws {
        tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("virux-q-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        store = try EventStore(path: (tmp as NSString).appendingPathComponent("e.db"))
        qstore = try QuarantineStore(directory: (tmp as NSString).appendingPathComponent("quarantine"), store: store)
        allowGate = MockAdminGate(allow: true)
        denyGate = MockAdminGate(allow: false)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: tmp)
    }

    private func makeExecutableSample(name: String = "evil") throws -> String {
        let p = (tmp as NSString).appendingPathComponent(name)
        try Data("#!/bin/sh\necho hi\n".utf8).write(to: URL(fileURLWithPath: p))
        _ = chmod(p, 0o755)
        return p
    }

    func testQuarantineMovesFileAndStripsExecBit() throws {
        let sample = try makeExecutableSample()
        let rec = try qstore.quarantine(filePath: sample, reason: "unit test", detectionID: 3)

        XCTAssertFalse(FileManager.default.fileExists(atPath: sample), "original must be gone")
        XCTAssertTrue(FileManager.default.fileExists(atPath: rec.quarantinePath), "file must be in store")
        XCTAssertNotNil(rec.sha256)
        XCTAssertEqual(rec.perms, 0o755)
        XCTAssertEqual(rec.status, .quarantined)

        // execute bit cleared
        let mode = (try FileManager.default.attributesOfItem(atPath: rec.quarantinePath)[.posixPermissions] as? NSNumber)?.intValue ?? 0
        XCTAssertEqual(mode & 0o111, 0, "execute bits must be cleared")

        // sidecar metadata written
        XCTAssertTrue(FileManager.default.fileExists(atPath: rec.quarantinePath + ".meta.json"))

        // audit recorded
        XCTAssertTrue(qstore.audit.recent().contains { $0.action == "quarantine" })
    }

    func testRestoreRequiresAdminAndReturnsFileVerbatim() throws {
        let sample = try makeExecutableSample()
        let rec = try qstore.quarantine(filePath: sample, reason: "t")
        let id = try XCTUnwrap(rec.id)

        XCTAssertThrowsError(try qstore.restore(id: id, gate: denyGate)) { err in
            guard case ResponseError.unauthorized = err else { return XCTFail("expected unauthorized") }
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: rec.quarantinePath), "denied restore must not move the file")

        let restored = try qstore.restore(id: id, gate: allowGate)
        XCTAssertEqual(restored.status, .restored)
        XCTAssertTrue(FileManager.default.fileExists(atPath: sample), "file must be back at original path")
        let mode = (try FileManager.default.attributesOfItem(atPath: sample)[.posixPermissions] as? NSNumber)?.intValue ?? 0
        XCTAssertEqual(mode, 0o755, "original permissions restored")
    }

    func testDeleteRequiresAdminAndRemovesFile() throws {
        let sample = try makeExecutableSample()
        let rec = try qstore.quarantine(filePath: sample, reason: "t")
        let id = try XCTUnwrap(rec.id)

        XCTAssertThrowsError(try qstore.delete(id: id, gate: denyGate))
        XCTAssertTrue(FileManager.default.fileExists(atPath: rec.quarantinePath))

        let deleted = try qstore.delete(id: id, gate: allowGate)
        XCTAssertEqual(deleted.status, .deleted)
        XCTAssertFalse(FileManager.default.fileExists(atPath: rec.quarantinePath))
    }

    func testCannotRestoreTwice() throws {
        let sample = try makeExecutableSample()
        let rec = try qstore.quarantine(filePath: sample, reason: "t")
        let id = try XCTUnwrap(rec.id)
        _ = try qstore.restore(id: id, gate: allowGate)
        XCTAssertThrowsError(try qstore.restore(id: id, gate: allowGate))
    }

    func testMissingFileThrows() {
        XCTAssertThrowsError(try qstore.quarantine(filePath: "/nonexistent/sample", reason: "t"))
    }
}

final class ResponseEngineTests: XCTestCase {
    var tmp: String!
    var store: EventStore!
    var qstore: QuarantineStore!
    var audit: AuditLog!

    override func setUpWithError() throws {
        tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("virux-r-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        store = try EventStore(path: (tmp as NSString).appendingPathComponent("e.db"))
        qstore = try QuarantineStore(directory: (tmp as NSString).appendingPathComponent("q"), store: store)
        audit = qstore.audit
    }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(atPath: tmp) }

    private func sample(_ name: String = "s") throws -> String {
        let p = (tmp as NSString).appendingPathComponent(name)
        try Data("x".utf8).write(to: URL(fileURLWithPath: p))
        return p
    }

    func testSeverityMapsToAction() {
        let engine = ResponseEngine(quarantineStore: qstore, terminator: MockProcessTerminator(), audit: audit)
        XCTAssertEqual(engine.decide(severity: .low, confidence: .high), .log)
        XCTAssertEqual(engine.decide(severity: .medium, confidence: .high), .log)
        XCTAssertEqual(engine.decide(severity: .high, confidence: .medium), .quarantine)
        XCTAssertEqual(engine.decide(severity: .critical, confidence: .medium), .quarantineAndTerminate)
    }

    func testHighSeverityQuarantines() throws {
        let p = try sample()
        let engine = ResponseEngine(quarantineStore: qstore, terminator: MockProcessTerminator(), audit: audit)
        let outcome = engine.apply(action: .quarantine, filePath: p, pid: nil, severity: .high, reason: "test")
        guard case .quarantined = outcome else { return XCTFail("expected quarantined, got \(outcome.summary)") }
        XCTAssertEqual(qstore.list(status: .quarantined).count, 1)
    }

    func testCriticalQuarantinesAndTerminates() throws {
        let p = try sample()
        let mock = MockProcessTerminator()
        let engine = ResponseEngine(quarantineStore: qstore, terminator: mock, audit: audit)
        let outcome = engine.apply(action: .quarantineAndTerminate, filePath: p, pid: 4242,
                                   severity: .critical, reason: "ransomware-like")
        guard case .quarantinedAndTerminated(_, let pid) = outcome else { return XCTFail("got \(outcome.summary)") }
        XCTAssertEqual(pid, 4242)
        XCTAssertEqual(mock.terminatedPIDs, [4242])
    }

    func testSystemPathIsAllowlisted() throws {
        let engine = ResponseEngine(quarantineStore: qstore, terminator: MockProcessTerminator(), audit: audit)
        let outcome = engine.apply(action: .quarantine, filePath: "/usr/bin/ssh", pid: nil, severity: .high, reason: "test")
        guard case .skipped = outcome else { return XCTFail("expected skipped, got \(outcome.summary)") }
        XCTAssertEqual(qstore.list().count, 0)
        XCTAssertTrue(audit.recent().contains { $0.action == "refuse-allowlisted" })
    }

    func testTrustedTeamIDIsAllowlisted() throws {
        let p = try sample()
        let policy = ResponsePolicy(trustedTeamIDs: ["APPLETEAM"])
        let engine = ResponseEngine(quarantineStore: qstore, terminator: MockProcessTerminator(), audit: audit, policy: policy)
        let outcome = engine.apply(action: .quarantine, filePath: p, pid: nil, severity: .high,
                                   reason: "test", teamID: "APPLETEAM")
        guard case .skipped = outcome else { return XCTFail("expected skipped") }
    }

    func testAntiMassQuarantineGuard() throws {
        let policy = ResponsePolicy(maxActionsPerWindow: 2, windowSeconds: 3600)
        let engine = ResponseEngine(quarantineStore: qstore, terminator: MockProcessTerminator(), audit: audit, policy: policy)
        for i in 0..<2 {
            _ = engine.apply(action: .quarantine, filePath: try sample("f\(i)"), pid: nil, severity: .high, reason: "t")
        }
        let third = engine.apply(action: .quarantine, filePath: try sample("f2"), pid: nil, severity: .high, reason: "t")
        guard case .skipped(let r) = third else { return XCTFail("expected rate-limited, got \(third.summary)") }
        XCTAssertTrue(r.contains("rate limit"))
        XCTAssertEqual(qstore.list(status: .quarantined).count, 2)
    }
}

final class TerminatorTests: XCTestCase {
    func testTerminatesARealProcess() throws {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/sleep")
        proc.arguments = ["30"]
        try proc.run()
        let pid = proc.processIdentifier
        XCTAssertTrue(pid > 1)
        XCTAssertEqual(kill(pid, 0), 0, "process should be running")

        let ok = SystemProcessTerminator().terminate(pid: pid, reason: "unit test")
        XCTAssertTrue(ok)
        XCTAssertNotEqual(kill(pid, 0), 0, "process should be gone after terminate")
        proc.waitUntilExit()
    }

    func testRefusesToSignalLaunchd() {
        XCTAssertFalse(SystemProcessTerminator().terminate(pid: 1, reason: "safety"))
        XCTAssertFalse(SystemProcessTerminator().terminate(pid: 0, reason: "safety"))
    }
}
