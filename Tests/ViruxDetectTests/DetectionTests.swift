import XCTest
import CryptoKit
import ViruxCore
@testable import ViruxDetect

final class SignatureTests: XCTestCase {
    func testSignVerifyRoundTrip() throws {
        let (priv, pub) = SignatureSigner.generateKeyPair()
        let bundle = SignatureBundle(entries: [
            SignatureEntry(sha256: "ABC", name: "TestBad", severity: .high)
        ])
        let data = try SignatureSigner.sign(bundle, privateKey: priv)
        let opened = try SignatureSigner.open(data, publicKey: pub)
        XCTAssertEqual(opened.entries.count, 1)
        XCTAssertEqual(opened.entries[0].sha256, "abc") // normalised lowercase
        XCTAssertEqual(opened.entries[0].severity, .high)
    }

    func testTamperedPayloadFailsVerification() throws {
        let (priv, pub) = SignatureSigner.generateKeyPair()
        let data = try SignatureSigner.sign(SignatureBundle(entries: []), privateKey: priv)
        var obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        obj["payload"] = Data("{\"version\":9}".utf8).base64EncodedString()
        let tampered = try JSONSerialization.data(withJSONObject: obj)
        XCTAssertThrowsError(try SignatureSigner.open(tampered, publicKey: pub))
    }

    func testWrongKeyFailsVerification() throws {
        let (priv, _) = SignatureSigner.generateKeyPair()
        let (_, otherPub) = SignatureSigner.generateKeyPair()
        let data = try SignatureSigner.sign(SignatureBundle(entries: []), privateKey: priv)
        XCTAssertThrowsError(try SignatureSigner.open(data, publicKey: otherPub))
    }

    func testMatcherLookupIsCaseInsensitive() {
        let m = SignatureMatcher(bundle: SignatureBundle(entries: [
            SignatureEntry(sha256: "DEADBEEF", name: "x", severity: .critical)
        ]))
        XCTAssertEqual(m.lookup("deadbeef")?.name, "x")
        XCTAssertEqual(m.lookup("DEADBEEF")?.severity, .critical)
        XCTAssertEqual(m.count, 1)
    }
}

final class RuleEngineTests: XCTestCase {

    private func exec(pid: Int32, ppid: Int32?, path: String, signing: String? = nil) -> SecurityEvent {
        SecurityEvent(kind: .exec,
                      process: ProcessRef(pid: pid, ppid: ppid, executablePath: path, signingID: signing),
                      source: "test")
    }

    func testUnsignedExecutableFromTempFires() {
        let m = RuleEngine().evaluate(exec(pid: 1, ppid: 1, path: "/tmp/evil"))
        XCTAssertEqual(m?.ruleID, "R-002")
        XCTAssertEqual(m?.severity, .medium)
    }

    func testSignedSystemExecutableNoMatch() {
        XCTAssertNil(RuleEngine().evaluate(exec(pid: 1, ppid: 1, path: "/usr/bin/ls", signing: "com.apple.ls")))
    }

    func testHostAppSpawningShellFires() {
        let engine = RuleEngine()
        _ = engine.evaluate(exec(pid: 100, ppid: 1,
                                 path: "/Applications/Safari.app/Contents/MacOS/Safari",
                                 signing: "com.apple.Safari"))
        let child = exec(pid: 101, ppid: 100, path: "/bin/bash", signing: "com.apple.bash")
        XCTAssertEqual(engine.evaluate(child)?.ruleID, "R-003")
    }

    func testPersistenceWriteFires() {
        let e = SecurityEvent(kind: .open,
                              process: ProcessRef(pid: 5),
                              filePath: "/Library/LaunchDaemons/com.evil.plist",
                              source: "test")
        XCTAssertEqual(RuleEngine().evaluate(e)?.ruleID, "R-004")
    }

    func testMassRenameBurstFiresOnce() {
        let cfg = RuleEngine.Config(massRenameWindow: 10, massRenameThreshold: 3)
        let engine = RuleEngine(config: cfg)
        var last: RuleMatch?
        for i in 0..<3 {
            let e = SecurityEvent(kind: .rename, process: ProcessRef(pid: 9),
                                  filePath: "/Users/x/file\(i).locked", source: "test")
            last = engine.evaluate(e)
        }
        XCTAssertEqual(last?.ruleID, "R-005")
        XCTAssertEqual(last?.severity, .critical)
    }

    func testBelowThresholdNoMassRename() {
        let cfg = RuleEngine.Config(massRenameWindow: 10, massRenameThreshold: 5)
        let engine = RuleEngine(config: cfg)
        var match: RuleMatch?
        for i in 0..<3 {
            match = engine.evaluate(SecurityEvent(kind: .rename, process: ProcessRef(pid: 9),
                                                  filePath: "/Users/x/f\(i)", source: "test"))
        }
        XCTAssertNil(match)
    }

    func testMassRenameDeduplicatedByCooldown() {
        let cfg = RuleEngine.Config(massRenameWindow: 10, massRenameThreshold: 3, ruleCooldown: 60)
        let engine = RuleEngine(config: cfg)
        var fires = 0
        for i in 0..<6 {
            if engine.evaluate(SecurityEvent(kind: .rename, process: ProcessRef(pid: 9),
                                             filePath: "/Users/x/f\(i).locked", source: "test"))?.ruleID == "R-005" {
                fires += 1
            }
        }
        XCTAssertEqual(fires, 1, "R-005 should fire once per cooldown window, not per event")
    }
}

final class PipelineTests: XCTestCase {

    private func tempStore() throws -> EventStore {
        let db = FileManager.default.temporaryDirectory
            .appendingPathComponent("virux-pl-\(UUID().uuidString).db").path
        return try EventStore(path: db)
    }

    func testSignatureMatchProducesHighDetection() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("virux-plbin-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let bin = dir.appendingPathComponent("bin")
        try Data("abc".utf8).write(to: bin)
        let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

        let store = try tempStore()
        let matcher = SignatureMatcher(bundle: SignatureBundle(entries: [
            SignatureEntry(sha256: hash, name: "FixtureEvil", severity: .high)
        ]))
        let pipeline = DetectionPipeline(store: store, signatures: matcher, hashExecImages: true)

        var e = SecurityEvent(kind: .exec,
                              process: ProcessRef(pid: 7, executablePath: bin.path),
                              source: "test")
        e.id = try store.insert(e)
        let det = pipeline.process(e)
        XCTAssertEqual(det?.severity, .high)
        XCTAssertEqual(det?.confidence, .high)
        XCTAssertEqual(store.countDetections(), 1)
    }

    func testCleanSignedEventMakesNoDetection() throws {
        let store = try tempStore()
        let pipeline = DetectionPipeline(store: store)
        var e = SecurityEvent(kind: .exec,
                              process: ProcessRef(pid: 3, executablePath: "/usr/bin/ls",
                                                  signingID: "com.apple.ls"),
                              source: "test")
        e.id = try store.insert(e)
        XCTAssertNil(pipeline.process(e))
        XCTAssertEqual(store.countDetections(), 0)
    }

    func testRuleDetectionIsPersistedAndRetrievable() throws {
        let store = try tempStore()
        let pipeline = DetectionPipeline(store: store)
        var e = SecurityEvent(kind: .exec, process: ProcessRef(pid: 10, executablePath: "/tmp/dropper"),
                              source: "test")
        e.id = try store.insert(e)
        _ = pipeline.process(e)
        let rows = store.recentDetections(limit: 5)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0].status, .observed)
        XCTAssertFalse(rows[0].reason.isEmpty)
    }
}
