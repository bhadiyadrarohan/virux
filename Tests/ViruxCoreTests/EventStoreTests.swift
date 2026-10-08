import XCTest
@testable import ViruxCore

final class EventStoreTests: XCTestCase {
    var path: String!

    override func setUpWithError() throws {
        path = FileManager.default.temporaryDirectory
            .appendingPathComponent("virux-store-\(UUID().uuidString).db").path
    }
    override func tearDownWithError() throws {
        for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + suffix) }
    }

    private func makeEvent(kind: EventKind, pid: Int32, hash: String? = nil) -> SecurityEvent {
        SecurityEvent(kind: kind,
                      process: ProcessRef(pid: pid, ppid: 1, executablePath: "/bin/ls",
                                          signingID: "com.apple.ls", teamID: nil),
                      filePath: "/tmp/x", fileHash: hash,
                      severity: .none, confidence: .low, source: "test",
                      extra: ["k": "v"])
    }

    func testInsertAndCount() throws {
        let store = try EventStore(path: path)
        XCTAssertEqual(store.count(), 0)
        try store.insert(makeEvent(kind: .exec, pid: 42))
        try store.insert(makeEvent(kind: .open, pid: 43, hash: "deadbeef"))
        XCTAssertEqual(store.count(), 2)
    }

    func testRecentOrderingAndFields() throws {
        let store = try EventStore(path: path)
        try store.insert(makeEvent(kind: .exec, pid: 1))
        try store.insert(makeEvent(kind: .open, pid: 2, hash: "abc123"))
        let rows = store.recent(limit: 10)
        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows[0].kind, .open)          // newest first
        XCTAssertEqual(rows[0].process.pid, 2)
        XCTAssertEqual(rows[0].fileHash, "abc123")
        XCTAssertEqual(rows[0].extra["k"], "v")
        XCTAssertEqual(rows[1].kind, .exec)
    }

    func testCountByKindAndPurge() throws {
        let store = try EventStore(path: path)
        for _ in 0..<3 { try store.insert(makeEvent(kind: .exec, pid: 9)) }
        try store.insert(makeEvent(kind: .close, pid: 9))
        let counts = Dictionary(uniqueKeysWithValues: store.countByKind())
        XCTAssertEqual(counts["exec"], 3)
        XCTAssertEqual(counts["close"], 1)

        // Purge with a negative horizon removes nothing; a future horizon removes all.
        XCTAssertEqual(try store.purge(olderThanDays: 3650), 0)
        XCTAssertEqual(try store.purge(olderThanDays: -1), 4)
        XCTAssertEqual(store.count(), 0)
    }

    func testRetentionPolicy() {
        let p = RetentionPolicy(eventRetentionDays: 90, maxStoreBytes: 1000, minKeepRows: 10)
        XCTAssertTrue(p.shouldPurgeForSize(currentBytes: 2000, currentRows: 50))
        XCTAssertFalse(p.shouldPurgeForSize(currentBytes: 2000, currentRows: 5))   // below min keep
        XCTAssertFalse(p.shouldPurgeForSize(currentBytes: 500, currentRows: 50))
    }
}