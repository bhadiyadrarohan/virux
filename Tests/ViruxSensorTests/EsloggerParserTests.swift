import XCTest
@testable import ViruxSensor
import ViruxCore

final class EsloggerParserTests: XCTestCase {

    func testParsesExecEvent() {
        let line = """
        {"event_type":"exec","time":"2026-10-08T10:00:00.123456Z","process":{"audit_token":{"pid":4321,"ppid":1},"executable":{"path":"/bin/ls"},"signing_id":"com.apple.ls","team_id":null},"event":{"exec":{"image":{"path":"/bin/ls"}}}}
        """
        let e = try? XCTUnwrap(EsloggerParser.parse(line: line))
        XCTAssertEqual(e?.kind, .exec)
        XCTAssertEqual(e?.process.pid, 4321)
        XCTAssertEqual(e?.process.ppid, 1)
        XCTAssertEqual(e?.process.executablePath, "/bin/ls")
        XCTAssertEqual(e?.process.signingID, "com.apple.ls")
        XCTAssertEqual(e?.source, "eslogger")
    }

    func testParsesOpenEventWithPath() {
        let line = """
        {"event_type":"open","time":"2026-10-08T10:00:01Z","process":{"audit_token":{"pid":99},"executable":{"path":"/usr/bin/cat"}},"event":{"open":{"file":{"path":"/etc/hosts"}}}}
        """
        let e = EsloggerParser.parse(line: line)
        XCTAssertEqual(e?.kind, .open)
        XCTAssertEqual(e?.filePath, "/etc/hosts")
    }

    func testUnknownKindDegradesGracefully() {
        let line = """
        {"event_type":"something_new","process":{"audit_token":{"pid":5}},"event":{"something_new":{}}}
        """
        let e = EsloggerParser.parse(line: line)
        XCTAssertEqual(e?.kind, .unknown)
        XCTAssertEqual(e?.process.pid, 5)
    }

    func testMalformedLineReturnsNil() {
        XCTAssertNil(EsloggerParser.parse(line: "not json at all"))
        XCTAssertNil(EsloggerParser.parse(line: "{}"))
    }

    func testSynthAdapterEmits() {
        let exp = expectation(description: "emits")
        exp.assertForOverFulfill = false
        let synth = SynthAdapter(interval: 0.05, limit: 3)
        synth.start(onEvent: { e in
            XCTAssertEqual(e.source, "synth")
            XCTAssertEqual(e.extra["synthetic"], "true")
            exp.fulfill()
        }, onError: { _ in })
        wait(for: [exp], timeout: 2)
        synth.stop()
    }
}