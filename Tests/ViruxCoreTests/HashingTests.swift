import XCTest
@testable import ViruxCore

final class HashingTests: XCTestCase {
    func testSHA256KnownVector() {
        XCTAssertEqual(
            Hashing.sha256(of: Data("abc".utf8)),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
    }

    func testSHA256OfFile() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("virux-hash-\(UUID().uuidString).txt")
        try Data("abc".utf8).write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }
        XCTAssertEqual(
            Hashing.sha256(ofFileAt: tmp.path),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
    }

    func testSHA256MissingFileIsNil() {
        XCTAssertNil(Hashing.sha256(ofFileAt: "/nonexistent/virux/file"))
    }
}