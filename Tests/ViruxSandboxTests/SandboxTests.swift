import XCTest
import Foundation
@testable import ViruxSandbox

// MARK: - Helpers

private func appendU32(_ data: inout Data, _ value: UInt32) {
    var le = value.littleEndian
    withUnsafeBytes(of: &le) { data.append(contentsOf: $0) }
}

/// Builds a minimal Mach-O 64-bit (arm64) header, optionally with a
/// LC_CODE_SIGNATURE load command, and optional trailing ASCII payload.
private func makeMachO(signed: Bool, fileType: UInt32 = 2, trailing: String = "") -> Data {
    var d = Data()
    appendU32(&d, 0xFEEDFACF)          // magic (MH_MAGIC_64)
    appendU32(&d, 0x0100000C)          // cputype arm64
    appendU32(&d, 0)                   // cpusubtype
    appendU32(&d, fileType)            // filetype
    appendU32(&d, signed ? 1 : 0)      // ncmds
    appendU32(&d, signed ? 16 : 0)     // sizeofcmds
    appendU32(&d, 0)                   // flags
    appendU32(&d, 0)                   // reserved
    if signed {
        appendU32(&d, 0x1D)            // LC_CODE_SIGNATURE
        appendU32(&d, 16)              // cmdsize
        appendU32(&d, 0)               // dataoff
        appendU32(&d, 0)               // datasize
    }
    d.append(contentsOf: Array(trailing.utf8))
    return d
}

private func writeTemp(_ data: Data, name: String = UUID().uuidString) throws -> String {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("virux-sbx-\(name)")
    try data.write(to: url)
    return url.path
}

private final class FakeProbe: ResourceProbe {
    var resources: SystemResources
    init(memoryGB: Double = 16, diskGB: Double = 100) {
        resources = SystemResources(freeMemoryBytes: UInt64(memoryGB * 1_073_741_824),
                                    freeDiskBytes: UInt64(diskGB * 1_073_741_824))
    }
    func sample() -> SystemResources { resources }
}

// MARK: - Mach-O analysis

final class MachOAnalyzerTests: XCTestCase {
    func testSignedMachOParsesAndIsClean() throws {
        let path = try writeTemp(makeMachO(signed: true))
        let f = try MachOAnalyzer.analyze(path: path)
        XCTAssertTrue(f.isMachO)
        XCTAssertEqual(f.architectures, ["arm64"])
        XCTAssertEqual(f.fileType, "MH_EXECUTE")
        XCTAssertTrue(f.hasCodeSignature)
        XCTAssertEqual(f.verdict, .clean)
    }

    func testUnsignedMachOIsSuspicious() throws {
        let path = try writeTemp(makeMachO(signed: false))
        let f = try MachOAnalyzer.analyze(path: path)
        XCTAssertTrue(f.isMachO)
        XCTAssertFalse(f.hasCodeSignature)
        XCTAssertEqual(f.verdict, .suspicious)
        XCTAssertTrue(f.reasons.contains { $0.contains("code signature") })
    }

    func testSuspiciousStringsDetected() throws {
        let path = try writeTemp(makeMachO(signed: false, trailing: "run /bin/sh -c osascript -e 'x'"))
        let f = try MachOAnalyzer.analyze(path: path)
        XCTAssertTrue(f.suspiciousStrings.contains("/bin/sh"))
        XCTAssertTrue(f.suspiciousStrings.contains("osascript"))
    }

    func testNonMachOIsInconclusive() throws {
        let path = try writeTemp(Data("just a plain text file, nothing to see".utf8))
        let f = try MachOAnalyzer.analyze(path: path)
        XCTAssertFalse(f.isMachO)
        XCTAssertEqual(f.verdict, .inconclusive)
    }

    func testSystemBinaryIsMachOAndClean() throws {
        let f = try MachOAnalyzer.analyze(path: "/bin/ls")
        XCTAssertTrue(f.isMachO)
        XCTAssertFalse(f.architectures.isEmpty)
        XCTAssertEqual(Set(f.architectures).count, f.architectures.count, "architectures must be deduped")
        XCTAssertEqual(Set(f.linkedLibraries).count, f.linkedLibraries.count, "libs must be deduped")
        XCTAssertEqual(f.verdict, .clean, "a signed system binary must not be flagged suspicious")
    }

    func testUnreadableFileThrows() {
        XCTAssertThrowsError(try MachOAnalyzer.analyze(path: "/nonexistent/virux/sample"))
    }
}

// MARK: - Resource gate

final class ResourceGateTests: XCTestCase {
    private let gate = ResourceGate(config: GateConfig(
        minFreeMemoryBytes: UInt64(4 * 1_073_741_824),
        minFreeDiskBytes: UInt64(8 * 1_073_741_824),
        maxConcurrentRuns: 1))

    func testAllowsWhenPlenty() {
        XCTAssertTrue(gate.decide(resources: SystemResources(freeMemoryBytes: 12 * 1_073_741_824,
                                                             freeDiskBytes: 100 * 1_073_741_824),
                                  activeRuns: 0).isAllowed)
    }

    func testDefersOnLowMemory() {
        let d = gate.decide(resources: SystemResources(freeMemoryBytes: 2 * 1_073_741_824,
                                                       freeDiskBytes: 100 * 1_073_741_824), activeRuns: 0)
        XCTAssertFalse(d.isAllowed)
        if case .deferred(let r) = d { XCTAssertTrue(r.contains("memory")) } else { XCTFail() }
    }

    func testDefersOnLowDisk() {
        let d = gate.decide(resources: SystemResources(freeMemoryBytes: 12 * 1_073_741_824,
                                                       freeDiskBytes: 3 * 1_073_741_824), activeRuns: 0)
        XCTAssertFalse(d.isAllowed)
        if case .deferred(let r) = d { XCTAssertTrue(r.contains("disk")) } else { XCTFail() }
    }

    func testDefersWhenMaxConcurrentReached() {
        XCTAssertFalse(gate.decide(resources: SystemResources(freeMemoryBytes: 12 * 1_073_741_824,
                                                              freeDiskBytes: 100 * 1_073_741_824),
                                   activeRuns: 1).isAllowed)
    }
}

// MARK: - Coordinator (static-first)

final class SandboxCoordinatorTests: XCTestCase {

    func testCleanSampleIsStaticOnlyAndNeverStartsVM() throws {
        let path = try writeTemp(makeMachO(signed: true))
        let backend = MockSandboxBackend()
        let coord = SandboxCoordinator(backend: backend, probe: FakeProbe())
        let outcome = coord.analyze(samplePath: path)
        guard case .staticOnly(let f) = outcome else { return XCTFail("expected staticOnly, got \(outcome.summary)") }
        XCTAssertEqual(f.verdict, .clean)
        XCTAssertEqual(backend.prepareCount, 0, "VM must not start for a clean static verdict")
        XCTAssertEqual(coord.vmRuns, 0)
    }

    func testSuspiciousSampleRunsVMAndResets() throws {
        let path = try writeTemp(makeMachO(signed: false, trailing: "/bin/sh"))
        let backend = MockSandboxBackend()
        let coord = SandboxCoordinator(backend: backend, probe: FakeProbe())
        guard case .analyzed = coord.analyze(samplePath: path) else {
            return XCTFail("expected analyzed outcome")
        }
        XCTAssertEqual(backend.runCount, 1)
        XCTAssertEqual(backend.resetCount, 1, "guest must be reset between runs")
        XCTAssertEqual(coord.vmRuns, 1)
    }

    func testLowMemoryDefersWithoutStartingVM() throws {
        let path = try writeTemp(makeMachO(signed: false))
        let backend = MockSandboxBackend()
        let coord = SandboxCoordinator(backend: backend, probe: FakeProbe(memoryGB: 2))
        guard case .deferred(let reason) = coord.analyze(samplePath: path) else {
            return XCTFail("expected deferred outcome")
        }
        XCTAssertTrue(reason.contains("memory"))
        XCTAssertEqual(backend.runCount, 0)
    }

    func testBackendFailureIsReportedAndResetAttempted() throws {
        let path = try writeTemp(makeMachO(signed: false))
        let backend = MockSandboxBackend()
        backend.shouldThrowOnRun = true
        let coord = SandboxCoordinator(backend: backend, probe: FakeProbe())
        guard case .failed = coord.analyze(samplePath: path) else {
            return XCTFail("expected failed outcome")
        }
        XCTAssertEqual(backend.resetCount, 1)
    }

    func testRealBackendReportsNotProvisioned() throws {
        let path = try writeTemp(makeMachO(signed: false))
        let coord = SandboxCoordinator(backend: VirtualizationBackend(), probe: FakeProbe())
        guard case .failed(let msg) = coord.analyze(samplePath: path) else {
            return XCTFail("expected failed outcome from unprovisioned backend")
        }
        XCTAssertTrue(msg.contains("not provisioned") || msg.contains("guest"))
    }

    func testUnreadableSampleFailsGracefully() {
        let coord = SandboxCoordinator(backend: MockSandboxBackend(), probe: FakeProbe())
        guard case .failed = coord.analyze(samplePath: "/nonexistent/sample") else {
            return XCTFail("expected failed outcome")
        }
    }
}
