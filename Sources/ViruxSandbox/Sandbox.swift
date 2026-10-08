import Foundation

/// Policy for one sandbox run. Defaults are conservative: no network, a short
/// observation window, one run at a time (enforced by the gate).
public struct SandboxPolicy: Sendable {
    public var maxObservationSeconds: TimeInterval
    public var allowNetwork: Bool
    public var resetBetweenRuns: Bool

    public init(maxObservationSeconds: TimeInterval = 120,
                allowNetwork: Bool = false,
                resetBetweenRuns: Bool = true) {
        self.maxObservationSeconds = maxObservationSeconds
        self.allowNetwork = allowNetwork
        self.resetBetweenRuns = resetBetweenRuns
    }

    public static let `default` = SandboxPolicy()
}

/// Behaviour captured during a sandbox run. A clean run is explicitly NOT a
/// certificate of safety.
public struct SandboxEvidence: Sendable {
    public var backendName: String
    public var durationSeconds: Double
    public var processes: [String]
    public var fileEvents: [String]
    public var networkEvents: [String]
    public var capturedArtifacts: [String]
    public var notes: [String]

    public init(backendName: String, durationSeconds: Double,
                processes: [String] = [], fileEvents: [String] = [],
                networkEvents: [String] = [], capturedArtifacts: [String] = [],
                notes: [String] = []) {
        self.backendName = backendName
        self.durationSeconds = durationSeconds
        self.processes = processes
        self.fileEvents = fileEvents
        self.networkEvents = networkEvents
        self.capturedArtifacts = capturedArtifacts
        self.notes = notes
    }
}

public enum SandboxOutcome: Sendable {
    case staticOnly(MachOFindings)
    case analyzed(MachOFindings, SandboxEvidence)
    case deferred(String)
    case failed(String)

    public var summary: String {
        switch self {
        case .staticOnly(let f):
            return "static-only (\(f.verdict.rawValue)): no VM needed"
        case .analyzed(let f, let e):
            return "sandboxed: static=\(f.verdict.rawValue), \(e.processes.count) proc, \(e.fileEvents.count) file, \(e.networkEvents.count) net"
        case .deferred(let r):
            return "deferred: \(r)"
        case .failed(let r):
            return "failed: \(r)"
        }
    }
}

/// A disposable VM backend. The real implementation uses Apple's
/// Virtualization framework; the mock is a test double ONLY.
public protocol SandboxBackend: AnyObject {
    var name: String { get }
    func prepare() throws
    func run(samplePath: String, policy: SandboxPolicy) throws -> SandboxEvidence
    func reset() throws
    func teardown() throws
}

// MARK: - Mock backend (test double, never used in production)

public final class MockSandboxBackend: SandboxBackend {
    public let name = "mock"
    public private(set) var prepareCount = 0
    public private(set) var runCount = 0
    public private(set) var resetCount = 0
    public var shouldThrowOnRun = false

    public init() {}

    public func prepare() throws { prepareCount += 1 }

    public func run(samplePath: String, policy: SandboxPolicy) throws -> SandboxEvidence {
        if shouldThrowOnRun { throw SandboxError.backendFailure("mock run failure") }
        runCount += 1
        return SandboxEvidence(
            backendName: name,
            durationSeconds: 0.01,
            processes: ["sample spawned 1 child"],
            fileEvents: ["created /tmp/mock.out"],
            networkEvents: [],
            capturedArtifacts: [],
            notes: ["MOCK evidence: not a real analysis, for tests only"])
    }

    public func reset() throws { resetCount += 1 }
    public func teardown() throws {}
}

// MARK: - Real backend (honest stub until a guest image is provisioned)

public enum SandboxError: Error, CustomStringConvertible {
    case backendFailure(String)
    case notProvisioned(String)

    public var description: String {
        switch self {
        case .backendFailure(let m): return m
        case .notProvisioned(let m): return m
        }
    }
}

/// The Virtualization.framework backend. It is deliberately NOT wired to boot a
/// guest yet: provisioning a macOS guest needs disk headroom this Mac does not
/// have (see docs/M4_SANDBOX_OPTIONS.md). It reports that honestly rather than
/// pretending to analyse.
public final class VirtualizationBackend: SandboxBackend {
    public let name = "virtualization"
    private let guestImagePath: String?

    public init(guestImagePath: String? = nil) { self.guestImagePath = guestImagePath }

    public func prepare() throws {
        guard let p = guestImagePath, FileManager.default.fileExists(atPath: p) else {
            throw SandboxError.notProvisioned(
                "no macOS guest image provisioned; VM detonation is gated on disk headroom. See docs/M4_SANDBOX_OPTIONS.md")
        }
    }
    public func run(samplePath: String, policy: SandboxPolicy) throws -> SandboxEvidence {
        throw SandboxError.notProvisioned(
            "guest execution not implemented in this build; see M4_REPORT.md for what is and is not done")
    }
    public func reset() throws {}
    public func teardown() throws {}
}

// MARK: - Coordinator

/// Static-first orchestrator. It always runs static analysis; it escalates to
/// the VM only when the static verdict is not clean AND the resource gate
/// allows. One run at a time; reset between runs; timeouts enforced by the
/// backend. Quarantine and sandbox stay separate: a negative sandbox verdict
/// never releases a quarantined item.
public final class SandboxCoordinator {
    private let backend: SandboxBackend
    private let gate: ResourceGate
    private let probe: ResourceProbe
    public let policy: SandboxPolicy
    public private(set) var activeRuns = 0
    public private(set) var vmRuns = 0
    public private(set) var staticOnlyRuns = 0

    public init(backend: SandboxBackend,
                gate: ResourceGate = ResourceGate(),
                probe: ResourceProbe = SystemResourceProbe(),
                policy: SandboxPolicy = .default) {
        self.backend = backend
        self.gate = gate
        self.probe = probe
        self.policy = policy
    }

    public var backendName: String { backend.name }

    public func currentResources() -> SystemResources { probe.sample() }

    public func analyze(samplePath: String) -> SandboxOutcome {
        let findings: MachOFindings
        do {
            findings = try MachOAnalyzer.analyze(path: samplePath)
        } catch {
            return .failed("static analysis failed: \(error)")
        }

        // Static-first: a clean static verdict does not warrant a VM run.
        if findings.verdict == .clean {
            staticOnlyRuns += 1
            return .staticOnly(findings)
        }

        let decision = gate.decide(resources: probe.sample(), activeRuns: activeRuns)
        guard decision.isAllowed else {
            if case .deferred(let reason) = decision { return .deferred(reason) }
            return .deferred("gate denied")
        }

        activeRuns += 1
        defer { activeRuns -= 1 }
        do {
            try backend.prepare()
            let evidence = try backend.run(samplePath: samplePath, policy: policy)
            if policy.resetBetweenRuns { try? backend.reset() }
            vmRuns += 1
            return .analyzed(findings, evidence)
        } catch {
            if policy.resetBetweenRuns { try? backend.reset() }
            return .failed("sandbox run failed: \(error)")
        }
    }
}
