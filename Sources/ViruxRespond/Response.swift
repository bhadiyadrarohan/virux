import Foundation
import Darwin
import Security
import ViruxCore

/// Administrator authorisation for sensitive actions. Default implementations
/// deny; the real one uses Authorization Services (the OS admin prompt).
public protocol AdminGate {
    func authorize(reason: String) -> Bool
}

/// Test double. Never used in production paths.
public final class MockAdminGate: AdminGate {
    public var allow: Bool
    public init(allow: Bool) { self.allow = allow }
    public func authorize(reason: String) -> Bool { allow }
}

/// Real gate: presents the macOS administrator authentication dialog via
/// Authorization Services. Fails closed (returns false) if it cannot prompt.
public final class SecurityAdminGate: AdminGate {
    public init() {}

    public func authorize(reason: String) -> Bool {
        var authRef: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &authRef) == errAuthorizationSuccess,
              let auth = authRef else { return false }
        defer { AuthorizationFree(auth, [.destroyRights]) }

        guard let rightName = strdup("system.privilege.admin") else { return false }
        defer { free(rightName) }

        // The AuthorizationItem must outlive the AuthorizationCopyRights call,
        // so allocate it on the heap rather than passing a temporary.
        let itemsPtr = UnsafeMutablePointer<AuthorizationItem>.allocate(capacity: 1)
        defer { itemsPtr.deallocate() }
        itemsPtr.initialize(to: AuthorizationItem(name: rightName, valueLength: 0, value: nil, flags: 0))
        defer { itemsPtr.deinitialize(count: 1) }

        var rights = AuthorizationRights(count: 1, items: itemsPtr)
        let flags: AuthorizationFlags = [.interactionAllowed, .extendRights, .preAuthorize]
        let status = AuthorizationCopyRights(auth, &rights, nil, flags, nil)
        return status == errAuthorizationSuccess
    }
}

/// Terminates a process. Sends SIGTERM, waits briefly, then SIGKILL.
public protocol ProcessTerminator {
    func terminate(pid: Int32, reason: String) -> Bool
}

public final class SystemProcessTerminator: ProcessTerminator {
    public init() {}

    public func terminate(pid: Int32, reason: String) -> Bool {
        guard pid > 1 else { return false }          // never signal launchd/0
        guard kill(pid, SIGTERM) == 0 else { return false }
        for _ in 0..<20 {
            usleep(50_000)
            if kill(pid, 0) != 0 { return true }     // process is gone
        }
        _ = kill(pid, SIGKILL)
        usleep(100_000)
        return kill(pid, 0) != 0
    }
}

public final class MockProcessTerminator: ProcessTerminator {
    public private(set) var terminatedPIDs: [Int32] = []
    public var returnsSuccess = true
    public init() {}
    public func terminate(pid: Int32, reason: String) -> Bool {
        terminatedPIDs.append(pid)
        return returnsSuccess
    }
}

public struct ResponsePolicy: Sendable {
    /// Paths whose contents are never touched by automatic response.
    public var systemPrefixes: [String]
    /// Team identifiers whose signed software is trusted and never auto-quarantined.
    public var trustedTeamIDs: Set<String>
    /// Anti-mass-quarantine guard: max automatic actions per window.
    public var maxActionsPerWindow: Int
    public var windowSeconds: TimeInterval
    public var enableProcessTermination: Bool

    public init(systemPrefixes: [String] = ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/"],
                trustedTeamIDs: Set<String> = [],
                maxActionsPerWindow: Int = 20,
                windowSeconds: TimeInterval = 60,
                enableProcessTermination: Bool = true) {
        self.systemPrefixes = systemPrefixes
        self.trustedTeamIDs = trustedTeamIDs
        self.maxActionsPerWindow = maxActionsPerWindow
        self.windowSeconds = windowSeconds
        self.enableProcessTermination = enableProcessTermination
    }
}

public enum ResponseAction: String, Sendable {
    case none, log, quarantine, quarantineAndTerminate
}

public enum ResponseOutcome: Sendable {
    case logged
    case skipped(String)
    case quarantined(QuarantineRecord)
    case quarantinedAndTerminated(QuarantineRecord, pid: Int32)
    case failed(String)

    public var summary: String {
        switch self {
        case .logged: return "observed (no action)"
        case .skipped(let r): return "skipped: \(r)"
        case .quarantined(let q): return "quarantined #\(q.id ?? 0): \(q.originalPath)"
        case .quarantinedAndTerminated(let q, let pid): return "quarantined #\(q.id ?? 0) + terminated pid \(pid)"
        case .failed(let r): return "failed: \(r)"
        }
    }
}

/// Maps severity/confidence to a response action, then performs it with
/// safety rails: system allowlist, anti-mass-quarantine rate limit, and an
/// audit entry for everything including refusals.
public final class ResponseEngine {
    private let quarantineStore: QuarantineStore
    private let terminator: ProcessTerminator
    private let audit: AuditLog
    public let policy: ResponsePolicy
    private var actionTimes: [Date] = []

    public init(quarantineStore: QuarantineStore,
                terminator: ProcessTerminator,
                audit: AuditLog,
                policy: ResponsePolicy = ResponsePolicy()) {
        self.quarantineStore = quarantineStore
        self.terminator = terminator
        self.audit = audit
        self.policy = policy
    }

    public func decide(severity: Severity, confidence: Confidence) -> ResponseAction {
        switch severity {
        case .critical: return policy.enableProcessTermination ? .quarantineAndTerminate : .quarantine
        case .high: return .quarantine
        case .medium, .low, .none: return .log
        }
    }

    @discardableResult
    public func apply(action: ResponseAction, filePath: String?, pid: Int32?,
                      severity: Severity, reason: String, detectionID: Int64? = nil,
                      signingID: String? = nil, teamID: String? = nil) -> ResponseOutcome {
        guard action == .quarantine || action == .quarantineAndTerminate else {
            audit.record(action: "observe", actor: "system", target: filePath,
                         detail: "no action (severity \(severity.rawValue))")
            return .logged
        }
        guard let path = filePath else {
            audit.record(action: "containment", actor: "system", target: nil,
                         detail: "no file path to quarantine", ok: false)
            return .failed("no file path to quarantine")
        }
        if isAllowlisted(path: path, teamID: teamID) {
            audit.record(action: "refuse-allowlisted", actor: "system", target: path,
                         detail: "protected system path or trusted signer", ok: false)
            return .skipped("allowlisted: \(path)")
        }
        if isRateLimited(now: Date()) {
            audit.record(action: "refuse-rate-limit", actor: "system", target: path,
                         detail: "over \(policy.maxActionsPerWindow) actions in \(Int(policy.windowSeconds))s", ok: false)
            return .skipped("anti-mass-quarantine rate limit reached")
        }
        do {
            let rec = try quarantineStore.quarantine(filePath: path, reason: reason,
                                                     detectionID: detectionID, signingID: signingID,
                                                     teamID: teamID, actor: "system")
            actionTimes.append(Date())
            if action == .quarantineAndTerminate, let pid = pid {
                let ok = terminator.terminate(pid: pid, reason: reason)
                audit.record(action: "terminate", actor: "system", target: "pid \(pid)",
                             detail: reason, ok: ok)
                if ok { return .quarantinedAndTerminated(rec, pid: pid) }
            }
            return .quarantined(rec)
        } catch {
            audit.record(action: "quarantine", actor: "system", target: path,
                         detail: "failed: \(error)", ok: false)
            return .failed("\(error)")
        }
    }

    private func isAllowlisted(path: String, teamID: String?) -> Bool {
        if policy.systemPrefixes.contains(where: { path.hasPrefix($0) }) { return true }
        if let t = teamID, policy.trustedTeamIDs.contains(t) { return true }
        return false
    }

    private func isRateLimited(now: Date) -> Bool {
        actionTimes.removeAll { now.timeIntervalSince($0) > policy.windowSeconds }
        return actionTimes.count >= policy.maxActionsPerWindow
    }
}
