import Foundation

/// A quarantined file. The file is moved to a protected store and its execute
/// bit is cleared; the record keeps everything needed to restore it exactly and
/// to explain why it was taken. Quarantine NEVER deletes automatically.
public struct QuarantineRecord: Codable, Sendable {
    public enum Status: String, Codable, Sendable {
        case quarantined, restored, deleted
    }

    public var id: Int64?
    public var timestamp: Date
    public var originalPath: String
    public var quarantinePath: String
    public var sha256: String?
    public var sizeBytes: Int64?
    public var reason: String
    public var detectionID: Int64?
    public var signingID: String?
    public var teamID: String?
    /// Original POSIX permissions, so a restore puts them back verbatim.
    public var perms: Int?
    public var status: Status

    public init(id: Int64? = nil, timestamp: Date = Date(), originalPath: String,
                quarantinePath: String, sha256: String? = nil, sizeBytes: Int64? = nil,
                reason: String, detectionID: Int64? = nil, signingID: String? = nil,
                teamID: String? = nil, perms: Int? = nil, status: Status = .quarantined) {
        self.id = id
        self.timestamp = timestamp
        self.originalPath = originalPath
        self.quarantinePath = quarantinePath
        self.sha256 = sha256
        self.sizeBytes = sizeBytes
        self.reason = reason
        self.detectionID = detectionID
        self.signingID = signingID
        self.teamID = teamID
        self.perms = perms
        self.status = status
    }
}

/// One entry in the append-only audit trail. Every enforcement action and every
/// user action that changes state is recorded, successful or not.
public struct AuditEntry: Codable, Sendable {
    public var id: Int64?
    public var timestamp: Date
    /// e.g. "quarantine", "restore", "delete", "terminate", "refuse-allowlisted",
    /// "refuse-rate-limit", "authorize-denied".
    public var action: String
    /// "system" (automatic), "user", or "admin".
    public var actor: String
    public var target: String?
    public var detail: String?
    public var ok: Bool

    public init(id: Int64? = nil, timestamp: Date = Date(), action: String,
                actor: String, target: String? = nil, detail: String? = nil, ok: Bool = true) {
        self.id = id
        self.timestamp = timestamp
        self.action = action
        self.actor = actor
        self.target = target
        self.detail = detail
        self.ok = ok
    }
}
