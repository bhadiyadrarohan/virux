import Foundation
import Darwin
import ViruxCore

public enum ResponseError: Error, CustomStringConvertible {
    case unauthorized(String)
    case notFound(String)
    case alreadyResolved(String)
    case io(String)

    public var description: String {
        switch self {
        case .unauthorized(let m): return "unauthorized: \(m)"
        case .notFound(let m): return "not found: \(m)"
        case .alreadyResolved(let m): return "already resolved: \(m)"
        case .io(let m): return "io error: \(m)"
        }
    }
}

/// Append-only trail of every enforcement action and user action. Writes to the
/// shared store; failures here never crash the caller.
public final class AuditLog {
    private let store: EventStore
    public init(store: EventStore) { self.store = store }

    @discardableResult
    public func record(action: String, actor: String, target: String? = nil,
                       detail: String? = nil, ok: Bool = true) -> Int64? {
        try? store.appendAudit(AuditEntry(action: action, actor: actor,
                                          target: target, detail: detail, ok: ok))
    }

    public func recent(limit: Int = 50) -> [AuditEntry] { store.recentAudit(limit: limit) }
}

/// Isolates files. Quarantine MOVES the file into a protected directory and
/// clears its execute bits, so it can no longer be run from its original path.
/// Nothing is ever deleted automatically; restore and delete are separate,
/// administrator-authorised actions.
public final class QuarantineStore {
    public let directory: String
    private let store: EventStore
    public let audit: AuditLog

    public init(directory: String, store: EventStore) throws {
        self.directory = directory
        self.store = store
        self.audit = AuditLog(store: store)
        try FileManager.default.createDirectory(atPath: directory,
                                                withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
    }

    @discardableResult
    public func quarantine(filePath: String, reason: String, detectionID: Int64? = nil,
                           signingID: String? = nil, teamID: String? = nil,
                           actor: String = "system") throws -> QuarantineRecord {
        let fm = FileManager.default
        guard fm.fileExists(atPath: filePath) else {
            audit.record(action: "quarantine", actor: actor, target: filePath,
                         detail: "file not found", ok: false)
            throw ResponseError.notFound(filePath)
        }
        let attrs = try? fm.attributesOfItem(atPath: filePath)
        let perms = (attrs?[.posixPermissions] as? NSNumber)?.intValue
        let size = (attrs?[.size] as? NSNumber)?.int64Value
        let hash = Hashing.sha256(ofFileAt: filePath)

        let dest = (directory as NSString)
            .appendingPathComponent("\(UUID().uuidString)-\((filePath as NSString).lastPathComponent)")
        do {
            try fm.moveItem(atPath: filePath, toPath: dest)
        } catch {
            audit.record(action: "quarantine", actor: actor, target: filePath,
                         detail: "move failed: \(error)", ok: false)
            throw ResponseError.io("move failed: \(error)")
        }
        // Clear execute bits so it cannot be launched from the store.
        _ = chmod(dest, mode_t((perms ?? 0o644) & ~0o111))

        var record = QuarantineRecord(timestamp: Date(), originalPath: filePath,
                                      quarantinePath: dest, sha256: hash, sizeBytes: size,
                                      reason: reason, detectionID: detectionID,
                                      signingID: signingID, teamID: teamID,
                                      perms: perms, status: .quarantined)
        record.id = try store.insertQuarantine(record)
        writeSidecar(record)
        audit.record(action: "quarantine", actor: actor, target: filePath,
                     detail: "moved to \(dest) sha256=\(hash ?? "?")")
        return record
    }

    public func list(status: QuarantineRecord.Status? = nil) -> [QuarantineRecord] {
        store.listQuarantine(status: status)
    }

    public func record(id: Int64) -> QuarantineRecord? { store.quarantine(id: id) }

    @discardableResult
    public func restore(id: Int64, gate: AdminGate) throws -> QuarantineRecord {
        guard let rec = store.quarantine(id: id) else { throw ResponseError.notFound("id \(id)") }
        guard rec.status == .quarantined else {
            throw ResponseError.alreadyResolved("status is \(rec.status.rawValue)")
        }
        guard gate.authorize(reason: "Restore \(rec.originalPath) from quarantine") else {
            audit.record(action: "authorize-denied", actor: "admin", target: rec.originalPath,
                         detail: "restore denied", ok: false)
            throw ResponseError.unauthorized("restore requires administrator authorization")
        }
        let fm = FileManager.default
        let parent = (rec.originalPath as NSString).deletingLastPathComponent
        if !parent.isEmpty { try? fm.createDirectory(atPath: parent, withIntermediateDirectories: true) }
        do {
            try fm.moveItem(atPath: rec.quarantinePath, toPath: rec.originalPath)
        } catch {
            audit.record(action: "restore", actor: "admin", target: rec.originalPath,
                         detail: "move failed: \(error)", ok: false)
            throw ResponseError.io("restore failed: \(error)")
        }
        if let p = rec.perms { _ = chmod(rec.originalPath, mode_t(p)) }
        try store.updateQuarantineStatus(id: id, status: .restored)
        removeSidecar(rec)
        audit.record(action: "restore", actor: "admin", target: rec.originalPath,
                     detail: "restored from quarantine")
        var out = rec; out.status = .restored; return out
    }

    @discardableResult
    public func delete(id: Int64, gate: AdminGate) throws -> QuarantineRecord {
        guard let rec = store.quarantine(id: id) else { throw ResponseError.notFound("id \(id)") }
        guard rec.status == .quarantined else {
            throw ResponseError.alreadyResolved("status is \(rec.status.rawValue)")
        }
        guard gate.authorize(reason: "Permanently delete quarantined file \(rec.originalPath)") else {
            audit.record(action: "authorize-denied", actor: "admin", target: rec.originalPath,
                         detail: "delete denied", ok: false)
            throw ResponseError.unauthorized("delete requires administrator authorization")
        }
        try? FileManager.default.removeItem(atPath: rec.quarantinePath)
        removeSidecar(rec)
        try store.updateQuarantineStatus(id: id, status: .deleted)
        audit.record(action: "delete", actor: "admin", target: rec.originalPath,
                     detail: "quarantined file permanently deleted")
        var out = rec; out.status = .deleted; return out
    }

    // MARK: - Sidecar metadata (survives DB loss)

    private func sidecarPath(_ rec: QuarantineRecord) -> String { rec.quarantinePath + ".meta.json" }

    private func writeSidecar(_ rec: QuarantineRecord) {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        if let data = try? enc.encode(rec) { try? data.write(to: URL(fileURLWithPath: sidecarPath(rec))) }
    }

    private func removeSidecar(_ rec: QuarantineRecord) {
        try? FileManager.default.removeItem(atPath: sidecarPath(rec))
    }
}
