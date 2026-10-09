import Foundation
import ViruxCore

/// Decoy (canary) files. Nothing legitimate should ever modify them, so a touch
/// is a high-confidence signal of destructive behaviour. Ransomware typically
/// enumerates and encrypts everything in reach, canaries included.
public struct CanaryFile: Codable, Sendable, Hashable {
    public var path: String
    public var expectedHash: String
    public var createdAt: Date
}

public enum CanaryStatus: Sendable, Equatable {
    case intact
    case modified(reason: String)
    case missing
}

public struct CanaryFinding: Sendable {
    public var canary: CanaryFile
    public var status: CanaryStatus
}

public final class CanaryManager {
    public let manifestPath: String
    public private(set) var canaries: [CanaryFile] = []

    public static let defaultNames = [
        "DO_NOT_DELETE_virux_canary.dat",
        "~$virux_canary.docx",
        "virux_canary_backup.dat",
    ]

    public init(manifestPath: String) {
        self.manifestPath = manifestPath
        load()
    }

    public var paths: Set<String> { Set(canaries.map { $0.path }) }

    /// Plants canary files in a directory. Existing canaries are left intact.
    @discardableResult
    public func plant(inDirectory dir: String, names: [String] = CanaryManager.defaultNames) throws -> [CanaryFile] {
        var planted: [CanaryFile] = []
        for name in names {
            let path = (dir as NSString).appendingPathComponent(name)
            if FileManager.default.fileExists(atPath: path) {
                if let existing = canaries.first(where: { $0.path == path }) {
                    planted.append(existing)
                    continue
                }
            }
            // Harmless, unique content so the hash is meaningful.
            let content = "VIRUX CANARY (decoy file, safe to delete)\n\(UUID().uuidString)\n\(Date())\n"
            let data = Data(content.utf8)
            try data.write(to: URL(fileURLWithPath: path))
            let hash = Hashing.sha256(of: data)
            var created = CanaryFile(path: path, expectedHash: hash, createdAt: Date())
            created.expectedHash = hash
            canaries.removeAll { $0.path == path }
            canaries.append(created)
            planted.append(created)
        }
        save()
        return planted
    }

    public func check() -> [CanaryFinding] {
        canaries.map { c in
            guard FileManager.default.fileExists(atPath: c.path) else {
                return CanaryFinding(canary: c, status: .missing)
            }
            guard let hash = Hashing.sha256(ofFileAt: c.path) else {
                return CanaryFinding(canary: c, status: .modified(reason: "unreadable"))
            }
            return hash == c.expectedHash
                ? CanaryFinding(canary: c, status: .intact)
                : CanaryFinding(canary: c, status: .modified(reason: "content hash changed"))
        }
    }

    public func forget(path: String) {
        canaries.removeAll { $0.path == path }
        save()
    }

    // MARK: - Persistence

    private func save() {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        if let data = try? enc.encode(canaries) {
            try? data.write(to: URL(fileURLWithPath: manifestPath))
        }
    }

    private func load() {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: manifestPath)) else { return }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        canaries = (try? dec.decode([CanaryFile].self, from: data)) ?? []
    }
}
