import Foundation
import ViruxCore

/// Groups the files that telemetry shows were touched, so an incident report
/// can state "what might be affected" without scanning the disk again.
public struct ImpactSummary: Sendable {
    public var affectedFiles: [String]
    public var byDirectory: [(String, Int)]
    public var byExtension: [(String, Int)]

    public var totalAffected: Int { affectedFiles.count }
}

public enum ImpactTracker {
    public static func summarize(events: [SecurityEvent], limit: Int = 5000) -> ImpactSummary {
        var files: [String] = []
        var seen = Set<String>()
        for e in events where e.filePath != nil {
            guard let p = e.filePath, !seen.contains(p) else { continue }
            seen.insert(p)
            files.append(p)
            if files.count >= limit { break }
        }

        var dirCount: [String: Int] = [:]
        var extCount: [String: Int] = [:]
        for f in files {
            let dir = (f as NSString).deletingLastPathComponent
            dirCount[dir, default: 0] += 1
            let ext = (f as NSString).pathExtension.lowercased()
            extCount[ext.isEmpty ? "(none)" : ext, default: 0] += 1
        }
        return ImpactSummary(affectedFiles: files,
                             byDirectory: dirCount.sorted { $0.value > $1.value }.map { ($0.key, $0.value) },
                             byExtension: extCount.sorted { $0.value > $1.value }.map { ($0.key, $0.value) })
    }
}
