import Foundation
import Darwin
import ViruxCore

public struct VolumeInfo: Sendable, Hashable {
    public var path: String
    public var name: String
    public var isRemovable: Bool
    public var isInternal: Bool
    public var totalBytes: Int64
    public var freeBytes: Int64

    public init(path: String, name: String, isRemovable: Bool, isInternal: Bool,
                totalBytes: Int64, freeBytes: Int64) {
        self.path = path
        self.name = name
        self.isRemovable = isRemovable
        self.isInternal = isInternal
        self.totalBytes = totalBytes
        self.freeBytes = freeBytes
    }
}

public struct VolumeArtifact: Sendable {
    public var path: String
    public var kind: String
    public var suspicious: Bool
    public var reason: String
}

public struct VolumeScanReport: Sendable {
    public var volume: VolumeInfo
    public var scannedAt: Date
    public var entriesSeen: Int
    public var executables: [String]
    public var artifacts: [VolumeArtifact]
    public var truncated: Bool
    public var durationSeconds: Double

    public var suspiciousArtifacts: [VolumeArtifact] { artifacts.filter { $0.suspicious } }
}

public enum VolumeLister {
    public static func mounted() -> [VolumeInfo] {
        let keys: [URLResourceKey] = [.volumeNameKey, .volumeIsRemovableKey, .volumeIsInternalKey,
                                      .volumeTotalCapacityKey, .volumeAvailableCapacityKey]
        let urls = FileManager.default.mountedVolumeURLs(includingResourceValuesForKeys: keys,
                                                         options: [.skipHiddenVolumes]) ?? []
        return urls.compactMap { url in
            guard let rv = try? url.resourceValues(forKeys: Set(keys)) else { return nil }
            return VolumeInfo(path: url.path,
                              name: rv.volumeName ?? url.lastPathComponent,
                              isRemovable: rv.volumeIsRemovable ?? false,
                              isInternal: rv.volumeIsInternal ?? true,
                              totalBytes: Int64(rv.volumeTotalCapacity ?? 0),
                              freeBytes: Int64(rv.volumeAvailableCapacity ?? 0))
        }
    }
}

/// Detects volumes appearing and disappearing between two samples.
public enum VolumeWatcher {
    public static func diff(previous: [VolumeInfo], current: [VolumeInfo])
        -> (added: [VolumeInfo], removed: [VolumeInfo]) {
        let prev = Set(previous.map { $0.path })
        let curr = Set(current.map { $0.path })
        return (current.filter { !prev.contains($0.path) }, previous.filter { !curr.contains($0.path) })
    }
}

/// A deliberately light, bounded look at a newly connected volume. It does NOT
/// perform a full-volume scan: it walks to a small depth with hard limits on
/// entries and time, flagging only the things a Mac should never see on a
/// removable drive (Windows autorun, shortcuts, hidden payloads).
public final class OnConnectScanner {
    public struct Config: Sendable {
        public var maxEntries: Int
        public var maxSeconds: TimeInterval
        public var maxDepth: Int
        public init(maxEntries: Int = 4000, maxSeconds: TimeInterval = 5, maxDepth: Int = 2) {
            self.maxEntries = maxEntries
            self.maxSeconds = maxSeconds
            self.maxDepth = maxDepth
        }
    }

    public let config: Config
    public init(config: Config = Config()) { self.config = config }

    private static let benignHidden: Set<String> = [".DS_Store", ".Trashes", ".Spotlight-V100",
                                                    ".fseventsd", ".TemporaryItems",
                                                    ".DocumentRevisions-V100", ".VolumeIcon.icns",
                                                    ".metadata_never_index", ".com.apple.timemachine.donotpresent"]

    public func scan(volume: VolumeInfo) -> VolumeScanReport {
        let start = Date()
        var entries = 0
        var executables: [String] = []
        var artifacts: [VolumeArtifact] = []
        var truncated = false

        let fm = FileManager.default
        var queue: [(String, Int)] = [(volume.path, 0)]

        while let (dir, depth) = queue.first {
            queue.removeFirst()
            if depth > config.maxDepth { continue }
            if entries >= config.maxEntries || Date().timeIntervalSince(start) > config.maxSeconds {
                truncated = true
                break
            }
            let names = (try? fm.contentsOfDirectory(atPath: dir)) ?? []
            for name in names {
                entries += 1
                if entries >= config.maxEntries { truncated = true; break }
                let full = (dir as NSString).appendingPathComponent(name)
                let lower = name.lowercased()
                var isDir: ObjCBool = false
                _ = fm.fileExists(atPath: full, isDirectory: &isDir)

                if name == "autorun.inf" {
                    artifacts.append(VolumeArtifact(path: full, kind: "autorun", suspicious: true,
                                                    reason: "Windows autorun file on a Mac volume"))
                } else if lower.hasSuffix(".lnk") || lower.hasSuffix(".url") {
                    artifacts.append(VolumeArtifact(path: full, kind: "windows-shortcut", suspicious: true,
                                                    reason: "Windows shortcut, unusual on macOS"))
                } else if depth == 0, lower.hasSuffix(".command") || lower.hasSuffix(".sh")
                            || lower.hasSuffix(".scpt") || lower.hasSuffix(".app") || lower.hasSuffix(".pkg") {
                    artifacts.append(VolumeArtifact(path: full, kind: "executable-payload", suspicious: true,
                                                    reason: "executable payload at the volume root"))
                } else if name.hasPrefix(".") && !Self.benignHidden.contains(name) {
                    let attrs = try? fm.attributesOfItem(atPath: full)
                    let posix = (attrs?[.posixPermissions] as? NSNumber)?.intValue ?? 0
                    if posix & 0o111 != 0 {
                        artifacts.append(VolumeArtifact(path: full, kind: "hidden-executable", suspicious: true,
                                                        reason: "hidden item with execute permission"))
                    }
                }

                let attrs = try? fm.attributesOfItem(atPath: full)
                let posix = (attrs?[.posixPermissions] as? NSNumber)?.intValue ?? 0
                if !isDir.boolValue, posix & 0o111 != 0 {
                    executables.append(full)
                }
                if isDir.boolValue, depth < config.maxDepth { queue.append((full, depth + 1)) }
            }
        }

        return VolumeScanReport(volume: volume, scannedAt: Date(), entriesSeen: entries,
                                executables: executables, artifacts: artifacts,
                                truncated: truncated,
                                durationSeconds: Date().timeIntervalSince(start))
    }
}
