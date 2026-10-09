import Foundation
import ViruxCore

/// One autostart entity found on disk.
public struct PersistenceItem: Sendable, Hashable {
    public var path: String
    public var kind: String
    public var label: String?
    public var sha256: String?
    public var programArguments: [String]
    public var runAtLoad: Bool
    public var suspicious: Bool
    public var reasons: [String]

    public init(path: String, kind: String, label: String?, sha256: String?,
                programArguments: [String], runAtLoad: Bool,
                suspicious: Bool, reasons: [String]) {
        self.path = path
        self.kind = kind
        self.label = label
        self.sha256 = sha256
        self.programArguments = programArguments
        self.runAtLoad = runAtLoad
        self.suspicious = suspicious
        self.reasons = reasons
    }
}

public struct PersistenceSnapshot: Sendable {
    public var takenAt: Date
    public var items: [PersistenceItem]
    public func item(at path: String) -> PersistenceItem? { items.first { $0.path == path } }

    public init(takenAt: Date, items: [PersistenceItem]) {
        self.takenAt = takenAt
        self.items = items
    }
}

public enum PersistenceChangeKind: String, Sendable { case added, removed, changed }

public struct PersistenceChange: Sendable {
    public var kind: PersistenceChangeKind
    public var item: PersistenceItem

    public init(kind: PersistenceChangeKind, item: PersistenceItem) {
        self.kind = kind
        self.item = item
    }
}

public struct PersistenceAlert: Sendable {
    public var severity: Severity
    public var message: String
    public var item: PersistenceItem

    public init(severity: Severity, message: String, item: PersistenceItem) {
        self.severity = severity
        self.message = message
        self.item = item
    }
}

/// Tracks autostart locations (launch agents/daemons, startup items). It alerts
/// only on security-relevant changes and deduplicates so the user is not
/// spammed with the same notification (REQUIREMENTS: startup monitoring).
public final class PersistenceMonitor {
    public let directories: [String]
    private var alertedKeys: Set<String> = []

    public init(directories: [String]? = nil, home: String = NSHomeDirectory()) {
        self.directories = directories ?? [
            (home as NSString).appendingPathComponent("Library/LaunchAgents"),
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/Library/StartupItems",
        ]
    }

    public func scan() -> PersistenceSnapshot {
        var items: [PersistenceItem] = []
        for dir in directories {
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for n in names where n.hasSuffix(".plist") {
                items.append(parse(path: (dir as NSString).appendingPathComponent(n), kind: kindFor(dir)))
            }
        }
        items.sort { $0.path < $1.path }
        return PersistenceSnapshot(takenAt: Date(), items: items)
    }

    private func kindFor(_ dir: String) -> String {
        if dir.contains("LaunchAgents") { return "LaunchAgent" }
        if dir.contains("LaunchDaemons") { return "LaunchDaemon" }
        if dir.contains("StartupItems") { return "StartupItem" }
        return "Persistence"
    }

    private func parse(path: String, kind: String) -> PersistenceItem {
        var label: String?
        var args: [String] = []
        var runAtLoad = false
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
           let plist = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any] {
            label = plist["Label"] as? String
            args = (plist["ProgramArguments"] as? [String]) ?? []
            if let p = plist["Program"] as? String { args.insert(p, at: 0) }
            runAtLoad = (plist["RunAtLoad"] as? Bool) ?? false
        }
        let hash = Hashing.sha256(ofFileAt: path)
        var reasons: [String] = []
        let joined = args.joined(separator: " ")
        for marker in ["/tmp/", "/var/tmp/", "/private/tmp/", "/Downloads/"] where joined.contains(marker) {
            reasons.append("references writable path \(marker)")
        }
        for cmd in ["curl", "wget", "osascript", "base64", "bash -c", "sh -c"] where joined.contains(cmd) {
            reasons.append("invokes \(cmd)")
        }
        return PersistenceItem(path: path, kind: kind, label: label, sha256: hash,
                               programArguments: args, runAtLoad: runAtLoad,
                               suspicious: !reasons.isEmpty, reasons: reasons)
    }

    public func diff(previous: PersistenceSnapshot?, current: PersistenceSnapshot) -> [PersistenceChange] {
        guard let previous else {
            return current.items.map { PersistenceChange(kind: .added, item: $0) }
        }
        var changes: [PersistenceChange] = []
        let prevPaths = Set(previous.items.map { $0.path })
        let currPaths = Set(current.items.map { $0.path })
        for item in current.items where !prevPaths.contains(item.path) {
            changes.append(PersistenceChange(kind: .added, item: item))
        }
        for item in previous.items where !currPaths.contains(item.path) {
            changes.append(PersistenceChange(kind: .removed, item: item))
        }
        for item in current.items {
            if let old = previous.item(at: item.path), old.sha256 != item.sha256 {
                changes.append(PersistenceChange(kind: .changed, item: item))
            }
        }
        return changes
    }

    /// Security-relevant alerts only, emitted once per unique change.
    public func alerts(for changes: [PersistenceChange], resetDedupe: Bool = false) -> [PersistenceAlert] {
        if resetDedupe { alertedKeys.removeAll() }
        var out: [PersistenceAlert] = []
        for c in changes {
            let relevant: Bool
            let severity: Severity
            switch c.kind {
            case .added:   relevant = true;  severity = c.item.suspicious ? .high : .medium
            case .changed: relevant = c.item.suspicious; severity = .high
            case .removed: relevant = false; severity = .low
            }
            guard relevant else { continue }
            let key = "\(c.kind.rawValue):\(c.item.path):\(c.item.sha256 ?? "")"
            if alertedKeys.contains(key) { continue }
            alertedKeys.insert(key)
            let why = c.item.suspicious ? c.item.reasons.joined(separator: "; ") : "new autostart entry"
            let name = c.item.label ?? (c.item.path as NSString).lastPathComponent
            out.append(PersistenceAlert(severity: severity,
                                        message: "\(c.kind.rawValue) \(c.item.kind) '\(name)': \(why)",
                                        item: c.item))
        }
        return out
    }
}
