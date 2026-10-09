import Foundation
import ViruxCore

/// A rule fired on a single event. Evidence is the triggering event id (when
/// known); severity is impact, confidence is certainty.
public struct RuleMatch: Sendable {
    public var ruleID: String
    public var title: String
    public var reason: String
    public var severity: Severity
    public var confidence: Confidence

    public init(ruleID: String, title: String, reason: String,
                severity: Severity, confidence: Confidence) {
        self.ruleID = ruleID
        self.title = title
        self.reason = reason
        self.severity = severity
        self.confidence = confidence
    }
}

/// Lightweight, deterministic behavioural rules. Deliberately conservative:
/// M3 runs observe-only, so the goal is an honest false-positive baseline, not
/// aggressive blocking. A rule returns a match or nil; the engine keeps the
/// highest-severity match per event.
public final class RuleEngine {

    public struct Config: Sendable {
        public var massRenameWindow: TimeInterval
        public var massRenameThreshold: Int
        /// Path prefixes considered part of the trusted OS.
        public var systemPrefixes: [String]
        /// Writable, often-abused locations.
        public var tempPrefixes: [String]
        public var shellNames: Set<String>
        /// Non-terminal apps that should rarely spawn a shell directly.
        public var hostApps: Set<String>
        public var autostartMarkers: [String]
        /// Suppress repeats of the same rule within this many seconds (dedup).
        public var ruleCooldown: TimeInterval
        /// Decoy files: any touch is critical.
        public var canaryPaths: Set<String>
        /// Backup/snapshot locations ransomware commonly targets.
        public var backupMarkers: [String]
        public var massModifyWindow: TimeInterval
        public var massModifyThreshold: Int

        public init(massRenameWindow: TimeInterval = 10,
                    massRenameThreshold: Int = 20,
                    systemPrefixes: [String] = ["/System/", "/usr/", "/bin/", "/sbin/"],
                    tempPrefixes: [String] = ["/tmp/", "/var/tmp/", "/private/tmp/"],
                    shellNames: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "osascript"],
                    hostApps: Set<String> = ["Safari", "Brave Browser", "Google Chrome",
                                             "Mail", "Microsoft Word", "Microsoft Excel",
                                             "Preview", "Notes"],
                    autostartMarkers: [String] = ["/Library/LaunchAgents/",
                                                  "/Library/LaunchDaemons/",
                                                  "/Library/StartupItems/"],
                    ruleCooldown: TimeInterval = 30,
                    canaryPaths: Set<String> = [],
                    backupMarkers: [String] = ["Backups.backupdb", "com.apple.TimeMachine",
                                               ".sparsebundle", "/.backup/", ".bak"],
                    massModifyWindow: TimeInterval = 10,
                    massModifyThreshold: Int = 40) {
            self.massRenameWindow = massRenameWindow
            self.massRenameThreshold = massRenameThreshold
            self.systemPrefixes = systemPrefixes
            self.tempPrefixes = tempPrefixes
            self.shellNames = shellNames
            self.hostApps = hostApps
            self.autostartMarkers = autostartMarkers
            self.ruleCooldown = ruleCooldown
            self.canaryPaths = canaryPaths
            self.backupMarkers = backupMarkers
            self.massModifyWindow = massModifyWindow
            self.massModifyThreshold = massModifyThreshold
        }
    }

    private let config: Config
    private let canaryKeys: Set<String>
    private var processByPID: [Int32: ProcessRef] = [:]
    private var renameTimes: [Date] = []
    private var recentModifications: [(Date, String)] = []
    private var lastFire: [String: Date] = [:]

    public init(config: Config = Config()) {
        self.config = config
        // Pre-normalise canary paths once so the hot path is a set lookup.
        var keys = Set<String>()
        for c in config.canaryPaths {
            let s = RuleEngine.standardize(c)
            keys.insert(s)
            if !s.hasPrefix("/private/") { keys.insert("/private" + s) }
        }
        self.canaryKeys = keys
    }

    /// Cheap, string-only normalisation: collapses redundant slashes and
    /// trailing separators. Telemetry and user-supplied paths often differ only
    /// in this way.
    static func standardize(_ p: String) -> String {
        var s = (p as NSString).standardizingPath
        if s.count > 1 && s.hasSuffix("/") { s.removeLast() }
        return s
    }

    /// Evaluates one event and returns the highest-severity match, if any.
    public func evaluate(_ event: SecurityEvent) -> RuleMatch? {
        if event.kind == .exec {
            processByPID[event.process.pid] = event.process
            if processByPID.count > 8192 { processByPID.removeAll(keepingCapacity: true) }
        }

        var matches: [RuleMatch] = []
        if let m = unsignedExec(event) { matches.append(m) }
        if let m = unsignedFromWritableLocation(event) { matches.append(m) }
        if let m = hostAppSpawnsShell(event) { matches.append(m) }
        if let m = autostartWrite(event) { matches.append(m) }
        if let m = massRename(event) { matches.append(m) }
        if let m = backupTampering(event) { matches.append(m) }
        if let m = canaryTouched(event) { matches.append(m) }
        if let m = massModification(event) { matches.append(m) }

        // Deduplicate: suppress repeats of the same rule within the cooldown.
        let eligible = matches.filter { m in
            if let t = lastFire[m.ruleID],
               event.timestamp.timeIntervalSince(t) < config.ruleCooldown { return false }
            return true
        }
        guard let best = eligible.max(by: { $0.severity.rank < $1.severity.rank }) else { return nil }
        lastFire[best.ruleID] = event.timestamp
        return best
    }

    // MARK: - Rules

    /// R-001: an unsigned executable launched from a non-system path.
    private func unsignedExec(_ e: SecurityEvent) -> RuleMatch? {
        guard e.kind == .exec,
              e.process.signingID == nil,
              let path = e.process.executablePath, !path.isEmpty,
              !isSystem(path) else { return nil }
        return RuleMatch(
            ruleID: "R-001",
            title: "Unsigned executable launched",
            reason: "\(path) executed (pid \(e.process.pid)) with no code-signing identity.",
            severity: .low,
            confidence: .low
        )
    }

    /// R-002: an unsigned executable launched from /tmp or Downloads.
    private func unsignedFromWritableLocation(_ e: SecurityEvent) -> RuleMatch? {
        guard e.kind == .exec, e.process.signingID == nil,
              let path = e.process.executablePath,
              isTemp(path) || path.contains("/Downloads/") else { return nil }
        return RuleMatch(
            ruleID: "R-002",
            title: "Unsigned executable from writable location",
            reason: "\(path) executed (pid \(e.process.pid)) from a writable location with no signing identity.",
            severity: .medium,
            confidence: .medium
        )
    }

    /// R-003: a common host app (browser, document viewer) spawned a shell.
    private func hostAppSpawnsShell(_ e: SecurityEvent) -> RuleMatch? {
        guard e.kind == .exec,
              let ppid = e.process.ppid,
              let parent = processByPID[ppid],
              let parentPath = parent.executablePath,
              let childPath = e.process.executablePath else { return nil }
        let parentName = (parentPath as NSString).lastPathComponent
        let childName = (childPath as NSString).lastPathComponent
        guard config.hostApps.contains(parentName), config.shellNames.contains(childName) else { return nil }
        return RuleMatch(
            ruleID: "R-003",
            title: "Host application spawned a shell",
            reason: "\(parentName) (pid \(ppid)) spawned \(childName) (pid \(e.process.pid)). Document and browser apps rarely spawn shells directly.",
            severity: .medium,
            confidence: .medium
        )
    }

    /// R-004: a write/rename into an autostart (persistence) location.
    private func autostartWrite(_ e: SecurityEvent) -> RuleMatch? {
        guard e.kind == .open || e.kind == .rename,
              let path = e.filePath,
              config.autostartMarkers.contains(where: { path.contains($0) }) else { return nil }
        return RuleMatch(
            ruleID: "R-004",
            title: "Persistence location modified",
            reason: "\(path) was written or renamed by pid \(e.process.pid). Autostart locations are common persistence targets.",
            severity: .medium,
            confidence: .medium
        )
    }

    /// R-005: a burst of renames in a short window (ransomware-like churn).
    private func massRename(_ e: SecurityEvent) -> RuleMatch? {
        guard e.kind == .rename else { return nil }
        renameTimes.append(e.timestamp)
        let cutoff = e.timestamp.addingTimeInterval(-config.massRenameWindow)
        renameTimes.removeAll { $0 < cutoff }
        guard renameTimes.count >= config.massRenameThreshold else { return nil }
        return RuleMatch(
            ruleID: "R-005",
            title: "Mass file rename burst",
            reason: "\(renameTimes.count) rename events within \(Int(config.massRenameWindow))s, consistent with bulk encryption or renaming. Latest: \(e.filePath ?? "unknown").",
            severity: .critical,
            confidence: .medium
        )
    }

    // MARK: - Helpers

    /// R-006: a write or delete in a backup / snapshot location.
    private func backupTampering(_ e: SecurityEvent) -> RuleMatch? {
        guard e.kind == .open || e.kind == .rename || e.kind == .unlink,
              let path = e.filePath,
              config.backupMarkers.contains(where: { path.contains($0) }) else { return nil }
        return RuleMatch(
            ruleID: "R-006",
            title: "Backup or snapshot location modified",
            reason: "\(path) was touched by pid \(e.process.pid). Backups and snapshots are common ransomware targets.",
            severity: .high,
            confidence: .medium
        )
    }

    /// R-007: a decoy canary file was touched. Legitimate software has no
    /// reason to modify these, so this is near-zero false positive.
    private func canaryTouched(_ e: SecurityEvent) -> RuleMatch? {
        guard e.kind == .open || e.kind == .rename || e.kind == .unlink,
              let path = e.filePath else { return nil }
        let s = RuleEngine.standardize(path)
        // Accept both the /var and /private/var spellings macOS uses.
        let hit = canaryKeys.contains(s)
            || canaryKeys.contains("/private" + s)
            || (s.hasPrefix("/private/") && canaryKeys.contains(String(s.dropFirst("/private".count))))
        guard hit else { return nil }
        return RuleMatch(
            ruleID: "R-007",
            title: "Canary (decoy) file touched",
            reason: "Decoy file \(path) was touched by pid \(e.process.pid). Nothing legitimate should modify canary files; treat as active destructive behaviour.",
            severity: .critical,
            confidence: .high
        )
    }

    /// R-008: many distinct files touched in a short window.
    private func massModification(_ e: SecurityEvent) -> RuleMatch? {
        guard e.kind == .open || e.kind == .close || e.kind == .rename,
              let path = e.filePath else { return nil }
        recentModifications.append((e.timestamp, path))
        let cutoff = e.timestamp.addingTimeInterval(-config.massModifyWindow)
        recentModifications.removeAll { $0.0 < cutoff }
        let distinct = Set(recentModifications.map { $0.1 }).count
        guard distinct >= config.massModifyThreshold else { return nil }
        return RuleMatch(
            ruleID: "R-008",
            title: "Mass file modification burst",
            reason: "\(distinct) distinct files touched within \(Int(config.massModifyWindow))s, consistent with bulk encryption. Latest: \(path).",
            severity: .high,
            confidence: .medium
        )
    }

    private func isSystem(_ path: String) -> Bool {
        config.systemPrefixes.contains { path.hasPrefix($0) }
    }
    private func isTemp(_ path: String) -> Bool {
        config.tempPrefixes.contains { path.hasPrefix($0) }
    }
}
