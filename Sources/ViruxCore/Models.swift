import Foundation

/// Normalised event kinds, mapped from Endpoint Security short names.
public enum EventKind: String, Codable, CaseIterable, Sendable {
    case exec, fork, exit, open, close, mount, rename, unlink, signal, unknown
}

/// Impact of an event or detection. Distinct from Confidence.
public enum Severity: String, Codable, CaseIterable, Sendable {
    case none, low, medium, high, critical

    /// Ordinal used for sorting and threshold comparisons.
    public var rank: Int {
        switch self {
        case .none: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }
}

/// Certainty that a detection is correct. Distinct from Severity.
public enum Confidence: String, Codable, CaseIterable, Sendable {
    case low, medium, high
}

/// Minimal, privacy-conscious description of a process at event time.
public struct ProcessRef: Codable, Sendable, Hashable {
    public var pid: Int32
    public var ppid: Int32?
    public var executablePath: String?
    public var signingID: String?
    public var teamID: String?

    public init(pid: Int32, ppid: Int32? = nil, executablePath: String? = nil,
                signingID: String? = nil, teamID: String? = nil) {
        self.pid = pid
        self.ppid = ppid
        self.executablePath = executablePath
        self.signingID = signingID
        self.teamID = teamID
    }
}

/// A single compact telemetry record. This is the unit stored and analysed.
public struct SecurityEvent: Codable, Sendable {
    public var id: Int64?
    public var timestamp: Date
    public var kind: EventKind
    public var process: ProcessRef
    public var filePath: String?
    public var fileHash: String?
    public var severity: Severity
    public var confidence: Confidence
    /// Where the event came from: "eslogger", "replay", or "synth".
    public var source: String
    /// Compact, curated extra fields (never full argv/env by default).
    public var extra: [String: String]

    public init(id: Int64? = nil,
                timestamp: Date = Date(),
                kind: EventKind,
                process: ProcessRef,
                filePath: String? = nil,
                fileHash: String? = nil,
                severity: Severity = .none,
                confidence: Confidence = .low,
                source: String,
                extra: [String: String] = [:]) {
        self.id = id
        self.timestamp = timestamp
        self.kind = kind
        self.process = process
        self.filePath = filePath
        self.fileHash = fileHash
        self.severity = severity
        self.confidence = confidence
        self.source = source
        self.extra = extra
    }
}

/// A plain-English, evidence-backed finding. Produced by the detection engine
/// (M3). Defined here so the store and UI can be built before detection exists.
public struct Detection: Codable, Sendable {
    public enum Status: String, Codable, Sendable {
        case observed, quarantined, allowed, ignored
    }
    public var id: Int64?
    public var timestamp: Date
    public var title: String
    public var reason: String
    public var severity: Severity
    public var confidence: Confidence
    public var evidenceEventIDs: [Int64]
    public var status: Status

    public init(id: Int64? = nil, timestamp: Date = Date(), title: String,
                reason: String, severity: Severity, confidence: Confidence,
                evidenceEventIDs: [Int64] = [], status: Status = .observed) {
        self.id = id
        self.timestamp = timestamp
        self.title = title
        self.reason = reason
        self.severity = severity
        self.confidence = confidence
        self.evidenceEventIDs = evidenceEventIDs
        self.status = status
    }
}