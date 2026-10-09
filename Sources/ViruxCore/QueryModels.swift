import Foundation

/// Filters for searching stored events. All fields are optional; an empty query
/// returns the most recent events up to `limit`.
public struct EventQuery: Sendable {
    public var since: Date?
    public var until: Date?
    public var kinds: Set<EventKind>?
    public var minSeverity: Severity?
    public var fileHash: String?
    public var pathContains: String?
    public var exeContains: String?
    public var source: String?
    public var ids: [Int64]?
    public var limit: Int

    public init(since: Date? = nil, until: Date? = nil, kinds: Set<EventKind>? = nil,
                minSeverity: Severity? = nil, fileHash: String? = nil,
                pathContains: String? = nil, exeContains: String? = nil,
                source: String? = nil, ids: [Int64]? = nil, limit: Int = 100) {
        self.since = since
        self.until = until
        self.kinds = kinds
        self.minSeverity = minSeverity
        self.fileHash = fileHash
        self.pathContains = pathContains
        self.exeContains = exeContains
        self.source = source
        self.ids = ids
        self.limit = limit
    }
}

public struct DetectionQuery: Sendable {
    public var since: Date?
    public var minSeverity: Severity?
    public var status: Detection.Status?
    public var titleContains: String?
    public var evidenceEventID: Int64?
    public var limit: Int

    public init(since: Date? = nil, minSeverity: Severity? = nil,
                status: Detection.Status? = nil, titleContains: String? = nil,
                evidenceEventID: Int64? = nil, limit: Int = 100) {
        self.since = since
        self.minSeverity = minSeverity
        self.status = status
        self.titleContains = titleContains
        self.evidenceEventID = evidenceEventID
        self.limit = limit
    }
}
