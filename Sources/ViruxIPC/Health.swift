import Foundation

/// Shared health record written by the daemon and read by the CLI and UI.
/// Its whole purpose is to make an unhealthy agent visible, never masked
/// (REQUIREMENTS R3, threat T2/T9).
public struct Health: Codable, Sendable {
    /// "protected" | "degraded" | "stopped" | "observe-only"
    public var state: String
    public var source: String
    public var startedAt: Date
    public var updatedAt: Date
    public var lastEventAt: Date?
    public var eventsReceived: Int
    public var eventsStored: Int
    public var insertErrors: Int
    public var lastError: String?
    public var dbPath: String
    public var dbSizeBytes: Int64
    public var rowCount: Int64
    public var notes: [String]

    public init(state: String, source: String, startedAt: Date, updatedAt: Date,
                lastEventAt: Date?, eventsReceived: Int, eventsStored: Int,
                insertErrors: Int, lastError: String?, dbPath: String,
                dbSizeBytes: Int64, rowCount: Int64, notes: [String]) {
        self.state = state
        self.source = source
        self.startedAt = startedAt
        self.updatedAt = updatedAt
        self.lastEventAt = lastEventAt
        self.eventsReceived = eventsReceived
        self.eventsStored = eventsStored
        self.insertErrors = insertErrors
        self.lastError = lastError
        self.dbPath = dbPath
        self.dbSizeBytes = dbSizeBytes
        self.rowCount = rowCount
        self.notes = notes
    }

    public static func load(from path: String) -> Health? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(Health.self, from: data)
    }

    public func write(to path: String) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(self).write(to: URL(fileURLWithPath: path), options: .atomic)
    }

    public static func defaultPath(dbPath: String) -> String { dbPath + ".health.json" }

    /// True when events have flowed recently enough to call the sensor live.
    public func isFresh(now: Date = Date(), within: TimeInterval = 30) -> Bool {
        guard let last = lastEventAt else { return false }
        return now.timeIntervalSince(last) <= within
    }
}