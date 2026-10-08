import Foundation

/// Retention policy scaffolding. Real enforcement runs inside the daemon on a
/// slow timer; the store does the deletion. Tuned later against measured disk
/// growth (see REQUIREMENTS R2).
public struct RetentionPolicy: Codable, Sendable {
    /// Keep event rows for this many days (initial goal: 90).
    public var eventRetentionDays: Int
    /// Never grow the events table beyond this many bytes; triggers early purge.
    public var maxStoreBytes: Int64
    /// Minimum number of most-recent rows to always keep, even if over size.
    public var minKeepRows: Int

    public init(eventRetentionDays: Int = 90,
                maxStoreBytes: Int64 = 2 * 1024 * 1024 * 1024,
                minKeepRows: Int = 1_000) {
        self.eventRetentionDays = eventRetentionDays
        self.maxStoreBytes = maxStoreBytes
        self.minKeepRows = minKeepRows
    }

    public static let `default` = RetentionPolicy()

    /// Decide whether a size-based purge is warranted.
    public func shouldPurgeForSize(currentBytes: Int64, currentRows: Int64) -> Bool {
        currentBytes > maxStoreBytes && currentRows > Int64(minKeepRows)
    }
}