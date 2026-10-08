import Foundation
import SQLite3

private let SQL_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

public enum StoreError: Error, CustomStringConvertible {
    case open(String)
    case exec(String)

    public var description: String {
        switch self {
        case .open(let m): return "store open failed: \(m)"
        case .exec(let m): return "store exec failed: \(m)"
        }
    }
}

/// Durable, local, append-mostly telemetry store backed by SQLite (WAL).
/// Thread-safe for the M1 usage pattern via serialised access on the caller.
public final class EventStore {
    private var db: OpaquePointer?
    public let path: String
    public static let schemaVersion = 1

    public init(path: String) throws {
        self.path = path
        let dir = (path as NSString).deletingLastPathComponent
        if !dir.isEmpty {
            try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        }
        var handle: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        let rc = sqlite3_open_v2(path, &handle, flags, nil)
        guard rc == SQLITE_OK, let h = handle else {
            let msg = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            if let bad = handle { sqlite3_close(bad) }
            throw StoreError.open(msg)
        }
        self.db = h
        try migrate()
    }

    deinit {
        if let db { sqlite3_close(db) }
    }

    private func lastError() -> String {
        guard let db else { return "no db" }
        return String(cString: sqlite3_errmsg(db))
    }

    private func exec(_ sql: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        if sqlite3_exec(db, sql, nil, nil, &err) != SQLITE_OK {
            let m = err.map { String(cString: $0) } ?? "unknown"
            sqlite3_free(err)
            throw StoreError.exec(m)
        }
    }

    private func migrate() throws {
        try exec("PRAGMA journal_mode=WAL;")
        try exec("PRAGMA synchronous=NORMAL;")
        try exec("""
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts REAL NOT NULL,
          kind TEXT NOT NULL,
          pid INTEGER,
          ppid INTEGER,
          exe TEXT,
          signing_id TEXT,
          team_id TEXT,
          file_path TEXT,
          file_hash TEXT,
          severity TEXT NOT NULL,
          confidence TEXT NOT NULL,
          source TEXT NOT NULL,
          extra TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
        CREATE INDEX IF NOT EXISTS idx_events_hash ON events(file_hash);
        CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
        """)
        try setMeta("schema_version", String(EventStore.schemaVersion))
    }

    // MARK: - Meta

    public func setMeta(_ key: String, _ value: String) throws {
        let sql = "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError.exec(lastError())
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, key, -1, SQL_TRANSIENT)
        sqlite3_bind_text(stmt, 2, value, -1, SQL_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_DONE else { throw StoreError.exec(lastError()) }
    }

    public func meta(_ key: String) -> String? {
        let sql = "SELECT v FROM meta WHERE k=?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, key, -1, SQL_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW, let c = sqlite3_column_text(stmt, 0) else { return nil }
        return String(cString: c)
    }

    // MARK: - Writes

    @discardableResult
    public func insert(_ e: SecurityEvent) throws -> Int64 {
        let sql = """
        INSERT INTO events
          (ts,kind,pid,ppid,exe,signing_id,team_id,file_path,file_hash,severity,confidence,source,extra)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError.exec(lastError())
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, e.timestamp.timeIntervalSince1970)
        sqlite3_bind_text(stmt, 2, e.kind.rawValue, -1, SQL_TRANSIENT)
        bindInt(stmt, 3, e.process.pid)
        bindOptionalInt(stmt, 4, e.process.ppid.map { Int64($0) })
        bindOptionalText(stmt, 5, e.process.executablePath)
        bindOptionalText(stmt, 6, e.process.signingID)
        bindOptionalText(stmt, 7, e.process.teamID)
        bindOptionalText(stmt, 8, e.filePath)
        bindOptionalText(stmt, 9, e.fileHash)
        sqlite3_bind_text(stmt, 10, e.severity.rawValue, -1, SQL_TRANSIENT)
        sqlite3_bind_text(stmt, 11, e.confidence.rawValue, -1, SQL_TRANSIENT)
        sqlite3_bind_text(stmt, 12, e.source, -1, SQL_TRANSIENT)
        bindOptionalText(stmt, 13, encodeExtra(e.extra))
        guard sqlite3_step(stmt) == SQLITE_DONE else { throw StoreError.exec(lastError()) }
        return sqlite3_last_insert_rowid(db)
    }

    /// Deletes events older than `days`. Returns number of rows removed.
    @discardableResult
    public func purge(olderThanDays days: Int, now: Date = Date()) throws -> Int {
        let cutoff = now.addingTimeInterval(-Double(days) * 86_400).timeIntervalSince1970
        let sql = "DELETE FROM events WHERE ts < ?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError.exec(lastError())
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, cutoff)
        guard sqlite3_step(stmt) == SQLITE_DONE else { throw StoreError.exec(lastError()) }
        return Int(sqlite3_changes(db))
    }

    // MARK: - Reads

    public func count() -> Int64 {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM events;", -1, &stmt, nil) == SQLITE_OK else { return 0 }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return sqlite3_column_int64(stmt, 0)
    }

    public func recent(limit: Int = 20) -> [SecurityEvent] {
        let sql = """
        SELECT id,ts,kind,pid,ppid,exe,signing_id,team_id,file_path,file_hash,
               severity,confidence,source,extra
        FROM events ORDER BY id DESC LIMIT ?;
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int(stmt, 1, Int32(limit))
        var out: [SecurityEvent] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(rowToEvent(stmt))
        }
        return out
    }

    public func countByKind() -> [(String, Int64)] {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT kind, COUNT(*) FROM events GROUP BY kind ORDER BY COUNT(*) DESC;", -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }
        var out: [(String, Int64)] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let k = sqlite3_column_text(stmt, 0).map { String(cString: $0) } ?? "?"
            out.append((k, sqlite3_column_int64(stmt, 1)))
        }
        return out
    }

    public func dbSizeBytes() -> Int64 {
        var total: Int64 = 0
        for suffix in ["", "-wal", "-shm"] {
            let p = path + suffix
            if let attrs = try? FileManager.default.attributesOfItem(atPath: p),
               let n = attrs[.size] as? NSNumber {
                total += n.int64Value
            }
        }
        return total
    }

    // MARK: - Row mapping

    private func rowToEvent(_ stmt: OpaquePointer?) -> SecurityEvent {
        let id = sqlite3_column_int64(stmt, 0)
        let ts = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 1))
        let kind = EventKind(rawValue: text(stmt, 2) ?? "") ?? .unknown
        let pid = Int32(sqlite3_column_int(stmt, 3))
        let ppid: Int32? = sqlite3_column_type(stmt, 4) == SQLITE_NULL ? nil : Int32(sqlite3_column_int(stmt, 4))
        let proc = ProcessRef(pid: pid, ppid: ppid, executablePath: text(stmt, 5),
                              signingID: text(stmt, 6), teamID: text(stmt, 7))
        let sev = Severity(rawValue: text(stmt, 10) ?? "") ?? .none
        let conf = Confidence(rawValue: text(stmt, 11) ?? "") ?? .low
        return SecurityEvent(
            id: id, timestamp: ts, kind: kind, process: proc,
            filePath: text(stmt, 8), fileHash: text(stmt, 9),
            severity: sev, confidence: conf, source: text(stmt, 12) ?? "?",
            extra: decodeExtra(text(stmt, 13))
        )
    }

    private func text(_ stmt: OpaquePointer?, _ col: Int32) -> String? {
        guard sqlite3_column_type(stmt, col) != SQLITE_NULL,
              let c = sqlite3_column_text(stmt, col) else { return nil }
        return String(cString: c)
    }

    // MARK: - Binding helpers

    private func bindInt(_ stmt: OpaquePointer?, _ idx: Int32, _ v: Int32) {
        sqlite3_bind_int(stmt, idx, v)
    }
    private func bindOptionalInt(_ stmt: OpaquePointer?, _ idx: Int32, _ v: Int64?) {
        if let v { sqlite3_bind_int64(stmt, idx, v) } else { sqlite3_bind_null(stmt, idx) }
    }
    private func bindOptionalText(_ stmt: OpaquePointer?, _ idx: Int32, _ v: String?) {
        if let v { sqlite3_bind_text(stmt, idx, v, -1, SQL_TRANSIENT) } else { sqlite3_bind_null(stmt, idx) }
    }

    private func encodeExtra(_ extra: [String: String]) -> String? {
        guard !extra.isEmpty,
              let data = try? JSONSerialization.data(withJSONObject: extra),
              let s = String(data: data, encoding: .utf8) else { return nil }
        return s
    }
    private func decodeExtra(_ s: String?) -> [String: String] {
        guard let s, let data = s.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: String] else { return [:] }
        return obj
    }
}