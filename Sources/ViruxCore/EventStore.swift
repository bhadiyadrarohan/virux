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
        CREATE TABLE IF NOT EXISTS detections (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts REAL NOT NULL,
          title TEXT NOT NULL,
          reason TEXT NOT NULL,
          severity TEXT NOT NULL,
          confidence TEXT NOT NULL,
          evidence TEXT,
          status TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_detections_ts ON detections(ts);
        CREATE TABLE IF NOT EXISTS reputation_cache (
          hash TEXT PRIMARY KEY,
          verdict TEXT NOT NULL,
          detail TEXT,
          updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS quarantine (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts REAL NOT NULL,
          original_path TEXT NOT NULL,
          quarantine_path TEXT NOT NULL,
          sha256 TEXT,
          size_bytes INTEGER,
          reason TEXT NOT NULL,
          detection_id INTEGER,
          signing_id TEXT,
          team_id TEXT,
          perms INTEGER,
          status TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
        CREATE INDEX IF NOT EXISTS idx_quarantine_hash ON quarantine(sha256);
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts REAL NOT NULL,
          action TEXT NOT NULL,
          actor TEXT NOT NULL,
          target TEXT,
          detail TEXT,
          ok INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
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

    // MARK: - Detections

    @discardableResult
    public func insertDetection(_ d: Detection) throws -> Int64 {
        let evidence = (try? JSONSerialization.data(withJSONObject: d.evidenceEventIDs))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
        let sql = """
        INSERT INTO detections (ts,title,reason,severity,confidence,evidence,status)
        VALUES (?,?,?,?,?,?,?);
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError.exec(lastError())
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, d.timestamp.timeIntervalSince1970)
        sqlite3_bind_text(stmt, 2, d.title, -1, SQL_TRANSIENT)
        sqlite3_bind_text(stmt, 3, d.reason, -1, SQL_TRANSIENT)
        sqlite3_bind_text(stmt, 4, d.severity.rawValue, -1, SQL_TRANSIENT)
        sqlite3_bind_text(stmt, 5, d.confidence.rawValue, -1, SQL_TRANSIENT)
        sqlite3_bind_text(stmt, 6, evidence, -1, SQL_TRANSIENT)
        sqlite3_bind_text(stmt, 7, d.status.rawValue, -1, SQL_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_DONE else { throw StoreError.exec(lastError()) }
        return sqlite3_last_insert_rowid(db)
    }

    public func recentDetections(limit: Int = 20) -> [Detection] {
        let sql = """
        SELECT id,ts,title,reason,severity,confidence,evidence,status
        FROM detections ORDER BY id DESC LIMIT ?;
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int(stmt, 1, Int32(limit))
        var out: [Detection] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let id = sqlite3_column_int64(stmt, 0)
            let ts = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 1))
            let sev = Severity(rawValue: text(stmt, 4) ?? "") ?? .none
            let conf = Confidence(rawValue: text(stmt, 5) ?? "") ?? .low
            let status = Detection.Status(rawValue: text(stmt, 7) ?? "") ?? .observed
            var evidence: [Int64] = []
            if let s = text(stmt, 6), let data = s.data(using: .utf8),
               let arr = try? JSONSerialization.jsonObject(with: data) as? [Int64] {
                evidence = arr
            }
            out.append(Detection(id: id, timestamp: ts, title: text(stmt, 2) ?? "",
                                 reason: text(stmt, 3) ?? "", severity: sev,
                                 confidence: conf, evidenceEventIDs: evidence, status: status))
        }
        return out
    }

    public func countDetections() -> Int64 {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM detections;", -1, &stmt, nil) == SQLITE_OK else { return 0 }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return sqlite3_column_int64(stmt, 0)
    }

    // MARK: - Reputation cache

    public func setReputation(hash: String, verdict: String, detail: String?) throws {
        let sql = """
        INSERT INTO reputation_cache (hash,verdict,detail,updated_at) VALUES (?,?,?,?)
        ON CONFLICT(hash) DO UPDATE SET verdict=excluded.verdict, detail=excluded.detail,
          updated_at=excluded.updated_at;
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError.exec(lastError())
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, hash, -1, SQL_TRANSIENT)
        sqlite3_bind_text(stmt, 2, verdict, -1, SQL_TRANSIENT)
        bindOptionalText(stmt, 3, detail)
        sqlite3_bind_double(stmt, 4, Date().timeIntervalSince1970)
        guard sqlite3_step(stmt) == SQLITE_DONE else { throw StoreError.exec(lastError()) }
    }

    public func reputation(hash: String) -> String? {
        let sql = "SELECT verdict FROM reputation_cache WHERE hash=?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, hash, -1, SQL_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW, let c = sqlite3_column_text(stmt, 0) else { return nil }
        return String(cString: c)
    }

    // MARK: - Quarantine

    @discardableResult
    public func insertQuarantine(_ q: QuarantineRecord) throws -> Int64 {
        let sql = """
        INSERT INTO quarantine
          (ts,original_path,quarantine_path,sha256,size_bytes,reason,detection_id,signing_id,team_id,perms,status)
        VALUES (?,?,?,?,?,?,?,?,?,?,?);
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { throw StoreError.exec(lastError()) }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, q.timestamp.timeIntervalSince1970)
        sqlite3_bind_text(stmt, 2, q.originalPath, -1, SQL_TRANSIENT)
        sqlite3_bind_text(stmt, 3, q.quarantinePath, -1, SQL_TRANSIENT)
        bindOptionalText(stmt, 4, q.sha256)
        bindOptionalInt(stmt, 5, q.sizeBytes)
        sqlite3_bind_text(stmt, 6, q.reason, -1, SQL_TRANSIENT)
        bindOptionalInt(stmt, 7, q.detectionID)
        bindOptionalText(stmt, 8, q.signingID)
        bindOptionalText(stmt, 9, q.teamID)
        if let p = q.perms { sqlite3_bind_int64(stmt, 10, Int64(p)) } else { sqlite3_bind_null(stmt, 10) }
        sqlite3_bind_text(stmt, 11, q.status.rawValue, -1, SQL_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_DONE else { throw StoreError.exec(lastError()) }
        return sqlite3_last_insert_rowid(db)
    }

    public func listQuarantine(status: QuarantineRecord.Status? = nil) -> [QuarantineRecord] {
        var sql = "SELECT id,ts,original_path,quarantine_path,sha256,size_bytes,reason,detection_id,signing_id,team_id,perms,status FROM quarantine"
        if status != nil { sql += " WHERE status=?" }
        sql += " ORDER BY id DESC;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }
        if let s = status { sqlite3_bind_text(stmt, 1, s.rawValue, -1, SQL_TRANSIENT) }
        var out: [QuarantineRecord] = []
        while sqlite3_step(stmt) == SQLITE_ROW { out.append(rowToQuarantine(stmt)) }
        return out
    }

    public func quarantine(id: Int64) -> QuarantineRecord? {
        let sql = "SELECT id,ts,original_path,quarantine_path,sha256,size_bytes,reason,detection_id,signing_id,team_id,perms,status FROM quarantine WHERE id=?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int64(stmt, 1, id)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return rowToQuarantine(stmt)
    }

    public func updateQuarantineStatus(id: Int64, status: QuarantineRecord.Status) throws {
        let sql = "UPDATE quarantine SET status=? WHERE id=?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { throw StoreError.exec(lastError()) }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, status.rawValue, -1, SQL_TRANSIENT)
        sqlite3_bind_int64(stmt, 2, id)
        guard sqlite3_step(stmt) == SQLITE_DONE else { throw StoreError.exec(lastError()) }
    }

    private func rowToQuarantine(_ stmt: OpaquePointer?) -> QuarantineRecord {
        QuarantineRecord(
            id: sqlite3_column_int64(stmt, 0),
            timestamp: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 1)),
            originalPath: text(stmt, 2) ?? "",
            quarantinePath: text(stmt, 3) ?? "",
            sha256: text(stmt, 4),
            sizeBytes: sqlite3_column_type(stmt, 5) == SQLITE_NULL ? nil : sqlite3_column_int64(stmt, 5),
            reason: text(stmt, 6) ?? "",
            detectionID: sqlite3_column_type(stmt, 7) == SQLITE_NULL ? nil : sqlite3_column_int64(stmt, 7),
            signingID: text(stmt, 8),
            teamID: text(stmt, 9),
            perms: sqlite3_column_type(stmt, 10) == SQLITE_NULL ? nil : Int(sqlite3_column_int64(stmt, 10)),
            status: QuarantineRecord.Status(rawValue: text(stmt, 11) ?? "") ?? .quarantined)
    }

    // MARK: - Audit

    @discardableResult
    public func appendAudit(_ a: AuditEntry) throws -> Int64 {
        let sql = "INSERT INTO audit (ts,action,actor,target,detail,ok) VALUES (?,?,?,?,?,?);"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { throw StoreError.exec(lastError()) }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, a.timestamp.timeIntervalSince1970)
        sqlite3_bind_text(stmt, 2, a.action, -1, SQL_TRANSIENT)
        sqlite3_bind_text(stmt, 3, a.actor, -1, SQL_TRANSIENT)
        bindOptionalText(stmt, 4, a.target)
        bindOptionalText(stmt, 5, a.detail)
        sqlite3_bind_int(stmt, 6, a.ok ? 1 : 0)
        guard sqlite3_step(stmt) == SQLITE_DONE else { throw StoreError.exec(lastError()) }
        return sqlite3_last_insert_rowid(db)
    }

    public func recentAudit(limit: Int = 50) -> [AuditEntry] {
        let sql = "SELECT id,ts,action,actor,target,detail,ok FROM audit ORDER BY id DESC LIMIT ?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int(stmt, 1, Int32(limit))
        var out: [AuditEntry] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(AuditEntry(
                id: sqlite3_column_int64(stmt, 0),
                timestamp: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 1)),
                action: text(stmt, 2) ?? "",
                actor: text(stmt, 3) ?? "",
                target: text(stmt, 4),
                detail: text(stmt, 5),
                ok: sqlite3_column_int(stmt, 6) != 0))
        }
        return out
    }

    // MARK: - Search

    private enum Bind { case text(String); case real(Double); case int(Int) }

    private static let severityRankSQL =
        "(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)"

    /// Searchable history over events.
    public func searchEvents(_ q: EventQuery) -> [SecurityEvent] {
        var whereParts: [String] = []
        var binds: [Bind] = []
        if let since = q.since { whereParts.append("ts >= ?"); binds.append(.real(since.timeIntervalSince1970)) }
        if let until = q.until { whereParts.append("ts <= ?"); binds.append(.real(until.timeIntervalSince1970)) }
        if let kinds = q.kinds, !kinds.isEmpty {
            whereParts.append("kind IN (\(Array(repeating: "?", count: kinds.count).joined(separator: ",")))")
            for k in kinds.sorted(by: { $0.rawValue < $1.rawValue }) { binds.append(.text(k.rawValue)) }
        }
        if let s = q.minSeverity { whereParts.append("\(Self.severityRankSQL) >= ?"); binds.append(.int(s.rank)) }
        if let h = q.fileHash { whereParts.append("file_hash = ?"); binds.append(.text(h)) }
        if let p = q.pathContains { whereParts.append("file_path LIKE ?"); binds.append(.text("%\(p)%")) }
        if let e = q.exeContains { whereParts.append("exe LIKE ?"); binds.append(.text("%\(e)%")) }
        if let src = q.source { whereParts.append("source = ?"); binds.append(.text(src)) }
        if let ids = q.ids, !ids.isEmpty {
            whereParts.append("id IN (\(Array(repeating: "?", count: ids.count).joined(separator: ",")))")
            for id in ids { binds.append(.int(Int(id))) }
        }

        var sql = """
        SELECT id,ts,kind,pid,ppid,exe,signing_id,team_id,file_path,file_hash,severity,confidence,source,extra
        FROM events
        """
        if !whereParts.isEmpty { sql += " WHERE " + whereParts.joined(separator: " AND ") }
        sql += " ORDER BY ts DESC LIMIT ?;"
        binds.append(.int(q.limit))

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }
        bindAll(stmt, binds)
        var out: [SecurityEvent] = []
        while sqlite3_step(stmt) == SQLITE_ROW { out.append(rowToEvent(stmt)) }
        return out
    }

    /// Searchable history over detections.
    public func searchDetections(_ q: DetectionQuery) -> [Detection] {
        var whereParts: [String] = []
        var binds: [Bind] = []
        if let since = q.since { whereParts.append("ts >= ?"); binds.append(.real(since.timeIntervalSince1970)) }
        if let s = q.minSeverity { whereParts.append("\(Self.severityRankSQL) >= ?"); binds.append(.int(s.rank)) }
        if let st = q.status { whereParts.append("status = ?"); binds.append(.text(st.rawValue)) }
        if let t = q.titleContains { whereParts.append("title LIKE ?"); binds.append(.text("%\(t)%")) }
        if let e = q.evidenceEventID { whereParts.append("evidence LIKE ?"); binds.append(.text("%\(e)%")) }

        var sql = "SELECT id,ts,title,reason,severity,confidence,evidence,status FROM detections"
        if !whereParts.isEmpty { sql += " WHERE " + whereParts.joined(separator: " AND ") }
        sql += " ORDER BY ts DESC LIMIT ?;"
        binds.append(.int(q.limit))

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }
        bindAll(stmt, binds)
        var out: [Detection] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            var evidence: [Int64] = []
            if let s = text(stmt, 6), let data = s.data(using: .utf8),
               let arr = try? JSONSerialization.jsonObject(with: data) as? [Int64] { evidence = arr }
            out.append(Detection(
                id: sqlite3_column_int64(stmt, 0),
                timestamp: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 1)),
                title: text(stmt, 2) ?? "", reason: text(stmt, 3) ?? "",
                severity: Severity(rawValue: text(stmt, 4) ?? "") ?? .none,
                confidence: Confidence(rawValue: text(stmt, 5) ?? "") ?? .low,
                evidenceEventIDs: evidence,
                status: Detection.Status(rawValue: text(stmt, 7) ?? "") ?? .observed))
        }
        return out
    }

    private func bindAll(_ stmt: OpaquePointer?, _ binds: [Bind]) {
        var i: Int32 = 1
        for b in binds {
            switch b {
            case .text(let s): sqlite3_bind_text(stmt, i, s, -1, SQL_TRANSIENT)
            case .real(let d): sqlite3_bind_double(stmt, i, d)
            case .int(let n): sqlite3_bind_int64(stmt, i, Int64(n))
            }
            i += 1
        }
    }
}