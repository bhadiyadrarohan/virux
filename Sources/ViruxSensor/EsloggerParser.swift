import Foundation
import ViruxCore

/// Parses Apple `eslogger` JSON lines into compact SecurityEvent records.
/// Deliberately defensive: eslogger's schema varies by event type and OS
/// version, so unknown shapes degrade to `.unknown` rather than failing.
public enum EsloggerParser {

    public static func parse(line: String, source: String = "eslogger") -> SecurityEvent? {
        guard let data = line.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              !obj.isEmpty else { return nil }

        let kind = eventKind(from: obj)
        let process = processRef(from: obj["process"] as? [String: Any] ?? [:])
        let timestamp = parseTime(obj["time"]) ?? Date()

        var filePath: String?
        var extra: [String: String] = [:]

        if let event = obj["event"] as? [String: Any] {
            // open/close/rename/unlink carry a path under various keys.
            if let open = event["open"] as? [String: Any],
               let file = open["file"] as? [String: Any] {
                filePath = file["path"] as? String
            }
            if let close = event["close"] as? [String: Any],
               let target = close["target"] as? [String: Any] {
                filePath = (target["path"] as? String) ?? pathFromFile(target)
            }
            if let unlink = event["unlink"] as? [String: Any],
               let target = unlink["target"] as? [String: Any] {
                filePath = pathFromFile(target)
            }
            if let rename = event["rename"] as? [String: Any] {
                if let src = (rename["source"] as? [String: Any]).flatMap(pathFromFile) {
                    extra["rename_source"] = src
                }
                if let dst = (rename["destination"] as? [String: Any]).flatMap(pathFromFile) {
                    filePath = dst
                }
            }
            // exec carries the newly executed image.
            if let exec = event["exec"] as? [String: Any],
               let image = exec["image"] as? [String: Any] {
                extra["exec_image"] = (image["path"] as? String) ?? ""
            }
        }

        if let script = (obj["process"] as? [String: Any])?["executable"] as? [String: Any],
           let p = script["path"] as? String {
            extra["proc_exe"] = p
        }

        return SecurityEvent(
            timestamp: timestamp,
            kind: kind,
            process: process,
            filePath: filePath,
            fileHash: nil,
            severity: .none,
            confidence: .low,
            source: source,
            extra: extra
        )
    }

    private static func eventKind(from obj: [String: Any]) -> EventKind {
        if let t = obj["event_type"] as? String, let k = EventKind(rawValue: t) { return k }
        if let event = obj["event"] as? [String: Any], let first = event.keys.first,
           let k = EventKind(rawValue: first) { return k }
        return .unknown
    }

    private static func processRef(from p: [String: Any]) -> ProcessRef {
        var pid: Int32 = 0
        if let token = p["audit_token"] as? [String: Any], let v = int32(token["pid"]) {
            pid = v
        } else if let v = int32(p["pid"]) {
            pid = v
        }
        var ppid: Int32?
        if let v = int32(p["ppid"]) { ppid = v }
        else if let token = p["audit_token"] as? [String: Any], let v = int32(token["ppid"]) { ppid = v }

        var exe: String?
        if let e = p["executable"] as? [String: Any] { exe = e["path"] as? String }
        else if let e = p["executable"] as? String { exe = e }

        return ProcessRef(pid: pid, ppid: ppid, executablePath: exe,
                          signingID: p["signing_id"] as? String,
                          teamID: p["team_id"] as? String)
    }

    private static func pathFromFile(_ d: [String: Any]) -> String? {
        if let p = d["path"] as? String { return p }
        if let f = d["file"] as? [String: Any] { return f["path"] as? String }
        return nil
    }

    private static func int32(_ any: Any?) -> Int32? {
        if let n = any as? Int { return Int32(n) }
        if let n = any as? Int32 { return n }
        if let n = any as? NSNumber { return n.int32Value }
        return nil
    }

    private static func parseTime(_ any: Any?) -> Date? {
        guard let s = any as? String else { return nil }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s)
    }
}