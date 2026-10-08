import Foundation
import CryptoKit

/// Local hashing. M1 computes SHA-256 for regular files, streaming so memory
/// stays flat. No content leaves the machine.
public enum Hashing {

    /// SHA-256 of an arbitrary byte buffer, lowercase hex.
    public static func sha256(of data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Streaming SHA-256 of a file. Returns nil if the file cannot be read or
    /// exceeds `maxBytes` (skipped in M1 rather than risking a huge read).
    public static func sha256(ofFileAt path: String, maxBytes: Int = 256 * 1024 * 1024) -> String? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        var total = 0
        while true {
            let chunk = handle.readData(ofLength: 1 << 20)
            if chunk.isEmpty { break }
            total += chunk.count
            if total > maxBytes { return nil }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}