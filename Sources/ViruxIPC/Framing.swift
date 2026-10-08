import Foundation

/// Length-prefixed framing for the local IPC channel: 4-byte big-endian length
/// followed by that many bytes of JSON. Avoids newline-in-JSON problems.
public enum Framing {
    public static func frame(_ payload: Data) -> Data {
        var be = UInt32(payload.count).bigEndian
        var out = Data(bytes: &be, count: 4)
        out.append(payload)
        return out
    }

    /// Attempts to read one frame header from the front of `buffer`.
    /// Returns (declaredLength, headerSize) or nil if the header is incomplete.
    public static func peekHeader(_ buffer: Data) -> (length: UInt32, headerSize: Int)? {
        guard buffer.count >= 4 else { return nil }
        let n = buffer.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self) }
        return (UInt32(bigEndian: n), 4)
    }
}