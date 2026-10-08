import Foundation
import ViruxCore

/// Messages exchanged between the Swift components and the Python worker over
/// the authenticated local channel.
public enum WorkerRequest: Codable, Sendable {
    case ping
    case analyze(path: String, sha256: String?)
    case report(detectionID: Int64)
}

public enum WorkerResponse: Codable, Sendable {
    case pong(version: String)
    case analysis(verdict: String, notes: [String], confidence: Confidence)
    case reportMarkdown(String)
    case error(String)
}

/// Peer identity resolved from the socket, used for least-privilege checks.
public struct PeerCredentials: Codable, Sendable, Equatable {
    public var uid: UInt32
    public var gid: UInt32
    public var pid: Int32

    public init(uid: UInt32, gid: UInt32, pid: Int32) {
        self.uid = uid
        self.gid = gid
        self.pid = pid
    }
}