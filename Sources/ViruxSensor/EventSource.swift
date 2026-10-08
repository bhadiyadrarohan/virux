import Foundation
import ViruxCore

/// A source of normalised telemetry. The daemon consumes one source. M1 ships
/// three: the eslogger bridge (needs root + Full Disk Access), a file replay,
/// and a synthetic generator. The real Endpoint Security sensor (M2) will
/// implement this same protocol.
public protocol EventSource: AnyObject {
    var name: String { get }
    /// Begin producing events. Handlers may be called from a background thread.
    func start(onEvent: @escaping (SecurityEvent) -> Void,
               onError: @escaping (String) -> Void)
    func stop()
}