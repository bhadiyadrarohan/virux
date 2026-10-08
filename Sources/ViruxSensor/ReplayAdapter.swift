import Foundation
import ViruxCore

/// Event source that replays a JSONL file of eslogger-shaped lines. Used by
/// tests and benchmarks so CI and offline runs never need root or live events.
public final class ReplayAdapter: EventSource {
    public let name = "replay"
    private let filePath: String
    private let delay: TimeInterval
    private var stopped = false

    public init(filePath: String, delay: TimeInterval = 0) {
        self.filePath = filePath
        self.delay = delay
    }

    public func start(onEvent: @escaping (SecurityEvent) -> Void,
                      onError: @escaping (String) -> Void) {
        DispatchQueue.global().async { [weak self] in
            guard let self else { return }
            guard let content = try? String(contentsOfFile: self.filePath, encoding: .utf8) else {
                onError("cannot read replay file at \(self.filePath)")
                return
            }
            for line in content.split(separator: "\n") {
                if self.stopped { return }
                if let event = EsloggerParser.parse(line: String(line), source: self.name) {
                    onEvent(event)
                    if self.delay > 0 { Thread.sleep(forTimeInterval: self.delay) }
                }
            }
        }
    }

    public func stop() { stopped = true }
}