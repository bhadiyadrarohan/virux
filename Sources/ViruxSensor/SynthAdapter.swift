import Foundation
import ViruxCore

/// Synthetic event generator for benchmarks and smoke tests. Emits harmless,
/// clearly-labelled records. Never used to represent real protection.
public final class SynthAdapter: EventSource {
    public let name = "synth"
    private let interval: TimeInterval
    private let limit: Int
    private var stopped = false
    private var timer: DispatchSourceTimer?

    public init(interval: TimeInterval = 0.5, limit: Int = .max) {
        self.interval = interval
        self.limit = limit
    }

    public func start(onEvent: @escaping (SecurityEvent) -> Void,
                      onError: @escaping (String) -> Void) {
        let queue = DispatchQueue(label: "ai.virux.synth")
        var emitted = 0
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: interval)
        timer.setEventHandler { [weak self] in
            guard let self, !self.stopped, emitted < self.limit else { return }
            emitted += 1
            let kinds: [EventKind] = [.exec, .open, .close, .fork, .exit]
            let kind = kinds[emitted % kinds.count]
            let event = SecurityEvent(
                kind: kind,
                process: ProcessRef(pid: Int32(1000 + (emitted % 50)), ppid: 1,
                                    executablePath: "/usr/bin/synth", signingID: "com.virux.synth",
                                    teamID: nil),
                filePath: kind == .open ? "/tmp/virux-synth-\(emitted % 10)" : nil,
                source: self.name,
                extra: ["synthetic": "true"]
            )
            onEvent(event)
        }
        timer.resume()
        self.timer = timer
    }

    public func stop() {
        stopped = true
        timer?.cancel()
        timer = nil
    }
}