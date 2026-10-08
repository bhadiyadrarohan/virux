import Foundation
import ViruxCore

/// Event source that spawns Apple's pre-entitled `eslogger` and streams its
/// JSON output. Requires root and Full Disk Access for the responsible process.
/// This is an M1 prototype bridge, not a product sensor.
public final class EsloggerAdapter: EventSource {
    public let name = "eslogger"
    private let eventTypes: [String]
    private let binaryPath: String
    private var process: Process?
    private var stdoutPipe: Pipe?
    private var lineBuffer = Data()
    private let lock = NSLock()

    public init(eventTypes: [String] = ["exec", "fork", "exit", "open", "close"],
                binaryPath: String = "/usr/bin/eslogger") {
        self.eventTypes = eventTypes
        self.binaryPath = binaryPath
    }

    public func start(onEvent: @escaping (SecurityEvent) -> Void,
                      onError: @escaping (String) -> Void) {
        guard FileManager.default.isExecutableFile(atPath: binaryPath) else {
            onError("eslogger not found at \(binaryPath)")
            return
        }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: binaryPath)
        proc.arguments = eventTypes
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            self?.consume(data, onEvent: onEvent)
        }

        proc.terminationHandler = { p in
            onError("eslogger exited with status \(p.terminationStatus)")
        }

        do {
            try proc.run()
            self.process = proc
            self.stdoutPipe = pipe
        } catch {
            onError("failed to launch eslogger: \(error.localizedDescription). Root and Full Disk Access are required.")
        }
    }

    private func consume(_ data: Data, onEvent: @escaping (SecurityEvent) -> Void) {
        lock.lock()
        lineBuffer.append(data)
        var lines: [String] = []
        while let idx = lineBuffer.firstIndex(of: 0x0A) {
            let lineData = lineBuffer[lineBuffer.startIndex..<idx]
            lineBuffer.removeSubrange(lineBuffer.startIndex...idx)
            if let s = String(data: lineData, encoding: .utf8), !s.isEmpty { lines.append(s) }
        }
        lock.unlock()
        for line in lines {
            if let event = EsloggerParser.parse(line: line, source: name) {
                onEvent(event)
            }
        }
    }

    public func stop() {
        stdoutPipe?.fileHandleForReading.readabilityHandler = nil
        process?.terminate()
        process = nil
        stdoutPipe = nil
    }
}