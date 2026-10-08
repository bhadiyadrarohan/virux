import Foundation
import ViruxCore

/// Ties the pieces together: local hashing of executed images, signature and
/// reputation lookups, behavioural rules, and detection persistence.
///
/// M3 is observe-only. Nothing here enforces (quarantine/terminate); it only
/// records explainable detections. Enforcement is staged later (DECISIONS D006).
public final class DetectionPipeline {

    public struct Stats: Sendable {
        public var processed = 0
        public var detections = 0
        public var hashedFiles = 0
    }

    private let store: EventStore
    private let engine: RuleEngine
    private let signatures: SignatureMatcher?
    private let hashExecImages: Bool
    private var hashCache: [String: String] = [:]
    private(set) public var stats = Stats()

    public init(store: EventStore,
                engine: RuleEngine = RuleEngine(),
                signatures: SignatureMatcher? = nil,
                hashExecImages: Bool = false) {
        self.store = store
        self.engine = engine
        self.signatures = signatures
        self.hashExecImages = hashExecImages
    }

    /// Processes one stored event. Returns a Detection if anything fired.
    @discardableResult
    public func process(_ event: SecurityEvent) -> Detection? {
        stats.processed += 1

        var bestRank = Severity.none.rank
        var severity = Severity.none
        var confidence = Confidence.low
        var title = ""
        var reason = ""
        var evidence: [Int64] = []

        // 1. Hash the executed image (bounded, cached) and look it up.
        if hashExecImages, event.kind == .exec,
           let path = event.process.executablePath, let hash = hashFor(path: path) {
            if let sig = signatures?.lookup(hash) {
                if sig.severity.rank > bestRank {
                    bestRank = sig.severity.rank
                    severity = sig.severity
                    confidence = .high
                    title = "Known-bad executable: \(sig.name)"
                    reason = "\(path) matches local signature '\(sig.name)' (sha256 \(hash))."
                }
            }
            if let rep = store.reputation(hash: hash), rep == "malicious" {
                if Severity.high.rank > bestRank {
                    bestRank = Severity.high.rank
                    severity = .high
                    confidence = .high
                    title = "Cached-malicious hash"
                    reason = "\(path) hash \(hash) is marked malicious in the local reputation cache."
                }
            }
        }

        // 2. Behavioural rules.
        if let match = engine.evaluate(event) {
            if match.severity.rank > bestRank {
                bestRank = match.severity.rank
                severity = match.severity
                confidence = match.confidence
                title = match.title
                reason = match.reason
            }
            if let id = event.id { evidence.append(id) }
        }

        guard severity != .none, !title.isEmpty else { return nil }

        var detection = Detection(timestamp: event.timestamp, title: title, reason: reason,
                                  severity: severity, confidence: confidence,
                                  evidenceEventIDs: Array(Set(evidence)).sorted(),
                                  status: .observed)
        detection.id = try? store.insertDetection(detection)
        stats.detections += 1
        return detection
    }

    // MARK: - Hashing with a bounded cache

    private func hashFor(path: String) -> String? {
        let attrs = try? FileManager.default.attributesOfItem(atPath: path)
        let size = (attrs?[.size] as? NSNumber)?.int64Value ?? -1
        let mtime = (attrs?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? -1
        let key = "\(path)|\(size)|\(mtime)"
        if let cached = hashCache[key] { return cached }
        guard let hash = Hashing.sha256(ofFileAt: path) else { return nil }
        if hashCache.count > 4096 { hashCache.removeAll(keepingCapacity: true) }
        hashCache[key] = hash
        stats.hashedFiles += 1
        return hash
    }
}
