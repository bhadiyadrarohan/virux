import Foundation
import ViruxCore
import ViruxRespond

/// A plain-English, evidence-backed report for one detection. Every claim is
/// tied to stored events; nothing is inferred beyond what was observed.
public struct InvestigationReport: Sendable {
    public var detection: Detection
    public var evidenceEvents: [SecurityEvent]
    public var processChain: [ProcessRef]
    public var relatedFiles: [String]
    public var relatedHashes: [String]
    public var processTreeASCII: String
    public var quarantine: QuarantineRecord?
    public var recommendedActions: [String]
    public var residualRisk: String

    public func markdown() -> String {
        var md = "# Incident report: \(detection.title)\n\n"
        md += "- **Detection id:** \(detection.id.map(String.init) ?? "n/a")\n"
        md += "- **When:** \(ISO8601DateFormatter().string(from: detection.timestamp))\n"
        md += "- **Severity (impact):** \(detection.severity.rawValue)\n"
        md += "- **Confidence (certainty):** \(detection.confidence.rawValue)\n"
        md += "- **Status:** \(detection.status.rawValue)\n\n"
        md += "## Why it was flagged\n\n\(detection.reason)\n\n"

        md += "## Process chain\n\n"
        if processChain.isEmpty {
            md += "_No process ancestry available in the retained telemetry._\n\n"
        } else {
            for (i, p) in processChain.enumerated() {
                let pad = String(repeating: "  ", count: i)
                let sign = p.signingID.map { "signed: \($0)" } ?? "UNSIGNED"
                md += "\(pad)- \(p.executablePath ?? "(unknown)") [pid \(p.pid)] (\(sign))\n"
            }
            md += "\n"
        }

        md += "## Process tree\n\n```\n\(processTreeASCII.isEmpty ? "(no tree)" : processTreeASCII)\n```\n\n"

        md += "## Evidence (\(evidenceEvents.count) events)\n\n"
        if evidenceEvents.isEmpty {
            md += "_No linked events._\n\n"
        } else {
            md += "| id | time | kind | pid | detail |\n|---|---|---|---|---|\n"
            for e in evidenceEvents {
                let detail = e.filePath ?? e.process.executablePath ?? ""
                md += "| \(e.id.map(String.init) ?? "-") | \(ISO8601DateFormatter().string(from: e.timestamp)) | \(e.kind.rawValue) | \(e.process.pid) | \(detail) |\n"
            }
            md += "\n"
        }

        if !relatedFiles.isEmpty {
            md += "## Potentially impacted files\n\n"
            for f in relatedFiles { md += "- `\(f)`\n" }
            md += "\n"
        }
        if !relatedHashes.isEmpty {
            md += "## Hashes\n\n"
            for h in relatedHashes { md += "- `\(h)`\n" }
            md += "\n"
        }

        md += "## Containment\n\n"
        if let q = quarantine {
            md += "- Quarantined as record #\(q.id ?? 0) at \(ISO8601DateFormatter().string(from: q.timestamp))\n"
            md += "- Original path: `\(q.originalPath)`\n"
            md += "- Store path: `\(q.quarantinePath)`\n"
            md += "- Status: \(q.status.rawValue)\n"
        } else {
            md += "- No quarantine record linked to this detection (observe-only, or already resolved).\n"
        }
        md += "\n## Recommended next actions\n\n"
        for a in recommendedActions { md += "- \(a)\n" }
        md += "\n## Residual risk if retained\n\n\(residualRisk)\n"
        return md
    }
}

public enum ReportBuilder {

    public static func build(detection: Detection,
                             store: EventStore,
                             quarantineStore: QuarantineStore?,
                             treeEventLimit: Int = 2000) -> InvestigationReport {
        let evidence = detection.evidenceEventIDs.isEmpty
            ? []
            : store.searchEvents(EventQuery(ids: detection.evidenceEventIDs, limit: 200))
                .sorted { ($0.id ?? 0) < ($1.id ?? 0) }

        // A window of surrounding telemetry gives the process tree context.
        let windowStart = detection.timestamp.addingTimeInterval(-600)
        let window = store.searchEvents(EventQuery(since: windowStart,
                                                   until: detection.timestamp.addingTimeInterval(60),
                                                   limit: treeEventLimit))
        let tree = ProcessTreeBuilder.build(from: window)
        let treeASCII = ProcessTreeRenderer.ascii(tree).prefix(4000)

        // Focus the process chain on the most notable evidence event: highest
        // severity first, then the most recent.
        let focus = evidence.max { a, b in
            a.severity.rank != b.severity.rank ? a.severity.rank < b.severity.rank : a.timestamp < b.timestamp
        }
        let focusPID = focus?.process.pid
        let chain = focusPID.map { ProcessTreeBuilder.ancestry(of: $0, from: window) } ?? []

        var files: [String] = []
        var hashes: [String] = []
        for e in evidence {
            if let f = e.filePath, !files.contains(f) { files.append(f) }
            if let h = e.fileHash, !hashes.contains(h) { hashes.append(h) }
        }

        let quarantine = quarantineStore?.list().first { $0.detectionID == detection.id }

        var actions: [String] = []
        switch detection.severity {
        case .critical:
            actions.append("Confirm the process is contained (terminated) and the file is quarantined.")
            actions.append("Check for other affected files and any backup/snapshot tampering.")
        case .high:
            actions.append("Review the flagged file inside the sandbox before restoring it.")
            actions.append("Verify the process is no longer running.")
        case .medium:
            actions.append("Observe: confirm whether the activity is expected for this machine.")
            actions.append("If benign, allowlist by signing identity rather than by path.")
        case .low, .none:
            actions.append("No action required; retained for correlation.")
        }
        actions.append("If restoring a quarantined file, do so only after confirming it is trusted.")

        let residual: String
        switch detection.severity {
        case .critical, .high:
            residual = "If the item is restored or left running, the observed behaviour can recur. A clean sandbox result is not proof of safety (DECISIONS D006)."
        case .medium:
            residual = "Unconfirmed. Reassess on new evidence; do not treat as safe or as confirmed malicious yet."
        case .low, .none:
            residual = "Low impact; monitor."
        }

        return InvestigationReport(detection: detection, evidenceEvents: evidence,
                                   processChain: chain, relatedFiles: files, relatedHashes: hashes,
                                   processTreeASCII: String(treeASCII), quarantine: quarantine,
                                   recommendedActions: actions, residualRisk: residual)
    }
}
