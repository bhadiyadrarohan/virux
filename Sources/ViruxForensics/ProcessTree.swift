import Foundation
import ViruxCore

/// A node in a reconstructed process tree.
public struct ProcessNode: Sendable {
    public var pid: Int32
    public var ppid: Int32?
    public var executablePath: String?
    public var signingID: String?
    public var firstSeen: Date
    public var eventCount: Int
    public var children: [ProcessNode]

    public var name: String {
        executablePath.map { ($0 as NSString).lastPathComponent } ?? "(unknown)"
    }
    public var isUnsigned: Bool { signingID == nil }
}

/// Rebuilds parent/child relationships from stored telemetry. It relies on the
/// pid/ppid carried in events, so it is only as complete as the event stream
/// (a parents' exec may predate the retention window).
public enum ProcessTreeBuilder {

    public static func build(from events: [SecurityEvent]) -> [ProcessNode] {
        var info: [Int32: (ref: ProcessRef, first: Date, count: Int)] = [:]
        for e in events {
            let pid = e.process.pid
            if pid <= 0 { continue }
            if var existing = info[pid] {
                existing.count += 1
                if e.timestamp < existing.first { existing.first = e.timestamp }
                if existing.ref.executablePath == nil { existing.ref.executablePath = e.process.executablePath }
                if existing.ref.signingID == nil { existing.ref.signingID = e.process.signingID }
                info[pid] = existing
            } else {
                info[pid] = (e.process, e.timestamp, 1)
            }
        }

        var nodes: [Int32: ProcessNode] = [:]
        for (pid, v) in info {
            nodes[pid] = ProcessNode(pid: pid, ppid: v.ref.ppid, executablePath: v.ref.executablePath,
                                     signingID: v.ref.signingID, firstSeen: v.first,
                                     eventCount: v.count, children: [])
        }

        var childrenOf: [Int32: [Int32]] = [:]
        var roots: [Int32] = []
        for (pid, node) in nodes {
            // Link to any parent that is present in the telemetry, including
            // launchd (pid 1). Only genuinely parentless processes are roots.
            if let ppid = node.ppid, ppid > 0, ppid != pid, nodes[ppid] != nil {
                childrenOf[ppid, default: []].append(pid)
            } else {
                roots.append(pid)
            }
        }

        var visiting: Set<Int32> = []
        func assemble(_ pid: Int32) -> ProcessNode {
            var n = nodes[pid]!
            if visiting.contains(pid) { return n }        // cycle guard
            visiting.insert(pid)
            let kids = (childrenOf[pid] ?? []).sorted {
                (nodes[$0]?.firstSeen ?? .distantPast) < (nodes[$1]?.firstSeen ?? .distantPast)
            }
            n.children = kids.map { assemble($0) }
            visiting.remove(pid)
            return n
        }
        return roots.sorted { (nodes[$0]?.firstSeen ?? .distantPast) < (nodes[$1]?.firstSeen ?? .distantPast) }
            .map { assemble($0) }
    }

    /// Returns the ancestor chain for a pid, nearest first.
    public static func ancestry(of pid: Int32, from events: [SecurityEvent]) -> [ProcessRef] {
        var refOf: [Int32: ProcessRef] = [:]
        var ppidOf: [Int32: Int32?] = [:]
        for e in events where e.process.pid > 0 {
            refOf[e.process.pid] = e.process
            if ppidOf[e.process.pid] == nil { ppidOf[e.process.pid] = e.process.ppid }
        }
        var chain: [ProcessRef] = []
        var current: Int32? = pid
        var hops = 0
        var seen: Set<Int32> = []
        while let c = current, let ref = refOf[c], hops < 64, !seen.contains(c) {
            chain.append(ref)
            seen.insert(c)
            current = ppidOf[c] ?? nil
            hops += 1
        }
        return chain
    }
}

public enum ProcessTreeRenderer {
    public static func ascii(_ roots: [ProcessNode]) -> String {
        var lines: [String] = []
        func label(_ n: ProcessNode) -> String {
            let sign = n.isUnsigned ? "  (unsigned)" : ""
            return "\(n.name) [pid \(n.pid), \(n.eventCount) events]\(sign)"
        }
        func walk(_ node: ProcessNode, prefix: String, isLast: Bool) {
            lines.append(prefix + (isLast ? "└─ " : "├─ ") + label(node))
            for (i, k) in node.children.enumerated() {
                walk(k, prefix: prefix + (isLast ? "   " : "│  "), isLast: i == node.children.count - 1)
            }
        }
        for r in roots { walk(r, prefix: "", isLast: true) }
        return lines.joined(separator: "\n")
    }
}
