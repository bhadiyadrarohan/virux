import Foundation
import ViruxCore

/// Renders a process tree as a standalone SVG relationship graph. Unsigned
/// processes are outlined in amber so the eye goes to them first.
public enum GraphRenderer {

    public static func processTreeSVG(_ roots: [ProcessNode],
                                      nodeWidth: Int = 240, nodeHeight: Int = 30,
                                      hGap: Int = 64, vGap: Int = 14,
                                      fontSize: Int = 12) -> String {
        struct Placed { var node: ProcessNode; var depth: Int; var row: Int; var parent: Int? }
        var placed: [Placed] = []
        var rowCounter = 0
        var maxDepth = 0

        func place(_ node: ProcessNode, depth: Int, parent: Int?) {
            let myIndex = placed.count
            let row = rowCounter
            rowCounter += 1
            maxDepth = max(maxDepth, depth)
            placed.append(Placed(node: node, depth: depth, row: row, parent: parent))
            for c in node.children { place(c, depth: depth + 1, parent: myIndex) }
        }
        for r in roots { place(r, depth: 0, parent: nil) }

        let colW = nodeWidth + hGap
        let rowH = nodeHeight + vGap
        let width = (maxDepth + 1) * colW + hGap
        let height = max(1, rowCounter) * rowH + vGap

        func box(_ p: Placed) -> (Int, Int) { (hGap + p.depth * colW, vGap + p.row * rowH) }

        var svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 \(width) \(height)\" "
        svg += "width=\"\(width)\" height=\"\(height)\" "
        svg += "font-family=\"-apple-system, Helvetica, Arial, sans-serif\">\n"
        svg += "<rect width=\"\(width)\" height=\"\(height)\" fill=\"#111318\"/>\n"

        for (i, p) in placed.enumerated() {
            guard let pi = p.parent, pi < placed.count else { continue }
            let (px, py) = box(placed[pi])
            let (cx, cy) = box(p)
            let x1 = px + nodeWidth, y1 = py + nodeHeight / 2
            let x2 = cx, y2 = cy + nodeHeight / 2
            let mx = (x1 + x2) / 2
            svg += "<path d=\"M\(x1) \(y1) C \(mx) \(y1), \(mx) \(y2), \(x2) \(y2)\" "
            svg += "fill=\"none\" stroke=\"#4a5160\" stroke-width=\"1.5\"/>\n"
            _ = i
        }

        for p in placed {
            let (x, y) = box(p)
            let stroke = p.node.isUnsigned ? "#f5a623" : "#3d8bfd"
            svg += "<rect x=\"\(x)\" y=\"\(y)\" width=\"\(nodeWidth)\" height=\"\(nodeHeight)\" rx=\"6\" "
            svg += "fill=\"#1b1f27\" stroke=\"\(stroke)\" stroke-width=\"1.5\"/>\n"
            let label = escape("\(p.node.name)  [\(p.node.pid)]" + (p.node.isUnsigned ? "  unsigned" : ""))
            svg += "<text x=\"\(x + 10)\" y=\"\(y + nodeHeight / 2 + fontSize / 3)\" fill=\"#e6e9ef\" "
            svg += "font-size=\"\(fontSize)\">\(label)</text>\n"
        }
        svg += "</svg>\n"
        return svg
    }

    static func escape(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }
}
