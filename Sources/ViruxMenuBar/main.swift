import AppKit
import SwiftUI
import ViruxCore
import ViruxIPC
import ViruxForensics
import ViruxRespond
import ViruxSandbox

// ViruxMenuBar: the menu-bar app. The icon is the Virux V mark with a
// green/yellow/red status dot. Clicking opens the dashboard, which reads the
// local store. Protection continues while this UI is closed.
//
// Runs as a bare SwiftPM executable; a distributable bundle (LSUIElement,
// Info.plist, notarization) is the packaging step at M8.

func defaultDBPath() -> String {
    let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    return base.appendingPathComponent("Virux/events.db").path
}

enum Pane: String, CaseIterable {
    case overview = "Overview"
    case detections = "Detections"
    case quarantine = "Quarantine"
    case timeline = "Timeline"
}

final class Model: ObservableObject {
    @Published var health: Health?
    @Published var recentEvents: [SecurityEvent] = []
    @Published var detections: [Detection] = []
    @Published var quarantine: [QuarantineRecord] = []
    @Published var totalRows: Int64 = 0
    @Published var dbSize: Int64 = 0
    @Published var pane: Pane = .overview
    @Published var report: String?
    @Published var reportTitle: String = ""
    @Published var persistenceAlerts: [String] = []
    @Published var resources: SystemResources?
    @Published var gateReason: String?

    let dbPath: String
    init(dbPath: String) { self.dbPath = dbPath; refresh() }

    private var quarantineDir: String {
        ((dbPath as NSString).deletingLastPathComponent as NSString).appendingPathComponent("Quarantine")
    }

    func refresh() {
        health = Health.load(from: Health.defaultPath(dbPath: dbPath))
        let res = SystemResourceProbe().sample()
        resources = res
        switch ResourceGate().decide(resources: res, activeRuns: 0) {
        case .allow: gateReason = nil
        case .deferred(let r): gateReason = r
        }
        guard let store = try? EventStore(path: dbPath) else { return }
        recentEvents = store.recent(limit: 80)
        detections = store.searchDetections(DetectionQuery(limit: 50))
        totalRows = store.count()
        dbSize = store.dbSizeBytes()
        if let qs = try? QuarantineStore(directory: quarantineDir, store: store) {
            quarantine = qs.list()
        }
    }

    func openReport(_ d: Detection) {
        guard let store = try? EventStore(path: dbPath) else { return }
        let qs = try? QuarantineStore(directory: quarantineDir, store: store)
        reportTitle = d.title
        report = ReportBuilder.build(detection: d, store: store, quarantineStore: qs).markdown()
    }

    func scanPersistence() {
        let snap = PersistenceMonitor().scan()
        let suspicious = snap.items.filter { $0.suspicious }
        persistenceAlerts = suspicious.map {
            "\($0.label ?? ($0.path as NSString).lastPathComponent): \($0.reasons.joined(separator: "; "))"
        }
    }
}

// MARK: - Helpers

func sevColor(_ s: Severity) -> Color {
    switch s {
    case .critical: return .red
    case .high: return .orange
    case .medium: return .yellow
    case .low: return .blue
    case .none: return .secondary
    }
}
func shortTime(_ d: Date?) -> String {
    guard let d else { return "never" }
    let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; return f.string(from: d)
}
func humanBytes(_ b: Int64) -> String {
    let u = ["B", "KB", "MB", "GB"]; var v = Double(b); var i = 0
    while v >= 1024 && i < u.count - 1 { v /= 1024; i += 1 }
    return String(format: "%.1f %@", v, u[i])
}

// MARK: - Views

struct DashboardView: View {
    @ObservedObject var model: Model

    var statusColor: Color {
        guard let h = model.health else { return .red }
        if !h.isFresh() { return .yellow }
        return h.state == "observe-only" || h.state == "protected" ? .green : .yellow
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Circle().fill(statusColor).frame(width: 10, height: 10)
                Text("Virux").font(.headline)
                Spacer()
                if model.report != nil {
                    Button("Back") { model.report = nil }
                } else {
                    Button("Refresh") { model.refresh() }
                }
                Button("Quit") { NSApplication.shared.terminate(nil) }
            }
            Divider()

            if let md = model.report {
                VStack(alignment: .leading, spacing: 6) {
                    Text(model.reportTitle).font(.subheadline).bold()
                    ScrollView {
                        Text(md).font(.system(size: 11, design: .monospaced))
                            .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .frame(maxHeight: .infinity)
            } else {
                Picker("", selection: $model.pane) {
                    ForEach(Pane.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden()
                Divider()
                switch model.pane {
                case .overview:   OverviewView(model: model)
                case .detections: DetectionsView(model: model)
                case .quarantine: QuarantineView(model: model)
                case .timeline:   TimelineView(model: model)
                }
            }
            Divider()
            Text("Observe-only: detections are recorded and nothing is enforced automatically.")
                .font(.caption2).foregroundStyle(.secondary)
        }
        .padding(14)
        .frame(width: 460, height: 560)
        .onAppear { model.refresh() }
    }
}

struct OverviewView: View {
    @ObservedObject var model: Model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 6) {
                if let h = model.health {
                    row("State", h.state + (h.isFresh() ? " (live)" : " (STALE)"))
                    row("Source", h.source)
                    row("Last event", shortTime(h.lastEventAt))
                    row("Events stored", "\(h.eventsStored)  errors \(h.insertErrors)")
                } else {
                    row("State", "unknown (is viruxd running?)")
                }
                row("Store", "\(model.totalRows) rows, \(humanBytes(model.dbSize))")
                row("Detections", "\(model.detections.count)")
                row("Quarantined", "\(model.quarantine.filter { $0.status == .quarantined }.count)")
                if let r = model.resources {
                    row("Host", String(format: "free mem %.2f GB, free disk %.2f GB",
                                       r.freeMemoryGB, r.freeDiskGB))
                }
                if let g = model.gateReason { row("Sandbox", "deferred: \(g)") }
                else { row("Sandbox", "ready") }

                Divider().padding(.vertical, 4)
                HStack {
                    Text("Startup / persistence").font(.caption).bold()
                    Spacer()
                    Button("Scan") { model.scanPersistence() }.controlSize(.small)
                }
                if model.persistenceAlerts.isEmpty {
                    Text("No suspicious autostart entries detected yet. Press Scan.")
                        .font(.caption2).foregroundStyle(.secondary)
                } else {
                    ForEach(model.persistenceAlerts, id: \.self) { a in
                        Text("• \(a)").font(.caption2).foregroundStyle(.orange)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top) {
            Text(k).font(.caption).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
            Text(v).font(.caption)
        }
    }
}

struct DetectionsView: View {
    @ObservedObject var model: Model
    var body: some View {
        if model.detections.isEmpty {
            Text("No detections recorded.").font(.caption).foregroundStyle(.secondary)
        } else {
            List(model.detections, id: \.id) { d in
                Button {
                    model.openReport(d)
                } label: {
                    HStack(alignment: .top, spacing: 8) {
                        Circle().fill(sevColor(d.severity)).frame(width: 8, height: 8).padding(.top, 4)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(d.title).font(.caption).bold()
                            Text("\(d.severity.rawValue) / \(d.confidence.rawValue) · \(shortTime(d.timestamp))")
                                .font(.caption2).foregroundStyle(.secondary)
                            Text(d.reason).font(.caption2).lineLimit(2).foregroundStyle(.secondary)
                        }
                    }
                }
                .buttonStyle(.plain)
            }
            .listStyle(.inset)
            .frame(minHeight: 300)
        }
    }
}

struct QuarantineView: View {
    @ObservedObject var model: Model
    var body: some View {
        if model.quarantine.isEmpty {
            Text("Quarantine is empty.").font(.caption).foregroundStyle(.secondary)
        } else {
            List(model.quarantine, id: \.id) { q in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text("#\(q.id ?? 0)").font(.caption2).foregroundStyle(.secondary)
                        Text(q.status.rawValue).font(.caption2).bold()
                            .foregroundStyle(q.status == .quarantined ? .orange : .secondary)
                    }
                    Text(q.originalPath).font(.caption2).lineLimit(1)
                    Text("sha256 \(q.sha256?.prefix(16) ?? "?")…").font(.caption2).foregroundStyle(.secondary)
                    Text(q.reason).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            .listStyle(.inset)
            .frame(minHeight: 280)
            Text("Restore and delete require administrator authorisation: virux quarantine-restore/delete ID")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }
}

struct TimelineView: View {
    @ObservedObject var model: Model
    var body: some View {
        List(model.recentEvents, id: \.id) { e in
            HStack(spacing: 8) {
                Text(shortTime(e.timestamp)).font(.caption2).foregroundStyle(.secondary).frame(width: 58, alignment: .leading)
                Text(e.kind.rawValue).font(.caption2).bold().frame(width: 52, alignment: .leading)
                Text("pid \(e.process.pid)").font(.caption2).foregroundStyle(.secondary).frame(width: 54, alignment: .leading)
                Text(e.process.executablePath.map { ($0 as NSString).lastPathComponent } ?? e.filePath ?? "")
                    .font(.caption2).lineLimit(1)
                if e.process.signingID == nil && e.kind == .exec {
                    Text("unsigned").font(.caption2).foregroundStyle(.orange)
                }
            }
        }
        .listStyle(.inset)
        .frame(minHeight: 300)
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var popover = NSPopover()
    var model: Model!
    var timer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let dbPath = ProcessInfo.processInfo.environment["VIRUX_DB"] ?? defaultDBPath()
        model = Model(dbPath: dbPath)

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        updateButton()

        popover.behavior = .transient
        popover.contentViewController = NSHostingController(rootView: DashboardView(model: model))
        if let button = statusItem.button {
            button.action = #selector(toggle)
            button.target = self
        }
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            self?.updateButton()
            self?.model.refresh()
        }
    }

    func updateButton() {
        guard let button = statusItem.button else { return }
        let h = model.health
        let color: NSColor
        if h == nil { color = .systemRed }
        else if !(h!.isFresh()) { color = .systemYellow }
        else { color = .systemGreen }

        if let logo = Self.logoImage {
            button.image = logo
            button.imagePosition = .imageLeading
            button.attributedTitle = Self.dot(color)
        } else {
            button.image = nil
            let s = NSMutableAttributedString(string: "V", attributes: [
                .foregroundColor: NSColor.labelColor,
                .font: NSFont.boldSystemFont(ofSize: 13)
            ])
            s.append(Self.dot(color))
            button.attributedTitle = s
        }
    }

    /// The Virux V mark, bundled as a template image so macOS tints it for
    /// light and dark menu bars.
    static let logoImage: NSImage? = {
        guard let img = Bundle.module.image(forResource: "MenuBarIcon") else { return nil }
        img.isTemplate = true
        img.size = NSSize(width: 20, height: 12)
        return img
    }()

    static func dot(_ color: NSColor) -> NSAttributedString {
        NSAttributedString(string: " \u{25CF}", attributes: [
            .foregroundColor: color,
            .font: NSFont.systemFont(ofSize: 9)
        ])
    }

    @objc func toggle() {
        if popover.isShown {
            popover.performClose(nil)
        } else if let button = statusItem.button {
            model.refresh()
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)

// Headless verification hook: launch, build the status item (and thus load the
// icon), then exit. Used by the verification scripts.
if let s = ProcessInfo.processInfo.environment["VIRUX_UI_SELFTEST_SECONDS"], let n = Double(s) {
    DispatchQueue.main.asyncAfter(deadline: .now() + n) {
        FileHandle.standardError.write("ViruxMenuBar: selftest elapsed (logoLoaded=\(AppDelegate.logoImage != nil)), exiting 0\n".data(using: .utf8)!)
        NSApplication.shared.terminate(nil)
    }
}

app.run()
