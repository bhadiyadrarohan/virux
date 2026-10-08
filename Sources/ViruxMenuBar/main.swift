import AppKit
import SwiftUI
import ViruxCore
import ViruxIPC

// ViruxMenuBar: M1 menu-bar placeholder. A "V" with a green/yellow/red status
// dot. Clicking opens a dashboard shell that reads the local store. Protection
// (telemetry) continues while this UI is closed because the UI holds no state.
//
// NOTE: In M1 this runs as a bare SwiftPM executable. A distributable app will
// need a proper bundle with LSUIElement and an Info.plist (M6 packaging).

func defaultDBPath() -> String {
    let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    return base.appendingPathComponent("Virux/events.db").path
}

struct DashboardSnapshot {
    var health: Health?
    var recent: [SecurityEvent]
    var byKind: [(String, Int64)]
    var totalRows: Int64
    var dbSize: Int64

    static func load(dbPath: String) -> DashboardSnapshot {
        let health = Health.load(from: Health.defaultPath(dbPath: dbPath))
        var recent: [SecurityEvent] = []
        var byKind: [(String, Int64)] = []
        var rows: Int64 = 0
        var size: Int64 = 0
        if let store = try? EventStore(path: dbPath) {
            recent = store.recent(limit: 25)
            byKind = store.countByKind()
            rows = store.count()
            size = store.dbSizeBytes()
        }
        return DashboardSnapshot(health: health, recent: recent, byKind: byKind,
                                 totalRows: rows, dbSize: size)
    }
}

final class Model: ObservableObject {
    @Published var snapshot = DashboardSnapshot(health: nil, recent: [], byKind: [], totalRows: 0, dbSize: 0)
    let dbPath: String
    init(dbPath: String) { self.dbPath = dbPath; refresh() }
    func refresh() { snapshot = DashboardSnapshot.load(dbPath: dbPath) }
}

struct DashboardView: View {
    @ObservedObject var model: Model

    var statusColor: Color {
        guard let h = model.snapshot.health else { return .red }
        if !h.isFresh() { return .yellow }
        return h.state == "observe-only" || h.state == "protected" ? .green : .yellow
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Circle().fill(statusColor).frame(width: 10, height: 10)
                Text("Virux").font(.headline)
                Spacer()
                Button("Refresh") { model.refresh() }
                Button("Quit") { NSApplication.shared.terminate(nil) }
            }
            Divider()
            Group {
                if let h = model.snapshot.health {
                    Text("State: \(h.state)").font(.subheadline)
                    Text("Source: \(h.source)").font(.caption)
                    Text("Last event: \(h.lastEventAt.map { Self.fmt($0) } ?? "never")").font(.caption)
                    Text("Stored: \(h.eventsStored)  Errors: \(h.insertErrors)").font(.caption)
                } else {
                    Text("No health record. Is viruxd running?").font(.caption)
                }
                Text("Rows: \(model.snapshot.totalRows)   DB: \(Self.human(model.snapshot.dbSize))").font(.caption)
            }
            Divider()
            Text("Recent events").font(.subheadline)
            List(model.snapshot.recent.prefix(12), id: \.id) { e in
                HStack {
                    Text(e.kind.rawValue).font(.caption).bold().frame(width: 48, alignment: .leading)
                    Text("pid \(e.process.pid)").font(.caption2).foregroundStyle(.secondary)
                    Text(e.process.executablePath.map { ($0 as NSString).lastPathComponent } ?? e.filePath ?? "")
                        .font(.caption2).lineLimit(1)
                }
            }
            .frame(minHeight: 160)
            Text("M1 shell: telemetry capture only. No detection or response yet.")
                .font(.caption2).foregroundStyle(.secondary)
        }
        .padding(14)
        .frame(width: 380)
        .onAppear { model.refresh() }
    }

    static func fmt(_ d: Date) -> String {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; return f.string(from: d)
    }
    static func human(_ b: Int64) -> String {
        let u = ["B", "KB", "MB", "GB"]; var v = Double(b); var i = 0
        while v >= 1024 && i < u.count - 1 { v /= 1024; i += 1 }
        return String(format: "%.1f %@", v, u[i])
    }
}

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
        }
    }

    func updateButton() {
        guard let button = statusItem.button else { return }
        let h = model.snapshot.health
        let color: NSColor
        if h == nil { color = .systemRed }
        else if !(h!.isFresh()) { color = .systemYellow }
        else { color = .systemGreen }
        let s = NSMutableAttributedString(string: "V ", attributes: [
            .foregroundColor: NSColor.labelColor,
            .font: NSFont.boldSystemFont(ofSize: 13)
        ])
        s.append(NSAttributedString(string: "\u{25CF}", attributes: [.foregroundColor: color]))
        button.attributedTitle = s
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

// Headless verification hook: when VIRUX_UI_SELFTEST_SECONDS is set the app
// launches, builds its status item, then exits. Used by the M1 test script.
if let s = ProcessInfo.processInfo.environment["VIRUX_UI_SELFTEST_SECONDS"], let n = Double(s) {
    DispatchQueue.main.asyncAfter(deadline: .now() + n) {
        FileHandle.standardError.write("ViruxMenuBar: selftest window elapsed, exiting 0\n".data(using: .utf8)!)
        NSApplication.shared.terminate(nil)
    }
}

app.run()