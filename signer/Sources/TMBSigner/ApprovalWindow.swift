import AppKit
import SignerCore
import SignerService
import SwiftUI

/// State of one approval window: the item, the countdown, and whether an
/// answer is already on its way (buttons off, nothing can be answered twice).
@MainActor final class ApprovalModel: ObservableObject {
    let item: ShownItem
    @Published var remaining: Int
    @Published var busy = false
    @Published var status = ""

    init(item: ShownItem, timeout: Int) {
        self.item = item
        remaining = timeout
    }
}

struct ApprovalView: View {
    @ObservedObject var model: ApprovalModel
    let answer: (HumanAnswer) -> Void

    var display: ApprovalDisplay { model.item.approval.display }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Approve a privileged command on \(display.hostID.quoted)")
                .font(.headline)
            Text("from endpoint \(model.item.host.name) (\(model.item.host.ssh))")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Text("Short code").foregroundStyle(.secondary)
                Text(display.shortCode)
                    .font(.system(size: 30, weight: .bold, design: .monospaced))
                    .textSelection(.enabled)
            }
            Text("The Touch ID sheet must show the same code and host.")
                .font(.caption).foregroundStyle(.secondary)
            if model.item.approval.hostCheck == .firstUse {
                Text("First use of this host: its identity key has just been pinned. Compare host_key below with `tmb-broker identity` on the host before you approve.")
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            ScrollView([.vertical, .horizontal]) {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(display.fields.enumerated()), id: \.offset) { _, f in
                        Text(f.line)
                    }
                    Text("argv: \(display.argv.count) entries").bold().padding(.top, 6)
                    ForEach(Array(display.argv.enumerated()), id: \.offset) { _, e in
                        Text(e.line)
                    }
                    Text("env: \(display.env.count) entries").bold().padding(.top, 6)
                    ForEach(Array(display.env.enumerated()), id: \.offset) { _, e in
                        Text(e.line)
                    }
                }
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(6)
            }
            .frame(minHeight: 260)
            .border(Color.secondary.opacity(0.3))
            Text("Escapes: \\u{XXXX} marks a character outside printable ASCII; the class is named after the value.")
                .font(.caption).foregroundStyle(.secondary)
            Divider()
            HStack {
                Text(model.busy ? model.status : "Denied automatically in \(model.remaining) s")
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Deny") { answer(.cancel) }
                    .keyboardShortcut(.cancelAction)
                    .disabled(model.busy)
                Button("Approve with Touch ID") { answer(.approve) }
                    .disabled(model.busy)
            }
        }
        .padding(16)
        .frame(minWidth: 640, idealWidth: 760, minHeight: 520, idealHeight: 640)
    }
}

/// One modal-style window per queue item. It stays above other windows
/// until answered; closing it is a deny, and so is the countdown running out.
@MainActor final class ApprovalWindowController: NSObject, NSWindowDelegate {
    let model: ApprovalModel
    let window: NSWindow
    private var timer: Timer?
    private let onAnswer: (ApprovalWindowController, HumanAnswer) -> Void

    init(item: ShownItem, timeout: Int, onAnswer: @escaping (ApprovalWindowController, HumanAnswer) -> Void) {
        model = ApprovalModel(item: item, timeout: timeout)
        self.onAnswer = onAnswer
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 760, height: 640),
                          styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        super.init()
        window.title = "TMB Signer: \(item.approval.display.shortCode)"
        window.level = .modalPanel
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.contentView = NSHostingView(rootView: ApprovalView(model: model) { [weak self] a in self?.answer(a) })
        window.center()
    }

    func show() {
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        let t = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    private func tick() {
        guard !model.busy else { return }
        model.remaining -= 1
        if model.remaining <= 0 { answer(.timeout) }
    }

    func answer(_ a: HumanAnswer) {
        guard !model.busy else { return }
        model.busy = true
        timer?.invalidate()
        switch a {
        case .approve: model.status = "Waiting for Touch ID..."
        case .cancel: model.status = "Sending deny..."
        case .timeout: model.status = "Timed out, sending deny..."
        }
        onAnswer(self, a)
    }

    func finish() {
        timer?.invalidate()
        window.delegate = nil
        window.close()
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        answer(.cancel)
        return false
    }
}
