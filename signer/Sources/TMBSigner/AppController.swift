import AppKit
import Foundation
import SignerCore
import SignerService

/// The menu bar item, the poll timer and the queue of windows. Network and
/// signing run off the main thread; one approval window is open at a time,
/// so a touch always belongs to the item on screen.
@MainActor final class AppController: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let paths = SignerPaths.standard
    private var statusItem: NSStatusItem!
    private var config: SignerConfig?
    private var workflow: SignerWorkflow?
    private var pins: HostTrust?
    private var keyName: String?
    private var problem: String?
    private var waiting: [ShownItem] = []
    private var current: ApprovalWindowController?
    private var polling = false
    private var pollTimer: Timer?
    private var recent: [String] = []
    private let pollQueue = DispatchQueue(label: "tmb.signer.poll")
    private let signQueue = DispatchQueue(label: "tmb.signer.sign")

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu
        reload()
    }

    // MARK: setup

    func reload() {
        pollTimer?.invalidate()
        workflow = nil
        problem = nil
        do {
            try KeyStore.ensurePrivateDirectory(paths.root)
            if !FileManager.default.fileExists(atPath: paths.config.path) {
                let template = #"{"version":1,"poll_seconds":5,"window_timeout_seconds":120,"sheet_timeout_seconds":30,"hosts":[]}"#
                try PrivateFile.createNew(paths.config, contents: Data((template + "\n").utf8))
            }
            let c = try SignerConfig.parse(Data(contentsOf: paths.config))
            config = c
            let trust = HostTrust(storage: FileHostStorage(url: paths.pins))
            pins = trust
            let store = KeyStore(paths: paths)
            let name = try store.activeName(configured: c.key)
            keyName = name
            let signer = try store.signer(name, sheetTimeout: TimeInterval(c.sheetTimeoutSeconds))
            let core = SignerCore(signer: signer, hosts: trust, preSignCheck: PreSign.live)
            workflow = SignerWorkflow(core: core, transport: SSHTransport())
            if c.hosts.isEmpty { problem = "no hosts in config.json" }
            let t = Timer(timeInterval: TimeInterval(c.pollSeconds), repeats: true) { _ in
                MainActor.assumeIsolated { self.pollNow() }
            }
            RunLoop.main.add(t, forMode: .common)
            pollTimer = t
            pollNow()
        } catch {
            problem = String(describing: error)
        }
        updateTitle()
    }

    // MARK: polling

    func pollNow() {
        guard let wf = workflow, let hosts = config?.hosts, !polling else { return }
        polling = true
        pollQueue.async {
            let reports = hosts.map { ($0, wf.poll($0)) }
            Task { @MainActor in self.absorb(reports) }
        }
    }

    private func absorb(_ reports: [(HostEndpoint, PollReport)]) {
        polling = false
        for (host, r) in reports {
            if let e = r.error { note("\(host.name): \(e)") }
            if !r.unsigned.isEmpty { note("\(host.name): \(r.unsigned.count) item(s) without payload, not answered") }
            for s in r.skipped { note("\(host.name): \(s)") }
            for d in r.denied {
                if case .deny(let x) = d.decision {
                    note("\(host.name): denied \(x.itemID) before showing: \(x.reason) -> \(describe(d.outcome))")
                    if let w = x.warning { alert("Host identity problem", w) }
                }
            }
            waiting += r.show
        }
        showNext()
        updateTitle()
    }

    // MARK: windows

    private func showNext() {
        guard current == nil, !waiting.isEmpty else { return }
        let item = waiting.removeFirst()
        let w = ApprovalWindowController(item: item, timeout: config?.windowTimeoutSeconds ?? 120) { [weak self] wc, a in
            self?.answered(wc, a)
        }
        current = w
        w.show()
    }

    private func answered(_ wc: ApprovalWindowController, _ a: HumanAnswer) {
        guard let wf = workflow else { return }
        let item = wc.model.item
        signQueue.async {
            let sent = wf.answer(item, a)
            Task { @MainActor in self.delivered(wc, sent) }
        }
    }

    private func delivered(_ wc: ApprovalWindowController, _ sent: SentDecision) {
        let code = wc.model.item.approval.display.shortCode
        switch sent.decision {
        case .approve: note("\(sent.host.name) \(code): approve -> \(describe(sent.outcome))")
        case .deny(let d): note("\(sent.host.name) \(code): deny (\(d.reason)) -> \(describe(sent.outcome))")
        }
        wc.finish()
        current = nil
        showNext()
        updateTitle()
    }

    private func describe(_ o: Result<DecideOutcome, TransportError>) -> String {
        switch o {
        case .success(.decided(let s)): return "decided \(s)"
        case .success(.recorded(let s)): return "recorded \(s)"
        case .success(.gone(let s)): return "gone: \(s)"
        case .success(.refused(let s)): return "refused: \(s)"
        case .failure(let e) where e.isProtocolError:
            return "not delivered: \(e); not shown again while the host lists it (signer and tmb on the host disagree on the protocol)"
        case .failure(let e): return "not delivered: \(e)"
        }
    }

    // MARK: menu

    private func updateTitle() {
        let n = waiting.count + (current == nil ? 0 : 1)
        statusItem.button?.title = problem != nil ? "TMB !" : (n > 0 ? "TMB \(n)" : "TMB")
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        func info(_ s: String) { let i = NSMenuItem(title: s, action: nil, keyEquivalent: ""); i.isEnabled = false; menu.addItem(i) }
        func action(_ s: String, _ sel: Selector, _ obj: Any? = nil) {
            let i = NSMenuItem(title: s, action: sel, keyEquivalent: "")
            i.target = self
            i.representedObject = obj
            menu.addItem(i)
        }
        if let p = problem { info("Problem: \(p)") }
        info("Key: \(keyName ?? "none")")
        info("Hosts: " + (config?.hosts.map(\.name).joined(separator: ", ") ?? "none"))
        info("Waiting: \(waiting.count + (current == nil ? 0 : 1))")
        action("Poll Now", #selector(pollAction))
        menu.addItem(.separator())
        let recentItem = NSMenuItem(title: "Recent", action: nil, keyEquivalent: "")
        let recentMenu = NSMenu()
        for r in recent.reversed() { let i = NSMenuItem(title: r, action: nil, keyEquivalent: ""); i.isEnabled = false; recentMenu.addItem(i) }
        if recent.isEmpty { recentMenu.addItem(withTitle: "nothing yet", action: nil, keyEquivalent: "") }
        recentItem.submenu = recentMenu
        menu.addItem(recentItem)
        menu.addItem(.separator())
        action("Create Key...", #selector(createKeyAction))
        let keys = (try? paths.keyNames()) ?? []
        for k in keys { action("Copy approver_keys Entry: \(k)", #selector(copyEntryAction), k) }
        let pinsItem = NSMenuItem(title: "Pinned Hosts", action: nil, keyEquivalent: "")
        let pinsMenu = NSMenu()
        for p in (try? pins?.pins()) ?? [] {
            let i = NSMenuItem(title: "Forget \(DisplayText(p.hostID).shown) (\(p.hostKey.prefix(16))...)",
                               action: #selector(forgetAction), keyEquivalent: "")
            i.target = self
            i.representedObject = p.hostID
            pinsMenu.addItem(i)
        }
        if pinsMenu.items.isEmpty { pinsMenu.addItem(withTitle: "none", action: nil, keyEquivalent: "") }
        pinsItem.submenu = pinsMenu
        menu.addItem(pinsItem)
        menu.addItem(.separator())
        action("Open Config Folder", #selector(openFolderAction))
        action("Reload Config", #selector(reloadAction))
        let quit = NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(quit)
    }

    @objc func pollAction() { pollNow() }
    @objc func reloadAction() { reload() }
    @objc func openFolderAction() { NSWorkspace.shared.open(paths.root) }

    @objc func createKeyAction() {
        let a = NSAlert()
        a.messageText = "Create a Secure Enclave key"
        a.informativeText = "Name (letters, digits, . _ -). The key needs Touch ID for every signature and stops working when the set of fingerprints changes."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        field.stringValue = "mac-key"
        a.accessoryView = field
        a.addButton(withTitle: "Create")
        a.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true)
        guard a.runModal() == .alertFirstButtonReturn else { return }
        do {
            let entry = try KeyStore(paths: paths).create(field.stringValue)
            showEntry(entry)
            reload()
        } catch {
            alert("Key not created", String(describing: error))
        }
    }

    @objc func copyEntryAction(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        do { showEntry(try KeyStore(paths: paths).entry(name)) } catch { alert("Cannot read key", String(describing: error)) }
    }

    private func showEntry(_ e: ApproverKeyEntry) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(e.json, forType: .string)
        alert("approver_keys entry copied",
              "Add it to approver_keys in the broker config on each host, then reload the broker (SIGHUP).\n\n\(e.json)\n\nfingerprint \(e.fingerprint)")
    }

    @objc func forgetAction(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String else { return }
        let a = NSAlert()
        a.messageText = "Forget the pinned identity of \(DisplayText(id).shown)?"
        a.informativeText = "The next item from this host pins whatever identity key it presents. Do this only after checking the new fingerprint with `tmb-broker identity` on the host."
        a.addButton(withTitle: "Forget")
        a.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true)
        guard a.runModal() == .alertFirstButtonReturn else { return }
        do { try pins?.forget(hostID: id); note("forgot pin of \(DisplayText(id).shown)") } catch { alert("Pin not removed", String(describing: error)) }
    }

    // MARK: helpers

    private func note(_ s: String) {
        let line = ISO8601DateFormatter().string(from: Date()) + " " + s
        FileHandle.standardError.write(Data((line + "\n").utf8))
        recent.append(line)
        if recent.count > 30 { recent.removeFirst(recent.count - 30) }
    }

    private func alert(_ title: String, _ text: String) {
        let a = NSAlert()
        a.messageText = title
        a.informativeText = text
        NSApp.activate(ignoringOtherApps: true)
        a.runModal()
    }
}
