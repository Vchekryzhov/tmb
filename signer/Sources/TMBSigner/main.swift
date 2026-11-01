import AppKit
import Foundation
import SignerCore
import SignerService

// The trusted signer menu bar app (ADR 0006, ADR 0007 R5). It refuses to
// start outside the person's local graphic session and when its own code
// signature is not intact; both checks run again before every signature.

func refuse(_ what: String, _ code: Int32) -> Never {
    FileHandle.standardError.write(Data("TMBSigner: refused: \(what)\n".utf8))
    exit(code)
}

if let e = GUISession.check() {
    refuse("not a local graphic login session (\(e)); the signer runs only in the Mac's own GUI session", 3)
}
if let e = CodeIntegrity.checkSelf() {
    refuse("code integrity check failed: \(e)", 4)
}

let args = CommandLine.arguments.dropFirst()
if args.first == "--print-key" {
    // The approver_keys entry for the broker config, without the menu.
    do {
        let paths = SignerPaths.standard
        let name = try args.dropFirst().first ?? KeyStore(paths: paths).activeName(configured: nil)
        let entry = try KeyStore(paths: paths).entry(name)
        print(entry.json)
        print("fingerprint " + entry.fingerprint)
        exit(0)
    } catch {
        refuse("\(error)", 2)
    }
}

MainActor.assumeIsolated {
    let app = NSApplication.shared
    let controller = AppController()
    app.delegate = controller
    app.setActivationPolicy(.accessory)
    withExtendedLifetime(controller) { app.run() }
}
