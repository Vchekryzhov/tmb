import Foundation
import Security
import Testing
@testable import SignerCore
@testable import SignerService

/// The pre-sign checks of ADR 0007 R5 as decisions over what Security
/// reports: the live calls only gather these inputs.
@Suite struct IntegrityTests {
    let runtime: UInt32 = 0x10000

    @Test func aValidHardenedSignatureWithCleanEntitlementsPasses() {
        #expect(CodeIntegrity.evaluate(validity: errSecSuccess, flags: runtime, entitlements: nil) == nil)
        #expect(CodeIntegrity.evaluate(validity: errSecSuccess, flags: runtime | 0x2,
                                       entitlements: ["com.apple.security.get-task-allow": false]) == nil)
    }

    @Test func anInvalidSignatureFails() {
        guard case .failed(let s) = CodeIntegrity.evaluate(validity: errSecCSSignatureFailed, flags: runtime, entitlements: nil)
        else { Issue.record("not failed"); return }
        #expect(s.contains("code signature"))
    }

    @Test func noHardenedRuntimeFails() {
        guard case .failed(let s) = CodeIntegrity.evaluate(validity: errSecSuccess, flags: 0x2, entitlements: nil)
        else { Issue.record("not failed"); return }
        #expect(s.contains("hardened runtime"))
    }

    @Test func everyDebugOrInjectionEntitlementFails() {
        for k in CodeIntegrity.forbiddenEntitlements {
            guard case .failed(let s) = CodeIntegrity.evaluate(validity: errSecSuccess, flags: runtime, entitlements: [k: true])
            else { Issue.record("\(k) passed"); continue }
            #expect(s.contains(k))
        }
    }

    @Test func theForbiddenListMatchesTheCIChecker() throws {
        // check-entitlements.sh is what CI runs on the bundle; both lists must agree
        let script = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Scripts/check-entitlements.sh")
        let text = try String(contentsOf: script, encoding: .utf8)
        let block = try #require(text.components(separatedBy: "FORBIDDEN=(").dropFirst().first?.components(separatedBy: ")").first)
        let listed = Set(block.split(whereSeparator: \.isWhitespace).map(String.init))
        #expect(listed == Set(CodeIntegrity.forbiddenEntitlements))
    }

    @Test func onlyALocalGraphicSessionMaySign() {
        #expect(GUISession.evaluate(status: errSecSuccess, attributes: [.sessionHasGraphicAccess]) == nil)
        #expect(GUISession.evaluate(status: errSecSuccess, attributes: []) == .notInteractive)
        #expect(GUISession.evaluate(status: errSecSuccess, attributes: [.sessionHasGraphicAccess, .sessionIsRemote]) == .notInteractive)
        #expect(GUISession.evaluate(status: -1, attributes: [.sessionHasGraphicAccess]) == .notInteractive)
    }

    @Test func preSignCheckRunsBothChecks() {
        #expect(PreSign.combine([{ nil }, { .notInteractive }])() == .notInteractive)
        #expect(PreSign.combine([{ .failed("x") }, { .notInteractive }])() == .failed("x"))
        #expect(PreSign.combine([{ nil }, { nil }])() == nil)
    }
}

@Suite struct DeadlineTests {
    final class Flag: @unchecked Sendable {
        private let lock = NSLock()
        private var v = 0
        func hit() { lock.withLock { v += 1 } }
        var count: Int { lock.withLock { v } }
    }

    @Test func aBodyThatOutlivesTheDeadlineIsCancelledOnce() throws {
        let f = Flag()
        let r = try SheetDeadline.run(after: 0.05, cancel: { f.hit() }) { () -> Int in
            Thread.sleep(forTimeInterval: 0.3)
            return 7
        }
        #expect(r == 7)
        #expect(f.count == 1)
    }

    @Test func aQuickBodyIsNotCancelled() throws {
        let f = Flag()
        _ = try SheetDeadline.run(after: 0.1, cancel: { f.hit() }) { 1 }
        Thread.sleep(forTimeInterval: 0.25)
        #expect(f.count == 0)
    }

    @Test func noDeadlineMeansNoCancel() throws {
        let f = Flag()
        _ = try SheetDeadline.run(after: nil, cancel: { f.hit() }) { 1 }
        #expect(f.count == 0)
    }
}
