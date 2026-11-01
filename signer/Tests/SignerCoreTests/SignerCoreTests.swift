import Foundation
import Testing
@testable import SignerCore

/// The decision seam: a queue item in, a signed approve or an unsigned deny
/// out, with a software key behind the signing protocol.
@Suite struct SignerCoreTests {
    let raw: Data
    let entry: QueueEntry
    init() throws {
        raw = try Vectors.sample()
        let p = try ApprovalPayload.parse(raw)
        entry = QueueEntry(id: p.itemID, hash: p.requestHash, payload: raw.base64EncodedString())
    }

    func core(_ signer: SoftwareSigner, hosts: HostTrust = HostTrust(storage: MemoryHostStorage()),
              preSignCheck: @escaping @Sendable () -> SigningError? = { nil }) -> SignerCore {
        SignerCore(signer: signer, hosts: hosts, preSignCheck: preSignCheck)
    }

    func pending(_ c: SignerCore, _ e: QueueEntry? = nil) throws -> PendingApproval {
        guard case .show(let p) = c.review(e ?? entry) else { throw PayloadError("expected show") }
        return p
    }

    func denial(_ d: Decision) -> Denial? {
        if case .deny(let x) = d { return x }
        return nil
    }

    @Test func approveSignsTheReceivedBytes() throws {
        let s = SoftwareSigner()
        let c = core(s)
        let p = try pending(c)
        guard case .approve(let a) = c.decide(p, answer: .approve) else { Issue.record("not approved"); return }
        #expect(s.signed == [raw])
        #expect(a.itemID == entry.id && a.itemHash == entry.hash)
        #expect(try SignatureCheck.verify(publicKeySPKI: s.publicKeySPKI(), payload: raw, signatureDER: a.signature))
        #expect(a.approverKey == SignatureCheck.fingerprint(publicKeySPKI: try s.publicKeySPKI()))
        let m = Decision.approve(a).message
        #expect(m == DecideMessage(itemID: entry.id, itemHash: entry.hash, decision: "approve",
                                   signature: a.signature.base64EncodedString(), approverKey: a.approverKey))
    }

    @Test func thePromptCarriesTheShortCodeAndHost() throws {
        let s = SoftwareSigner()
        let c = core(s)
        _ = c.decide(try pending(c), answer: .approve)
        #expect(s.prompts.count == 1)
        #expect(s.prompts[0].reason.contains("LVSJ-XUSG"))
        #expect(s.prompts[0].reason.contains("build-01"))
    }

    @Test func cancelAndTimeoutDenyWithoutTouchingTheKey() throws {
        let s = SoftwareSigner()
        let c = core(s)
        #expect(denial(c.decide(try pending(c), answer: .cancel))?.reason == .cancelled)
        #expect(denial(c.decide(try pending(c), answer: .timeout))?.reason == .timedOut)
        #expect(s.prompts.isEmpty)
    }

    @Test func signerFailuresDeny() throws {
        let cases: [(SigningError, DenyReason)] = [
            (.cancelled, .cancelled), (.timedOut, .timedOut), (.biometryFailed, .biometryFailed),
            (.keyUnusable, .keyUnusable), (.notInteractive, .notInteractive), (.failed("x"), .signingFailed("x")),
        ]
        for (err, reason) in cases {
            let c = core(SoftwareSigner(failure: err))
            let d = c.decide(try pending(c), answer: .approve)
            #expect(denial(d)?.reason == reason, "\(err)")
            #expect(d.message == DecideMessage(itemID: entry.id, itemHash: entry.hash, decision: "deny", signature: nil, approverKey: nil))
        }
    }

    @Test func aSignatureThatDoesNotVerifyIsNotSent() throws {
        let s = SoftwareSigner()
        s.corrupt = true
        let c = core(s)
        #expect(denial(c.decide(try pending(c), answer: .approve))?.reason == .signingFailed("signature does not verify"))
    }

    @Test func aFailedIntegrityCheckDeniesBeforeSigning() throws {
        let s = SoftwareSigner()
        let c = core(s, preSignCheck: { .failed("code signature invalid") })
        #expect(denial(c.decide(try pending(c), answer: .approve))?.reason == .signingFailed("code signature invalid"))
        #expect(s.prompts.isEmpty)
    }

    @Test func aChangedHostKeyDeniesWithAWarningAndKeepsThePin() throws {
        let hosts = HostTrust(storage: MemoryHostStorage())
        _ = try hosts.pinIfNew(hostID: "build-01", hostKey: keyA)
        let s = SoftwareSigner()
        guard case .deny(let d) = core(s, hosts: hosts).review(entry) else { Issue.record("not denied"); return }
        let presented = try ApprovalPayload.parse(raw).hostKey
        #expect(d.reason == .hostKeyChanged(hostID: "build-01", pinned: keyA, presented: presented))
        #expect(d.warning?.contains(keyA) == true)
        #expect(d.warning?.contains(presented) == true)
        #expect(try hosts.check(hostID: "build-01", hostKey: keyA) == .pinned)
        #expect(s.prompts.isEmpty)
    }

    @Test func aHostKeyChangedAfterReviewDeniesAtDecision() throws {
        let hosts = HostTrust(storage: MemoryHostStorage())
        let s = SoftwareSigner()
        let c = core(s, hosts: hosts)
        let p = try pending(c)
        try hosts.forget(hostID: "build-01")
        _ = try hosts.pinIfNew(hostID: "build-01", hostKey: keyA)
        guard case .hostKeyChanged = denial(c.decide(p, answer: .approve))?.reason else { Issue.record("not denied"); return }
        #expect(s.prompts.isEmpty)
    }

    @Test func firstUsePinsTheHost() throws {
        let hosts = HostTrust(storage: MemoryHostStorage())
        let p = try pending(core(SoftwareSigner(), hosts: hosts))
        #expect(p.hostCheck == .firstUse)
        #expect(try hosts.check(hostID: "build-01", hostKey: p.payload.hostKey) == .pinned)
        #expect(try pending(core(SoftwareSigner(), hosts: hosts)).hostCheck == .pinned)
    }

    @Test func invalidPayloadsDeny() throws {
        let v = try Vectors.load()
        for c in v.invalid where c.name != "other version prefix" {
            let e = QueueEntry(id: entry.id, hash: entry.hash, payload: c.payload)
            guard case .deny(let d) = core(SoftwareSigner()).review(e), case .invalidPayload = d.reason else {
                Issue.record("\(c.name) not denied"); continue
            }
            #expect(d.itemID == entry.id && d.itemHash == entry.hash)
        }
        let notBase64 = QueueEntry(id: entry.id, hash: entry.hash, payload: "%%%")
        guard case .deny = core(SoftwareSigner()).review(notBase64) else { Issue.record("base64"); return }
    }

    @Test func anotherPayloadVersionIsSkippedNotDenied() throws {
        // a broker newer than this signer: not an undisplayable payload but
        // a version this signer does not speak; answering deny would make one
        // stale signer refuse every request
        let v = try Vectors.load()
        let c = try #require(v.invalid.first { $0.name == "other version prefix" })
        let e = QueueEntry(id: entry.id, hash: entry.hash, payload: c.payload)
        guard case .skip(let note) = core(SoftwareSigner()).review(e) else { Issue.record("not skipped"); return }
        #expect(note.contains("tmb-approval-v2"))
        for bad in ["tmb-approval-v\u{0}{}", "tmb-approval-vx\u{0}{}", "tmb-approval-v2{}", "tmb-approval-v1\u{0}[]"] {
            let e = QueueEntry(id: entry.id, hash: entry.hash, payload: Data(bad.utf8).base64EncodedString())
            guard case .deny = core(SoftwareSigner()).review(e) else { Issue.record("\(bad) not denied"); continue }
        }
    }

    @Test func aPayloadForAnotherQueueItemDenies() throws {
        let other = QueueEntry(id: "0000000000000000", hash: String(repeating: "0", count: 64), payload: entry.payload)
        guard case .deny(let d) = core(SoftwareSigner()).review(other), case .invalidPayload = d.reason else {
            Issue.record("not denied"); return
        }
        #expect(d.itemID == other.id)
    }

    @Test func anUndisplayableFieldDeniesAndPinsNothing() throws {
        let hosts = HostTrust(storage: MemoryHostStorage())
        let c = SignerCore(signer: SoftwareSigner(), hosts: hosts, limits: DisplayLimits(maxShownLength: 1 << 16, maxEntries: 2))
        guard case .deny(let d) = c.review(entry) else { Issue.record("not denied"); return }
        #expect(d.reason == .undisplayable(field: "argv"))
        #expect(try hosts.check(hostID: "build-01", hostKey: try ApprovalPayload.parse(raw).hostKey) == .firstUse)
    }
}
