import Foundation
import Testing
@testable import SignerCore
@testable import SignerService

/// The polling workflow over the real SSH transport with recorded
/// `tmb approve` outputs and a software key: what is shown, what is sent.
@Suite struct WorkflowTests {
    let host = HostEndpoint(name: "build", ssh: "build-01")
    let itemHash = String(repeating: "ab", count: 32)

    func workflow(_ runner: ScriptedRunner, signer: SoftwareSigner = SoftwareSigner(),
                  hosts: HostTrust = HostTrust(storage: MemoryHostStorage()),
                  preSignCheck: @escaping @Sendable () -> SigningError? = { nil }) -> SignerWorkflow {
        SignerWorkflow(core: SignerCore(signer: signer, hosts: hosts, preSignCheck: preSignCheck),
                       transport: SSHTransport(runner: runner))
    }

    func sent(_ r: ScriptedRunner, _ i: Int) throws -> [String: String] {
        try JSONSerialization.jsonObject(with: try #require(r.calls[i].stdin)) as! [String: String]
    }

    @Test func aNewItemIsShownOnceUntilAnswered() throws {
        let r = ScriptedRunner([try Recording.load("list-sample"), try Recording.load("list-sample")])
        let w = workflow(r)
        let first = w.poll(host)
        #expect(first.show.count == 1)
        #expect(first.show[0].approval.display.shortCode == "LVSJ-XUSG")
        #expect(first.show[0].approval.hostCheck == .firstUse)
        #expect(w.poll(host).show.isEmpty)
    }

    @Test func approveSendsOneSignedDecision() throws {
        let s = SoftwareSigner()
        let r = ScriptedRunner([try Recording.load("list-sample"), try Recording.load("decide-approve-decided")])
        let w = workflow(r, signer: s)
        let item = try #require(w.poll(host).show.first)
        let res = w.answer(item, .approve)
        #expect(res.outcome == .success(.decided("approve")))
        guard case .approve(let a) = res.decision else { Issue.record("not approved"); return }
        let m = try sent(r, 1)
        #expect(m["decision"] == "approve" && m["item_hash"] == itemHash)
        #expect(m["signature"] == a.signature.base64EncodedString())
        #expect(m["approver_key"] == SignatureCheck.fingerprint(publicKeySPKI: try s.publicKeySPKI()))
        #expect(s.prompts.count == 1 && s.prompts[0].reason == "approve LVSJ-XUSG on build-01")
    }

    @Test func cancelAndTimeoutSendAnUnsignedDeny() throws {
        for answer in [HumanAnswer.cancel, .timeout] {
            let s = SoftwareSigner()
            let r = ScriptedRunner([try Recording.load("list-sample"), try Recording.load("decide-deny-decided")])
            let w = workflow(r, signer: s)
            let res = w.answer(try #require(w.poll(host).show.first), answer)
            #expect(res.outcome == .success(.decided("deny")))
            #expect(try sent(r, 1) == ["item_id": "abababababababab", "item_hash": itemHash, "decision": "deny"])
            #expect(s.prompts.isEmpty)
        }
    }

    @Test func aFailedPreSignCheckDeniesWithoutTheKey() throws {
        let s = SoftwareSigner()
        let r = ScriptedRunner([try Recording.load("list-sample"), try Recording.load("decide-deny-decided")])
        let w = workflow(r, signer: s, preSignCheck: { .notInteractive })
        let res = w.answer(try #require(w.poll(host).show.first), .approve)
        guard case .deny(let d) = res.decision else { Issue.record("not denied"); return }
        #expect(d.reason == .notInteractive)
        #expect(try sent(r, 1)["decision"] == "deny")
        #expect(s.prompts.isEmpty)
    }

    @Test func anItemStillQueuedAfterItsAnswerIsNotShownAgain() throws {
        // a signature below the threshold leaves the item in the queue
        let r = ScriptedRunner([try Recording.load("list-sample"), try Recording.load("decide-recorded"),
                                try Recording.load("list-sample"), try Recording.load("list-empty"),
                                try Recording.load("list-sample")])
        let w = workflow(r)
        let res = w.answer(try #require(w.poll(host).show.first), .approve)
        #expect(res.outcome == .success(.recorded("1 of 2")))
        #expect(w.poll(host).show.isEmpty)
        #expect(w.poll(host).show.isEmpty)
        // gone from the queue once, so a later listing is a new item
        #expect(w.poll(host).show.count == 1)
    }

    @Test func aChangedHostKeyIsDeniedAtOnceWithAWarning() throws {
        let pins = HostTrust(storage: MemoryHostStorage())
        _ = try pins.pinIfNew(hostID: "build-01", hostKey: String(repeating: "e", count: 64))
        let r = ScriptedRunner([try Recording.load("list-sample"), try Recording.load("decide-deny-decided")])
        let w = workflow(r, hosts: pins)
        let rep = w.poll(host)
        #expect(rep.show.isEmpty)
        #expect(rep.denied.count == 1)
        guard case .deny(let d) = rep.denied[0].decision else { Issue.record("not denied"); return }
        #expect(d.warning?.contains("build-01") == true)
        #expect(rep.denied[0].outcome == .success(.decided("deny")))
        #expect(try sent(r, 1)["decision"] == "deny")
        #expect(try pins.check(hostID: "build-01", hostKey: String(repeating: "e", count: 64)) == .pinned)
    }

    @Test func anEndpointPresentingAnotherHostIDIsDeniedAndNotPinned() throws {
        let pins = HostTrust(storage: MemoryHostStorage())
        let r = ScriptedRunner([try Recording.load("list-sample"), try Recording.load("decide-deny-decided")])
        let w = workflow(r, hosts: pins)
        let rep = w.poll(HostEndpoint(name: "build", ssh: "build-01", hostID: "build-02"))
        #expect(rep.show.isEmpty)
        guard case .deny(let d) = rep.denied.first?.decision else { Issue.record("not denied"); return }
        #expect(d.warning?.contains("build-02") == true)
        #expect(try pins.pins().isEmpty)
    }

    @Test func aDeniedItemIsAnsweredOnlyOnce() throws {
        let pins = HostTrust(storage: MemoryHostStorage())
        _ = try pins.pinIfNew(hostID: "build-01", hostKey: String(repeating: "e", count: 64))
        let r = ScriptedRunner([try Recording.load("list-sample"), try Recording.load("decide-deny-decided"),
                                try Recording.load("list-sample")])
        let w = workflow(r, hosts: pins)
        _ = w.poll(host)
        let again = w.poll(host)
        #expect(again.denied.isEmpty && again.show.isEmpty)
        #expect(r.calls.count == 3)
    }

    @Test func listErrorsAndUnsignedItemsAreReported() throws {
        let err = CommandResult(status: 255, stdout: Data(), stderr: Data("ssh: Could not resolve hostname\n".utf8))
        let w1 = workflow(ScriptedRunner([.success(err)]))
        #expect(w1.poll(host).error == .unreachable("ssh: Could not resolve hostname"))
        let out = #"{"type":"queue","items":[{"id":"aaaaaaaaaaaaaaaa","hash":"\#(String(repeating: "a", count: 64))"}]}"#
        let w2 = workflow(ScriptedRunner([.success(CommandResult(status: 0, stdout: Data(out.utf8), stderr: Data()))]))
        let rep = w2.poll(host)
        #expect(rep.unsigned == ["aaaaaaaaaaaaaaaa"] && rep.show.isEmpty && rep.denied.isEmpty)
    }

    @Test func aFailedSendIsReportedAndTheItemCanComeBack() throws {
        let down = CommandResult(status: 255, stdout: Data(), stderr: Data("ssh: Connection reset\n".utf8))
        let r = ScriptedRunner([.success(try Recording.load("list-sample").result), .success(down),
                                .success(try Recording.load("list-sample").result)])
        let w = workflow(r)
        let res = w.answer(try #require(w.poll(host).show.first), .cancel)
        #expect(res.outcome == .failure(.unreachable("ssh: Connection reset")))
        // the decision did not arrive: the item is still pending on the host
        #expect(w.poll(host).show.count == 1)
    }

    @Test func anotherPayloadVersionIsReportedOnceAndNotAnswered() throws {
        let v2 = Data("tmb-approval-v2\u{0}{}".utf8).base64EncodedString()
        let out = #"{"type":"queue","items":[{"id":"abababababababab","hash":"\#(itemHash)","payload":"\#(v2)"}]}"#
        let list = CommandResult(status: 0, stdout: Data(out.utf8), stderr: Data())
        let r = ScriptedRunner([.success(list), .success(list)])
        let w = workflow(r)
        let rep = w.poll(host)
        #expect(rep.show.isEmpty && rep.denied.isEmpty)
        #expect(rep.skipped.count == 1 && rep.skipped[0].contains("tmb-approval-v2"))
        #expect(w.poll(host).skipped.isEmpty)
        #expect(r.calls.count == 2) // two listings, no decide
    }

    @Test func aProtocolErrorDoesNotBringTheItemBackEveryPoll() throws {
        // the client refused our message (exit 2) or answered with something
        // that is not its machine output: retrying would only ask for
        // another touch with the same result
        let rejected = CommandResult(status: 2, stdout: Data(), stderr: Data("tmb approve: decision on stdin: unknown field x\n".utf8))
        let junk = CommandResult(status: 0, stdout: Data("not json".utf8), stderr: Data())
        for (bad, want) in [(rejected, TransportError.remote(2, "tmb approve: decision on stdin: unknown field x")),
                            (junk, .badOutput("answer is not one JSON object"))] {
            let r = ScriptedRunner([.success(try Recording.load("list-sample").result), .success(bad),
                                    .success(try Recording.load("list-sample").result), .success(try Recording.load("list-empty").result),
                                    .success(try Recording.load("list-sample").result)])
            let w = workflow(r)
            let res = w.answer(try #require(w.poll(host).show.first), .cancel)
            #expect(res.outcome == .failure(want))
            #expect(want.isProtocolError)
            #expect(w.poll(host).show.isEmpty)
            #expect(w.poll(host).show.isEmpty)
            // gone from the queue once, so a later listing is a new item
            #expect(w.poll(host).show.count == 1)
        }
        #expect(!TransportError.unreachable("x").isProtocolError && !TransportError.remote(127, "x").isProtocolError)
    }
}
