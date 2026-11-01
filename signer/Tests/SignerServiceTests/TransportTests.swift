import Foundation
import Testing
@testable import SignerCore
@testable import SignerService

/// One recorded run of `tmb approve` (recorded/*.json): what the real client
/// printed and returned against the approver socket (recorded/recorder.go.txt).
struct Recording: Decodable {
    let args: [String]
    let stdin: String
    let exit: Int32
    let stdout: String
    let stderr: String

    static let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("recorded")

    static func load(_ name: String) throws -> Recording {
        try JSONDecoder().decode(Recording.self, from: Data(contentsOf: dir.appendingPathComponent(name + ".json")))
    }

    var result: CommandResult { CommandResult(status: exit, stdout: Data(stdout.utf8), stderr: Data(stderr.utf8)) }
}

/// The runner behind the transport in tests: no process, no SSH. It hands
/// out the given results in order and keeps every call it got.
final class ScriptedRunner: CommandRunner, @unchecked Sendable {
    struct Call: Equatable {
        let executable: String
        let arguments: [String]
        let stdin: Data?
    }
    private let lock = NSLock()
    private var results: [Result<CommandResult, CommandError>]
    private(set) var calls: [Call] = []

    init(_ results: [Result<CommandResult, CommandError>]) { self.results = results }
    convenience init(_ recordings: [Recording]) { self.init(recordings.map { .success($0.result) }) }

    func run(_ executable: String, _ arguments: [String], stdin: Data?) throws -> CommandResult {
        try lock.withLock {
            calls.append(Call(executable: executable, arguments: arguments, stdin: stdin))
            guard !results.isEmpty else { throw CommandError.failed("no scripted result left") }
            return try results.removeFirst().get()
        }
    }
}

let sampleHost = HostEndpoint(name: "build", ssh: "viktor@build-01.example", port: 2222,
                              tmb: "/usr/local/bin/tmb", socket: "/run/tmb/approver.sock")

@Suite struct TransportTests {
    @Test func listRunsTmbApproveOverBatchModeSSH() throws {
        let r = ScriptedRunner([try Recording.load("list-empty")])
        _ = try SSHTransport(runner: r).list(sampleHost)
        #expect(r.calls.count == 1)
        #expect(r.calls[0].executable == "/usr/bin/ssh")
        #expect(r.calls[0].stdin == nil)
        #expect(r.calls[0].arguments == [
            "-T", "-a", "-x", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10",
            "-p", "2222", "--", "viktor@build-01.example",
            "'/usr/local/bin/tmb' 'approve' '--list' '--json' '--socket' '/run/tmb/approver.sock'",
        ])
    }

    @Test func defaultsLeavePortAndSocketToSSHAndTmb() throws {
        let r = ScriptedRunner([try Recording.load("list-empty")])
        _ = try SSHTransport(runner: r).list(HostEndpoint(name: "b", ssh: "b"))
        #expect(r.calls[0].arguments.suffix(3) == ["--", "b", "'tmb' 'approve' '--list' '--json'"])
        #expect(!r.calls[0].arguments.contains("-p"))
    }

    @Test func anEmptyQueueIsNoEntries() throws {
        let l = try SSHTransport(runner: ScriptedRunner([try Recording.load("list-empty")])).list(sampleHost)
        #expect(l.entries.isEmpty && l.unsigned.isEmpty)
    }

    @Test func aRecordedQueueGivesEntriesTheCoreCanShow() throws {
        let l = try SSHTransport(runner: ScriptedRunner([try Recording.load("list-sample")])).list(sampleHost)
        #expect(l.entries.count == 1)
        let e = l.entries[0]
        #expect(e.id == "abababababababab")
        #expect(e.hash == String(repeating: "ab", count: 32))
        let core = SignerCore(signer: SoftwareSigner(), hosts: HostTrust(storage: MemoryHostStorage()))
        guard case .show(let p) = core.review(e) else { Issue.record("not shown"); return }
        #expect(p.display.shortCode == "LVSJ-XUSG")
        #expect(p.display.argv.map(\.text.shown) == ["systemctl", "restart", "nginx"])
    }

    @Test func escapedStringsInTheRecordedQueueStillParse() throws {
        // termsafe writes DEL and bidi as \u escapes: still the same payload
        let l = try SSHTransport(runner: ScriptedRunner([try Recording.load("list-tricky")])).list(sampleHost)
        let core = SignerCore(signer: SoftwareSigner(), hosts: HostTrust(storage: MemoryHostStorage()))
        guard case .show(let p) = core.review(l.entries[0]) else { Issue.record("not shown"); return }
        #expect(p.display.shortCode == "PRX6-IUIM")
        #expect(p.display.argv.contains { $0.text.shown == "bidi\\u{202E}evil" })
    }

    @Test func itemsWithoutPayloadAreReportedNotSigned() throws {
        let out = #"{"type":"queue","items":[{"id":"aaaaaaaaaaaaaaaa","hash":"\#(String(repeating: "a", count: 64))","executable":"/usr/bin/id"}]}"# + "\n"
        let r = ScriptedRunner([.success(CommandResult(status: 0, stdout: Data(out.utf8), stderr: Data()))])
        let l = try SSHTransport(runner: r).list(sampleHost)
        #expect(l.entries.isEmpty)
        #expect(l.unsigned == ["aaaaaaaaaaaaaaaa"])
    }

    @Test func listFailuresAreErrors() throws {
        func result(_ status: Int32, _ out: String, _ err: String = "") -> Result<CommandResult, CommandError> {
            .success(CommandResult(status: status, stdout: Data(out.utf8), stderr: Data(err.utf8)))
        }
        let cases: [(Result<CommandResult, CommandError>, TransportError)] = [
            (result(255, "", "ssh: connect to host build-01 port 22: Connection refused\n"),
             .unreachable("ssh: connect to host build-01 port 22: Connection refused")),
            (result(3, "", "tmb approve: dial unix /run/tmb/approver.sock: no such file\n"),
             .unreachable("tmb approve: dial unix /run/tmb/approver.sock: no such file")),
            (result(127, "", "bash: tmb: command not found\n"), .remote(127, "bash: tmb: command not found")),
            (result(0, "not json\n"), .badOutput("queue is not one JSON object")),
            (result(0, #"{"type":"decided"}"# + "\n"), .badOutput("answer is not a queue")),
            (result(0, #"{"type":"queue","items":{"not":"a list"}}"# + "\n"), .badOutput("answer is not a queue")),
            (result(0, #"{"type":"queue","items":[{"id":1}]}"# + "\n"), .badOutput("queue item 0 has no string id and hash")),
            (.failure(.timedOut), .unreachable("ssh did not finish in time")),
        ]
        for (res, want) in cases {
            #expect(throws: want) { try SSHTransport(runner: ScriptedRunner([res])).list(sampleHost) }
        }
    }

    @Test func decideSendsTheMessageOnStdin() throws {
        let rec = try Recording.load("decide-approve-decided")
        let r = ScriptedRunner([rec])
        let m = DecideMessage(itemID: "abababababababab", itemHash: String(repeating: "ab", count: 32), decision: "approve",
                              signature: "bm90LWEtcmVhbC1kZXItc2lnbmF0dXJl",
                              approverKey: String(repeating: "1", count: 64))
        #expect(try SSHTransport(runner: r).decide(sampleHost, m) == .decided("approve"))
        #expect(r.calls[0].arguments.last == "'/usr/local/bin/tmb' 'approve' '--decide' '--socket' '/run/tmb/approver.sock'")
        // the same object the real client accepted in the recording
        let sent = try JSONSerialization.jsonObject(with: try #require(r.calls[0].stdin)) as! [String: String]
        let recorded = try JSONSerialization.jsonObject(with: Data(rec.stdin.utf8)) as! [String: String]
        #expect(sent == recorded)
    }

    @Test func anUnsignedDenyHasNoSignatureFields() throws {
        let rec = try Recording.load("decide-deny-decided")
        let r = ScriptedRunner([rec])
        let m = DecideMessage(itemID: "abababababababab", itemHash: String(repeating: "ab", count: 32), decision: "deny",
                              signature: nil, approverKey: nil)
        #expect(try SSHTransport(runner: r).decide(sampleHost, m) == .decided("deny"))
        let sent = try JSONSerialization.jsonObject(with: try #require(r.calls[0].stdin)) as! [String: String]
        #expect(sent == (try JSONSerialization.jsonObject(with: Data(rec.stdin.utf8)) as! [String: String]))
    }

    @Test func decideOutcomesFollowTheRecordedExitCodes() throws {
        let m = DecideMessage(itemID: "abababababababab", itemHash: String(repeating: "ab", count: 32), decision: "deny",
                              signature: nil, approverKey: nil)
        let cases: [(String, DecideOutcome)] = [
            ("decide-recorded", .recorded("1 of 2")),
            ("decide-already-decided", .gone("already_decided")),
            ("decide-no-such-item", .gone("no_such_item")),
            ("decide-signature-invalid", .refused("signature_invalid")),
        ]
        for (name, want) in cases {
            #expect(try SSHTransport(runner: ScriptedRunner([try Recording.load(name)])).decide(sampleHost, m) == want, "\(name)")
        }
        #expect(throws: TransportError.remote(2, "tmb approve: decision on stdin: unknown field type")) {
            try SSHTransport(runner: ScriptedRunner([try Recording.load("decide-junk-stdin")])).decide(sampleHost, m)
        }
    }

    @Test func endpointsThatCouldBeOptionsAreRefusedBeforeSSH() throws {
        for bad in [HostEndpoint(name: "x", ssh: "-oProxyCommand=sh"), HostEndpoint(name: "x", ssh: ""),
                    HostEndpoint(name: "x", ssh: "a b"), HostEndpoint(name: "x", ssh: "a\nb"),
                    HostEndpoint(name: "x", ssh: "h", port: 0), HostEndpoint(name: "x", ssh: "h", port: 70000)] {
            let r = ScriptedRunner([Recording]())
            #expect(throws: TransportError.self) { try SSHTransport(runner: r).list(bad) }
            #expect(r.calls.isEmpty)
        }
    }

    @Test func remoteWordsAreSingleQuotedForTheRemoteShell() {
        #expect(SSHTransport.remoteCommand(["it's", "a b", "$(x)"]) == #"'it'\''s' 'a b' '$(x)'"#)
    }
}
