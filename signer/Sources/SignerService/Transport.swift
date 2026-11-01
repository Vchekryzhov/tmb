import Foundation
import SignerCore

/// One host the signer polls, from the Mac-side config. `ssh` is the
/// destination handed to /usr/bin/ssh (a Host alias from ~/.ssh/config or
/// user@host); `tmb` and `socket` are the client path and the approver
/// socket on the host (defaults: `tmb` from PATH, its own default socket).
/// `hostID`, when set, is the `host_id` this endpoint must present.
public struct HostEndpoint: Equatable, Sendable, Codable {
    public let name: String
    public let ssh: String
    public let port: Int?
    public let tmb: String?
    public let socket: String?
    public let hostID: String?

    public init(name: String, ssh: String, port: Int? = nil, tmb: String? = nil, socket: String? = nil, hostID: String? = nil) {
        self.name = name
        self.ssh = ssh
        self.port = port
        self.tmb = tmb
        self.socket = socket
        self.hostID = hostID
    }

    enum CodingKeys: String, CodingKey {
        case name, ssh, port, tmb, socket
        case hostID = "host_id"
    }
}

/// The queue of one host: entries the core can review, and the ids of
/// items that carry no payload (a broker without signer support), which
/// the signer neither shows nor answers.
public struct QueueListing: Equatable, Sendable {
    public let entries: [QueueEntry]
    public let unsigned: [String]
}

/// What the broker said to a decision, by the exit code of `tmb approve`
/// (#105): 0 `decided` or `recorded` (a signature below the threshold),
/// 1 the item is gone (`already_decided`, `no_such_item`), 125 a refusal
/// with the broker's reason.
public enum DecideOutcome: Equatable, Sendable {
    case decided(String)
    case recorded(String)
    case gone(String)
    case refused(String)
}

public enum TransportError: Error, Equatable, CustomStringConvertible {
    /// The endpoint config is unusable; nothing was run.
    case badEndpoint(String)
    /// SSH or the approver socket could not be reached (ssh 255, tmb 3).
    case unreachable(String)
    /// The remote command failed otherwise (tmb missing, usage error).
    case remote(Int32, String)
    /// `tmb approve` printed something that is not its machine output.
    case badOutput(String)

    /// The answer was refused by `tmb approve` itself (exit 2: our message
    /// does not parse for it) or is not its machine output: a protocol
    /// mismatch between this signer and the client on the host, which a
    /// retry of the same message would only repeat.
    public var isProtocolError: Bool {
        switch self {
        case .badOutput: return true
        case .remote(let code, _): return code == 2
        default: return false
        }
    }

    public var description: String {
        switch self {
        case .badEndpoint(let s): return "bad host entry: " + s
        case .unreachable(let s): return "unreachable: " + s
        case .remote(let c, let s): return "remote exit \(c): " + s
        case .badOutput(let s): return "bad output: " + s
        }
    }
}

/// The transport seam (spec seam 6): `tmb approve` in machine mode on a
/// host. Production runs it over SSH; tests feed recorded outputs.
public protocol ApproveTransport: Sendable {
    func list(_ host: HostEndpoint) throws -> QueueListing
    func decide(_ host: HostEndpoint, _ message: DecideMessage) throws -> DecideOutcome
}

/// `tmb approve --list --json` and `tmb approve --decide` over
/// /usr/bin/ssh in batch mode: no password or host key prompts, no agent,
/// X11 or port forwarding. The SSH host key is the user's known_hosts
/// business; the broker identity is pinned by the core (HostTrust).
public struct SSHTransport: ApproveTransport {
    public static let ssh = "/usr/bin/ssh"
    let runner: any CommandRunner

    public init(runner: any CommandRunner = ProcessRunner()) { self.runner = runner }

    public func list(_ host: HostEndpoint) throws -> QueueListing {
        let r = try run(host, ["approve", "--list", "--json"], stdin: nil)
        guard r.status == 0 else { throw Self.failure(r) }
        return try Self.parseQueue(r.stdout)
    }

    public func decide(_ host: HostEndpoint, _ message: DecideMessage) throws -> DecideOutcome {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let r = try run(host, ["approve", "--decide"], stdin: try e.encode(message) + Data("\n".utf8))
        switch r.status {
        case 0:
            let f = try Self.frame(r.stdout)
            switch f.type {
            case "decided": return .decided(f.detail)
            case "recorded": return .recorded(f.detail)
            default: throw TransportError.badOutput("unexpected answer \(f.type)")
            }
        case 1, 125:
            let f = try Self.frame(r.stdout)
            guard f.type == "denied", !f.reason.isEmpty else { throw TransportError.badOutput("unexpected answer \(f.type)") }
            return r.status == 1 ? .gone(f.reason) : .refused(f.reason)
        default:
            throw Self.failure(r)
        }
    }

    func run(_ host: HostEndpoint, _ words: [String], stdin: Data?) throws -> CommandResult {
        let args = try Self.arguments(host, words)
        do {
            return try runner.run(Self.ssh, args, stdin: stdin)
        } catch CommandError.timedOut {
            throw TransportError.unreachable("ssh did not finish in time")
        } catch {
            throw TransportError.unreachable(String(describing: error))
        }
    }

    static func arguments(_ host: HostEndpoint, _ words: [String]) throws -> [String] {
        let dest = host.ssh
        guard !dest.isEmpty, !dest.hasPrefix("-"),
              dest.unicodeScalars.allSatisfy({ $0.value > 0x20 && $0.value < 0x7F })
        else { throw TransportError.badEndpoint("ssh destination \(String(reflecting: dest)) for \(host.name)") }
        var args = ["-T", "-a", "-x", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10"]
        if let p = host.port {
            guard (1...65535).contains(p) else { throw TransportError.badEndpoint("port \(p) for \(host.name)") }
            args += ["-p", String(p)]
        }
        var remote = [host.tmb ?? "tmb"] + words
        if let s = host.socket { remote += ["--socket", s] }
        for w in remote where w.isEmpty || w.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) {
            throw TransportError.badEndpoint("remote word \(String(reflecting: w)) for \(host.name)")
        }
        return args + ["--", dest, remoteCommand(remote)]
    }

    /// ssh hands the command to the remote login shell as one string, so
    /// every word is single-quoted.
    static func remoteCommand(_ words: [String]) -> String {
        words.map { "'" + $0.replacingOccurrences(of: "'", with: #"'\''"#) + "'" }.joined(separator: " ")
    }

    static func failure(_ r: CommandResult) -> TransportError {
        let err = String(decoding: r.stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        switch r.status {
        case 255, 3: return .unreachable(err)
        default: return .remote(r.status, err)
        }
    }

    static func object(_ out: Data, _ what: String) throws -> [String: Any] {
        guard let o = try? JSONSerialization.jsonObject(with: out) as? [String: Any] else {
            throw TransportError.badOutput("\(what) is not one JSON object")
        }
        return o
    }

    static func parseQueue(_ out: Data) throws -> QueueListing {
        let o = try object(out, "queue")
        guard o["type"] as? String == "queue", let items = o["items"] as? [Any] else {
            throw TransportError.badOutput("answer is not a queue")
        }
        var entries: [QueueEntry] = []
        var unsigned: [String] = []
        for (i, any) in items.enumerated() {
            guard let it = any as? [String: Any], let id = it["id"] as? String, let hash = it["hash"] as? String else {
                throw TransportError.badOutput("queue item \(i) has no string id and hash")
            }
            if let p = it["payload"] as? String, !p.isEmpty {
                entries.append(QueueEntry(id: id, hash: hash, payload: p))
            } else {
                unsigned.append(id)
            }
        }
        return QueueListing(entries: entries, unsigned: unsigned)
    }

    static func frame(_ out: Data) throws -> (type: String, reason: String, detail: String) {
        let o = try object(out, "answer")
        return (o["type"] as? String ?? "", o["reason"] as? String ?? "", o["detail"] as? String ?? "")
    }
}
