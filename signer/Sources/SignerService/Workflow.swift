import Foundation
import SignerCore

/// One queue item waiting for the person, bound to the host it came from.
public struct ShownItem: Sendable, Identifiable {
    public let id: String
    public let host: HostEndpoint
    public let approval: PendingApproval
}

/// A decision and what the host said to it.
public struct SentDecision: Sendable {
    public let host: HostEndpoint
    public let decision: Decision
    public let outcome: Result<DecideOutcome, TransportError>
}

/// The result of one poll of one host.
public struct PollReport: Sendable {
    /// New items for the window, one window each, in queue order.
    public var show: [ShownItem] = []
    /// Items the core refused before showing (bad payload, changed host
    /// key, wrong host id): their unsigned deny is already sent.
    public var denied: [SentDecision] = []
    /// Ids of items without a payload (broker without signer support).
    public var unsigned: [String] = []
    public var error: TransportError?
}

/// Polls hosts and turns answers into decisions. An item is shown once:
/// it stays out of later polls while its window is open and, after its
/// answer was delivered, for as long as the host still lists it (a
/// signature below the threshold keeps it queued). A decision that did not
/// reach the host lets the item come back. Safe to call from any thread.
public final class SignerWorkflow: @unchecked Sendable {
    let core: SignerCore
    let transport: any ApproveTransport
    private let lock = NSLock()
    private var open: Set<String> = []
    private var answered: Set<String> = []

    public init(core: SignerCore, transport: any ApproveTransport) {
        self.core = core
        self.transport = transport
    }

    static func key(_ host: HostEndpoint, _ hash: String) -> String { host.name + "\u{0}" + hash }

    public func poll(_ host: HostEndpoint) -> PollReport {
        var rep = PollReport()
        let listing: QueueListing
        do { listing = try transport.list(host) } catch {
            rep.error = error as? TransportError ?? .badOutput(String(describing: error))
            return rep
        }
        rep.unsigned = listing.unsigned
        let listed = Set(listing.entries.map { Self.key(host, $0.hash) })
        let fresh: [QueueEntry] = lock.withLock {
            let prefix = host.name + "\u{0}"
            answered = answered.filter { !$0.hasPrefix(prefix) || listed.contains($0) }
            var out: [QueueEntry] = []
            for e in listing.entries {
                let k = Self.key(host, e.hash)
                if open.contains(k) || answered.contains(k) { continue }
                open.insert(k)
                out.append(e)
            }
            return out
        }
        for e in fresh {
            let k = Self.key(host, e.hash)
            if let d = foreignHost(host, e) {
                rep.denied.append(send(host, .deny(d), key: k))
                continue
            }
            switch core.review(e) {
            case .show(let p): rep.show.append(ShownItem(id: k, host: host, approval: p))
            case .deny(let d): rep.denied.append(send(host, .deny(d), key: k))
            }
        }
        return rep
    }

    /// The person's answer for a shown item: sign or deny, then deliver.
    public func answer(_ item: ShownItem, _ answer: HumanAnswer) -> SentDecision {
        send(item.host, core.decide(item.approval, answer: answer), key: item.id)
    }

    private func send(_ host: HostEndpoint, _ d: Decision, key: String) -> SentDecision {
        let outcome: Result<DecideOutcome, TransportError>
        do { outcome = .success(try transport.decide(host, d.message)) } catch {
            outcome = .failure(error as? TransportError ?? .badOutput(String(describing: error)))
        }
        lock.withLock {
            open.remove(key)
            if case .success = outcome { answered.insert(key) }
        }
        return SentDecision(host: host, decision: d, outcome: outcome)
    }

    /// An endpoint configured with a host id must present that host id;
    /// checked before the core sees the item, so nothing is pinned.
    private func foreignHost(_ host: HostEndpoint, _ e: QueueEntry) -> Denial? {
        guard let want = host.hostID,
              let raw = Data(base64Encoded: e.payload),
              let p = try? ApprovalPayload.parse(raw),
              Array(p.hostID.utf8) != Array(want.utf8)
        else { return nil }
        let got = DisplayText(p.hostID).shown
        return Denial(itemID: e.id, itemHash: e.hash, reason: .invalidPayload("host_id \"\(got)\" is not \"\(want)\""),
                      warning: "endpoint \(host.name) is configured for host_id \"\(DisplayText(want).shown)\" "
                          + "but presented \"\(got)\": denied")
    }
}
