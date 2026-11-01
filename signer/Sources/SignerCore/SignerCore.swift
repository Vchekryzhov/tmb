import Foundation

/// The parts of a `tmb approve` queue item (proto.QueueItem) the core uses:
/// `id`, `hash` (echoed by decide) and `payload` (base64 of the exact bytes
/// to sign). The other QueueItem fields are display copies and are ignored.
public struct QueueEntry: Equatable, Sendable {
    public let id: String
    public let hash: String
    public let payload: String
    public init(id: String, hash: String, payload: String) {
        self.id = id
        self.hash = hash
        self.payload = payload
    }
}

/// Why the signer denies (ADR 0006 В7). Every one is an unsigned `deny`.
public enum DenyReason: Equatable, Sendable {
    case invalidPayload(String)
    case undisplayable(field: String)
    case hostKeyChanged(hostID: String, pinned: String, presented: String)
    case hostStoreFailed(String)
    case cancelled
    case timedOut
    case biometryFailed
    case keyUnusable
    case notInteractive
    case signingFailed(String)
}

public struct Denial: Equatable, Sendable {
    public let itemID: String
    public let itemHash: String
    public let reason: DenyReason
    /// Text the app must show the person (a changed host key).
    public let warning: String?

    public init(itemID: String, itemHash: String, reason: DenyReason, warning: String? = nil) {
        self.itemID = itemID
        self.itemHash = itemHash
        self.reason = reason
        self.warning = warning
    }
}

public struct SignedApproval: Equatable, Sendable {
    public let itemID: String
    public let itemHash: String
    /// The received payload bytes, the ones signed.
    public let payload: Data
    /// DER ECDSA signature over SHA-256 of `payload`.
    public let signature: Data
    /// Fingerprint of the signing key (proto.KeyFingerprint).
    public let approverKey: String
}

/// The `decide` fields of proto.Request for one decision. The transport
/// (#110) wraps them in whatever `tmb approve` machine mode reads on stdin.
public struct DecideMessage: Equatable, Sendable, Encodable {
    public let itemID: String
    public let itemHash: String
    public let decision: String
    public let signature: String?
    public let approverKey: String?

    enum CodingKeys: String, CodingKey {
        case itemID = "item_id"
        case itemHash = "item_hash"
        case decision
        case signature
        case approverKey = "approver_key"
    }
}

public enum Decision: Equatable, Sendable {
    case approve(SignedApproval)
    case deny(Denial)

    public var message: DecideMessage {
        switch self {
        case .approve(let a):
            return DecideMessage(itemID: a.itemID, itemHash: a.itemHash, decision: "approve",
                                 signature: a.signature.base64EncodedString(), approverKey: a.approverKey)
        case .deny(let d):
            return DecideMessage(itemID: d.itemID, itemHash: d.itemHash, decision: "deny", signature: nil, approverKey: nil)
        }
    }
}

/// One item ready for the window: the received bytes, what was parsed from
/// them, the display model and the Touch ID prompt.
public struct PendingApproval: Sendable {
    public let itemID: String
    public let itemHash: String
    /// The exact received bytes; `decide` signs these and nothing else.
    public let raw: Data
    public let payload: ApprovalPayload
    public let display: ApprovalDisplay
    /// `.firstUse` when this review pinned the host: the window says so.
    public let hostCheck: HostCheck
    public let prompt: SigningPrompt
}

public enum Review: Sendable {
    case show(PendingApproval)
    case deny(Denial)
}

/// What the person did in the window.
public enum HumanAnswer: Sendable {
    case approve
    case cancel
    /// The window's own wait ran out.
    case timeout
}

/// The signer core: review a queue item (parse, show, check the host),
/// then turn the person's answer into a signed approve or an unsigned deny.
/// The app (#110) owns the window, the queue polling and the transport;
/// it calls `review` per item, shows `display`, and sends `message`.
public struct SignerCore: Sendable {
    let signer: any PayloadSigner
    let hosts: HostTrust
    let limits: DisplayLimits
    let preSignCheck: @Sendable () -> SigningError?

    /// `preSignCheck` runs right before each signature: the app passes its
    /// `SecCodeCheckValidity` and GUI-session checks (ADR 0007 Р5); a
    /// non-nil result denies without touching the key.
    public init(signer: any PayloadSigner, hosts: HostTrust, limits: DisplayLimits = .standard,
                preSignCheck: @escaping @Sendable () -> SigningError? = { nil }) {
        self.signer = signer
        self.hosts = hosts
        self.limits = limits
        self.preSignCheck = preSignCheck
    }

    public func review(_ e: QueueEntry) -> Review {
        func deny(_ r: DenyReason, _ warning: String? = nil) -> Review {
            .deny(Denial(itemID: e.id, itemHash: e.hash, reason: r, warning: warning))
        }
        guard let raw = Data(base64Encoded: e.payload) else { return deny(.invalidPayload("payload is not base64")) }
        let p: ApprovalPayload
        do { p = try ApprovalPayload.parse(raw) } catch { return deny(.invalidPayload(String(describing: error))) }
        guard Array(p.itemID.utf8) == Array(e.id.utf8), Array(p.requestHash.utf8) == Array(e.hash.utf8) else {
            return deny(.invalidPayload("payload is for another queue item"))
        }
        let display: ApprovalDisplay
        do { display = try ApprovalDisplay(payload: p, raw: raw, limits: limits) } catch DisplayError.undisplayable(let f) {
            return deny(.undisplayable(field: f))
        } catch { return deny(.undisplayable(field: "?")) }
        let check: HostCheck
        do { check = try hosts.pinIfNew(hostID: p.hostID, hostKey: p.hostKey) } catch {
            return deny(.hostStoreFailed(String(describing: error)))
        }
        if case .mismatch(let pinned) = check {
            return deny(Self.hostChanged(p, pinned), Self.hostWarning(display, p, pinned))
        }
        let prompt = SigningPrompt(reason: "approve \(display.shortCode) on \(display.hostID.shown)")
        return .show(PendingApproval(itemID: e.id, itemHash: e.hash, raw: raw, payload: p, display: display,
                                     hostCheck: check, prompt: prompt))
    }

    public func decide(_ a: PendingApproval, answer: HumanAnswer) -> Decision {
        func deny(_ r: DenyReason, _ warning: String? = nil) -> Decision {
            .deny(Denial(itemID: a.itemID, itemHash: a.itemHash, reason: r, warning: warning))
        }
        switch answer {
        case .cancel: return deny(.cancelled)
        case .timeout: return deny(.timedOut)
        case .approve: break
        }
        do {
            if case .mismatch(let pinned) = try hosts.check(hostID: a.payload.hostID, hostKey: a.payload.hostKey) {
                return deny(Self.hostChanged(a.payload, pinned), Self.hostWarning(a.display, a.payload, pinned))
            }
        } catch { return deny(.hostStoreFailed(String(describing: error))) }
        if let e = preSignCheck() { return deny(Self.reason(e)) }
        let sig: Data
        let spki: Data
        do {
            spki = try signer.publicKeySPKI()
            sig = try signer.sign(a.raw, prompt: a.prompt)
        } catch {
            return deny(Self.reason(SigningError.classify(error)))
        }
        guard (try? SignatureCheck.verify(publicKeySPKI: spki, payload: a.raw, signatureDER: sig)) == true else {
            return deny(.signingFailed("signature does not verify"))
        }
        return .approve(SignedApproval(itemID: a.itemID, itemHash: a.itemHash, payload: a.raw, signature: sig,
                                       approverKey: SignatureCheck.fingerprint(publicKeySPKI: spki)))
    }

    static func reason(_ e: SigningError) -> DenyReason {
        switch e {
        case .cancelled: return .cancelled
        case .timedOut: return .timedOut
        case .biometryFailed: return .biometryFailed
        case .keyUnusable: return .keyUnusable
        case .notInteractive: return .notInteractive
        case .failed(let s): return .signingFailed(s)
        }
    }

    static func hostChanged(_ p: ApprovalPayload, _ pinned: String) -> DenyReason {
        .hostKeyChanged(hostID: p.hostID, pinned: pinned, presented: p.hostKey)
    }

    static func hostWarning(_ d: ApprovalDisplay, _ p: ApprovalPayload, _ pinned: String) -> String {
        "host \"\(d.hostID.shown)\" presented identity key \(DisplayText(p.hostKey).shown), "
            + "but \(DisplayText(pinned).shown) is pinned: denied, the pin was not changed"
    }
}
