import CryptoKit
import Foundation

/// Why payload bytes were refused. The signer never shows or signs a
/// payload it could not parse strictly.
public struct PayloadError: Error, Equatable, CustomStringConvertible {
    public let description: String
    init(_ d: String) { description = "approval payload: " + d }
}

/// The approval payload (ADR 0006, В12): the exact bytes a broker builds per
/// queue item and a signer shows and signs. The Go side is
/// `src/internal/proto/payload.go`; both follow the same canonical form and
/// field rules and are tested against signer/Tests/vectors/approval-v1.json.
///
/// Strings are kept as Unicode scalars exactly as received: Swift String
/// equality is canonical equivalence, so every comparison here goes through
/// UTF-8 bytes.
public struct ApprovalPayload: Sendable {
    public static let prefix = Data("tmb-approval-v1\u{0}".utf8)
    static let shortCodePrefix = Data("tmb-approval-code-v1\u{0}".utf8)

    public let hostID: String
    public let hostKey: String
    public let itemID: String
    public let requestHash: String
    public let challenge: String
    public let requester: String
    public let uid: UInt32
    public let user: String
    public let executable: String
    public let exeDev: UInt64
    public let exeIno: UInt64
    public let argv: [String]
    public let cwd: String
    public let env: [String]
    public let nonce: String
    /// Unix milliseconds, broker clock.
    public let queuedAt: Int64
    /// Unix milliseconds, broker clock: no decision is accepted after it.
    public let deadline: Int64
    public let tokenTTLSeconds: Int

    /// Field names in canonical order.
    static let fieldOrder = [
        "host_id", "host_key", "item_id", "request_hash", "challenge", "requester",
        "uid", "user", "executable", "exe_dev", "exe_ino", "argv", "cwd", "env",
        "nonce", "queued_at", "deadline", "token_ttl_seconds",
    ]

    /// Parses payload bytes strictly: the prefix, one JSON object with
    /// exactly the known fields, the field rules, and re-encoding must give
    /// the received bytes. Anything else throws and yields no payload.
    public static func parse(_ raw: Data) throws -> ApprovalPayload {
        let bytes = [UInt8](raw)
        let pre = [UInt8](prefix)
        guard bytes.starts(with: pre) else { throw PayloadError("missing the tmb-approval-v1 prefix") }
        let body = Array(bytes[pre.count...])
        var reader = JSONReader(body)
        let members = try reader.readDocumentObject()
        var fields: [String: JSONValue] = [:]
        for (k, v) in members {
            guard fieldOrder.contains(k) else { throw PayloadError("unknown field") }
            guard fields[k] == nil else { throw PayloadError("duplicate field") }
            fields[k] = v
        }
        guard fields.count == fieldOrder.count else { throw PayloadError("missing field") }
        func str(_ k: String) throws -> String {
            guard case .string(let s) = fields[k]! else { throw PayloadError("\(k) is not a string") }
            return s
        }
        func strs(_ k: String) throws -> [String] {
            guard case .array(let a) = fields[k]! else { throw PayloadError("\(k) is not an array") }
            return try a.map {
                guard case .string(let s) = $0 else { throw PayloadError("\(k) holds a non-string") }
                return s
            }
        }
        func int<T: FixedWidthInteger>(_ k: String, _: T.Type) throws -> T {
            guard case .number(let n) = fields[k]!, let v = T(n, radix: 10), isPlainInteger(n) else {
                throw PayloadError("\(k) is not an integer in range")
            }
            return v
        }
        let uid64 = try int("uid", Int64.self)
        guard uid64 >= 0, uid64 <= Int64(UInt32.max) else { throw PayloadError("uid out of range") }
        let p = ApprovalPayload(
            hostID: try str("host_id"), hostKey: try str("host_key"), itemID: try str("item_id"),
            requestHash: try str("request_hash"), challenge: try str("challenge"),
            requester: try str("requester"), uid: UInt32(uid64), user: try str("user"),
            executable: try str("executable"), exeDev: try int("exe_dev", UInt64.self),
            exeIno: try int("exe_ino", UInt64.self), argv: try strs("argv"), cwd: try str("cwd"),
            env: try strs("env"), nonce: try str("nonce"), queuedAt: try int("queued_at", Int64.self),
            deadline: try int("deadline", Int64.self), tokenTTLSeconds: try int("token_ttl_seconds", Int.self))
        try p.check()
        guard p.canonicalJSON() == body else { throw PayloadError("not in canonical form") }
        return p
    }

    /// Prefix plus canonical JSON. Used to prove a parse round-trips; the
    /// signer signs the received bytes, never this.
    func encoded() throws -> Data {
        try check()
        return Self.prefix + Data(canonicalJSON())
    }

    /// The field rules of payload.go `check`.
    func check() throws {
        func hex64(_ s: String) -> Bool {
            let u = Array(s.utf8)
            return u.count == 64 && u.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
        }
        if hostID.isEmpty { throw PayloadError("empty host_id") }
        if !hex64(hostKey) { throw PayloadError("host_key is not a SHA-256 hex fingerprint") }
        if !hex64(requestHash) { throw PayloadError("request_hash is not a SHA-256 hex digest") }
        if Array(itemID.utf8) != Array(requestHash.utf8.prefix(16)) { throw PayloadError("item_id does not match request_hash") }
        if !hex64(challenge) { throw PayloadError("challenge is not 32 bytes of hex") }
        if requester.utf8.isEmpty || nonce.utf8.isEmpty { throw PayloadError("empty requester or nonce") }
        if executable.utf8.first != 0x2F || cwd.utf8.first != 0x2F {
            throw PayloadError("executable or cwd is not an absolute path")
        }
        if argv.isEmpty { throw PayloadError("empty argv") }
        if queuedAt <= 0 || deadline <= queuedAt { throw PayloadError("deadline is not after queued_at") }
        if tokenTTLSeconds <= 0 { throw PayloadError("token_ttl_seconds is not positive") }
        var prev: [UInt8] = []
        var prevKey: [UInt8] = []
        for (i, e) in env.enumerated() {
            let b = Array(e.utf8)
            guard let eq = b.firstIndex(of: 0x3D), eq > 0 else { throw PayloadError("env entry \(i) is not KEY=VALUE") }
            let k = Array(b[..<eq])
            if i > 0 && (!prev.lexicographicallyPrecedes(b) || k == prevKey) {
                throw PayloadError("env is not sorted with distinct keys")
            }
            prev = b
            prevKey = k
        }
    }

    func canonicalJSON() -> [UInt8] {
        var w = CanonicalWriter()
        w.out.append(0x7B)
        w.str("host_id", hostID)
        w.str("host_key", hostKey)
        w.str("item_id", itemID)
        w.str("request_hash", requestHash)
        w.str("challenge", challenge)
        w.str("requester", requester)
        w.num("uid", String(uid))
        w.str("user", user)
        w.str("executable", executable)
        w.num("exe_dev", String(exeDev))
        w.num("exe_ino", String(exeIno))
        w.list("argv", argv)
        w.str("cwd", cwd)
        w.list("env", env)
        w.str("nonce", nonce)
        w.num("queued_at", String(queuedAt))
        w.num("deadline", String(deadline))
        w.num("token_ttl_seconds", String(tokenTTLSeconds))
        w.out.append(0x7D)
        return w.out
    }

    /// The human-comparable code: the first 8 base32 characters of
    /// SHA-256("tmb-approval-code-v1\0" || payload) as XXXX-XXXX, the same
    /// as proto.ShortCode. A help for the eye, not a proof.
    public static func shortCode(of payload: Data) -> String {
        var h = SHA256()
        h.update(data: shortCodePrefix)
        h.update(data: payload)
        let s = base32(Array(Data(h.finalize()).prefix(5)))
        return String(s.prefix(4)) + "-" + String(s.suffix(4))
    }

    /// What an approver key signs: SHA-256 of the whole payload.
    public static func digest(of payload: Data) -> Data {
        Data(SHA256.hash(data: payload))
    }
}

private func isPlainInteger(_ n: String) -> Bool {
    // The canonical integer form: optional minus, no leading zeros, digits only.
    let u = Array(n.utf8)
    let digits = u.first == 0x2D ? Array(u.dropFirst()) : u
    guard !digits.isEmpty, digits.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return false }
    return digits.count == 1 || digits[0] != 0x30
}

private func base32(_ bytes: [UInt8]) -> String {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    var out = ""
    var buffer: UInt32 = 0
    var bits = 0
    for b in bytes {
        buffer = (buffer << 8) | UInt32(b)
        bits += 8
        while bits >= 5 {
            out.append(alphabet[Int((buffer >> UInt32(bits - 5)) & 31)])
            bits -= 5
        }
    }
    if bits > 0 { out.append(alphabet[Int((buffer << UInt32(5 - bits)) & 31)]) }
    return out
}

/// Writes the canonical object one field at a time (payload.go canonWriter).
struct CanonicalWriter {
    var out: [UInt8] = []
    var fields = 0

    mutating func key(_ k: String) {
        if fields > 0 { out.append(0x2C) }
        fields += 1
        string(k)
        out.append(0x3A)
    }

    mutating func str(_ k: String, _ v: String) { key(k); string(v) }
    mutating func num(_ k: String, _ v: String) { key(k); out.append(contentsOf: v.utf8) }

    mutating func list(_ k: String, _ vs: [String]) {
        key(k)
        out.append(0x5B)
        for (i, v) in vs.enumerated() {
            if i > 0 { out.append(0x2C) }
            string(v)
        }
        out.append(0x5D)
    }

    /// Escapes only '"', '\', the short escapes b f n r t, other code points
    /// below U+0020 and U+2028/U+2029 as \u with lowercase hex; everything
    /// else is literal UTF-8.
    mutating func string(_ s: String) {
        let hex = Array("0123456789abcdef".utf8)
        out.append(0x22)
        for r in s.unicodeScalars {
            switch r.value {
            case 0x22, 0x5C: out.append(0x5C); out.append(UInt8(r.value))
            case 0x08: out.append(contentsOf: [0x5C, 0x62])
            case 0x0C: out.append(contentsOf: [0x5C, 0x66])
            case 0x0A: out.append(contentsOf: [0x5C, 0x6E])
            case 0x0D: out.append(contentsOf: [0x5C, 0x72])
            case 0x09: out.append(contentsOf: [0x5C, 0x74])
            case let v where v < 0x20 || v == 0x2028 || v == 0x2029:
                out.append(contentsOf: [0x5C, 0x75])
                for shift in stride(from: 12, through: 0, by: -4) { out.append(hex[Int((v >> UInt32(shift)) & 15)]) }
            default:
                out.append(contentsOf: String(r).utf8)
            }
        }
        out.append(0x22)
    }
}

extension Data {
    /// Lowercase hex, the form of proto fingerprints and digests.
    public var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
