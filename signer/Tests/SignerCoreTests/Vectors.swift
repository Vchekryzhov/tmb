import Foundation

// The shared vectors of src/internal/proto (approval-v1.json), read from the
// repository so Go and Swift test the very same bytes.
struct Vectors: Decodable {
    struct Valid: Decodable {
        let name: String
        let payload: String
        let fields: Fields
        let short_code: String
        let digest: String
    }
    struct Fields: Decodable {
        let host_id, host_key, item_id, request_hash, challenge, requester: String
        let uid: UInt64
        let user, executable: String
        let exe_dev, exe_ino: UInt64
        let argv: [String]
        let cwd: String
        let env: [String]
        let nonce: String
        let queued_at, deadline: Int64
        let token_ttl_seconds: Int
    }
    struct Invalid: Decodable {
        let name: String
        let payload: String
    }
    struct Signature: Decodable {
        let name, source, public_key, payload, signature: String
        let valid: Bool
    }
    let public_key: String
    let valid: [Valid]
    let invalid: [Invalid]
    let signatures: [Signature]

    static let url = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("vectors/approval-v1.json")

    static func load() throws -> Vectors {
        try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url))
    }

    /// The bytes of the Go "sample" vector.
    static func sample() throws -> Data { b64(try load().valid[0].payload) }

    /// The sample vector with one textual replacement applied to its bytes.
    static func sample(replacing from: String, with to: String) throws -> Data {
        let s = String(decoding: try sample(), as: UTF8.self)
        precondition(s.contains(from), from)
        return Data(s.replacingOccurrences(of: from, with: to).utf8)
    }
}

func b64(_ s: String) -> Data { Data(base64Encoded: s)! }

func scalars(_ s: String) -> [Unicode.Scalar] { Array(s.unicodeScalars) }
