import CryptoKit
import Foundation
import Testing
@testable import SignerCore

@Suite struct PayloadVectorTests {
    let v: Vectors
    init() throws { v = try Vectors.load() }

    @Test func vectorFileHasCases() {
        #expect(v.valid.count >= 3)
        #expect(v.invalid.count >= 40)
        #expect(v.signatures.count >= 4)
    }

    @Test func validVectorsParseToTheGoFields() throws {
        for c in v.valid {
            let p = try ApprovalPayload.parse(b64(c.payload))
            let f = c.fields
            #expect(p.hostID == f.host_id, "\(c.name)")
            #expect(p.hostKey == f.host_key)
            #expect(p.itemID == f.item_id)
            #expect(p.requestHash == f.request_hash)
            #expect(p.challenge == f.challenge)
            #expect(p.requester == f.requester)
            #expect(UInt64(p.uid) == f.uid)
            #expect(scalars(p.user) == scalars(f.user))
            #expect(scalars(p.executable) == scalars(f.executable))
            #expect(p.exeDev == f.exe_dev)
            #expect(p.exeIno == f.exe_ino)
            #expect(p.argv.map(scalars) == f.argv.map(scalars), "\(c.name)")
            #expect(scalars(p.cwd) == scalars(f.cwd))
            #expect(p.env.map(scalars) == f.env.map(scalars), "\(c.name)")
            #expect(p.nonce == f.nonce)
            #expect(p.queuedAt == f.queued_at)
            #expect(p.deadline == f.deadline)
            #expect(p.tokenTTLSeconds == f.token_ttl_seconds)
        }
    }

    @Test func reEncodingGivesTheReceivedBytes() throws {
        for c in v.valid {
            let raw = b64(c.payload)
            #expect(try ApprovalPayload.parse(raw).encoded() == raw, "\(c.name)")
        }
    }

    @Test func shortCodeAndDigestMatchGo() {
        for c in v.valid {
            let raw = b64(c.payload)
            #expect(ApprovalPayload.shortCode(of: raw) == c.short_code, "\(c.name)")
            #expect(ApprovalPayload.digest(of: raw).hexString == c.digest, "\(c.name)")
        }
    }

    @Test func everyInvalidVectorIsRefused() {
        for c in v.invalid {
            let raw = Data(base64Encoded: c.payload) ?? Data()
            #expect(throws: PayloadError.self, "\(c.name)") { try ApprovalPayload.parse(raw) }
        }
    }

    @Test func signatureVectorsVerifyAsInGo() throws {
        for s in v.signatures {
            let ok = try SignatureCheck.verify(publicKeySPKI: b64(s.public_key), payload: b64(s.payload), signatureDER: b64(s.signature))
            #expect(ok == s.valid, "\(s.name)")
        }
    }
}

// Rules beyond the vectors, each a mutation of the Go sample bytes, so the
// expectation never depends on the Swift encoder.
@Suite struct PayloadRuleTests {
    @Test func keepsCanonicallyEquivalentTextApart() throws {
        // U+00E9 and e + U+0301 compare equal as Swift Strings; the bytes
        // differ, so only one of them can be the received payload.
        let nfc = try Vectors.sample(replacing: "\"cwd\":\"/", with: "\"cwd\":\"/\u{E9}")
        let nfd = try Vectors.sample(replacing: "\"cwd\":\"/", with: "\"cwd\":\"/e\u{301}")
        let p = try ApprovalPayload.parse(nfc)
        #expect(try p.encoded() == nfc)
        #expect(try ApprovalPayload.parse(nfd).encoded() == nfd)
        #expect(try p.encoded() != nfd)
    }

    @Test func refusesItemIDNotFromRequestHash() throws {
        let raw = try Vectors.sample(replacing: "\"item_id\":\"", with: "\"item_id\":\"0")
        #expect(throws: PayloadError.self) { try ApprovalPayload.parse(raw) }
    }

    @Test func refusesLoneSurrogateAndEscapedSlash() throws {
        let lone = try Vectors.sample(replacing: "\"cwd\":\"/", with: "\"cwd\":\"/\\ud800")
        let slash = try Vectors.sample(replacing: "\"cwd\":\"/", with: "\"cwd\":\"\\/")
        #expect(throws: PayloadError.self) { try ApprovalPayload.parse(lone) }
        #expect(throws: PayloadError.self) { try ApprovalPayload.parse(slash) }
    }

    @Test func refusesOverlongUTF8() throws {
        var raw = try Vectors.sample()
        let marker = Data("\"cwd\":\"/".utf8)
        let r = raw.range(of: marker)!
        raw.insert(contentsOf: [0xC0, 0xAF], at: r.upperBound)
        #expect(throws: PayloadError.self) { try ApprovalPayload.parse(raw) }
    }

    @Test func refusesEnvWithDuplicateKey() throws {
        let raw = try Vectors.sample(replacing: "\"env\":[", with: "\"env\":[\"A=1\",\"A=2\",")
        #expect(throws: PayloadError.self) { try ApprovalPayload.parse(raw) }
    }
}
