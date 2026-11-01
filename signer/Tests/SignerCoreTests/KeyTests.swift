import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Testing
@testable import SignerCore

/// The test signer: a software P-256 key behind the same protocol as the
/// Secure Enclave key. `failure` makes it fail the way a Touch ID sheet can.
final class SoftwareSigner: PayloadSigner, @unchecked Sendable {
    let key = P256.Signing.PrivateKey()
    var failure: SigningError?
    var signed: [Data] = []
    var prompts: [SigningPrompt] = []
    var corrupt = false

    init(failure: SigningError? = nil) { self.failure = failure }

    func publicKeySPKI() throws -> Data { key.publicKey.derRepresentation }

    func sign(_ payload: Data, prompt: SigningPrompt) throws -> Data {
        prompts.append(prompt)
        if let failure { throw failure }
        signed.append(payload)
        let der = try key.signature(for: payload).derRepresentation
        return corrupt ? der.dropLast() + Data([der.last! ^ 1]) : der
    }
}

func tempDir() throws -> URL {
    let u = FileManager.default.temporaryDirectory.appendingPathComponent("tmb-signer-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
    return u
}

func mode(_ url: URL) throws -> Int {
    (try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as! NSNumber).intValue
}

@Suite struct ApproverKeyEntryTests {
    @Test func exportsTheApproverKeysEntry() throws {
        let spki = b64(try Vectors.load().public_key)
        let e = try ApproverKeyEntry(name: "mac-work", publicKeySPKI: spki)
        let json = try JSONSerialization.jsonObject(with: Data(e.json.utf8)) as! [String: String]
        #expect(json == ["name": "mac-work", "class": "mac-se", "public_key": try Vectors.load().public_key])
        #expect(e.json.hasPrefix(#"{"name":"mac-work","class":"mac-se","public_key":""#))
        #expect(!e.json.contains(#"\/"#))
        #expect(e.fingerprint == "4b3da683ea9a36074542b569f1b41f49cf5a0391bc8f96a305455c4f900001ca")
        // a quote or a backslash in the name stays valid JSON
        let q = try ApproverKeyEntry(name: #"a"b\c"#, publicKeySPKI: spki)
        let back = try JSONSerialization.jsonObject(with: Data(q.json.utf8)) as! [String: String]
        #expect(back["name"] == #"a"b\c"#)
    }

    @Test func refusesABadNameOrKey() {
        let spki = P256.Signing.PrivateKey().publicKey.derRepresentation
        #expect(throws: KeyError.self) { try ApproverKeyEntry(name: "", publicKeySPKI: spki) }
        #expect(throws: KeyError.self) { try ApproverKeyEntry(name: "a\nb", publicKeySPKI: spki) }
        #expect(throws: KeyError.self) { try ApproverKeyEntry(name: "ok", publicKeySPKI: Data([1, 2, 3])) }
    }
}

@Suite struct PrivateFileTests {
    @Test func writesOwnerOnlyAndRefusesToOverwrite() throws {
        let f = try tempDir().appendingPathComponent("key.blob")
        try PrivateFile.createNew(f, contents: Data("blob".utf8))
        #expect(try mode(f) == 0o600)
        #expect(try PrivateFile.read(f) == Data("blob".utf8))
        #expect(throws: KeyError.self) { try PrivateFile.createNew(f, contents: Data("other".utf8)) }
        #expect(try PrivateFile.read(f) == Data("blob".utf8))
    }

    @Test func refusesAFileOthersCanRead() throws {
        let f = try tempDir().appendingPathComponent("key.blob")
        try PrivateFile.createNew(f, contents: Data("blob".utf8))
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: f.path)
        #expect(throws: KeyError.self) { try PrivateFile.read(f) }
    }

    @Test func refusesASymlink() throws {
        let d = try tempDir()
        let f = d.appendingPathComponent("key.blob")
        try PrivateFile.createNew(f, contents: Data("blob".utf8))
        let l = d.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: l, withDestinationURL: f)
        #expect(throws: KeyError.self) { try PrivateFile.read(l) }
    }

    @Test func replaceKeepsOwnerOnlyMode() throws {
        let f = try tempDir().appendingPathComponent("hosts.json")
        try PrivateFile.replace(f, contents: Data("1".utf8))
        try PrivateFile.replace(f, contents: Data("2".utf8))
        #expect(try mode(f) == 0o600)
        #expect(try PrivateFile.read(f) == Data("2".utf8))
    }
}

@Suite struct SecureEnclaveSignerTests {
    @Test func accessControlIsBiometryOnly() {
        let flags = SecureEnclaveSigner.accessControlFlags
        #expect(flags.contains(.privateKeyUsage))
        #expect(flags.contains(.biometryCurrentSet))
        #expect(!flags.contains(.userPresence))
        #expect(!flags.contains(.devicePasscode))
        #expect(!flags.contains(.biometryAny))
        #expect(!flags.contains(.watch))
    }

    @Test func classifiesAuthenticationErrors() {
        func la(_ c: LAError.Code) -> Error { NSError(domain: LAErrorDomain, code: c.rawValue) }
        #expect(SigningError.classify(la(.userCancel)) == .cancelled)
        #expect(SigningError.classify(la(.systemCancel)) == .cancelled)
        #expect(SigningError.classify(la(.userFallback)) == .cancelled)
        #expect(SigningError.classify(la(.appCancel)) == .timedOut)
        #expect(SigningError.classify(la(.authenticationFailed)) == .biometryFailed)
        #expect(SigningError.classify(la(.biometryLockout)) == .biometryFailed)
        #expect(SigningError.classify(la(.biometryNotEnrolled)) == .biometryFailed)
        #expect(SigningError.classify(la(.biometryNotAvailable)) == .biometryFailed)
        #expect(SigningError.classify(la(.notInteractive)) == .notInteractive)
        #expect(SigningError.classify(NSError(domain: NSOSStatusErrorDomain, code: Int(errSecItemNotFound))) == .keyUnusable)
        #expect(SigningError.classify(SigningError.timedOut) == .timedOut)
    }

    @Test func refusesAMissingOrForeignBlob() throws {
        let d = try tempDir()
        #expect(throws: (any Error).self) { try SecureEnclaveSigner(contentsOf: d.appendingPathComponent("none")) }
        let f = d.appendingPathComponent("key.blob")
        try PrivateFile.createNew(f, contents: Data("not a secure enclave blob".utf8))
        #expect(throws: (any Error).self) { try SecureEnclaveSigner(contentsOf: f) }
    }

    /// Creates a real Secure Enclave key (no Touch ID prompt: creation needs
    /// none). Opt-in, since CI runners have no Secure Enclave:
    /// TMB_SIGNER_SE_TEST=1 Scripts/test.sh
    @Test(.enabled(if: ProcessInfo.processInfo.environment["TMB_SIGNER_SE_TEST"] == "1"))
    func createsAndReloadsASecureEnclaveKey() throws {
        let f = try tempDir().appendingPathComponent("key.blob")
        let s = try SecureEnclaveSigner.create(at: f)
        #expect(try mode(f) == 0o600)
        let again = try SecureEnclaveSigner(contentsOf: f)
        #expect(try again.publicKeySPKI() == s.publicKeySPKI())
        _ = try ApproverKeyEntry(name: "se-test", publicKeySPKI: s.publicKeySPKI())
    }
}
