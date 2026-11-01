import CryptoKit
import Foundation
import SignerCore

/// A software P-256 key behind the signing protocol (tests only).
final class SoftwareSigner: PayloadSigner, @unchecked Sendable {
    let key = P256.Signing.PrivateKey()
    private let lock = NSLock()
    var failure: SigningError?
    private(set) var prompts: [SigningPrompt] = []

    init(failure: SigningError? = nil) { self.failure = failure }

    func publicKeySPKI() throws -> Data { key.publicKey.derRepresentation }

    func sign(_ payload: Data, prompt: SigningPrompt) throws -> Data {
        try lock.withLock {
            prompts.append(prompt)
            if let failure { throw failure }
            return try key.signature(for: payload).derRepresentation
        }
    }
}

func tempDir() throws -> URL {
    let u = FileManager.default.temporaryDirectory.appendingPathComponent("tmb-signer-svc-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
    return u
}
