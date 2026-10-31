import CryptoKit
import Foundation

/// Verification as the broker does it (proto.VerifyPayloadSignature): DER
/// ECDSA P-256 over SHA-256 of the whole payload.
public enum SignatureCheck {
    /// Throws only when the public key is not a DER SPKI of a P-256 key; a
    /// malformed or wrong signature is `false`.
    public static func verify(publicKeySPKI: Data, payload: Data, signatureDER: Data) throws -> Bool {
        let key = try P256.Signing.PublicKey(derRepresentation: publicKeySPKI)
        guard let sig = try? P256.Signing.ECDSASignature(derRepresentation: signatureDER) else { return false }
        return key.isValidSignature(sig, for: payload)
    }

    /// The identity of a public key: lowercase hex SHA-256 of its DER SPKI,
    /// the form of proto.KeyFingerprint (ADR 0005), used for `approver_key`.
    public static func fingerprint(publicKeySPKI: Data) -> String {
        Data(SHA256.hash(data: publicKeySPKI)).hexString
    }
}
