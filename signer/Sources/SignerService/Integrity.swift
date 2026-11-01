import Foundation
import Security
import SignerCore

/// The signer's own code signature (ADR 0007 Р5): checked at start and
/// before each signature. The process must carry a valid signature with
/// the hardened runtime flag and none of the entitlements that let another
/// process of this user attach or inject code. This stops careless bundle
/// tampering, not root.
public enum CodeIntegrity {
    /// The same list as signer/Scripts/check-entitlements.sh (a test keeps
    /// them equal).
    public static let forbiddenEntitlements = [
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.debugger",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.allow-jit",
    ]

    /// kSecCodeSignatureRuntime from <Security/CSCommon.h>.
    static let runtimeFlag: UInt32 = 0x10000

    static func evaluate(validity: OSStatus, flags: UInt32, entitlements: [String: Any]?) -> SigningError? {
        guard validity == errSecSuccess else {
            return .failed("own code signature does not verify (OSStatus \(validity))")
        }
        guard flags & runtimeFlag != 0 else { return .failed("own code signature has no hardened runtime flag") }
        for k in forbiddenEntitlements where (entitlements?[k] as? Bool) == true {
            return .failed("own code signature carries \(k)")
        }
        return nil
    }

    /// `SecCodeCheckValidity` on the running process, then the flags and
    /// entitlements of its signature.
    public static func checkSelf() -> SigningError? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
            return .failed("cannot get own code object")
        }
        let validity = SecCodeCheckValidity(code, [], nil)
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any]
        else { return evaluate(validity: validity == errSecSuccess ? errSecCSUnsigned : validity, flags: 0, entitlements: nil) }
        let flags = (dict[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        return evaluate(validity: validity, flags: flags, entitlements: dict[kSecCodeInfoEntitlementsDict as String] as? [String: Any])
    }
}

/// Signing only from the person's local graphic login session: a process
/// started over SSH (or in a session without the window server) refuses.
public enum GUISession {
    static func evaluate(status: OSStatus, attributes: SessionAttributeBits) -> SigningError? {
        guard status == errSecSuccess, attributes.contains(.sessionHasGraphicAccess),
              !attributes.contains(.sessionIsRemote)
        else { return .notInteractive }
        return nil
    }

    public static func check() -> SigningError? {
        var id = SecuritySessionId()
        var attrs = SessionAttributeBits()
        let status = SessionGetInfo(SecuritySessionId(bitPattern: -1), &id, &attrs)
        return evaluate(status: status, attributes: attrs)
    }
}

public enum PreSign {
    /// The first failing check wins; all must pass to sign.
    public static func combine(_ checks: [@Sendable () -> SigningError?]) -> @Sendable () -> SigningError? {
        { checks.lazy.compactMap { $0() }.first }
    }

    /// What the app passes as `SignerCore.preSignCheck`.
    public static let live = combine([GUISession.check, CodeIntegrity.checkSelf])
}
