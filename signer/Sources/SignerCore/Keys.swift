import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

/// What the Touch ID sheet says (`LAContext.localizedReason`): the short
/// code and the host, so the sheet and the window can be matched by eye.
public struct SigningPrompt: Equatable, Sendable {
    public let reason: String
    public init(reason: String) { self.reason = reason }
}

/// Why a signature was not made. Each one ends in an unsigned deny.
public enum SigningError: Error, Equatable, Sendable {
    case cancelled
    case timedOut
    case biometryFailed
    case keyUnusable
    case notInteractive
    case failed(String)

    /// Maps LocalAuthentication and key errors to the deny reasons of
    /// ADR 0006 В7. `appCancel` is the app cancelling the sheet on its own
    /// timer, so it counts as a timeout. Anything that is not an
    /// authentication outcome (CryptoKit, Security, a blob made unusable by
    /// a changed fingerprint set) means the key cannot be used.
    public static func classify(_ error: Error) -> SigningError {
        if let e = error as? SigningError { return e }
        let ns = error as NSError
        guard ns.domain == LAErrorDomain, let code = LAError.Code(rawValue: ns.code) else { return .keyUnusable }
        switch code {
        case .userCancel, .systemCancel, .userFallback: return .cancelled
        case .appCancel: return .timedOut
        case .notInteractive: return .notInteractive
        case .authenticationFailed, .biometryLockout, .biometryNotAvailable, .biometryNotEnrolled,
             .passcodeNotSet, .biometryDisconnected, .biometryNotPaired, .companionNotAvailable:
            return .biometryFailed
        default: return .failed("LAError \(ns.code)")
        }
    }
}

/// The signing seam (spec seam 5): production uses a Secure Enclave key,
/// tests a software P-256 key. One call is one human authentication and
/// one signature; an implementation never caches an authenticated context.
public protocol PayloadSigner: Sendable {
    /// DER SubjectPublicKeyInfo of the P-256 public key.
    func publicKeySPKI() throws -> Data
    /// DER ECDSA P-256 signature over SHA-256 of `payload`, exactly these
    /// bytes. Throws a `SigningError` (or anything `classify` maps).
    func sign(_ payload: Data, prompt: SigningPrompt) throws -> Data
}

public enum KeyError: Error, Equatable, CustomStringConvertible {
    case badName
    case badPublicKey
    case secureEnclaveUnavailable
    case accessControl(String)
    case file(String)

    public var description: String {
        switch self {
        case .badName: return "key name must be non-empty printable ASCII"
        case .badPublicKey: return "public key is not a DER SPKI of a P-256 key"
        case .secureEnclaveUnavailable: return "no Secure Enclave on this Mac"
        case .accessControl(let s): return "access control: " + s
        case .file(let s): return s
        }
    }
}

/// An `approver_keys` entry (ADR 0007 Р1) for the broker config:
/// `{"name":..,"class":"mac-se","public_key":<base64 DER SPKI>}`. The
/// person copies it to the host by hand (ADR 0006 В11).
public struct ApproverKeyEntry: Equatable, Sendable {
    public static let macSE = "mac-se"
    public let name: String
    public let keyClass: String
    public let publicKey: String
    /// proto.KeyFingerprint of the key: what `decide` sends as approver_key.
    public let fingerprint: String

    public init(name: String, publicKeySPKI: Data, keyClass: String = ApproverKeyEntry.macSE) throws {
        guard !name.isEmpty, name.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value < 0x7F }) else {
            throw KeyError.badName
        }
        guard (try? P256.Signing.PublicKey(derRepresentation: publicKeySPKI)) != nil else { throw KeyError.badPublicKey }
        self.name = name
        self.keyClass = keyClass
        publicKey = publicKeySPKI.base64EncodedString()
        fingerprint = SignatureCheck.fingerprint(publicKeySPKI: publicKeySPKI)
    }

    /// One JSON object, keys in the documented order, '/' not escaped.
    public var json: String {
        func q(_ s: String) -> String {
            let e = JSONEncoder()
            e.outputFormatting = [.withoutEscapingSlashes]
            return String(decoding: try! e.encode(s), as: UTF8.self)
        }
        return "{\"name\":\(q(name)),\"class\":\(q(keyClass)),\"public_key\":\(q(publicKey))}"
    }
}

/// Owner-only files for the key blob and the host store: created 0600,
/// read only when they are regular files of this user that nobody else
/// can read or write, never through a symlink.
public enum PrivateFile {
    /// Creates `url` with `contents`; refuses when it already exists.
    public static func createNew(_ url: URL, contents: Data) throws {
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw KeyError.file("cannot create \(url.path): \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        try writeAll(fd, contents, url)
    }

    /// Replaces `url` atomically (temporary file in the same directory, then
    /// rename), so a crash leaves the old or the new contents.
    public static func replace(_ url: URL, contents: Data) throws {
        let tmp = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
        try createNew(tmp, contents: contents)
        guard rename(tmp.path, url.path) == 0 else {
            let msg = String(cString: strerror(errno))
            unlink(tmp.path)
            throw KeyError.file("cannot replace \(url.path): \(msg)")
        }
    }

    public static func read(_ url: URL) throws -> Data {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw KeyError.file("cannot open \(url.path): \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0 else { throw KeyError.file("cannot stat \(url.path)") }
        guard st.st_mode & S_IFMT == S_IFREG else { throw KeyError.file("\(url.path) is not a regular file") }
        guard st.st_uid == geteuid() else { throw KeyError.file("\(url.path) belongs to another user") }
        guard st.st_mode & 0o077 == 0 else { throw KeyError.file("\(url.path) is accessible to group or others") }
        var out = Data()
        var buf = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let n = Darwin.read(fd, &buf, buf.count)
            if n < 0 { throw KeyError.file("cannot read \(url.path)") }
            if n == 0 { return out }
            out.append(contentsOf: buf[..<n])
        }
    }

    private static func writeAll(_ fd: Int32, _ data: Data, _ url: URL) throws {
        guard fchmod(fd, 0o600) == 0 else { throw KeyError.file("cannot chmod \(url.path)") }
        try data.withUnsafeBytes { (p: UnsafeRawBufferPointer) in
            var off = 0
            while off < p.count {
                let n = write(fd, p.baseAddress! + off, p.count - off)
                guard n > 0 else { throw KeyError.file("cannot write \(url.path)") }
                off += n
            }
        }
        guard fsync(fd) == 0 else { throw KeyError.file("cannot sync \(url.path)") }
    }
}

/// The production signer: a Secure Enclave P-256 key created with
/// `privateKeyUsage` and `biometryCurrentSet` (ADR 0006 В2, В5), kept as its
/// `dataRepresentation` blob in an owner-only file. Every `sign` builds a
/// fresh `LAContext`, signs once and invalidates the context, so one touch
/// gives one signature. A changed fingerprint set makes the key unusable.
///
/// The menu bar app (#110) runs `SecCodeCheckValidity` and the GUI-session
/// check before calling `sign` (via `SignerCore.preSignCheck`).
public final class SecureEnclaveSigner: PayloadSigner {
    public static let accessControlFlags: SecAccessControlCreateFlags = [.privateKeyUsage, .biometryCurrentSet]

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    private let blob: Data
    private let spki: Data

    /// Creates a new key and writes its blob to `url` (refusing to overwrite).
    /// Creation does not prompt; the first signature does.
    public static func create(at url: URL) throws -> SecureEnclaveSigner {
        guard isAvailable else { throw KeyError.secureEnclaveUnavailable }
        var err: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, accessControlFlags, &err)
        else {
            throw KeyError.accessControl(err.map { String(describing: $0.takeRetainedValue()) } ?? "unknown")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        try PrivateFile.createNew(url, contents: key.dataRepresentation)
        return SecureEnclaveSigner(blob: key.dataRepresentation, spki: key.publicKey.derRepresentation)
    }

    /// Loads the key blob from an owner-only file. Reading the public key
    /// needs no authentication.
    public convenience init(contentsOf url: URL) throws {
        let blob = try PrivateFile.read(url)
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        self.init(blob: blob, spki: key.publicKey.derRepresentation)
    }

    private init(blob: Data, spki: Data) {
        self.blob = blob
        self.spki = spki
    }

    public func publicKeySPKI() throws -> Data { spki }

    public func sign(_ payload: Data, prompt: SigningPrompt) throws -> Data {
        let context = LAContext()
        context.localizedReason = prompt.reason
        context.interactionNotAllowed = false
        defer { context.invalidate() }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
            return try key.signature(for: payload).derRepresentation
        } catch {
            throw SigningError.classify(error)
        }
    }
}
