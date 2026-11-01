import Foundation
import SignerCore

/// The signer's keys: Secure Enclave blobs in `keys/<name>.key`. Several
/// keys may exist (a spare against loss); the config names the one that
/// signs, or the only one present signs.
public struct KeyStore: Sendable {
    public let paths: SignerPaths
    public init(paths: SignerPaths) { self.paths = paths }

    public func activeName(configured: String?) throws -> String {
        let names = try paths.keyNames()
        if let c = configured {
            guard names.contains(c) else { throw ConfigError("configured key \"\(c)\" is not in \(paths.keys.path)") }
            return c
        }
        switch names.count {
        case 0: throw ConfigError("no key yet: create one from the menu")
        case 1: return names[0]
        default: throw ConfigError("several keys (\(names.joined(separator: ", "))): set \"key\" in \(paths.config.path)")
        }
    }

    public func signer(_ name: String, sheetTimeout: TimeInterval?) throws -> SecureEnclaveSigner {
        try SecureEnclaveSigner(contentsOf: paths.key(name), sheetTimeout: sheetTimeout)
    }

    /// The approver_keys entry for the broker config (reading the public
    /// key does not prompt).
    public func entry(_ name: String) throws -> ApproverKeyEntry {
        try ApproverKeyEntry(name: name, publicKeySPKI: signer(name, sheetTimeout: nil).publicKeySPKI())
    }

    /// Creates a new Secure Enclave key (no prompt) and returns its entry.
    public func create(_ name: String) throws -> ApproverKeyEntry {
        let url = try paths.key(name)
        try Self.ensurePrivateDirectory(paths.root)
        try Self.ensurePrivateDirectory(paths.keys)
        let s = try SecureEnclaveSigner.create(at: url)
        return try ApproverKeyEntry(name: name, publicKeySPKI: s.publicKeySPKI())
    }

    /// Creates `url` as a 0700 directory, or checks that the existing one
    /// is a directory nobody else can write to.
    public static func ensurePrivateDirectory(_ url: URL) throws {
        if mkdir(url.path, 0o700) != 0 && errno != EEXIST {
            throw ConfigError("cannot create \(url.path): \(String(cString: strerror(errno)))")
        }
        var st = stat()
        guard lstat(url.path, &st) == 0, st.st_mode & S_IFMT == S_IFDIR else { throw ConfigError("\(url.path) is not a directory") }
        guard st.st_uid == geteuid(), st.st_mode & 0o022 == 0 else {
            throw ConfigError("\(url.path) is writable by others or not owned by this user")
        }
    }
}
