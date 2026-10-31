import Foundation

/// A pinned host: `host_id` from the broker config and `host_key`, the
/// fingerprint of the broker identity key (ADR 0007 Р6).
public struct PinnedHost: Equatable, Sendable, Codable {
    public let hostID: String
    public let hostKey: String

    enum CodingKeys: String, CodingKey {
        case hostID = "host_id"
        case hostKey = "host_key"
    }
}

/// Where pins live. The file storage is the production one; the memory
/// storage serves tests and previews.
public protocol HostStorage: Sendable {
    func load() throws -> [PinnedHost]
    func save(_ hosts: [PinnedHost]) throws
}

/// The pins as an owner-only JSON file `{"version":1,"hosts":[...]}`,
/// replaced atomically. A missing file is an empty store; a file others can
/// read or write, or one that does not parse, is an error (and so a deny).
public struct FileHostStorage: HostStorage {
    public let url: URL
    public init(url: URL) { self.url = url }

    struct File: Codable {
        let version: Int
        let hosts: [PinnedHost]
    }

    public func load() throws -> [PinnedHost] {
        var st = stat()
        if lstat(url.path, &st) != 0 && errno == ENOENT { return [] }
        let f = try JSONDecoder().decode(File.self, from: PrivateFile.read(url))
        guard f.version == 1 else { throw KeyError.file("\(url.path): unknown version \(f.version)") }
        return f.hosts
    }

    public func save(_ hosts: [PinnedHost]) throws {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try PrivateFile.replace(url, contents: e.encode(File(version: 1, hosts: hosts)))
    }
}

public final class MemoryHostStorage: HostStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var hosts: [PinnedHost] = []
    public init() {}
    public func load() throws -> [PinnedHost] { lock.withLock { hosts } }
    public func save(_ h: [PinnedHost]) throws { lock.withLock { hosts = h } }
}

public enum HostCheck: Equatable, Sendable {
    /// The host is pinned with this key.
    case pinned
    /// The host id has no pin yet.
    case firstUse
    /// The host id is pinned with another key: deny and warn.
    case mismatch(pinned: String)
}

/// TOFU for hosts, like SSH known_hosts (ADR 0006 В10): the first key seen
/// for a host id is pinned; a different key later is a mismatch, and the
/// pin is never updated silently. Only `forget`, an explicit action of the
/// person, removes a pin. Host ids and keys compare by UTF-8 bytes.
public final class HostTrust: Sendable {
    private let storage: any HostStorage
    private let lock = NSLock()

    public init(storage: any HostStorage) { self.storage = storage }

    public func check(hostID: String, hostKey: String) throws -> HostCheck {
        try lock.withLock { Self.verdict(try storage.load(), hostID, hostKey) }
    }

    /// Pins the key when the host id is new; otherwise only checks.
    public func pinIfNew(hostID: String, hostKey: String) throws -> HostCheck {
        try lock.withLock {
            var hosts = try storage.load()
            let v = Self.verdict(hosts, hostID, hostKey)
            if v == .firstUse {
                hosts.append(PinnedHost(hostID: hostID, hostKey: hostKey))
                try storage.save(hosts)
            }
            return v
        }
    }

    public func forget(hostID: String) throws {
        try lock.withLock {
            let id = Array(hostID.utf8)
            try storage.save(try storage.load().filter { Array($0.hostID.utf8) != id })
        }
    }

    public func pins() throws -> [PinnedHost] { try lock.withLock { try storage.load() } }

    private static func verdict(_ hosts: [PinnedHost], _ hostID: String, _ hostKey: String) -> HostCheck {
        let id = Array(hostID.utf8)
        guard let pin = hosts.first(where: { Array($0.hostID.utf8) == id }) else { return .firstUse }
        return Array(pin.hostKey.utf8) == Array(hostKey.utf8) ? .pinned : .mismatch(pinned: pin.hostKey)
    }
}
