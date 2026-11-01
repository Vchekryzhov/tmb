import Foundation

public struct ConfigError: Error, Equatable, CustomStringConvertible {
    public let description: String
    init(_ s: String) { description = s }
}

/// The Mac-side config (`config.json` in the support directory): the hosts
/// to poll, the active key and the timers. Unknown keys are refused so a
/// typo does not silently fall back to a default.
public struct SignerConfig: Equatable, Sendable, Decodable {
    public let version: Int
    /// Name of the key in `keys/` that signs; nil means the only key there.
    public let key: String?
    public let pollSeconds: Int
    /// How long the window waits for an answer before it denies.
    public let windowTimeoutSeconds: Int
    /// How long the Touch ID sheet waits before it is cancelled (a deny).
    public let sheetTimeoutSeconds: Int
    public let hosts: [HostEndpoint]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, key, hosts
        case pollSeconds = "poll_seconds"
        case windowTimeoutSeconds = "window_timeout_seconds"
        case sheetTimeoutSeconds = "sheet_timeout_seconds"
    }

    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        key = try c.decodeIfPresent(String.self, forKey: .key)
        pollSeconds = try c.decodeIfPresent(Int.self, forKey: .pollSeconds) ?? 5
        windowTimeoutSeconds = try c.decodeIfPresent(Int.self, forKey: .windowTimeoutSeconds) ?? 120
        sheetTimeoutSeconds = try c.decodeIfPresent(Int.self, forKey: .sheetTimeoutSeconds) ?? 30
        hosts = try c.decode([HostEndpoint].self, forKey: .hosts)
    }

    static let hostKeys: Set<String> = ["name", "ssh", "port", "tmb", "socket", "host_id"]

    public static func parse(_ data: Data) throws -> SignerConfig {
        guard let top = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ConfigError("config is not a JSON object")
        }
        let known = Set(CodingKeys.allCases.map(\.rawValue))
        if let k = top.keys.sorted().first(where: { !known.contains($0) }) { throw ConfigError("unknown config key \"\(k)\"") }
        for case let h as [String: Any] in top["hosts"] as? [Any] ?? [] {
            if let k = h.keys.sorted().first(where: { !hostKeys.contains($0) }) { throw ConfigError("unknown host key \"\(k)\"") }
        }
        let c: SignerConfig
        do { c = try JSONDecoder().decode(SignerConfig.self, from: data) } catch {
            throw ConfigError("config: \(error)")
        }
        guard c.version == 1 else { throw ConfigError("unknown config version \(c.version)") }
        if let k = c.key, !SignerPaths.validKeyName(k) { throw ConfigError("bad key name \"\(k)\"") }
        guard (1...3600).contains(c.pollSeconds) else { throw ConfigError("poll_seconds must be 1..3600") }
        guard (10...3600).contains(c.windowTimeoutSeconds) else { throw ConfigError("window_timeout_seconds must be 10..3600") }
        guard (1...600).contains(c.sheetTimeoutSeconds) else { throw ConfigError("sheet_timeout_seconds must be 1..600") }
        var names = Set<String>()
        for h in c.hosts {
            guard !h.name.isEmpty else { throw ConfigError("host with an empty name") }
            guard names.insert(h.name).inserted else { throw ConfigError("duplicate host name \"\(h.name)\"") }
        }
        return c
    }
}

/// Where the signer keeps its files, by default
/// `~/Library/Application Support/TMB Signer/`: `config.json`, `pins.json`
/// (HostTrust) and `keys/<name>.key` (Secure Enclave key blobs, 0600).
public struct SignerPaths: Sendable {
    public let root: URL
    public init(root: URL) { self.root = root }

    public static var standard: SignerPaths {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return SignerPaths(root: base.appendingPathComponent("TMB Signer", isDirectory: true))
    }

    public var config: URL { root.appendingPathComponent("config.json") }
    public var pins: URL { root.appendingPathComponent("pins.json") }
    public var keys: URL { root.appendingPathComponent("keys", isDirectory: true) }

    public func key(_ name: String) throws -> URL {
        guard Self.validKeyName(name) else { throw ConfigError("bad key name \"\(name)\"") }
        return keys.appendingPathComponent(name + ".key")
    }

    /// Names of the key files present, sorted.
    public func keyNames() throws -> [String] {
        guard FileManager.default.fileExists(atPath: keys.path) else { return [] }
        return try FileManager.default.contentsOfDirectory(atPath: keys.path)
            .filter { $0.hasSuffix(".key") }
            .map { String($0.dropLast(4)) }
            .filter(Self.validKeyName)
            .sorted()
    }

    /// Letters, digits, '.', '_', '-'; not starting with '.'; at most 64.
    public static func validKeyName(_ s: String) -> Bool {
        guard !s.isEmpty, s.utf8.count <= 64, !s.hasPrefix(".") else { return false }
        return s.unicodeScalars.allSatisfy { c in
            (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || c == "." || c == "_" || c == "-"
        }
    }
}
