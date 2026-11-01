import Foundation
import Testing
@testable import SignerService

@Suite struct ConfigTests {
    @Test func aFullConfigParses() throws {
        let json = """
        {"version":1,"key":"mac-work","poll_seconds":3,"window_timeout_seconds":90,"sheet_timeout_seconds":20,
         "hosts":[{"name":"build","ssh":"viktor@build-01","port":2222,"tmb":"/usr/local/bin/tmb",
                   "socket":"/run/tmb/approver.sock","host_id":"build-01"},
                  {"name":"ci","ssh":"ci-runner"}]}
        """
        let c = try SignerConfig.parse(Data(json.utf8))
        #expect(c.key == "mac-work")
        #expect(c.pollSeconds == 3 && c.windowTimeoutSeconds == 90 && c.sheetTimeoutSeconds == 20)
        #expect(c.hosts == [
            HostEndpoint(name: "build", ssh: "viktor@build-01", port: 2222, tmb: "/usr/local/bin/tmb",
                         socket: "/run/tmb/approver.sock", hostID: "build-01"),
            HostEndpoint(name: "ci", ssh: "ci-runner"),
        ])
    }

    @Test func omittedValuesTakeDefaults() throws {
        let c = try SignerConfig.parse(Data(#"{"version":1,"hosts":[]}"#.utf8))
        #expect(c.key == nil)
        #expect(c.pollSeconds == 5 && c.windowTimeoutSeconds == 120 && c.sheetTimeoutSeconds == 30)
    }

    @Test func badConfigsAreRefused() {
        for bad in [
            #"{"version":2,"hosts":[]}"#,
            #"{"hosts":[]}"#,
            #"{"version":1}"#,
            #"{"version":1,"hosts":[{"name":"a","ssh":"x"},{"name":"a","ssh":"y"}]}"#,
            #"{"version":1,"hosts":[{"name":"","ssh":"x"}]}"#,
            #"{"version":1,"hosts":[],"poll_seconds":0}"#,
            #"{"version":1,"hosts":[],"window_timeout_seconds":5}"#,
            #"{"version":1,"hosts":[],"sheet_timeout_seconds":0}"#,
            #"{"version":1,"hosts":[],"key":"../x"}"#,
            #"{"version":1,"hosts":[],"polls_seconds":3}"#,
            #"{"version":1,"hosts":[{"name":"a","ssh":"x","sock":"/s"}]}"#,
            "not json",
        ] {
            #expect(throws: ConfigError.self, "\(bad)") { try SignerConfig.parse(Data(bad.utf8)) }
        }
    }

    @Test func keyNamesAreSafeFileNames() {
        for ok in ["mac-work", "a", "Key_2.old"] { #expect(SignerPaths.validKeyName(ok), "\(ok)") }
        for bad in ["", ".hidden", "a/b", "..", "a b", "ключ", String(repeating: "a", count: 65)] {
            #expect(!SignerPaths.validKeyName(bad), "\(bad)")
        }
    }

    @Test func pathsLiveUnderTheSupportDirectory() throws {
        let p = SignerPaths(root: URL(fileURLWithPath: "/tmp/tmb-signer"))
        #expect(p.config.path == "/tmp/tmb-signer/config.json")
        #expect(p.pins.path == "/tmp/tmb-signer/pins.json")
        #expect(try p.key("mac-work").path == "/tmp/tmb-signer/keys/mac-work.key")
        #expect(throws: ConfigError.self) { try p.key("../x") }
    }

    @Test func keysAreListedByName() throws {
        let d = try tempDir()
        let p = SignerPaths(root: d)
        #expect(try p.keyNames() == [])
        try FileManager.default.createDirectory(at: p.keys, withIntermediateDirectories: true)
        for n in ["b.key", "a.key", "notes.txt", ".x.key"] { FileManager.default.createFile(atPath: p.keys.appendingPathComponent(n).path, contents: Data()) }
        #expect(try p.keyNames() == ["a", "b"])
    }
}

@Suite struct KeyStoreTests {
    func store(_ names: [String]) throws -> KeyStore {
        let p = SignerPaths(root: try tempDir())
        try KeyStore.ensurePrivateDirectory(p.keys)
        for n in names { FileManager.default.createFile(atPath: p.keys.appendingPathComponent(n + ".key").path, contents: Data()) }
        return KeyStore(paths: p)
    }

    @Test func theOnlyKeySignsWithoutConfig() throws {
        #expect(try store(["mac-work"]).activeName(configured: nil) == "mac-work")
    }

    @Test func theConfiguredKeyMustExist() throws {
        let s = try store(["a", "b"])
        #expect(try s.activeName(configured: "b") == "b")
        #expect(throws: ConfigError.self) { try s.activeName(configured: "c") }
        #expect(throws: ConfigError.self) { try s.activeName(configured: nil) }
        #expect(throws: ConfigError.self) { try store([]).activeName(configured: nil) }
    }

    @Test func theKeyDirectoryIsPrivate() throws {
        let d = try tempDir().appendingPathComponent("k")
        try KeyStore.ensurePrivateDirectory(d)
        let mode = (try FileManager.default.attributesOfItem(atPath: d.path)[.posixPermissions] as! NSNumber).intValue
        #expect(mode == 0o700)
        chmod(d.path, 0o777)
        #expect(throws: ConfigError.self) { try KeyStore.ensurePrivateDirectory(d) }
    }
}
