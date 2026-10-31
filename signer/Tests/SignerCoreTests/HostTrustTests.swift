import Foundation
import Testing
@testable import SignerCore

let keyA = String(repeating: "a", count: 64)
let keyB = String(repeating: "b", count: 64)

@Suite struct HostTrustTests {
    @Test func pinsOnFirstUseAndMatchesAfter() throws {
        let t = HostTrust(storage: MemoryHostStorage())
        #expect(try t.check(hostID: "build-01", hostKey: keyA) == .firstUse)
        #expect(try t.pinIfNew(hostID: "build-01", hostKey: keyA) == .firstUse)
        #expect(try t.check(hostID: "build-01", hostKey: keyA) == .pinned)
        #expect(try t.pinIfNew(hostID: "build-01", hostKey: keyA) == .pinned)
    }

    @Test func aChangedKeyIsAMismatchAndNeverReplacesThePin() throws {
        let t = HostTrust(storage: MemoryHostStorage())
        _ = try t.pinIfNew(hostID: "build-01", hostKey: keyA)
        #expect(try t.check(hostID: "build-01", hostKey: keyB) == .mismatch(pinned: keyA))
        #expect(try t.pinIfNew(hostID: "build-01", hostKey: keyB) == .mismatch(pinned: keyA))
        #expect(try t.check(hostID: "build-01", hostKey: keyA) == .pinned)
    }

    @Test func hostIDsCompareByBytesNotByUnicodeEquivalence() throws {
        let t = HostTrust(storage: MemoryHostStorage())
        _ = try t.pinIfNew(hostID: "caf\u{E9}", hostKey: keyA)
        #expect(try t.check(hostID: "cafe\u{301}", hostKey: keyB) == .firstUse)
    }

    @Test func forgetIsTheOnlyWayToRepin() throws {
        let t = HostTrust(storage: MemoryHostStorage())
        _ = try t.pinIfNew(hostID: "build-01", hostKey: keyA)
        try t.forget(hostID: "build-01")
        #expect(try t.pinIfNew(hostID: "build-01", hostKey: keyB) == .firstUse)
    }

    @Test func fileStoragePersistsOwnerOnly() throws {
        let f = try tempDir().appendingPathComponent("hosts.json")
        let t = HostTrust(storage: FileHostStorage(url: f))
        #expect(try t.check(hostID: "build-01", hostKey: keyA) == .firstUse)
        _ = try t.pinIfNew(hostID: "build-01", hostKey: keyA)
        #expect(try mode(f) == 0o600)
        let again = HostTrust(storage: FileHostStorage(url: f))
        #expect(try again.check(hostID: "build-01", hostKey: keyB) == .mismatch(pinned: keyA))
    }

    @Test func fileStorageRefusesAFileOthersCanWrite() throws {
        let f = try tempDir().appendingPathComponent("hosts.json")
        let t = HostTrust(storage: FileHostStorage(url: f))
        _ = try t.pinIfNew(hostID: "build-01", hostKey: keyA)
        try FileManager.default.setAttributes([.posixPermissions: 0o666], ofItemAtPath: f.path)
        #expect(throws: (any Error).self) { try t.check(hostID: "build-01", hostKey: keyA) }
    }

    @Test func fileStorageRefusesAMalformedFile() throws {
        let f = try tempDir().appendingPathComponent("hosts.json")
        try PrivateFile.createNew(f, contents: Data("{\"hosts\":{}}".utf8))
        #expect(throws: (any Error).self) { try HostTrust(storage: FileHostStorage(url: f)).check(hostID: "x", hostKey: keyA) }
    }
}
