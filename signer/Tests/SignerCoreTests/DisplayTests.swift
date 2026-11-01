import Foundation
import Testing
@testable import SignerCore

@Suite struct DisplayTests {
    func tricky() throws -> (Data, ApprovalPayload) {
        let raw = b64(try Vectors.load().valid[1].payload)
        return (raw, try ApprovalPayload.parse(raw))
    }

    @Test func argvIsOneLinePerArgumentWithIndexLengthAndEscapes() throws {
        let (raw, p) = try tricky()
        let d = try ApprovalDisplay(payload: p, raw: raw)
        #expect(d.argv.map(\.line) == [
            #"argv[0] 0 bytes """#,
            #"argv[1] 23 bytes "quote \" and \\ backslash""#,
            #"argv[2] 16 bytes "nl\ncr\rtab\tbs\u{0008}ff\u{000C}"  [escaped: control]"#,
            #"argv[3] 10 bytes "ctl\u{0001}\u{001F} del\u{007F}"  [escaped: control]"#,
            #"argv[4] 11 bytes "<html>&amp;""#,
            #"argv[5] 14 bytes "\u{00E9} \u{65E5}\u{672C} \u{1F600}"  [escaped: non-ASCII]"#,
            #"argv[6] 11 bytes "bidi\u{202E}evil"  [escaped: bidi]"#,
            #"argv[7] 12 bytes "zero\u{200B}width"  [escaped: zero-width]"#,
            #"argv[8] 8 bytes "ls\u{2028}\u{2029}"  [escaped: control]"#,
            #"argv[9] 10 bytes "--flag=a b""#,
        ])
    }

    @Test func everyShownCharacterIsPrintableASCII() throws {
        let (raw, p) = try tricky()
        let d = try ApprovalDisplay(payload: p, raw: raw)
        let all = d.argv.map(\.line) + d.env.map(\.line) + d.fields.map(\.line)
        for line in all {
            #expect(line.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value < 0x7F }, "\(line)")
        }
    }

    @Test func fieldsShowEverythingThePayloadBinds() throws {
        let raw = try Vectors.sample()
        let d = try ApprovalDisplay(payload: try ApprovalPayload.parse(raw), raw: raw)
        #expect(d.shortCode == "LVSJ-XUSG")
        #expect(d.fields.map(\.name) == [
            "host_id", "host_key", "item_id", "request_hash", "challenge", "requester",
            "uid", "user", "executable", "exe_dev", "exe_ino", "cwd", "nonce",
            "queued_at", "deadline", "token_ttl_seconds",
        ])
        let byName = Dictionary(uniqueKeysWithValues: d.fields.map { ($0.name, $0.line) })
        #expect(byName["user"] == #"user "root""#)
        #expect(byName["queued_at"] == "queued_at 1793534400000 (2026-11-01T12:00:00.000Z)")
        #expect(d.env.map(\.line) == [#"env[0] 12 bytes "LANG=C.UTF-8""#, #"env[1] 23 bytes "PATH=/usr/sbin:/usr/bin""#])
    }

    @Test func emptyUserAndEmptyArgumentAreVisible() throws {
        let (raw, p) = try tricky()
        let d = try ApprovalDisplay(payload: p, raw: raw)
        #expect(d.fields.first { $0.name == "user" }?.line == #"user """#)
        #expect(d.argv[0].text.shown == "")
    }

    @Test func refusesAFieldLongerThanTheDefaultLimit() throws {
        let long = String(repeating: "a", count: 64 * 1024 + 1)
        let raw = try Vectors.sample(replacing: "\"nginx\"", with: "\"\(long)\"")
        let p = try ApprovalPayload.parse(raw)
        #expect(throws: DisplayError.undisplayable(field: "argv[2]")) { try ApprovalDisplay(payload: p, raw: raw) }
    }

    @Test func showsALongArgumentWhole() throws {
        let long = String(repeating: "a", count: 64 * 1024)
        let raw = try Vectors.sample(replacing: "\"nginx\"", with: "\"\(long)\"")
        let d = try ApprovalDisplay(payload: try ApprovalPayload.parse(raw), raw: raw)
        #expect(d.argv[2].text.shown == long)
    }

    @Test func refusesTooManyArguments() throws {
        let (raw, p) = try tricky()
        let limits = DisplayLimits(maxShownLength: 1 << 16, maxEntries: 9)
        #expect(throws: DisplayError.undisplayable(field: "argv")) { try ApprovalDisplay(payload: p, raw: raw, limits: limits) }
    }
}
