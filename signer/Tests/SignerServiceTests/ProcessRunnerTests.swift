import Foundation
import Testing
@testable import SignerService

/// The production runner on local programs (no SSH).
@Suite struct ProcessRunnerTests {
    @Test func stdinReachesTheChildAndBothStreamsComeBack() throws {
        let r = try ProcessRunner().run("/bin/sh", ["-c", "cat; echo err >&2; exit 3"], stdin: Data("hello\n".utf8))
        #expect(r.status == 3)
        #expect(String(decoding: r.stdout, as: UTF8.self) == "hello\n")
        #expect(String(decoding: r.stderr, as: UTF8.self) == "err\n")
    }

    @Test func noStdinIsEndOfFile() throws {
        let r = try ProcessRunner().run("/bin/cat", [], stdin: nil)
        #expect(r.status == 0 && r.stdout.isEmpty)
    }

    @Test func aHungChildIsKilledAtTheTimeout() {
        let start = Date()
        #expect(throws: CommandError.timedOut) { try ProcessRunner(timeout: 0.3).run("/bin/sleep", ["10"], stdin: nil) }
        #expect(Date().timeIntervalSince(start) < 5)
    }

    @Test func oversizedOutputFails() {
        #expect(throws: CommandError.failed("output larger than 1000 bytes")) {
            try ProcessRunner(maxOutput: 1000).run("/bin/sh", ["-c", "head -c 5000 /dev/zero"], stdin: nil)
        }
    }

    @Test func aMissingProgramFails() {
        #expect(throws: CommandError.self) { try ProcessRunner().run("/nonexistent/ssh", [], stdin: nil) }
    }
}
