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

    @Test func aBusyDispatchPoolDoesNotStallTheRun() throws {
        // CI runs suites in parallel on few cores: the global dispatch pool
        // can be full of other work. The runner's own blocking reads and
        // writes must not wait for a pool thread.
        try withSaturatedGlobalQueue {
            let r = try ProcessRunner(drainTimeout: 5).run("/bin/sh", ["-c", "cat; echo err >&2"], stdin: Data("hi\n".utf8))
            #expect(r.status == 0 && r.stdout == Data("hi\n".utf8) && r.stderr == Data("err\n".utf8))
        }
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

    @Test func aDescendantHoldingTheOutputDoesNotHangTheRun() {
        // the child exits at once; the background sleep keeps its stdout open
        let start = Date()
        #expect(throws: CommandError.self) {
            try ProcessRunner(timeout: 5, drainTimeout: 0.3).run("/bin/sh", ["-c", "sleep 10 & exit 0"], stdin: nil)
        }
        #expect(Date().timeIntervalSince(start) < 4)
    }

    @Test func aChildThatIgnoresStdinDoesNotKillTheApp() throws {
        // writing to a pipe nobody reads raises SIGPIPE unless it is ignored
        let r = try ProcessRunner().run("/usr/bin/true", [], stdin: Data(count: 4 << 20))
        #expect(r.status == 0)
    }

    @Test func aMissingProgramFails() {
        #expect(throws: CommandError.self) { try ProcessRunner().run("/nonexistent/ssh", [], stdin: nil) }
    }
}
