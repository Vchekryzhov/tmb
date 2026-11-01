import Foundation

public struct CommandResult: Equatable, Sendable {
    public let status: Int32
    public let stdout: Data
    public let stderr: Data
    public init(status: Int32, stdout: Data, stderr: Data) {
        self.status = status
        self.stdout = stdout
        self.stderr = stderr
    }
}

public enum CommandError: Error, Equatable {
    case timedOut
    case failed(String)
}

/// Runs one program with arguments (no shell) and optional stdin.
public protocol CommandRunner: Sendable {
    func run(_ executable: String, _ arguments: [String], stdin: Data?) throws -> CommandResult
}

/// Ignores SIGPIPE for the whole process, once: writing stdin to a child
/// that exited (or closed it) must be an EPIPE error, not the end of the app.
public enum BrokenPipe {
    private static let ignored: Void = { signal(SIGPIPE, SIG_IGN) }()
    public static func ignore() { _ = ignored }
}

/// The production runner: a child process with its own pipes, killed when
/// it outlives `timeout`. Output past `maxOutput` bytes per stream is cut
/// off and the run fails, so a misbehaving host cannot fill memory. Once
/// the child is gone its output must close within `drainTimeout`: a
/// descendant that keeps the pipes open (an ssh multiplexer, a background
/// job) fails the run instead of hanging it; the reader threads are left
/// to end when the descendant does.
public struct ProcessRunner: CommandRunner {
    public let timeout: TimeInterval
    public let maxOutput: Int
    public let drainTimeout: TimeInterval

    public init(timeout: TimeInterval = 30, maxOutput: Int = 16 << 20, drainTimeout: TimeInterval = 2) {
        self.timeout = timeout
        self.maxOutput = maxOutput
        self.drainTimeout = drainTimeout
    }

    final class Sink: @unchecked Sendable {
        private let lock = NSLock()
        private var data = Data()
        private(set) var overflow = false
        let limit: Int
        init(limit: Int) { self.limit = limit }
        func drain(_ h: FileHandle) {
            while true {
                let chunk = h.availableData
                if chunk.isEmpty { return }
                lock.withLock {
                    if data.count + chunk.count > limit { overflow = true } else { data.append(chunk) }
                }
            }
        }
        var value: Data { lock.withLock { data } }
    }

    public func run(_ executable: String, _ arguments: [String], stdin: Data?) throws -> CommandResult {
        BrokenPipe.ignore()
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = arguments
        let out = Pipe(), err = Pipe(), inp = Pipe()
        p.standardOutput = out
        p.standardError = err
        p.standardInput = stdin == nil ? FileHandle.nullDevice : inp
        let done = DispatchSemaphore(value: 0)
        p.terminationHandler = { _ in done.signal() }
        do { try p.run() } catch { throw CommandError.failed("cannot start \(executable): \(error.localizedDescription)") }

        // The reads and the stdin write block, so each gets its own thread.
        // On DispatchQueue.global() they waited for a pool thread, and on a
        // loaded machine (parallel tests on a few cores, readers left behind
        // by a descendant) the pool was full: the child never got its stdin
        // and its output was never read before the drain deadline.
        let so = Sink(limit: maxOutput), se = Sink(limit: maxOutput)
        let readers = DispatchGroup()
        for (sink, pipe) in [(so, out), (se, err)] {
            let h = pipe.fileHandleForReading
            readers.enter()
            Thread.detachNewThread {
                sink.drain(h)
                readers.leave()
            }
        }
        if let stdin {
            let h = inp.fileHandleForWriting
            Thread.detachNewThread {
                try? h.write(contentsOf: stdin)
                try? h.close()
            }
        }
        if done.wait(timeout: .now() + timeout) == .timedOut {
            p.terminate()
            if done.wait(timeout: .now() + 2) == .timedOut { kill(p.processIdentifier, SIGKILL); done.wait() }
            _ = readers.wait(timeout: .now() + drainTimeout)
            throw CommandError.timedOut
        }
        if readers.wait(timeout: .now() + drainTimeout) == .timedOut {
            throw CommandError.failed("\(executable) exited but its output stayed open past \(drainTimeout)s")
        }
        if so.overflow || se.overflow { throw CommandError.failed("output larger than \(maxOutput) bytes") }
        return CommandResult(status: p.terminationStatus, stdout: so.value, stderr: se.value)
    }
}
