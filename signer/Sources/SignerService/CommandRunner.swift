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

/// The production runner: a child process with its own pipes, killed when
/// it outlives `timeout`. Output past `maxOutput` bytes per stream is cut
/// off and the run fails, so a misbehaving host cannot fill memory.
public struct ProcessRunner: CommandRunner {
    public let timeout: TimeInterval
    public let maxOutput: Int

    public init(timeout: TimeInterval = 30, maxOutput: Int = 16 << 20) {
        self.timeout = timeout
        self.maxOutput = maxOutput
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

        let so = Sink(limit: maxOutput), se = Sink(limit: maxOutput)
        let readers = DispatchGroup()
        for (sink, pipe) in [(so, out), (se, err)] {
            DispatchQueue.global().async(group: readers) { sink.drain(pipe.fileHandleForReading) }
        }
        if let stdin {
            let h = inp.fileHandleForWriting
            DispatchQueue.global().async {
                try? h.write(contentsOf: stdin)
                try? h.close()
            }
        }
        if done.wait(timeout: .now() + timeout) == .timedOut {
            p.terminate()
            if done.wait(timeout: .now() + 2) == .timedOut { kill(p.processIdentifier, SIGKILL); done.wait() }
            readers.wait()
            throw CommandError.timedOut
        }
        readers.wait()
        if so.overflow || se.overflow { throw CommandError.failed("output larger than \(maxOutput) bytes") }
        return CommandResult(status: p.terminationStatus, stdout: so.value, stderr: se.value)
    }
}
