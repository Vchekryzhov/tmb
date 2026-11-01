import Foundation

/// Runs `body` while every worker thread the global dispatch queue can get
/// (GCD stops adding threads at 64) is parked on a semaphore: work that
/// needs `DispatchQueue.global()` to make progress stalls until `body`
/// returns, as it does on a loaded CI runner.
func withSaturatedGlobalQueue<T>(_ body: () throws -> T) rethrows -> T {
    let release = DispatchSemaphore(value: 0)
    let started = DispatchSemaphore(value: 0)
    let n = 96
    for _ in 0..<n {
        DispatchQueue.global().async {
            started.signal()
            release.wait()
        }
    }
    // let the pool fill up (it cannot run all 96 at once)
    for _ in 0..<min(n, ProcessInfo.processInfo.activeProcessorCount) { started.wait() }
    Thread.sleep(forTimeInterval: 0.2)
    defer { for _ in 0..<n { release.signal() } }
    return try body()
}
