/// Holds back a reload of the app's workflow while approvals are on screen
/// or waiting for a window. The workflow owns the core that reviewed each
/// shown item and the set of items already open; replacing it under an
/// open window would orphan that item (its answer would find no workflow,
/// or be signed by a core that never reviewed it) and let the next poll
/// show waiting items a second time.
public struct ReloadGate: Sendable {
    public private(set) var pending = false

    public init() {}

    /// A reload was asked for. True: reload now. False: the app is busy,
    /// the reload runs when it becomes idle.
    public mutating func request(busy: Bool) -> Bool {
        pending = busy
        return !busy
    }

    /// The last window was answered and nothing waits. True: run the held
    /// reload now.
    public mutating func becameIdle() -> Bool {
        defer { pending = false }
        return pending
    }
}
