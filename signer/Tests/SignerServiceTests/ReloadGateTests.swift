import Testing
@testable import SignerService

/// The app replaces its workflow (and the core that reviewed the items) on
/// Reload Config and after Create Key. While a window is open or items
/// wait for one, the reload is held back: every shown item is answered by
/// the core that reviewed it, none is orphaned or shown twice.
@Suite struct ReloadGateTests {
    @Test func anIdleAppReloadsAtOnce() {
        var g = ReloadGate()
        let now = g.request(busy: false)
        let later = g.becameIdle()
        #expect(now && !later && !g.pending)
    }

    @Test func aBusyAppReloadsOnceItIsIdle() {
        var g = ReloadGate()
        let first = g.request(busy: true)
        let second = g.request(busy: true) // asked twice: still one reload
        #expect(!first && !second && g.pending)
        let idle = g.becameIdle()
        let again = g.becameIdle()
        #expect(idle && !again && !g.pending)
    }

    @Test func anExplicitIdleReloadClearsAHeldOne() {
        var g = ReloadGate()
        _ = g.request(busy: true)
        let now = g.request(busy: false)
        let later = g.becameIdle()
        #expect(now && !later)
    }
}
