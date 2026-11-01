import Foundation
import Testing
@testable import SignerCore

/// A deterministic generator (SplitMix64): the same seed gives the same
/// mutations on every run, so a failure is reproducible.
struct SeededGenerator: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// The strict parser on mutated vector bytes: truncations, byte flips,
/// insertions and deletions never crash or hang it, and whatever it
/// accepts re-encodes to exactly the bytes it was given (no second
/// spelling of a payload reaches the window or the key).
@Suite struct PayloadRobustnessTests {
    @Test func mutatedPayloadsAreRejectedOrCanonical() throws {
        var rng = SeededGenerator(state: 0x746D_625F_7369_676E) // fixed seed
        let interesting: [UInt8] = [0x00, 0x22, 0x5C, 0x7B, 0x7D, 0x5B, 0x5D, 0x2C, 0x3A, 0x30, 0x2D, 0x7F, 0x80, 0xC3, 0xE2, 0xFF]
        let seeds = try Vectors.load().valid.map { b64($0.payload) }
        for seed in seeds {
            for _ in 0..<1500 {
                var b = [UInt8](seed)
                for _ in 0..<Int.random(in: 1...3, using: &rng) {
                    switch Int.random(in: 0..<4, using: &rng) {
                    case 0:
                        b = Array(b.prefix(Int.random(in: 0...b.count, using: &rng)))
                    case 1 where !b.isEmpty:
                        b[Int.random(in: 0..<b.count, using: &rng)] ^= UInt8(1 << Int.random(in: 0..<8, using: &rng))
                    case 2:
                        let v = Bool.random(using: &rng) ? interesting.randomElement(using: &rng)! : UInt8.random(in: 0...255, using: &rng)
                        b.insert(v, at: Int.random(in: 0...b.count, using: &rng))
                    default:
                        if !b.isEmpty { b.remove(at: Int.random(in: 0..<b.count, using: &rng)) }
                    }
                }
                let raw = Data(b)
                guard let p = try? ApprovalPayload.parse(raw) else { continue }
                #expect(try p.encoded() == raw, "accepted a non-canonical mutation of a vector")
            }
        }
        // the unmutated seeds are accepted and canonical
        for seed in seeds { #expect(try ApprovalPayload.parse(seed).encoded() == seed) }
    }
}
