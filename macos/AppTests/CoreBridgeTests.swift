import AppCore
import Testing

/// The Swift–Rust bridge, end to end (E5-S1): the call loads the static
/// library, passes UniFFI's contract and checksum checks, and brings a
/// string back from Rust.
struct CoreBridgeTests {
    @Test func coreVersionCrossesTheBridge() {
        let parts = coreVersion().split(separator: ".", omittingEmptySubsequences: false)
        #expect(parts.count == 3)
        #expect(parts.allSatisfy { !$0.isEmpty && $0.allSatisfy(\.isNumber) })
    }
}
