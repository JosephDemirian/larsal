import AppKit
import LarsalCore
import Testing

/// LD-206: a test proves it left the owner's clipboard alone from Larsal's own
/// record (Rust names every pasteboard it writes or clears), not from the
/// general pasteboard. No test reads it (AGENTS.md rule 10).
@MainActor
enum PasteboardProof {
    /// Every pasteboard Rust wrote is private to this process, and the
    /// session's own is among them when the test copied.
    static func expectOnlyPrivate(
        _ session: Session, copied: Bool = true, sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let written = pasteboardsWritten()
        let prefix = "app.larsal.clipboard.\(getpid())."
        #expect(written.allSatisfy { $0.hasPrefix(prefix) }, "\(written)", sourceLocation: sourceLocation)
        let mine = session.pasteboardName()
        #expect(mine?.hasPrefix(prefix) == true, "a private pasteboard", sourceLocation: sourceLocation)
        if copied, let mine {
            #expect(written.contains(mine), "\(written)", sourceLocation: sourceLocation)
        }
    }
}
