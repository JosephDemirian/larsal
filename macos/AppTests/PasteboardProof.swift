import AppCore
import AppKit
import OSLog
import Testing

/// LD-206: a test proves it left the owner's clipboard alone from App's own
/// record (Rust names every pasteboard it writes or clears), not from the
/// general pasteboard's change count, which the owner's own copying moves.
/// No test reads the general pasteboard's contents (AGENTS.md rule 10).
@MainActor
enum PasteboardProof {
    /// The general pasteboard's change count, for the logged note only.
    static func count() -> Int { NSPasteboard.general.changeCount }

    /// Every pasteboard Rust wrote in this process is a private one of this
    /// process, and `session`'s own is among them when the test copied. A
    /// change count that moved since `before` is a logged note, not a
    /// failure (another program copied meanwhile).
    static func expectOnlyPrivate(
        _ session: Session, copied: Bool = true, before: Int, sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let written = pasteboardsWritten()
        let prefix = "com.app.clipboard.\(getpid())."
        #expect(written.allSatisfy { $0.hasPrefix(prefix) }, "\(written)", sourceLocation: sourceLocation)
        let mine = session.pasteboardName()
        #expect(mine?.hasPrefix(prefix) == true, "a private pasteboard", sourceLocation: sourceLocation)
        if copied, let mine {
            #expect(written.contains(mine), "\(written)", sourceLocation: sourceLocation)
        }
        if count() != before {
            Logger.app.notice("LD-206 note: the general pasteboard's count moved; App's record shows no write there.")
        }
    }
}
