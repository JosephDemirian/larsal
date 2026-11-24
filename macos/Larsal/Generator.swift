import AppKit
import LarsalCore
import SwiftUI

/// The password generator (E5-S6; FEA-02, FEA-03; mockup `generator()`).
/// Rust makes, holds, copies and uses the value (generator.rs); this model
/// keeps the options (no secret) and the value on screen, an allowed
/// crossing (LD-220 (1)), shown as a Show the user asked for (FEA-02.23). The value goes on
/// close, on lock and when the next one comes (D-02-5).
@Observable
final class GeneratorModel {
    /// Opened from the editor's password field, not the toolbar.
    let fromEditor: Bool
    private(set) var options: GeneratorOptions
    /// The value on screen; empty when there is none.
    private(set) var value = ""
    /// Its strength, rated in Rust off the screen thread (FEA-05.8, LD-137).
    private(set) var rating: Rating?
    /// Why nothing was made (D-02-3 (b)).
    private(set) var problem: String?
    /// Counts the values Rust made: the output field takes each new one.
    private(set) var made = 0
    @ObservationIgnored private let session: Session
    /// One Rust call at a time, the latest wins: what is on screen is what
    /// Rust holds.
    @ObservationIgnored private var pending: Job?
    @ObservationIgnored private var worker: Task<Void, Never>?
    @ObservationIgnored private var closed = false
    /// New entry with it: the value stays in Rust while the editor opens.
    @ObservationIgnored var keep = false

    private enum Job {
        case make(GeneratorOptions)
        case edit(String)
    }

    init(session: Session, vault: UInt64, fromEditor: Bool) {
        self.session = session
        self.fromEditor = fromEditor
        // FEA-02.17: from a password field, its length.
        options = session.generatorOptions(vault: fromEditor ? vault : nil)
        submit(.make(options))
    }

    /// Changes an option; a new value comes at once (FEA-02.14).
    func change(_ edit: (inout GeneratorOptions) -> Void) {
        var next = options
        edit(&next)
        guard next != options else { return }
        options = next
        submit(.make(next))
    }

    /// A chip: the last chip on turns back on, so the chips alone never
    /// leave nothing to choose from (D-02-3, as the mockup does).
    func toggle(_ chip: WritableKeyPath<GeneratorOptions, Bool>) {
        change { options in
            options[keyPath: chip].toggle()
            if ![options.upper, options.lower, options.digits, options.special, options.extended].contains(true) {
                options[keyPath: chip] = true
            }
        }
    }

    /// New password (FEA-02.14 Regenerate).
    func regenerate() { submit(.make(options)) }

    /// The user typed over the value (FEA-02.16): Rust takes the text and
    /// rates it (D-03-7).
    func edited(_ text: String) {
        value = text
        submit(.edit(text))
    }

    /// Waits for the Rust call in progress, so Copy and Use act on the value
    /// on screen.
    func settled() async {
        while let running = worker { await running.value }
    }

    /// Closes: Rust drops the value, and keeps the options when `save`
    /// (FEA-02.18); the value goes from the screen.
    func close(save: Bool) {
        guard !closed else { return }
        closed = true
        pending = nil
        value = ""
        session.closeGenerator(save: save ? options : nil)
    }

    private func submit(_ job: Job) {
        guard !closed else { return }
        pending = job
        guard worker == nil else { return }
        worker = Task { [weak self] in
            await self?.drain()
            self?.worker = nil
        }
    }

    private func drain() async {
        let session = session
        while let job = pending, !closed {
            pending = nil
            switch job {
            case .make(let options):
                let next = await Task.detached { session.generate(options: options) }.value
                guard pending == nil, !closed else { continue }
                value = next.value
                rating = next.rating
                problem = next.problem
                made += 1
            case .edit(let text):
                let next = await Task.detached { Result { try session.editGenerated(text: text) } }.value
                guard pending == nil, !closed else { continue }
                switch next {
                case .success(let rated):
                    rating = rated
                    problem = nil
                case .failure(let error):
                    // Refused (over 64 KiB): Rust dropped the value, so the
                    // screen shows the reason and Copy and Use are off.
                    value = ""
                    rating = nil
                    problem = message(error)
                }
            }
        }
        // A value made after the close goes too.
        if closed { session.closeGenerator(save: nil) }
    }
}

/// One popover per window: two overlays are equal when they are the same.
extension GeneratorModel: Equatable {
    nonisolated static func == (lhs: GeneratorModel, rhs: GeneratorModel) -> Bool { lhs === rhs }
}

extension VaultModel {
    /// A menu or popover drawn in the window (mockup `overlay`); the
    /// generator's popover holds its model.
    enum Overlay: Equatable {
        case more, sort
        case generator(GeneratorModel)
    }

    /// The generator while its popover is open (`Overlay.generator`).
    var generator: GeneratorModel? {
        if case .generator(let model) = overlay { model } else { nil }
    }

    /// Opens the generator under the toolbar button, or for the editor's
    /// password field (FEA-02.17).
    func openGenerator(fromEditor: Bool) {
        overlay = .generator(GeneratorModel(session: session, vault: vault.id, fromEditor: fromEditor))
    }

    /// The toolbar's Generator button and ⌥⌘G: opens or closes it.
    func toggleGenerator() {
        if generator == nil { openGenerator(fromEditor: false) } else { overlay = nil }
    }

    /// The popover closed (`overlay`'s change): the value goes; the window's
    /// generator saves its options, a field's only on Use (FEA-02.18).
    func closed(_ generator: GeneratorModel) {
        if !generator.keep { generator.close(save: !generator.fromEditor) }
    }

    /// Copy (FEA-02.20): Rust copies the value it holds; the notice says so.
    func copyGenerated() {
        guard let generator else { return }
        Task {
            await generator.settled()
            notifyCopy("Password") { try session.copyGenerated() }
        }
    }

    /// Use password (`ACT-GEN-APPLY`): the value becomes the draft's
    /// password in Rust; the popover closes and keeps the options.
    func useGenerated() {
        guard let generator else { return }
        Task {
            await generator.settled()
            do {
                // FEA-02 on the Sharing page, unless an entry editor is over
                // it: the editor that opened the generator takes the value.
                if editor == nil, let group = sharing.editor {
                    try group.generated()
                } else {
                    _ = try session.useGenerated(vault: vault.id)
                    editor?.generated()
                }
                generator.close(save: true)
                overlay = nil
            } catch {
                notify(Toast(glyph: "warning", text: message(error)))
            }
        }
    }

    /// New entry with it: a new entry in the group on screen whose password
    /// is the value; the generator closes and keeps its options.
    func newEntryWithGenerated() {
        guard let generator else { return }
        Task {
            await generator.settled()
            // Opening the editor closes the popover; the value stays in Rust
            // until it is used.
            generator.keep = true
            newEntry()
            if editor != nil, (try? session.useGenerated(vault: vault.id)) != nil { editor?.generated() }
            generator.close(save: true)
        }
    }
}
