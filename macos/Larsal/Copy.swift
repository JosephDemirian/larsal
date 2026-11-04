import LarsalCore
import SwiftUI

/// Copy (APP-03, E6-S1). The value never reaches Swift: Rust resolves the
/// field and writes it to the clipboard with its markers and its clear timer.
extension VaultModel {
    /// The mockup's `.toast`: a glyph, the words, and the quieter rest.
    struct Toast: Equatable {
        let glyph: String
        let text: String
        var note: String?
        /// What VoiceOver reads.
        var spoken: String { [text, note].compactMap { $0 }.joined(separator: " ") }
    }

    /// Copies a field of the selected entry.
    func copy(_ field: String) {
        run(field == "UserName" ? "Username" : field) {
            try session.copyField(vault: vault.id, entry: $0, field: field)
        }
    }

    /// Copies the current one-time code, computed in Rust (FEA-04).
    func copyCode() { run("One-time password") { try session.copyCode(vault: vault.id, entry: $0) } }

    /// Copies the SSH key's fingerprint.
    func copyFingerprint() { run("Fingerprint") { try session.copyFingerprint(vault: vault.id, entry: $0) } }

    /// `copy.selection` (APP-03.7, LD-219 (4)): text the user selected in
    /// the vault's view, copied in Rust with the markers and the countdown;
    /// the notice reads "Copied." (APP-03.21). True when it was copied.
    @discardableResult
    func copySelection(_ text: String) -> Bool {
        var copied = false
        notifyCopy("") {
            let result = try session.copySelection(text: text)
            copied = !result.empty
            return result
        }
        return copied
    }

    /// One Rust copy for the selected entry and its notice: the label and the
    /// seconds (`MSG-COPIED`), nothing to copy (`MSG-COPY-EMPTY`, also for a
    /// field, code or key the entry lacks: APP-03.4, APP-03.5), or Rust's
    /// reason (`MSG-COPY-FAILED`).
    private func run(_ label: String, _ copy: (String) throws -> Copied) {
        overlay = nil
        guard let selection else { return }
        notifyCopy(label) { try copy(selection) }
    }

    /// The notice of one Rust copy (APP-03.21), for any copy action.
    func notifyCopy(_ label: String, _ copy: () throws -> Copied) {
        let empty = { (label: String) in Toast(glyph: "info", text: label + " is empty. Nothing to copy.") }
        do {
            let copied = try copy()
            notify(
                copied.empty
                    ? empty(copied.label)
                    : Toast(
                        glyph: "check", text: copied.label.isEmpty ? "Copied." : copied.label + " copied.",
                        note: copied.seconds > 0 ? "Clears in \(copied.seconds) s." : nil))
        } catch LarsalError.UnknownField {
            notify(empty(label))
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    /// APP-03.1: a copy item is enabled when its field is there and not
    /// empty; a protected value is not known here, so it counts as there.
    func canCopy(_ field: String) -> Bool {
        detail?.fields.contains { $0.name == field && ($0.protected || !$0.value.isEmpty) } ?? false
    }

    /// Shows the notice for 2.6 seconds, as the mockup does; a new one
    /// replaces it.
    func notify(_ next: Toast) {
        toast = next
        toastTimer?.cancel()
        toastTimer = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(2600))
            if !Task.isCancelled { self?.toast = nil }
        }
    }
}

/// The mockup's `.toast` (APP-03.21): 20 above the window's foot, centred;
/// it takes no clicks and never the focus.
struct ToastView: View {
    let toast: VaultModel.Toast

    var body: some View {
        HStack(spacing: 8) {
            Glyph(name: toast.glyph).foregroundStyle(Tok.toastIcon)
            Text(verbatim: toast.text)
            if let note = toast.note { Text(verbatim: note).opacity(0.65) }
        }
        .font(.sans(13))
        .num()
        .foregroundStyle(Tok.toastInk)
        .frame(height: 20)
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: toast.spoken))
        .accessibilityAddTraits(.isStaticText)
        .background(Tok.primary, in: RoundedRectangle(cornerRadius: 10))
        // `box-shadow: 0 10px 30px rgba(0,0,0,.25)`.
        .background(BoxShadow(radius: 10, drop: 10, blur: 30, alpha: 0.25))
        .fixedSize()
        .allowsHitTesting(false)
    }
}
