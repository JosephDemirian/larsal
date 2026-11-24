import AppKit
import SwiftUI

enum CapsLock {
    static let note = "Caps Lock is turned on."
}

extension EnvironmentValues {
    /// A fake Caps Lock state for one view's tests (APP-06); `nil`, as in the
    /// app, reads the key natively from `NSEvent.modifierFlags`.
    @Entry var capsLockFake: Bool?
}

extension View {
    /// M06-37 (APP-06.6, F-076): "Caps Lock is turned on." under this
    /// password-kind field while `focused` and Caps Lock is on; never in
    /// place of an error (`error`). Not for the repeat fields.
    func capsLockNote(focused: Bool, error: Bool = false) -> some View {
        modifier(CapsLockNote(focused: focused, error: error))
    }
}

/// Checked on focus, on every key press and release (Caps Lock itself
/// included) in Larsal's windows, and when Larsal becomes active (APP-06.6).
private struct CapsLockNote: ViewModifier {
    let focused: Bool
    let error: Bool
    @Environment(\.capsLockFake) private var fake
    @State private var capsOn = false
    @State private var monitor: Any?

    private func isOn() -> Bool { fake ?? NSEvent.modifierFlags.contains(.capsLock) }

    func body(content: Content) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            content
            if capsOn && focused && !error {
                Text(verbatim: CapsLock.note)
                    .font(.sans(13))
                    .foregroundStyle(Tok.muted)
                    .frame(height: 18)
                    .padding(.top, 8)
            }
        }
        .onChange(of: focused) { capsOn = isOn() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            capsOn = isOn()
        }
        .onAppear {
            capsOn = isOn()
            monitor = NSEvent.addLocalMonitorForEvents(matching: [.flagsChanged, .keyDown, .keyUp]) { event in
                capsOn = isOn()
                return event
            }
        }
        .onDisappear {
            if let monitor { NSEvent.removeMonitor(monitor) }
            monitor = nil
        }
    }
}
