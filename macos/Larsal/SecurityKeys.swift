import LarsalCore
import Observation
import SwiftUI

/// M06-35 (APP-06.15, INT-07.19; F-126): a security key challenge waits for
/// a touch. Rust tells the window at each change (WindowEvents); the save
/// line and the wizard's progress line read it.
@Observable
final class KeyTouch {
    static let shared = KeyTouch()
    static let words = "Waiting for a touch on the security key…"
    var waits = false
}

/// A key list that follows larsal-hwkey's watch while it shows (F-126;
/// APP-06.8, APP-07.15, MOD-12.10, INT-07.14): a look at start, one 0.5 s
/// after a key is plugged in, and "Look for Keys Again". Only list items
/// live here, never a challenge or an answer.
@Observable
final class KeyPicker {
    private(set) var keys: [KeyItem] = []
    private(set) var looking = false
    /// M06-36 after "Look for Keys Again", or why nothing is listed.
    private(set) var note: String?
    /// After each look (the unlock form chooses its item, APP-06.8).
    @ObservationIgnored var afterLook: () -> Void = {}
    @ObservationIgnored private var watch: KeyWatch?
    @ObservationIgnored private var announce = false

    /// Tests and hidden launches never reach a USB key (OD-01: no slot of
    /// the owner's key is touched).
    static var reachesKeys: Bool {
        !launchHidden() && ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil
    }

    /// Starts the watch; none where no key may be reached. Tests put a
    /// fake here and hand looks to the sink.
    static var watching: (KeyLooks) -> KeyWatch? = { reachesKeys ? KeyWatch(screen: $0) : nil }

    func start() {
        guard watch == nil else { return }
        watch = Self.watching(KeySink { [weak self] in self?.found($0) })
        looking = watch != nil
    }

    /// Stops the watch; a running look ends on its own thread.
    func stop() {
        watch?.stop()
        watch = nil
        looking = false
    }

    /// "Look for Keys Again": then M06-36 shows.
    func lookAgain() {
        guard let watch, !looking else { return }
        looking = true
        announce = true
        watch.lookAgain()
    }

    func found(_ look: KeyLook) {
        looking = false
        keys = look.items
        note = announce || keys.isEmpty ? look.note : nil
        announce = false
        afterLook()
    }
}

/// The watch's looks, from its own thread to the main actor.
nonisolated final class KeySink: KeyLooks {
    private let deliver: @MainActor @Sendable (KeyLook) -> Void

    init(_ deliver: @escaping @MainActor @Sendable (KeyLook) -> Void) {
        self.deliver = deliver
    }

    func found(look: KeyLook) {
        Task { @MainActor [deliver] in deliver(look) }
    }
}

/// The security key row's menu in the wizard and on the credentials page
/// (APP-07.15, MOD-12.10; F-126): the keys and slots found, "Look for Keys
/// Again" with M06-36, and Remove where the row has no Remove button.
/// Option A draws only the row and its button (W-19).
struct KeyMenu: View {
    let picker: KeyPicker
    let chosen: KeyPick?
    let choose: (KeyItem) -> Void
    var remove: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(picker.keys, id: \.pick) { item in
                MenuItem(lead: .check(item.pick == chosen), title: item.label) { choose(item) }
            }
            MenuItem(lead: .glyph("arrows-clockwise"), title: "Look for Keys Again", action: picker.lookAgain)
                .disabled(picker.looking)
            if let remove {
                MenuItem(lead: .glyph("trash"), title: "Remove Security Key", negative: true, action: remove)
            }
            if picker.looking || picker.note != nil {
                Text(verbatim: picker.looking ? "Looking for keys…" : picker.note ?? "")
                    .font(.sans(12)).foregroundStyle(Tok.muted)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 10).padding(.vertical, 6)
                    .accessibilityAddTraits(.updatesFrequently)
            }
        }
        .padding(6)
        .frame(width: 340, alignment: .leading)
        .onAppear(perform: picker.start)
        .onDisappear(perform: picker.stop)
    }
}

/// The wizard's security key part (M07-13, APP-07.15; F-126): Option A's
/// row; Add… opens the key menu, the chosen item takes the words' place.
struct WizardKeyRow: View {
    let model: NewVaultModel

    var body: some View {
        MarkRow(
            title: "Security key", detail: model.securityKey?.label ?? "A YubiKey or OnlyKey with challenge-response."
        ) {
            BrandMark(brand: "yubico")
        } control: {
            Button(model.securityKey == nil ? "Add…" : "Change…") { model.keyMenu.toggle() }
                .buttonStyle(Btn(size: .small))
                .popover(isPresented: Bindable(model).keyMenu, arrowEdge: .bottom) {
                    KeyMenu(picker: model.keyPicker, chosen: model.securityKey?.pick, choose: model.chooseSecurityKey)
                }
            if model.securityKey != nil {
                Button("Remove", action: model.removeSecurityKey).buttonStyle(Btn(size: .small))
            }
        }
    }
}
