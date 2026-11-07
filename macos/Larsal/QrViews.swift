import AppKit
import LarsalCore
import SwiftUI

/// The pop-up on the window (design/option-a/proposals.html `qrProposal`):
/// the chrome moves in without the code; the code appears whole and still
/// (FEA-10.11). A dialog too large for its bounds gives MSG-QR-SIZE with no
/// code pixels at all (FEA-10.12).
struct QrPopupView: View {
    let popup: QrPopup
    /// Tests set Reduce Motion here; SwiftUI's own value is read only.
    var reduceMotion: Bool?
    /// The frames' motion; tests stretch it to see the code wait for its end.
    var motion = Animation.easeOut(duration: 0.16)
    @Environment(\.accessibilityReduceMotion) private var systemReduce
    @State private var entered = false

    private var reduce: Bool { reduceMotion ?? systemReduce }

    var body: some View {
        if reduce {
            // No motion at all, also when it stops one that is under way.
            QrPopupContent(popup: popup).onAppear { popup.settle() }
        } else {
            QrPopupContent(popup: popup)
                .opacity(entered || popup.settled ? 1 : 0)
                .offset(y: entered || popup.settled ? 0 : 6)
                .onAppear {
                    if popup.settled { return }
                    // The code comes when the motion has truly ended; a motion that
                    // never ends shows no code, and the hold bound closes it.
                    withAnimation(motion, completionCriteria: .removed) {
                        entered = true
                    } completion: {
                        popup.settle()
                    }
                }
        }
    }
}

/// The dialog in its current state, without the motion.
struct QrPopupContent: View {
    let popup: QrPopup
    @Environment(\.displayScale) private var scale

    var body: some View {
        switch popup.stage {
        case .warning(let action):
            QrWarning(popup: popup, action: action)
        case .refused(let text):
            QrCard(popup: popup, width: 460) { QrStatus(text: text) }
        default:
            let layout = popup.symbol.map { QrLayout(modules: Int($0.size), scale: scale) }
            ViewThatFits {
                QrCard(popup: popup, width: layout?.outer ?? 460) { QrBody(popup: popup, layout: layout) }
                    .onAppear { popup.sizeRefused = false }
                QrCard(popup: popup, width: 460) {
                    QrStatus(text: QrText.size)
                    QrLine(text: QrText.exposure).padding(.top, 16)
                    QrLine(text: QrText.capture).padding(.top, 4)
                }
                .onAppear { popup.sizeRefused = true }
            }
        }
    }
}

/// `.dlg` with the card's head and three buttons.
private struct QrCard<Content: View>: View {
    let popup: QrPopup
    let width: CGFloat
    @ViewBuilder let content: Content
    @FocusState private var focused: QrStop?

    var body: some View {
        let off = !popup.canExport
        DialogCard(
            tint: "cyan", glyph: "qr-code", title: QrText.title, text: popup.purposeIsLong ? nil : popup.purpose,
            width: width
        ) {
            DialogBody {
                if popup.purposeIsLong { QrLongPurpose(text: popup.purpose) }
                content
            }
        } foot: {
            SheetButton(title: "Save Image…") { popup.ask(.save) }
                .disabled(off)
                .opacity(off ? 0.55 : 1)
                .qrStop(.save, popup, $focused)
            SheetButton(title: "Share…") { popup.ask(.share) }
                .disabled(off || !popup.shareAvailable)
                .opacity(off || !popup.shareAvailable ? 0.55 : 1)
                .accessibilityHint(Text(verbatim: popup.shareAvailable ? "" : QrText.shareUnavailable))
                .qrStop(.share, popup, $focused)
            SheetButton(title: "Done", kind: .primary) { popup.revoke() }
                .qrStop(.done, popup, $focused)
        }
        .qrFocusCycle(popup, $focused)
    }
}

/// FEA-10.13: a long field name wraps as plain text in a bounded space, so the
/// controls below it stay on screen.
private struct QrLongPurpose: View {
    let text: String

    var body: some View {
        ScrollView {
            Text(verbatim: text)
                .foregroundStyle(Tok.muted)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxHeight: 88)
        .padding(.bottom, 12)
    }
}

/// The panel, its two lines, the count and the unavailable line.
private struct QrBody: View {
    let popup: QrPopup
    let layout: QrLayout?

    var body: some View {
        let points = layout?.points ?? 296
        Group {
            if let layout, popup.settled, popup.stage == .code {
                QrCodeView(popup: popup, layout: layout)
                    .accessibilityElement()
                    .accessibilityLabel(Text(verbatim: "QR code for " + popup.purpose))
                    .accessibilityAddTraits(.isImage)
            } else {
                Color.clear
            }
        }
        .frame(width: points, height: points)
        .padding(.leading, layout?.leading ?? 60)
        QrLine(text: QrText.exposure).padding(.top, 16)
        QrLine(text: QrText.capture).padding(.top, 4)
        // These come with the code, in one layout pass, so its first paint is
        // already at its final place (FEA-10.11); the frame's entry has neither.
        if popup.settled {
            QrLine(text: QrText.closing(popup.seconds ?? 44)).num().padding(.top, 12)
            if !popup.shareAvailable {
                QrLine(text: QrText.shareUnavailable).padding(.top, 12)
            }
        }
    }
}

/// `.help`, wrapping.
private struct QrLine: View {
    let text: String

    var body: some View {
        Text(verbatim: text)
            .font(.sans(12))
            .foregroundStyle(Tok.muted)
            .lineBox(12, 16)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// A refusal or MSG-QR-SIZE where the code would be: Done is the way on.
private struct QrStatus: View {
    let text: String

    var body: some View {
        QrLine(text: text).accessibilityAddTraits(.updatesFrequently)
    }
}

/// `qrExportWarning`: Cancel is the default and takes Return and Escape.
private struct QrWarning: View {
    let popup: QrPopup
    let action: QrExport
    @FocusState private var focused: QrStop?

    var body: some View {
        let keep = { popup.cancelWarning() }
        DialogCard(
            tint: "orange", glyph: "warning", title: action == .save ? QrText.saveTitle : QrText.shareTitle,
            text: QrText.warning
        ) {
            if action == .share { DialogBody { QrLine(text: QrText.shareLimit) } }
        } foot: {
            SheetButton(title: "Cancel", cancel: true, action: keep)
                .background {
                    Button("", action: keep).keyboardShortcut(.defaultAction).opacity(0).accessibilityHidden(true)
                }
                .qrStop(.cancel, popup, $focused)
            SheetButton(title: action == .save ? "Save Image" : "Choose Where to Share", kind: .danger) {
                popup.confirm()
            }
            .qrStop(.confirm, popup, $focused)
        }
        .qrFocusCycle(popup, $focused)
    }
}

extension View {
    /// One stop of the cycle: it takes real focus, and wears the frames' ring,
    /// 2 points of accent, 2 outside the button, only while it has it.
    fileprivate func qrStop(
        _ stop: QrStop, _ popup: QrPopup, _ focused: FocusState<QrStop?>.Binding
    ) -> some View {
        // A click on a disabled button must not take a stop outside the cycle.
        focusable(popup.focusStops.contains(stop))
            .focused(focused, equals: stop)
            .focusEffectDisabled()
            .overlay {
                if popup.focus == stop {
                    RoundedRectangle(cornerRadius: 10).stroke(Tok.accent, lineWidth: 2).padding(-2)
                }
            }
    }

    /// FEA-10.13: Tab and Shift-Tab stay in the dialog, Space acts on the stop,
    /// and SwiftUI's focus and the popup's follow each other.
    fileprivate func qrFocusCycle(_ popup: QrPopup, _ focused: FocusState<QrStop?>.Binding) -> some View {
        onKeyPress(keys: [.tab, KeyEquivalent("\u{19}")], phases: [.down, .repeat]) { press in
            popup.moveFocus(back: press.modifiers.contains(.shift) || press.key.character == "\u{19}")
            return .handled
        }
        .onKeyPress(.space, phases: .down) { _ in
            popup.activateFocus()
            return .handled
        }
        .onAppear { focused.wrappedValue = popup.focus }
        .onChange(of: popup.focus) { _, stop in focused.wrappedValue = stop }
        .onChange(of: focused.wrappedValue) { _, stop in if let stop { popup.focus = stop } }
    }
}

/// The code. Whole black modules on white, in whole physical pixels, never
/// scaled, tinted or draggable, and only what `paintable` gives (FEA-10.12).
struct QrCodeView: NSViewRepresentable {
    let popup: QrPopup
    let layout: QrLayout

    func makeNSView(context: Context) -> QrCodeNSView { QrCodeNSView() }

    func updateNSView(_ view: QrCodeNSView, context: Context) {
        view.cell = CGFloat(layout.pitch) / layout.scale
        view.source = { [weak popup] in popup?.paintable() }
        view.painted = { [weak popup] in popup?.painted() }
        view.needsDisplay = true
    }
}

final class QrCodeNSView: NSView {
    var cell: CGFloat = 1
    var source: (() -> Qr?)?
    var painted: (() -> Void)?

    override var isFlipped: Bool { true }
    override var mouseDownCanMoveWindow: Bool { false }
    override func menu(for event: NSEvent) -> NSMenu? { nil }

    override func draw(_ dirtyRect: NSRect) {
        guard let symbol = source?(), let context = NSGraphicsContext.current?.cgContext else { return }
        let side = Int(symbol.size)
        let origin = backingAlignedRect(bounds, options: .alignAllEdgesNearest).origin
        context.setShouldAntialias(false)
        context.setFillColor(.white)
        context.fill(bounds)
        context.setFillColor(.black)
        for (index, value) in symbol.modules.enumerated() where value == 1 {
            let (row, column) = (index / side, index % side)
            let corner = CGPoint(x: origin.x + CGFloat(column) * cell, y: origin.y + CGFloat(row) * cell)
            context.addRect(CGRect(origin: corner, size: CGSize(width: cell, height: cell)))
        }
        context.fillPath()
        painted?()
    }
}

/// The right-click item of a protected field: that field, never a fallback
/// password (FEA-10.2).
struct QrFieldMenu: View {
    let model: VaultModel
    let field: String

    var body: some View {
        Button(QrText.title) { model.showQr(field: field) }
    }
}

/// The right-click item of a Wi-Fi entry's Security row (FEA-10.4).
struct QrJoinMenu: View {
    let model: VaultModel

    var body: some View {
        Button(QrText.join) { model.showWifiJoin() }
    }
}

/// `.ibtn` beside a protected field (ACT-QR-SHOW).
struct QrFieldButton: View {
    let model: VaultModel
    let field: String

    var body: some View {
        IconButton(glyph: "qr-code", label: QrText.title) { model.showQr(field: field) }
            .qrInvoker()
    }
}

/// A QR button as FEA-10.13’s invoker. It can hold focus only with full
/// keyboard access; clicked without it, the focus never left where it was.
private struct QrInvoker: ViewModifier {
    @Namespace private var id
    @FocusState private var focused: Bool

    func body(content: Content) -> some View {
        let (focus, id) = (QrFocus.shared, id)
        content
            .focused($focused)
            .onChange(of: focused) { _, now in
                if now { focus.held = id } else if focus.held == id { focus.held = nil }
            }
            .onChange(of: focus.turn) { if focus.button == id { focused = true } }
            .onAppear { focus.there.insert(id) }
            .onDisappear { focus.there.remove(id) }
    }
}

extension View {
    func qrInvoker() -> some View { modifier(QrInvoker()) }
}

/// The field ⌃⌥⌘Q takes while focus is inside it (FEA-10.2).
struct QrFocusedFieldKey: FocusedValueKey {
    typealias Value = String
}

extension FocusedValues {
    var qrField: String? {
        get { self[QrFocusedFieldKey.self] }
        set { self[QrFocusedFieldKey.self] = newValue }
    }
}

extension FieldView {
    /// FEA-10.1: the password, and every protected field.
    var qrOffered: Bool { protected || kind == .password }
}

extension View {
    /// A protected field of the detail: its right-click item and the
    /// shortcut's focus (FEA-10.2). An unprotected field gets neither.
    func qrField(_ model: VaultModel, _ field: FieldView) -> some View {
        Group {
            if field.qrOffered {
                contextMenu { QrFieldMenu(model: model, field: field.name) }
                    .focusedValue(\.qrField, field.name)
            } else {
                self
            }
        }
    }
}

/// Keeps the field the focus is in for the shortcut, read when it is pressed: a
/// shortcut's action is not rebuilt as the focus moves (FEA-10.2).
struct QrFocusReader: View {
    let model: VaultModel
    @FocusedValue(\.qrField) private var focused

    var body: some View {
        Color.clear
            .accessibilityHidden(true)
            .onChange(of: focused, initial: true) { _, field in model.qrHeld.field = field }
    }
}

/// The Entry menu's items (ACT-QR-SHOW, ACT-QR-FIELD, ACT-QR-WIFI, FEA-10.2).
struct EntryQrItems: View {
    let state: MenuState

    var body: some View {
        let model = state.vault
        let entry = state.copyEntry
        Button(QrText.title) { model?.showQrFromKeys(focused: model?.qrHeld.field) }
            .keyboardShortcut("q", modifiers: [.control, .option, .command])
            .disabled(entry == nil)
        Menu(QrText.field) {
            ForEach(entry?.fields.filter(\.qrOffered).map(\.name) ?? [], id: \.self) { name in
                Button(name) { model?.showQrFromKeys(focused: name) }
            }
        }
        .disabled(entry?.fields.contains(where: \.qrOffered) != true)
        Button(QrText.join) { model?.showWifiJoinFromMenu() }
            .disabled(model?.editor != nil || model?.canJoinWifi != true)
    }
}
