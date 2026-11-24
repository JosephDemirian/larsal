import AppKit
import ImageIO
import LarsalCore
import SwiftUI

/// MOD-05.9 Preview (SD-13, L05-3, LD-65): one attachment inside Larsal, never
/// through another app or a file on disk. An image is the PNG Rust decoded
/// and wrote again; text is plain text (`Text(verbatim:)`, AT-E01), so no
/// markup renders, nothing loads and no link can be followed. The value is
/// a Show value: it goes when the sheet closes.
struct PreviewSheet: View {
    let model: VaultModel
    let name: String
    let preview: AttachmentPreview
    @State private var image: CGImage?
    @State private var decoded = false

    var body: some View {
        DialogCard(tint: "blue", glyph: "paperclip", title: name, wide: true) {
            DialogBody { content.frame(maxWidth: .infinity, alignment: .leading) }
        } foot: {
            // MOD-05.9: Open and Save from the preview.
            SheetButton(title: "Open") { inEditor { model.openAttachment(name) } }
            SheetButton(title: "Save…") {
                guard let folder = VaultModel.attachmentFolderPanel() else { return }
                inEditor { model.saveAttachment(name, to: folder.path(percentEncoded: false)) }
            }
            SheetButton(title: "Done", kind: .primary) { model.dialog = nil }
        }
        .task {
            // A 4,096-pixel image is a 64 MiB buffer: decoded off the main thread.
            guard case .image(let png) = preview else { return }
            let decoder = Self.decoder
            image = await Task.detached { decoder(png) }.value
            decoded = true
        }
    }

    // ponytail: no zoom; Rust keeps the image's own size and shape (at most
    // 4,096 pixels a side), drawn shrunk to fit the card, never enlarged.
    // Add zoom when people need the full detail of large images.
    @ViewBuilder
    private var content: some View {
        switch preview {
        case .image:
            if let image {
                let size = CGSize(width: image.width, height: image.height)
                Image(nsImage: NSImage(cgImage: image, size: size)).resizable().scaledToFit()
                    .frame(maxWidth: min(size.width, 512), maxHeight: min(size.height, 360))
                    .accessibilityLabel(Text(verbatim: name))
            } else if decoded {
                note
            } else {
                ProgressView().controlSize(.small)
            }
        case .text(let text):
            ScrollView {
                Text(verbatim: text).font(.mono(13)).frame(maxWidth: .infinity, alignment: .leading)
            }
            // The AppKit scroll bar parts have no names (AT-K06).
            .scrollIndicators(.never)
            .frame(maxHeight: 320)
        case .unsupported:
            note
        }
    }

    private var note: some View {
        Text(verbatim: "This kind of file cannot be shown here. Open it from the entry editor.")
            .foregroundStyle(Tok.muted)
    }

    /// Open and Save are the editor's own actions (MOD-05.12, MOD-05.14),
    /// made on the entry's draft, so the entry's editor opens on its
    /// attachments first.
    private func inEditor(_ action: () -> Void) {
        if model.editor == nil {
            model.edit()
            model.editor?.page = .advanced
        }
        if model.editor != nil { action() }
    }

    /// Decodes every pixel now, not at the first draw; the sheet runs it off
    /// the main thread (a test wraps it to prove that).
    static var decoder: @Sendable (Data) -> CGImage? = { png in
        guard let source = CGImageSourceCreateWithData(png as CFData, nil) else { return nil }
        return CGImageSourceCreateImageAtIndex(source, 0, [kCGImageSourceShouldCacheImmediately: true] as CFDictionary)
    }
}

extension VaultModel {
    /// Save… (MOD-05.14): a folder, not a file name (never shown by tests,
    /// AGENTS.md rule 10).
    static var attachmentFolderPanel: () -> URL? = {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.prompt = "Save"
        return panel.runModal() == .OK ? panel.url : nil
    }
}
