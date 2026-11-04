import AppCore
import Foundation
import Testing

/// E7-S6 (INT-01.8 to INT-01.15, APP-01.30) on the settings page, over App's
/// browser integration in a throwaway folder under /tmp: its setup files go
/// under `<folder>/home`, never the owner's Library (INT-01.10), and the
/// build is unsigned.
@MainActor
@Suite(.serialized)
struct BrowserSetupTests {
    let folder = "/tmp/e7s6-tests-\(UUID().uuidString.prefix(8))"

    private func model() -> AppSettingsModel {
        try? FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true)
        let session = Session()
        let browsers = Browsers.inFolder(settings: session.settings(), folder: folder)
        return AppSettingsModel(
            session: session, loginItem: FakeLoginItem(), loginEditable: true, accessibility: { true },
            sshProbe: { _ in frameSshStatus }, browsers: browsers)
    }

    @Test("T27 INT-01.15: an unsigned build shows the Safari switch disabled with MI01-04")
    func safariWaitsForSigning() {
        defer { try? FileManager.default.removeItem(atPath: folder) }
        let model = model()
        model.setFlag("browser.enabled", true)
        #expect(!model.safariAllowed)
        #expect(model.isDisabled("browser.safari"))
        #expect(model.safariNote == "Safari needs a signed copy of App. This build is not signed.")
    }

    @Test("APP-01.30: Chrome on writes its setup file on OK, off removes it; a browser that never ran says so")
    func chromeSwitchWritesOnOK() throws {
        defer { try? FileManager.default.removeItem(atPath: folder) }
        let model = model()
        let chrome = folder + "/home/Library/Application Support/Google/Chrome"
        let file = chrome + "/NativeMessagingHosts/com.app.browser.json"
        model.setFlag("browser.enabled", true)
        model.setBrowser("googlechrome", true)
        #expect(model.changed)
        #expect(!model.ok(), "MI01-07: Chrome never ran here")
        #expect(model.error?.contains("Chrome wasn't found") == true)
        #expect(!model.browsersOn.contains("googlechrome"), "the switch shows the file's state")
        try FileManager.default.createDirectory(atPath: chrome, withIntermediateDirectories: true)
        model.setBrowser("googlechrome", true)
        #expect(model.ok())
        #expect(FileManager.default.fileExists(atPath: file))
        #expect(model.browsersOn == ["googlechrome"])
        model.setBrowser("googlechrome", false)
        #expect(model.ok())
        #expect(!FileManager.default.fileExists(atPath: file))
    }
}
