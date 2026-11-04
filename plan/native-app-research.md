# Native Mac app: the proven standard

Research for the E5-S1 re-plan (README D3, LD-155, AGENTS.md rule 9). Done 2026-10-27 from public repositories, official docs and crates.io.

Clean room: only layout, build steps and tool choices were studied. No code was copied. Several of these repositories are GPL or AGPL, so not one line of them goes into this project.

## What was studied

| Larsal | Rust core and bindings | Swift app | License |
|---|---|---|---|
| Bitwarden (password manager) | `sdk-internal`: core crates plus the bindings crate `bitwarden-uniffi`; released as the package `sdk-swift` | `bitwarden/ios` | GPL-3.0 (app) |
| Proton Pass and Proton Authenticator (password manager, one-time codes; the Authenticator project builds for macOS) | `proton-pass-common`: bindings crates `proton-pass-mobile` and `proton-authenticator-mobile` | `protonpass/ios-pass`, `protonpass/ios-authenticator` | GPL-3.0 |
| Element X (encrypted chat) | `matrix-rust-sdk`: `bindings/matrix-sdk-ffi`, built by an `xtask`; released as `matrix-rust-components-swift` | `element-hq/element-x-ios` | AGPL-3.0 (app), Apache-2.0 (SDK) |
| Firefox iOS | `application-services`: one combined crate `megazords/ios-rust` | `mozilla-mobile/firefox-ios` | MPL-2.0 |
| Signal | `libsignal`: `rust/bridge/ffi` and a hand-written Swift layer in `swift/` (no UniFFI) | (Signal-iOS) | AGPL-3.0 |
| Strongbox (native Mac password manager, App Store) | none | `macbox/`: AppKit, Objective-C and Swift | AGPL-3.0 |
| MacPass (native Mac password manager, direct download) | none | AppKit, Objective-C | GPL-3.0 |

The Rust-core apps answer points 1 to 5 and 9. The two native Mac password managers answer the Mac-specific points 6 to 8.

## 1. Repo layout

**Standard:** a separate bindings crate that depends on the core crates and is the only crate that exports anything to Swift. The Swift package wrapper sits next to it. The app has its own folder or repository.

- Bitwarden: core crates have a `uniffi` feature. `crates/bitwarden-uniffi` (crate types `lib`, `staticlib`, `cdylib`) re-exports them. `crates/bitwarden-uniffi/swift/` holds `Package.swift`, `build.sh` and the generated sources, which are git-ignored. Releases go to the separate `sdk-swift` repository, and the app pins it by commit or points at the local path for SDK work.
- Proton: `proton-pass-common` (core) is wrapped by `proton-pass-mobile` (bindings, `cdylib` and `staticlib`), with the package in `proton-pass-mobile/iOS/PassRustCore/`. The app repositories download a released zip, pinned by version and SHA-256 in `.rust-package`.
- matrix-rust-sdk: `bindings/matrix-sdk-ffi` with the package in `bindings/apple/`.
- Mozilla: a single combined crate, `megazords/ios-rust`, links every component into one static library and has its own `Package.swift`.
- Signal: `rust/bridge/ffi` (`libsignal-ffi`) plus `swift/`, with `Package.swift` at the repository root.

**Where they differ:** the big teams split the work across repositories because they ship iOS, Android and web. We ship one Mac app from one workspace, so everything stays in one repository, as Signal does.

**For us:** `crates/larsal-ffi/` (the bindings crate; today's `larsal-desktop` without Tauri), `crates/uniffi-bindgen/` (a 3-line binary), and `macos/` (the Xcode project, the Swift sources and the local package `LarsalCore`).

Sources: [bitwarden-uniffi](https://github.com/bitwarden/sdk-internal/tree/main/crates/bitwarden-uniffi), [sdk-swift](https://github.com/bitwarden/sdk-swift), [Bitwarden project-common.yml](https://github.com/bitwarden/ios/blob/main/project-common.yml), [proton-pass-common](https://github.com/protonpass/proton-pass-common), [ios-authenticator .rust-package](https://github.com/protonpass/ios-authenticator/blob/main/.rust-package), [matrix-sdk-ffi](https://github.com/matrix-org/matrix-rust-sdk/tree/main/bindings/matrix-sdk-ffi), [megazords/ios-rust](https://github.com/mozilla/application-services/tree/main/megazords/ios-rust), [libsignal swift](https://github.com/signalapp/libsignal/tree/main/swift)

## 2. Build pipeline

**Standard:**
1. `cargo build` a static library for each Apple target.
2. `lipo` the macOS slices into one universal library (aarch64 and x86_64 apple-darwin).
3. Run UniFFI's bindgen in library mode, which reads the built library and writes the headers, the modulemap and the Swift sources.
4. `xcodebuild -create-xcframework`.
5. Wrap the result in a Swift package: a `binaryTarget` for the xcframework plus one target with the generated Swift.

- **Who runs it:** a shell script or Makefile in three of the four (Bitwarden `swift/build.sh`, Proton `Makefile` targets `ios-lipo-macos` and `ios-xcframework`, Mozilla `build-xcframework.sh`). matrix-rust-sdk uses an xtask (`cargo xtask swift build-framework`, lipo per platform). None uses cargo-swift: it exists (0.11.1) but none of these projects adopted it.
- **Bindgen binary:** each keeps a tiny crate in the workspace, pinned to the same UniFFI version (Bitwarden `crates/uniffi-bindgen`, Proton `tools/uniffi-bindgen-cli`, Mozilla `tools/embedded-uniffi-bindgen`). The UniFFI manual recommends this. For Swift, UniFFI also ships `uniffi-bindgen-swift`, which writes the headers, an xcframework-ready modulemap and the sources separately.
- **Proc-macros, not UDL:** Bitwarden and Proton use proc-macros only (`uniffi::setup_scaffolding!`, `#[derive(uniffi::Object)]`, `#[uniffi::export]`). Mozilla still has 13 older UDL files.
- **Version:** the 0.32 line. Bitwarden pins `=0.32.0`, Proton `0.32` and matrix `0.32.1`; Mozilla is on an experimental 0.31. The newest is 0.32.2 (2026-09-23), licensed MPL-2.0.

**Where they differ:** matrix calls `uniffi_bindgen` as a library from its xtask. Signal uses cbindgen and writes its Swift by hand. Proton's macOS slice is arm64 plus x86_64, while its Authenticator build is arm64 only.

**For us:** `scripts/build-core.sh`, about 20 lines, running steps 1 to 5 with `uniffi-bindgen-swift`, UniFFI pinned at `=0.32.2`.
- Development builds compile the host target only (aarch64-apple-darwin).
- The x86_64 slice and `lipo` come at E14. They need `rustup target add x86_64-apple-darwin`, which is an install and needs the owner's yes.
- Generated files are not kept: Bitwarden git-ignores them.

Sources: [Bitwarden build.sh](https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-uniffi/swift/build.sh), [Bitwarden Package.swift](https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-uniffi/swift/Package.swift), [Bitwarden Cargo.toml (uniffi =0.32.0)](https://github.com/bitwarden/sdk-internal/blob/main/Cargo.toml), [Proton Makefile](https://github.com/protonpass/proton-pass-common/blob/main/Makefile), [Proton AuthenticatorRustCore Package.swift](https://github.com/protonpass/proton-pass-common/blob/main/proton-authenticator-mobile/iOS/AuthenticatorRustCore/Package.swift), [matrix xtask swift.rs](https://github.com/matrix-org/matrix-rust-sdk/blob/main/xtask/src/swift.rs), [Mozilla build-xcframework.sh](https://github.com/mozilla/application-services/blob/main/megazords/ios-rust/build-xcframework.sh), [UniFFI: uniffi-bindgen-swift](https://mozilla.github.io/uniffi-rs/latest/swift/uniffi-bindgen-swift.html), [UniFFI: the bindgen binary](https://mozilla.github.io/uniffi-rs/latest/tutorial/foreign_language_bindings.html), [uniffi on crates.io](https://crates.io/crates/uniffi)

## 3. Xcode project

**Standard:** a checked-in `.xcodeproj` or XcodeGen. Nobody uses Tuist.
- **Checked in:** Proton Pass, Proton Authenticator, Firefox iOS, MacPass and Strongbox. Proton Pass, Proton Authenticator and Firefox use Xcode's synchronized folders (`PBXFileSystemSynchronizedRootGroup`): a file added on disk joins its target without a project edit.
- **XcodeGen:** Bitwarden (`project-*.yml`, run through Mint by `Scripts/bootstrap.sh`) and Element X (`project.yml`; it also commits the generated project).
- **Command line:** `xcodebuild` with a shared scheme, in all of them:
  - Bitwarden: `xcrun xcodebuild build-for-testing`, then `test-without-building`.
  - MacPass: `xcodebuild build -project MacPass.xcodeproj -scheme MacPass` with signing off.
  - Element X: wraps the call in a Swift `tools` package (`swift run tools ci unit-tests`).

**For us:** a checked-in `macos/Larsal.xcodeproj` with synchronized folders and a shared scheme `Larsal`, so there is no generator to install. Build and test with:

```
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -destination 'platform=macOS' test
```

On this Mac, Xcode 27.0 with Swift 6.4 is installed, but `xcode-select` points at CommandLineTools. So scripts set `DEVELOPER_DIR` when it is unset. If agents find the project file hard to edit, XcodeGen is the fallback; installing it needs the owner's yes.

Sources: [Bitwarden Mintfile](https://github.com/bitwarden/ios/blob/main/Mintfile), [Bitwarden bootstrap.sh](https://github.com/bitwarden/ios/blob/main/Scripts/bootstrap.sh), [Bitwarden test workflow](https://github.com/bitwarden/ios/blob/main/.github/workflows/test.yml), [Element X project.yml](https://github.com/element-hq/element-x-ios/blob/develop/project.yml), [Element X unit-tests workflow](https://github.com/element-hq/element-x-ios/blob/develop/.github/workflows/unit-tests.yml), [Proton Authenticator project](https://github.com/protonpass/ios-authenticator/tree/main/Authenticator.xcodeproj), [Firefox Client.xcodeproj](https://github.com/mozilla-mobile/firefox-ios/tree/main/firefox-ios/Client.xcodeproj), [MacPass nightly workflow](https://github.com/MacPass/MacPass/blob/master/.github/workflows/nightly.yml)

## 4. Swift standards

**Standard:**
- Swift 6 language mode with the main actor as the default isolation.
- SwiftLint plus a formatter.
- Swift Testing for unit tests and XCTest's UI testing for UI tests.
- SwiftUI with view models. No architecture framework (TCA is used by none of them).
- macOS 14 or newer.

**Language mode:**
- Element X and Proton Authenticator: `SWIFT_VERSION 6`, `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`, `SWIFT_APPROACHABLE_CONCURRENCY = YES`.
- Proton Pass and Firefox: Swift 6.0 with `SWIFT_STRICT_CONCURRENCY = complete`.
- Bitwarden: `SWIFT_STRICT_CONCURRENCY: complete` in its shared kit.
- The generated UniFFI Swift is built in Swift 5 mode or with warnings suppressed (Proton `.swiftLanguageMode(.v5)`, Bitwarden `-suppress-warnings`).

**Lint and format:**
- SwiftLint is everywhere:
  - Bitwarden pins 0.63.1 in its Mintfile.
  - Proton runs `swiftlint lint --strict` in pre-commit.
  - Element X runs it after the build.
  - Firefox pins 0.65.0 with a SHA-256 checksum.
  - libsignal runs it in CI.
- The formatter differs:
  - Bitwarden, Proton and Element X use SwiftFormat.
  - libsignal uses Apple's swift-format (`swift format`, then `git diff --exit-code`). It ships with Xcode, so there is nothing to install.

**Tests:**
- Bitwarden's testing guide says new unit tests use Swift Testing and old ones stay in XCTest.
- Proton's package tests use `import Testing`.
- UI tests use XCTest's UI testing: Proton `iOSUITests` and `AuthenticatorUITests`, Element X `UITests` in a separate workflow.
- Bitwarden and Element X also take snapshot tests with a third-party library.

**Pattern:**
- Element X: view models with an `@Observable` context, plus coordinators.
- Proton Authenticator: `@Observable` and layered local packages.
- Bitwarden: its own Coordinator, Processor and Store pattern.

**Minimum macOS:** Proton Authenticator targets 14.0 and 15.2, Element X 14.5, MacPass 10.13 (old AppKit). `@Observable` needs macOS 14.

**For us:**
- Swift 6 with the main actor as default isolation.
- macOS 14.
- `swift format lint --strict`, because it ships with Xcode.
- SwiftLint pinned with a checksum, as Firefox does. It is a check tool, so it falls under the E0 permission for check tools (rule 7; lead ruling in LD-156).
- Swift Testing for unit tests, XCTest UI tests for G8.
- Plain SwiftUI with one `@Observable` view model per screen. View models hold view data only and call `larsal-ffi`. AppKit fills SwiftUI's gaps through `NSApplicationDelegateAdaptor` and the window.
- No snapshot library: AT-K05 covers the look.

Sources: [Element X target.yml](https://github.com/element-hq/element-x-ios/blob/develop/ElementX/SupportingFiles/target.yml), [Element X StateStoreViewModelV2](https://github.com/element-hq/element-x-ios/blob/develop/ElementX/Sources/Other/SwiftUI/ViewModel/StateStoreViewModelV2.swift), [Proton Pass project](https://github.com/protonpass/ios-pass/tree/main/ProtonPass.xcodeproj), [Proton pre-commit](https://github.com/protonpass/ios-authenticator/blob/main/.pre-commit-config.yaml), [Bitwarden .swiftlint.yml](https://github.com/bitwarden/ios/blob/main/.swiftlint.yml), [Bitwarden Architecture.md](https://github.com/bitwarden/ios/blob/main/Docs/Architecture.md), [Bitwarden Testing.md](https://github.com/bitwarden/ios/blob/main/Docs/Testing.md), [Firefox .swiftlint-version](https://github.com/mozilla-mobile/firefox-ios/blob/main/.swiftlint-version), [libsignal CI](https://github.com/signalapp/libsignal/blob/main/.github/workflows/build_and_test.yml)

## 5. Logging

**Standard:** Swift logs through `os.Logger` (subsystem and category), which redacts dynamic values by default. There are three ways to get Rust logs out:

- Bitwarden: a `tracing-oslog` layer writes straight to the Apple log on iOS, and an optional UniFFI callback is offered as well.
- Mozilla: `rust-log-forwarder` is a UniFFI callback interface (`set_logger`) that Swift implements.
- matrix-rust-sdk: Rust writes its own rolling log files, and Element X sends its Swift logs into Rust.

**For us:** the callback, because it needs no new crate. `larsal-ffi` installs a `tracing` layer that keeps Rust rule 9 (it drops field values) and calls a Swift `LogSink`. The sink writes to `Logger(subsystem: "app.larsal.desktop", category: target)`. `tracing-oslog` would add a crate and an AT-J03 review for no gain.

Sources: [Bitwarden logging callback](https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-uniffi/docs/logging-callback.md), [Mozilla rust-log-forwarder](https://github.com/mozilla/application-services/blob/main/components/support/rust-log-forwarder/src/lib.rs), [matrix-sdk-ffi platform](https://github.com/matrix-org/matrix-rust-sdk/tree/main/bindings/matrix-sdk-ffi/src/platform), [Apple Logger](https://developer.apple.com/documentation/os/logger)

## 6. Secrets across the boundary

**What proven apps do:**
- Bitwarden decrypts in Rust but hands decrypted items to Swift (`LoginView.password: String`). Its biometric unlock passes the user key to the SDK as a String (`decryptedUserKey`).
- Proton Pass decrypts in Swift.
- So neither keeps secrets out of Swift.
- libsignal keeps keys as opaque Rust handles that Swift only points to. UniFFI's `#[derive(uniffi::Object)]` gives the same thing: an `Arc` handle.

**How values cross in UniFFI:** strings and records are copied through a `RustBuffer`, which Rust frees without wiping it. Our zeroing allocator (LD-133, E6-S6) wipes it on free. A Swift `String` cannot be wiped.

**Clipboard:**
- MacPass and Strongbox write the value plus the empty marker type `org.nspasteboard.ConcealedType`, which clipboard managers skip. MacPass adds `org.nspasteboard.TransientType` when it will clear. Both clear with a timer.
- Bitwarden iOS uses the iOS-only pasteboard options `localOnly` and `expirationDate`.

**Standard for us:** stricter than both apps, as rule 4 asks.
- The vault and the session are UniFFI Objects.
- List views carry no secret.
- Show returns one String, the only secret that crosses. Swift drops it on Hide, on entry change and on lock.
- Copy is a Rust call (`session.copy_field`). `larsal-platform/clipboard.rs` writes the pasteboard with both markers and clears it only while `changeCount` still shows our value. `larsal-cli` needs the same code for SC-07.
- The quick-unlock key stays in Rust (point 7).

Sources: [sdk-swift BitwardenVault.swift (LoginView)](https://github.com/bitwarden/sdk-swift/blob/main/Sources/BitwardenSdk/BitwardenVault.swift), [sdk-swift BitwardenCore.swift (decryptedKey)](https://github.com/bitwarden/sdk-swift/blob/main/Sources/BitwardenSdk/BitwardenCore.swift), [Bitwarden PasteboardService](https://github.com/bitwarden/ios/blob/main/BitwardenShared/Core/Platform/Services/PasteboardService.swift), [MacPass pasteboard controller](https://github.com/MacPass/MacPass/blob/master/MacPass/MPPasteBoardController.m), [Strongbox ClipboardManager](https://github.com/strongbox-password-safe/Strongbox/blob/master/macbox/MacBox/ClipboardManager.m), [nspasteboard.org markers](http://nspasteboard.org/), [UniFFI interfaces](https://mozilla.github.io/uniffi-rs/latest/proc_macro/interfaces.html)

## 7. macOS features: Swift or Rust

**Standard:** the proven apps do every one of these in the native layer. We follow that, except where a secret or the command line tool needs the code in Rust.

| Feature | What proven apps do | For us |
|---|---|---|
| Clipboard and auto-clear | Native layer: MacPass, Strongbox, Bitwarden (point 6) | Rust `larsal-platform` (approved `objc2-app-kit`), shared with `larsal-cli`. Swift shows the countdown from an event. |
| Touch ID quick unlock | `LAContext` plus a Keychain item with `biometryCurrentSet`, `WhenUnlockedThisDeviceOnly`, in the native layer: MacPass, Bitwarden `KeychainRepository`. Strongbox adds Apple Watch. | Keychain in Rust `larsal-platform/quick_unlock.rs` through the approved `security-framework`, whose `PasswordOptions` has `use_protected_keychain` and `BIOMETRY_CURRENT_SET`. Swift only asks `LAContext` whether biometry is available, to show or hide the button. Deviation from Bitwarden: the key never becomes a Swift value (rule 4). |
| Lock on sleep, screen lock, user switch | `NSWorkspace` `willSleep`, `screensDidSleep`, `sessionDidResignActive`; `DistributedNotificationCenter` `com.apple.screenIsLocked` (Strongbox; MacPass uses the same `NSWorkspace` notifications) | Swift, calling `session.lock_all()`. Lock clears our clipboard in Rust. |
| Idle lock | Strongbox: system idle through `CGEventSource`. MacPass: time since the last event in the app. | Swift, counting in-app events only (SR-01, as MacPass does) |
| Hide from screen capture | `sharingType = .none` on every window: MacPass, Strongbox. Apple now calls `.none` "a legacy constant that macOS no longer uses" and says not to rely on it. Developers report that ScreenCaptureKit honours it inconsistently. | Swift sets it on every window, for parity (SC-05). AT-D04 records the result for each capture path. |
| Secure input | Cocoa password fields use `NSSecureTextField` (Apple TN2150). SwiftUI `SecureField` is that field. Code search found no `EnableSecureEventInput` call in MacPass or Strongbox. | Swift `SecureField`. `EnableSecureEventInput` only while a shown (plain) password field has focus (SR-06). |
| Single instance, open from Finder | Document-based apps (MacPass, Strongbox) get one instance from Launch Services and Finder opens through Apple Events. | Swift `application(_:open:)` and `CFBundleDocumentTypes`. No `NSDocument`, because saving stays in `larsal-core/storage.rs`. The APP-09 socket stays in Rust, for command-line launches with flags. |
| Process hardening | Hardened runtime (MacPass, Proton) | Hardened runtime, plus Rust `larsal-platform/hardening.rs` (shared with `larsal-cli`), called first at start-up |

**Keychain and signing:** biometric Keychain items need the data protection keychain. Apple's TN3137 says its keychain access groups come from code-signing entitlements that "must be authorized by a provisioning profile". So E6-S3 needs a signing team. For development a free personal team may do; signed builds need D7.

Sources: [Strongbox DatabasesCollection.swift (lock triggers, idle)](https://github.com/strongbox-password-safe/Strongbox/blob/master/macbox/MacBox/DatabasesCollection.swift), [MacPass lock daemon](https://github.com/MacPass/MacPass/blob/master/MacPass/MPLockDaemon.m), [MacPass window controller (sharingType)](https://github.com/MacPass/MacPass/blob/master/MacPass/MPDocumentWindowController.m), [Strongbox WindowController.m (sharingType)](https://github.com/strongbox-password-safe/Strongbox/blob/master/macbox/MacBox/WindowController.m), [Strongbox BiometricIdHelper](https://github.com/strongbox-password-safe/Strongbox/blob/master/macbox/Model/BiometricIdHelper.m), [Bitwarden KeychainRepository](https://github.com/bitwarden/ios/blob/main/BitwardenShared/Core/Auth/Services/KeychainRepository.swift), [Apple: NSWindow.SharingType.none](https://developer.apple.com/documentation/appkit/nswindow/sharingtype-swift.enum/none), [Apple forums: ScreenCaptureKit and sharing none](https://developer.apple.com/forums/thread/808016), [Apple TN2150 secure event input](https://developer.apple.com/library/archive/technotes/tn2150/_index.html), [Apple TN3137 Mac keychains](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains), [security-framework PasswordOptions](https://docs.rs/security-framework/3.7.0/security_framework/passwords/struct.PasswordOptions.html)

## 8. Hardening and distribution

**What proven apps do:**
- MacPass (outside the App Store): hardened runtime on, no App Sandbox. Its entitlements are Apple Events automation, `disable-library-validation` (for plug-ins) and `keychain-access-groups`.
- Strongbox (App Store and a second store): App Sandbox with user-selected read-write files and security-scoped bookmarks, plus network and USB.
- Proton Pass macOS and Proton Authenticator (App Store): App Sandbox, hardened runtime on.

**Apple's rules for direct download:** Developer ID signing, hardened runtime and notarization. Upload with `xcrun notarytool submit --wait`, then `xcrun stapler staple`.

**Standard outside the App Store:** hardened runtime, Developer ID, notarized and stapled. No `get-task-allow` in release. App Sandbox only for App Store builds.

**For us:** no sandbox, as MacPass. The sandbox only grants the file the user picked, and four parts of our plan need more:
- `storage.rs` writes a temp file and a backup next to the vault.
- The APP-09 socket.
- The SSH agent (E9).
- Auto-Type (E8, Accessibility).

Entitlements:
- Release: `keychain-access-groups` only, for quick unlock.
- Debug: `get-task-allow`, which Xcode adds.

D7 is needed for Developer ID, notarization and the provisioning profile.

Sources: [MacPass entitlements](https://github.com/MacPass/MacPass/blob/master/MacPass/MacPass.entitlements), [Strongbox entitlements](https://github.com/strongbox-password-safe/Strongbox/blob/master/macbox/StrongBox.entitlements), [Proton Pass macOS entitlements](https://github.com/protonpass/ios-pass/blob/main/macOS/macOS.entitlements), [Proton Authenticator entitlements](https://github.com/protonpass/ios-authenticator/blob/main/Authenticator/App/Authenticator.entitlements), [Apple: notarizing](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution), [Apple: hardened runtime](https://developer.apple.com/documentation/security/hardened-runtime)

## 9. Checks

**What their CI runs:**
- Bitwarden: `xcodebuild build-for-testing` and `test-without-building` on a pinned Xcode (`.xcode-version`), with coverage. SwiftLint runs as a build phase on developer Macs.
- Element X: unit tests through `swift run tools ci unit-tests`. UI, accessibility and integration tests run in separate workflows. SwiftLint runs after the build.
- Proton: SwiftFormat and `swiftlint lint --strict` in pre-commit.
- libsignal: `swift format` plus `git diff --exit-code`, SwiftLint, `swift test`, and `build_ffi.sh --verify-ffi`, which checks that the generated headers are up to date.
- Firefox: one pinned SwiftLint version for local and CI runs.

**Standard:** build and unit-test with `xcodebuild` on a pinned Xcode, lint, and check formatting on every change. UI tests run separately.

**For us, in `scripts/check.sh`:**
- **G1:**
  - `swift format lint --strict --recursive macos/`.
  - `swiftlint lint --strict` once it is installed.
  - Remove the `ui-local` step.
  - The unsafe count lets `larsal-ffi` pass when its source has no hand-written `unsafe`.
- **G2:** `scripts/build-core.sh`, then `xcodebuild test ... -skip-testing:LarsalUITests` with `SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` and `DEVELOPER_DIR` set.
- **G8 (Mac QA):** the `LarsalUITests` suite plus screenshots. It needs a logged-in screen session, so it stays out of `check.sh`.

The bindings are rebuilt on every run and never stored, so no freshness check is needed.

Sources: [Bitwarden test workflow](https://github.com/bitwarden/ios/blob/main/.github/workflows/test.yml), [Element X workflows](https://github.com/element-hq/element-x-ios/tree/develop/.github/workflows), [Proton pre-commit](https://github.com/protonpass/ios-pass/blob/main/.pre-commit-config.yaml), [libsignal CI](https://github.com/signalapp/libsignal/blob/main/.github/workflows/build_and_test.yml), [Firefox .swiftlint-version](https://github.com/mozilla-mobile/firefox-ios/blob/main/.swiftlint-version)

## What changes in our plan

These are edits for the lead to make. This research changes no other file. Edits 1 to 28 and 32 to 34 were applied on 2026-10-27 (LD-156); 29 to 31 are done by the Builder in E5-S1. Our rules stay as they are: secrets stay in Rust, only Show crosses, crypto only in `larsal-crypto`, demo data only.

**AGENTS.md**
1. Naming table: `larsal-desktop` becomes `larsal-ffi`. Add the row "Xcode project: `macos/Larsal.xcodeproj`, scheme `Larsal`".
2. "Where things are": add `macos/` (Swift app) and this file.

**README.md**
3. Checks: G1 gains Swift format and SwiftLint; G2 gains `build-core.sh` and `xcodebuild test`. Add a note on `DEVELOPER_DIR`.
4. D7: add "also needed for Touch ID quick unlock in signed builds (provisioning profile, TN3137)".

**plan/architecture.md**
5. The shape:

   ```
   macos/ (SwiftUI) → larsal-ffi (UniFFI) → larsal-core → larsal-format → larsal-model
   larsal-crypto (the only door to crypto)
   larsal-platform (used by larsal-ffi and larsal-cli)
   ```

   Remove `ui/` and Tauri.
6. Folders:
   - Remove `ui/` and `crates/larsal-desktop/`.
   - Add `crates/larsal-ffi/`, `crates/uniffi-bindgen/` and `scripts/build-core.sh`.
   - Add `macos/`, holding `Larsal.xcodeproj`, `Larsal/`, `LarsalTests/`, `LarsalUITests/`, `Larsal.entitlements` and `LarsalCore/Package.swift`. The generated `LarsalFFI.xcframework` and Swift sources are not kept.
7. `larsal-platform`:
   - Keep `clipboard.rs` (now also for `larsal-cli`, SC-07), `quick_unlock.rs` (Keychain through `security-framework`), `hardening.rs`, `memory.rs`, `net.rs` and `macos/`.
   - Move `lock_signals.rs` and `screen.rs` to Swift (`macos/Larsal/Platform/`).
8. The `larsal-desktop` section becomes `larsal-ffi`:
   - Keep `session.rs`, `messages.rs`, `cli.rs` and `instance.rs`.
   - Add the UniFFI Objects (Session, Vault), a `log.rs` callback, and `API.md` (replaces `COMMANDS.md`: every exported function, its inputs and outputs, and the one secret it returns, for Show only).
   - Drop `main.rs`, `build.rs`, `tauri.conf.json`, `capabilities/`, `gen/`, `permissions/` and `icons/`.
9. The `ui/` section becomes `macos/`: SwiftUI screens from the mockup, `@Observable` view models, and `Platform/` (lock signals, window guard with `sharingType` and secure input, biometry availability, log sink). The rules:
   - No secret kept beyond Show.
   - Vault text shown as plain `String` text, never through `LocalizedStringKey` or Markdown.
   - The look matches the mockup.
10. Approved crates:
    - Remove `tauri` and `tauri-build`.
    - Add `uniffi` `=0.32.2` (MPL-2.0: named `deny.toml` exceptions, AT-J03).
    - Remove `objc2-local-authentication`.
    - Keep `objc2`, `objc2-foundation`, `objc2-app-kit` (clipboard) and `security-framework` (Keychain).
    - `libc`: drop "and tauri".
    - Note for E6-S3: SR-04's AES-256-GCM needs `aes-gcm` in `larsal-crypto` (AT-J03), or a lead ruling to use the approved `aes`, `cbc` and `hmac`.
11. Rust rules:
    - Rule 2: `larsal-ffi` joins the exceptions for generated scaffolding only, with no hand-written `unsafe`. Expected because the scaffolding exports C symbols; neither Bitwarden's nor matrix's bindings crate forbids unsafe. E5-S1 confirms this on the first build.
    - Rule 8: messages come from `larsal-ffi`.
    - Rule 11: add "a Rust panic ends the app (`panic = "abort"`); UniFFI cannot turn it into a Swift error; this fails closed and is accepted".
12. New "Swift rules":
    - Swift 6 with the main actor as default isolation; macOS 14.
    - `swift format` and SwiftLint.
    - Swift Testing and XCTest UI tests.
    - `os.Logger`.
    - No Swift package from outside without an AT-J03 review.
13. Main flows: Copy is a Rust call and the value never reaches Swift. Show returns one `String`.

**plan/epics.md**
14. E5 title: "Mac app (larsal-ffi, macos/)".
15. E5-S1 rewritten as "Native shell and Rust bridge":
    - `larsal-ffi` with UniFFI 0.32.2 proc-macros, `crates/uniffi-bindgen`, and `scripts/build-core.sh` (staticlib to xcframework to `LarsalCore` package).
    - `macos/Larsal.xcodeproj` with Swift 6, macOS 14, hardened runtime, no sandbox, and a hidden title bar window.
    - The APP-09 part 2 Rust code is reused.
    - Checks: `check.sh` passes with the new Swift steps; AT-E08; `otool -L` shows no WebKit; `cargo deny check` passes with the UniFFI exceptions.
    - Tauri files and `ui/` are deleted.
16. E5-S2: `COMMANDS.md` becomes `crates/larsal-ffi/API.md`. AT-E03 is the new boundary check. Copy uses E6-S1 (built first, or a stub).
17. E5-S3: password fields are `SecureField`; AT-D05.
18. E5-S4: AT-E01 and AT-E02 in the new wording. The LD-152 navigation guard is dropped (there is no web view).
19. E5-S5: AT-E06 with SwiftUI drop targets. E5-S11: SwiftUI commands plus the AppKit menu bar icon.
20. E6 title: "(larsal-platform, macos/)".
    - E6-S1: Rust clipboard, shared with `larsal-cli`.
    - E6-S2: Swift lock signals.
    - E6-S3: Rust Keychain through `security-framework`, Swift availability check, needs a signing team.
    - E6-S4: add the hardened runtime check.
    - E6-S5: Swift `sharingType` and secure input.
    - E6-S6: add "Swift view state holds no secret after Hide or lock".
21. E14-S3: Developer ID, `notarytool`, `stapler`, release entitlements `keychain-access-groups` only, no sandbox. The x86_64 slice is decided here (it needs the target installed).

**plan/attacks-and-checks.md**
22. Rename AT-E to "Screen layer and the Swift–Rust boundary":
    - **AT-E01:** Markdown, link and control-character text in every field is shown as plain text.
    - **AT-E02:** the URL opener refuses `file:`, `javascript:`, `data:` and unknown schemes.
    - **AT-E03:** call every `larsal-ffi` export with hostile arguments, after lock and from two threads at once. Passes with a typed error, no panic, and no secret in the error.
    - **AT-E04 retired:** there is no web engine. Replaced by "`otool -L` lists no WebKit", plus E6-S7's network capture.
    - **AT-E05 retired:** covered by AT-C03 and AT-J05.
    - **AT-E06:** unchanged.
    - **AT-E07:** check the Swift view state and the process memory after Hide and lock (one process now).
    - **AT-E08:** unchanged.
23. AT-D04: test the screenshot tool, screen recording (ScreenCaptureKit) and screen sharing, and record each result. Apple calls `sharingType = .none` legacy, so the pass rule becomes "set on every window, result per capture path recorded".
24. AT-J05: add `codesign -d --entitlements -` (no `get-task-allow`), `codesign -dv` (runtime flag), `spctl -a -vv` and `stapler validate`.
25. Gates: G1 and G2 tools as in point 9. G8 uses `LarsalUITests`.

**plan/security.md**
26. Change the component column:
    - SC-04, SC-05, SC-06, SR-01, SR-02 and SR-06 move from `ui` and `larsal-platform` to `macos`.
    - SR-03, SR-08, SR-09, SF-16 and SC-08 move from `larsal-desktop` to `larsal-ffi` and `macos`.
    - SR-04 becomes `larsal-platform` and `macos`.
27. SC-05: note Apple's legacy wording.

**plan/team.md**
28. Builders of `macos/` stories write Swift under the same clean room. Mac QA may drive XCUITest.

**scripts/check.sh, Cargo.toml, deny.toml**
29. `check.sh`:
    - Default `DEVELOPER_DIR` to `/Applications/Xcode.app/Contents/Developer`.
    - Add the Swift steps of point 9.
    - Remove `ui_local`.
    - Allow `larsal-ffi` in the unsafe count.
30. `Cargo.toml`: remove the `tauri` pins and add `uniffi = "=0.32.2"`. `larsal-ffi` opts out of the workspace `unsafe_code = "forbid"`, as `larsal-platform` does.
31. `deny.toml`: remove the five Tauri MPL-2.0 exceptions and the Tauri skips. Add exact-version MPL-2.0 exceptions for the UniFFI crates.

**spec/decisions.md**
32. Add a new LD row for these choices with this file as the source (rule 9).
33. Mark LD-150, LD-151, LD-152 and LD-154 superseded. Keep LD-153's APP-09 split, with `larsal-ffi` in place of `larsal-desktop`.
34. Open items, "Thread CPU-time clock": "the first binary" becomes `larsal-ffi`.
